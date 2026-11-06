"""Agent管理HTTP、节点身份及短期状态缓存；失败不重试变更。"""
from __future__ import annotations
import json
import logging
import threading
import time
from .http_client import file_headers, request

# 保留迁移前的运行日志分类名。
LOG = logging.getLogger("inference_guardian.controller")

class NodeClient:
    """通过认证管理接口访问Agent；请求失败保留未知状态，不猜测容器已停止。"""

    def __init__(self, nodes, timeout=5):
        self.nodes, self.timeout = nodes, timeout
        self.status_locks = {node["url"]: threading.Lock() for node in nodes.values()}
        self.status_cache = {}

    def call(self, node_id, path, payload=None, timeout=None):
        node = self.nodes[node_id]
        status, _, body = request(node["url"].rstrip("/") + path,
            "POST" if payload is not None else "GET", payload, file_headers(node),
            timeout or self.timeout, ca_file=node.get("ca_file"),
            cert_file=node.get("cert_file"), key_file=node.get("key_file"))
        if status != 200:
            raise RuntimeError(f"node operation HTTP {status}")
        result = json.loads(body)
        if not isinstance(result, dict) or result.get("node_id") != node_id:
            raise RuntimeError("Agent identity missing or different from configured node")
        return result

    def status(self, node_id, *, fresh=False):
        """合并同一Agent的极短期状态查询，减少多个恢复组同时采集造成的争用。"""
        endpoint = self.nodes[node_id]["url"]
        # 锁按Agent地址共享；缓存只用于观测，不能作为变更成功的持久证据。
        with self.status_locks[endpoint]:
            cached = self.status_cache.get(endpoint)
            if not fresh and cached and time.monotonic() - cached[0] < 0.25:
                return cached[1]
            try:
                value = self.call(node_id, "/v1/status", timeout=self.nodes[node_id].get("status_timeout_seconds", self.timeout))["containers"]
                if not isinstance(value, dict) or not all(isinstance(v, dict) for v in value.values()):
                    raise ValueError("Agent container observations malformed")
                expected = self.nodes[node_id].get("expected_bootstrap_stage_hashes")
                if expected is not None:
                    if set(value) != set(expected):
                        raise ValueError("Agent allowlist differs from the adopted contract")
                    for name, observed in value.items():
                        if observed.get("bootstrap_stage_hashes") != expected[name]:
                            observed.update(configuration_ok=False, detail="Agent startup contract differs from adoption")
            except Exception as exc:
                LOG.warning("node status unavailable node=%s error=%s", node_id, type(exc).__name__)
                value = None
            self.status_cache[endpoint] = (time.monotonic(), value)
            return value

    def action(self, member, action, action_id, generation, group, stop_timeout=30, stage=None):
        """发送具备动作ID和代次的固定操作；bootstrap只传阶段名，不传可执行命令。"""
        payload = {
            "node_id": member["node"], "action_id": action_id, "container": member["container"], "action": action,
            "generation": generation, "recovery_group": group,
            "stop_timeout_seconds": stop_timeout,
        }
        if stage is not None:
            payload["stage"] = stage
        try:
            result = self.call(member["node"], "/v1/action", payload,
                               timeout=self.nodes[member["node"]].get("action_timeout_seconds", max(self.timeout, stop_timeout + 55)))
            if result.get("ok") is not True or result.get("action_id") != action_id:
                raise RuntimeError("node action not confirmed")
            return result
        finally:
            # 失败响应也可能发生在Docker已执行之后。等待旧状态采样结束再失效缓存，
            # 防止一个早于动作的在途status在pop之后又写回旧缓存。
            endpoint = self.nodes[member["node"]]["url"]
            with self.status_locks[endpoint]:
                self.status_cache.pop(endpoint, None)

