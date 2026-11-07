"""执行有界HTTP/TCP探针并分类证据，不在本模块直接决定是否重启模型。

pass表示当前配置的状态码与断言通过，fail表示获得了不符合预期的响应，
unknown表示网络/鉴权/端点/容量等原因使观测不足；三者都不是硬件诊断结论。
"""
from __future__ import annotations

from .._compat import _retain_import_identity

_retain_import_identity(__name__, "inference_guardian.probes")

from dataclasses import dataclass
import json
import socket
import time
import uuid
from urllib.parse import urlsplit

from ..http_client import request, file_headers


@dataclass
class ProbeResult:
    """统一携带探针分类、可选HTTP状态和解析结果，供Controller结合其他证据判断。"""

    state: str
    status: int | None = None
    reason: str = ""
    data: object = None
    elapsed: float = 0


def lookup(data, path):
    """按点分路径读取JSON对象或数组，例如choices.0.message.content。"""
    for key in path.split(".") if path else []:
        data = data[int(key)] if isinstance(data, list) else data[key]
    return data


def matches(data, checks):
    """同一断言列表按AND求值；路径缺失或类型不匹配视为不通过。

    空列表表示没有额外约束。exists只要求路径可读取，即使其值为None也成立；
    nonempty则使用值的真假判断，二者不能互相替代。
    """
    for check in checks:
        try:
            value = lookup(data, check["path"])
            op, expected = check["op"], check.get("value")
            if op == "exists":
                passed = True
            elif op == "nonempty":
                passed = bool(value)
            elif op == "equals":
                passed = value == expected
            elif op == "contains":
                passed = expected in value
            elif op == "gte":
                passed = not isinstance(value, bool) and isinstance(value, (float, int)) and value >= expected
            elif op == "lte":
                passed = not isinstance(value, bool) and isinstance(value, (float, int)) and value <= expected
            else:
                passed = False
            if not passed:
                return False
        except (KeyError, IndexError, TypeError, ValueError):
            return False
    return True


def run_probe(config, default_timeout=5):
    """执行单次探针，应用响应大小/超时限制及必选、备选JSON断言。

    json_checks中的条件必须全部通过；配置json_any_checks时还须至少一个分支
    完整通过，用于content或reasoning_content等不同合法输出。此函数不重试。
    """
    started = time.monotonic()
    try:
        if config["url"].startswith("tcp://"):
            # 连接成功仅证明监听存在，不证明Mooncake协议/KV传输正常；失败是unknown。
            endpoint = urlsplit(config["url"])
            with socket.create_connection((endpoint.hostname, endpoint.port),
                                          timeout=config.get("timeout_seconds", default_timeout)):
                return ProbeResult("pass", reason="tcp_connected", elapsed=time.monotonic()-started)
        payload = config.get("json")
        if config.get("nonce"):
            # 每次请求使用新标记，降低重复canary复用同一缓存结果的机会；这不
            # 证明绕过所有缓存，也不保证一次请求覆盖所有P/D路由组合。
            nonce = uuid.uuid4().hex
            def substitute(value):
                if isinstance(value, str):
                    return value.replace("{{nonce}}", nonce)
                if isinstance(value, dict):
                    return {k: substitute(v) for k, v in value.items()}
                if isinstance(value, list):
                    return [substitute(v) for v in value]
                return value
            payload = substitute(payload)
        status, headers, body = request(config["url"], config.get("method", "GET"), payload,
            file_headers(config), config.get("timeout_seconds", default_timeout),
            config.get("max_response_bytes", 1024 * 1024), config.get("ca_file"),
            config.get("cert_file"), config.get("key_file"))
        # 鉴权、端点配置或限流不能作为引擎死亡证据，保留unknown供上层处理。
        if status in {401, 403, 404, 429}:
            return ProbeResult("unknown", status, "auth_endpoint_or_capacity", elapsed=time.monotonic()-started)
        if status != config.get("expected_status", 200):
            return ProbeResult("fail", status, "unexpected_status", elapsed=time.monotonic()-started)
        data = None
        if config.get("json_checks") or config.get("json_any_checks") or config.get("parse_json"):
            try:
                data = json.loads(body)
            except (ValueError, UnicodeError):
                return ProbeResult("fail", status, "invalid_json")
        lower_headers = {k.lower(): v for k, v in headers.items()}
        if config.get("content_type_prefix") and not lower_headers.get("content-type", "").startswith(config["content_type_prefix"]):
            return ProbeResult("fail", status, "content_type")
        if len(body) < config.get("min_response_bytes", 0):
            return ProbeResult("fail", status, "empty_result")
        if not matches(data, config.get("json_checks", [])) or (
            "json_any_checks" in config and not any(matches(data, checks) for checks in config["json_any_checks"])
        ):
            return ProbeResult("fail", status, "result_assertion")
        return ProbeResult("pass", status, "ok", data, time.monotonic()-started)
    except (OSError, ValueError, http_error_types()) as exc:
        # 超时、连接/TLS错误等只表示观测不足。不能把“没有拿到响应”写成
        # 引擎明确返回503，避免上层错误累计连续故障；日志也不携带请求正文。
        return ProbeResult("unknown", reason=type(exc).__name__, elapsed=time.monotonic()-started)


def http_error_types():
    """提供标准库HTTP异常类型，使传输失败统一归为unknown。"""
    import http.client
    return http.client.HTTPException
