"""校验Controller恢复配置，并解析相对于配置文件的状态及凭据路径。

这里只校验配置结构与成员归属，不推导真实TP/DP/EP通信拓扑，也不证明模型或NPU兼容。
"""
from __future__ import annotations

from .._compat import _retain_import_identity

_retain_import_identity(__name__, "inference_guardian.config")

import copy
import hashlib
import json
import math
from pathlib import Path
import re
from urllib.parse import urlsplit

from .topology import canary_specs, validate_layout
from ..health.identity import probe_id
from .recovery_scope import validate_partial
from ..health.process_evidence import validate_detection

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
DEFAULT_POLICY = {
    # 这些门限分别控制采样、业务探针和冷启动；不能把慢Prefill统一按一个短超时判死。
    "poll_interval_seconds": 5, "request_timeout_seconds": 5,
    "failure_threshold": 3, "canary_interval_seconds": 60,
    "canary_max_age_seconds": 300,
    "startup_timeout_seconds": 900, "stop_timeout_seconds": 30,
    "backoff_seconds": 30, "max_attempts": 2,
    "max_attempts_per_window": 3, "attempt_window_seconds": 3600,
    "stable_reset_seconds": 600, "drain_seconds": 15,
    "ramp_up_seconds": 60,
    "readiness_ttl_seconds": 30,
    "stall_after_seconds": 600, "progress_max_age_seconds": 30,
}


class ConfigError(ValueError):
    """表示配置不满足恢复契约；应在启动前修复，不将其当作模型故障。"""
    pass


def require(condition, message):
    """统一将不满足的配置条件转为带定位信息的ConfigError。"""
    if not condition:
        raise ConfigError(message)


def valid_url(url, label):
    """检查HTTP(S)地址和端口格式，禁止在URL内嵌凭据或片段。"""
    try:
        parsed = urlsplit(url)
        _ = parsed.port
        require(parsed.scheme in {"http", "https"} and bool(parsed.hostname), f"{label}: HTTP(S) URL required")
        require(not parsed.username and not parsed.password and not parsed.fragment,
                f"{label}: credentials/fragments in URL are forbidden; use files")
    except (ValueError, TypeError):
        raise ConfigError(f"{label}: invalid URL") from None


def validate_checks(checks, label, *, nonempty=False):
    """校验JSON断言列表及比较操作的参数；这里只检查语法，不执行请求。"""
    require(isinstance(checks, list) and (checks or not nonempty),
            f"{label}: {'nonempty ' if nonempty else ''}assertion list required")
    for check in checks:
        require(isinstance(check, dict), f"{label}: assertion object required")
        op = check.get("op")
        require(isinstance(op, str) and op in {"equals", "nonempty", "contains", "gte", "lte", "exists"},
                f"{label}: invalid assertion")
        require(isinstance(check.get("path"), str), f"{label}: assertion path required")
        if op in {"equals", "contains", "gte", "lte"}:
            require("value" in check, f"{label}: {op} assertion value required")
        if op in {"gte", "lte"}:
            value = check["value"]
            require(type(value) in (int, float) and math.isfinite(value),
                    f"{label}: {op} assertion value must be finite numeric")


def validate_probe(probe, label):
    """检查探针方法、断言及资源上限，要求凭据使用文件引用。"""
    require(isinstance(probe, dict), f"{label}: object required")
    if "id" in probe:
        require(isinstance(probe["id"], str) and IDENTIFIER.fullmatch(probe["id"]), f"{label}: invalid probe id")
    if "description" in probe:
        description = probe["description"]
        require(isinstance(description, str) and 1 <= len(description) <= 256 and description.isprintable(),
                f"{label}: description must be 1-256 printable characters")
    if isinstance(probe.get("url"), str) and probe["url"].startswith("tcp://"):
        # Mooncake master没有HTTP健康接口；TCP只作为监听门槛，不授权重启。
        require(not set(probe) - {"url", "timeout_seconds", "id", "description"},
                f"{label}: TCP probes only accept url, timeout_seconds, id and description")
        try:
            parsed = urlsplit(probe["url"])
            require(bool(parsed.hostname) and parsed.port is not None and 1 <= parsed.port <= 65535,
                    f"{label}: TCP host and explicit port required")
            require(not (parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment),
                    f"{label}: TCP URL must contain only host and port")
        except (ValueError, TypeError):
            raise ConfigError(f"{label}: invalid TCP URL") from None
        timeout = probe.get("timeout_seconds", 5)
        require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 120,
                f"{label}: TCP timeout must be finite and in (0, 120]")
        return
    valid_url(probe.get("url"), label)
    require(probe.get("method", "GET") in {"GET", "POST"}, f"{label}: method must be GET or POST")
    require("headers" not in probe, f"{label}: use header_files, not inline secret headers")
    if "restart_on_status" in probe:
        statuses = probe["restart_on_status"]
        require(isinstance(statuses, list) and all(type(code) is int and 500 <= code <= 599 for code in statuses),
                f"{label}: restart_on_status must contain explicit 5xx engine-failure statuses")
        require(len(statuses) == len(set(statuses)) and probe.get("expected_status", 200) not in statuses,
                f"{label}: restart statuses cannot repeat or equal expected_status")
    validate_checks(probe.get("json_checks", []), f"{label}.json_checks")
    if "json_any_checks" in probe:
        branches = probe["json_any_checks"]
        require(isinstance(branches, list) and branches, f"{label}.json_any_checks: nonempty branch list required")
        for index, checks in enumerate(branches):
            validate_checks(checks, f"{label}.json_any_checks[{index}]", nonempty=True)
    for key in ("timeout_seconds", "max_response_bytes"):
        if key in probe:
            require(type(probe[key]) in (int, float) and math.isfinite(probe[key]) and probe[key] > 0,
                    f"{label}: {key} must be finite and positive")
    for key in ("max_response_bytes", "min_response_bytes"):
        if key in probe:
            require(type(probe[key]) is int and probe[key] > 0, f"{label}: {key} must be positive integer")


def validate(config):
    """返回带默认策略的深拷贝，并校验恢复组、成员和启动阶段一致性。

    同一节点容器只能归一个恢复组；start_steps必须完整且不重复覆盖成员。
    bootstrap步骤只能选择已定义成员与阶段，canary必须校验内容，不能仅依赖HTTP 200。
    """
    require(isinstance(config, dict), "config must be an object")
    c = copy.deepcopy(config)
    require(c.get("version") == 1, "version must be 1")
    require(c.get("mode", "observe") in {"observe", "auto"}, "mode must be observe or auto")
    c.setdefault("mode", "observe")
    require(isinstance(c.get("state_dir"), str) and c["state_dir"], "state_dir required")
    supplied_policy = c.get("policy", {})
    require(not set(supplied_policy) - set(DEFAULT_POLICY), "unknown policy keys")
    # 同时服务Python3.7宿主的接管/Token校验；不能使用Python3.9的dict合并运算符。
    c["policy"] = dict(DEFAULT_POLICY, **supplied_policy)
    for key, value in c["policy"].items():
        require(type(value) in (int, float) and math.isfinite(value) and value > 0,
                f"policy.{key} must be finite and positive")
    for key in ("failure_threshold", "max_attempts", "max_attempts_per_window"):
        require(type(c["policy"][key]) is int, f"policy.{key} must be integer")
    require(type(c["policy"]["stop_timeout_seconds"]) is int and c["policy"]["stop_timeout_seconds"] <= 120,
            "policy.stop_timeout_seconds must be an integer in 1..120 (node protocol)")
    require(isinstance(c.get("nodes"), dict) and c["nodes"], "nodes required")
    endpoints = set()
    for node_id, node in c["nodes"].items():
        require(isinstance(node, dict), "node must be an object")
        require(isinstance(node_id, str) and IDENTIFIER.fullmatch(node_id), "invalid node identifier")
        valid_url(node.get("url"), f"node {node_id}")
        parsed = urlsplit(node["url"])
        require(not parsed.query, "management URL must not contain a query")
        endpoint = (parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80), parsed.path.rstrip("/"))
        require(endpoint not in endpoints, "multiple node IDs cannot share one Agent endpoint")
        endpoints.add(endpoint)
        require(node.get("token_file"), f"node {node_id}: token_file required")
        require(node["url"].startswith("https://") or node.get("allow_insecure_http") is True,
                f"node {node_id}: HTTP requires explicit allow_insecure_http")
    groups = c.get("groups")
    require(isinstance(groups, list) and groups, "at least one group required")
    # 阻止两个恢复组对同一模型容器下发竞争动作；不会自动推导通信组成员。
    ids, ownership = set(), set()
    for group in groups:
        require(isinstance(group, dict), "group must be an object")
        gid = group.get("id", "")
        require(IDENTIFIER.fullmatch(gid) and gid not in ids, "group id invalid or duplicated")
        ids.add(gid)
        require(group.get("framework") in {"vllm-ascend", "vllm-omni"}, f"{gid}: unknown framework")
        require(group.get("topology") in {"pd_disaggregated", "multi_node_mixed", "single_node_mixed"},
                f"{gid}: unknown topology")
        require(isinstance(group.get("members"), list) and group["members"], f"{gid}: members required")
        members = set()
        hosts = set()
        for member in group["members"]:
            require(isinstance(member, dict), f"{gid}: member must be an object")
            mid = member.get("id", "")
            require(IDENTIFIER.fullmatch(mid) and mid not in members, f"{gid}: member id invalid/duplicated")
            members.add(mid)
            require(member.get("node") in c["nodes"], f"{gid}/{mid}: unknown node")
            hosts.add(member["node"])
            require(IDENTIFIER.fullmatch(member.get("container", "")), f"{gid}/{mid}: invalid container name")
            key = (member["node"], member["container"])
            require(key not in ownership, "a container cannot belong to multiple recovery groups")
            ownership.add(key)
        if group["topology"] == "single_node_mixed":
            require(len(hosts) == 1, f"{gid}: single_node_mixed must use one node")
        validate_layout(group, members, require, validate_probe)
        require(isinstance(group.get("health_checks"), list) and group["health_checks"], f"{gid}: health_checks required")
        for probe in group["health_checks"]:
            validate_probe(probe, f"{gid}: health check")
        names = [probe_id(spec, index) for index, spec in enumerate(group["health_checks"])]
        require(len(names) == len(set(names)), f"{gid}: health probe ids must be unique")
        # 可选局部恢复不改变旧配置规范化结果；引用完整逻辑实例及已授权健康点。
        validate_partial(group, require, validate_probe, validate_layout)
        validate_detection(group, require)
        require(("canary" in group) != ("canaries" in group), f"{gid}: configure either canary or canaries")
        checks = canary_specs(group)
        require(isinstance(checks, list) and 0 < len(checks) <= 32, f"{gid}: canaries must be a bounded nonempty list")
        for canary in checks:
            validate_probe(canary, f"{gid}: canary")
            require(canary.get("json_checks") or canary.get("json_any_checks") or canary.get("min_response_bytes"),
                    f"{gid}: canary must assert result content, not only HTTP status")
        names = [probe_id(spec, index) for index, spec in enumerate(checks)]
        require(len(names) == len(set(names)), f"{gid}: canary ids must be unique")
        for key in ("stall_probe", "quarantine_probe"):
            if group.get(key):
                validate_probe(group[key], f"{gid}: {key}")
        if group.get("quarantine_probe"):
            predicate = group["quarantine_probe"]
            require(predicate.get("json_checks") or predicate.get("json_any_checks"),
                    f"{gid}: quarantine predicate required")
        route = group.get("route")
        require(isinstance(route, dict), f"{gid}: route required")
        valid_url(route.get("url"), f"{gid}: route")
        require(type(route.get("max_inflight", 1)) is int and route.get("max_inflight", 1) > 0,
                f"{gid}: max_inflight must be positive integer")
        require("headers" not in route, f"{gid}: use route.header_files")
    gateway = c.get("gateway", {})
    require(type(gateway.get("enabled", True)) is bool, "gateway.enabled must be boolean")
    require(type(gateway.get("listen_port")) is int and 1 <= gateway["listen_port"] <= 65535,
            "gateway.listen_port required")
    require(gateway.get("listen_host"), "gateway.listen_host required")
    return c


def load_config(path):
    # 文件引用绑定配置目录，不能随运维命令的工作目录漂移到另一套凭据或状态。
    """读取并校验JSON，将相对文件引用绑定到配置所在目录。

    避免切换工作目录后读取不同凭据；header_files的键是HTTP头名，需单独解析其值。
    """
    path = Path(path).resolve()
    c = json.loads(path.read_text(encoding="utf-8"))
    def resolve(value, key=""):
        if isinstance(value, dict):
            return {k: resolve(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [resolve(v) for v in value]
        if isinstance(value, str) and (key.endswith("_file") or key == "state_dir"):
            return str((path.parent / value).resolve())
        return value
    c = resolve(c)
    # header_files的键是HTTP头名而非*_file，所以其值需单独做路径解析。
    def resolve_headers(value):
        if isinstance(value, dict):
            for k, v in value.items():
                if k == "header_files":
                    value[k] = {h: str((path.parent / p).resolve()) for h, p in v.items()}
                else:
                    resolve_headers(v)
        elif isinstance(value, list):
            for v in value:
                resolve_headers(v)
    resolve_headers(c)
    return validate(c)


def config_hash(c):
    """为已解析的完整配置计算稳定指纹，用于拒绝旧配置下的状态或就绪证据。"""
    return hashlib.sha256(json.dumps(c, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
