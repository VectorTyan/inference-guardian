"""将明确授权的健康端点错误转为重启证据，避免Proxy/容量503误触发整组恢复。"""
from __future__ import annotations

from .._compat import _retain_import_identity

_retain_import_identity(__name__, "inference_guardian.health_policy")

import hashlib


def health_failure_key(spec, index):
    """内部计数身份保持索引/方法/URL绑定，不因显示名称变化而串接故障证据。"""
    identity = f"{index}:{spec.get('method', 'GET')}:{spec['url']}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def health_failure_counts(checks, results, previous):
    """每个端点独立连续计数；未显式配置restart_on_status的响应只影响就绪。

    端点索引、方法和URL共同绑定计数，防止不同节点交替报错拼成三次连续失败。
    未知/成功或其它状态清零该端点计数；控制面unknown仍由Controller优先阻断。
    """
    counts = {}
    for index, (spec, result) in enumerate(zip(checks, results)):
        # 状态会通过运维CLI输出；URL可能含敏感查询参数，只持久化端点摘要。
        key = health_failure_key(spec, index)
        confirmed = result.state == "fail" and result.status in spec.get("restart_on_status", [])
        counts[key] = previous.get(key, 0) + 1 if confirmed else 0
    return counts


def management_issue(statuses):
    """按既有优先级返回(阶段,原因,是否清故障计数)，不修改状态或采集证据。"""
    if any(s.get("operation_busy") is True for s in statuses.values()):
        return "UNKNOWN", "node_action_pending_or_unconfirmed", True
    if any(s.get("requires_bootstrap") is True and s.get("bootstrap_configured") is not True
           for s in statuses.values()):
        return "QUARANTINED", "model_startup_contract_missing", False
    if any(s.get("state") == "unknown" for s in statuses.values()):
        return "UNKNOWN", "node_or_container_status_unavailable", True
    if any(s.get("restart_policy", "no") not in {"no", ""} for s in statuses.values()):
        return "QUARANTINED", "competing_container_restart_policy", False
    if any(s.get("auto_remove") is True for s in statuses.values()):
        return "QUARANTINED", "auto_remove_container", False
    if any(s.get("configuration_ok") is False for s in statuses.values()):
        return "QUARANTINED", "node_configuration_mismatch", False
    return None


def management_contract_confirmed(statuses):
    """变更前的严格管理门槛；启动阶段不要求进程规则已匹配。"""
    return not any(item.get("state") not in {"running", "stopped", "unhealthy"}
                   or item.get("configuration_ok") is not True or item.get("operation_busy") is not False
                   or item.get("restart_policy") not in {"no", ""} or item.get("auto_remove") is not False
                   or (item.get("requires_bootstrap") is True and item.get("bootstrap_configured") is not True)
                   for item in statuses.values())


def inference_healthy(statuses, hard_failure, health_ok, canary_ok):
    """完整就绪条件，保留旧Agent字面进程规则失败的窄兼容分支。"""
    return not hard_failure and health_ok and canary_ok and all(
        s.get("state") == "running" or (s.get("state") == "unhealthy" and s.get("running") is True
            and s.get("process_ok") is False and s.get("detail") == "Required process count not satisfied")
        for s in statuses.values())


def recovery_reason(hard_failure, explicit_engine_dead, confirmed_stall, retry_now):
    """按原优先级选择恢复原因；返回None表示本轮没有恢复授权。"""
    if hard_failure:
        return "container_confirmed_stopped"
    if explicit_engine_dead:
        return "explicit_engine_health_failure"
    if confirmed_stall:
        return "confirmed_stall"
    if retry_now:
        return "previous_recovery_incomplete"
    return None
