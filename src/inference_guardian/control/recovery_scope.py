"""显式配置的局部恢复：保留成员必须健康，未知不能扩大故障范围。

同一恢复组仍共享预算、代次和管理屏障。这里只选择/构造计划，不发送动作；
Controller在首次变更前持久化选择，重启后不能把局部失败默认为全组故障。
"""
from __future__ import annotations

from .._compat import _retain_import_identity

import hashlib
import json

from ..health.policy import health_failure_key
from .topology import recovery_steps
from ..health.process_evidence import confirmed_exits


def plan_hash(group):
    return hashlib.sha256(json.dumps(group, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def select_scope(group, runtime, statuses, results, threshold):
    """返回(kind,阻断原因)。只有明确故障或已落盘的同契约恢复才能授权动作。"""
    policy = group["partial_recovery"]
    previous = runtime.get("recovery_scope") if runtime.get("recovery_required") else None
    if runtime.get("recovery_required") and (not isinstance(previous, dict)
            or previous.get("kind") not in {"partial", "full"} or previous.get("plan_hash") != plan_hash(group)):
        return None, "recovery_scope_missing_or_changed"
    probes = group["health_checks"]
    by_id = {p["id"]: (index, p, result) for index, (p, result) in enumerate(zip(probes, results))}
    counts = runtime.get("health_failure_counts", {})
    process_exits = confirmed_exits(group, runtime, statuses, results)

    def failed(members, names):
        return any(statuses[mid].get("state") == "stopped" or mid in process_exits for mid in members) or any(
            result.state == "fail" and result.status in spec.get("restart_on_status", [])
            and counts.get(health_failure_key(spec, index), 0) >= threshold
            for index, spec, result in (by_id[name] for name in names))

    if len(results) != len(probes):
        return None, "recovery_probe_results_incomplete"
    if failed(policy["preserved_members"], policy["preserved_checks"]):
        return "full", None
    if previous and previous["kind"] == "full":
        return "full", None
    preserved_ok = all(statuses[mid].get("running") is True for mid in policy["preserved_members"])
    preserved_ok = preserved_ok and all(by_id[name][2].state == "pass" for name in policy["preserved_checks"])
    if not preserved_ok:
        return None, "preserved_members_not_confirmed_healthy"
    if failed(policy["members"], policy["fault_checks"]) or previous:
        return "partial", None
    return None, "fault_scope_not_confirmed"


def execution_plan(group, runtime):
    """未声明局部策略的历史配置保持完整恢复；不注入默认字段改变旧哈希。"""
    if group.get("partial_recovery") and runtime.get("recovery_scope", {}).get("kind") == "partial":
        policy = group["partial_recovery"]
        return [m for m in group["members"] if m["id"] in policy["members"]], policy["recovery_steps"]
    return group["members"], recovery_steps(group)


def validate_partial(group, require, validate_probe, validate_layout):
    """局部步骤仅允许复用全计划相同成员/阶段；覆盖完整逻辑实例，不拆rank。"""
    if "partial_recovery" not in group:
        return
    policy = group["partial_recovery"]
    keys = {"members", "preserved_members", "fault_checks", "preserved_checks", "recovery_steps"}
    require(isinstance(policy, dict) and set(policy) == keys, "invalid partial_recovery fields")
    all_members = {m["id"] for m in group["members"]}
    for key in ("members", "preserved_members", "fault_checks", "preserved_checks"):
        value = policy[key]
        require(isinstance(value, list) and value and all(isinstance(v, str) for v in value)
                and len(value) == len(set(value)), "partial_recovery requires unique nonempty " + key)
    selected, preserved = set(policy["members"]), set(policy["preserved_members"])
    require(not selected & preserved and selected | preserved == all_members,
            "partial recovery must partition all members")
    instances = group.get("instances", [])
    require(bool(instances), "partial recovery requires explicit instances")
    for instance in instances:
        assigned = set(instance["members"])
        require(assigned <= selected or assigned <= preserved, "partial recovery cannot split an instance")
    require(all(isinstance(p.get("id"), str) for p in group["health_checks"]),
            "partial recovery requires explicit health check ids")
    checks = {p.get("id"): p for p in group["health_checks"]}
    for key in ("fault_checks", "preserved_checks"):
        require(set(policy[key]) <= set(checks), "partial recovery references unknown health checks")
    require(not set(policy["fault_checks"]) & set(policy["preserved_checks"]), "partial recovery check sets overlap")
    plan = dict(id=group["id"], topology=group["topology"], recovery_steps=policy["recovery_steps"])
    validate_layout(plan, selected, require, validate_probe)
    expected = [(step["action"], step.get("stage"), [mid for mid in step["members"] if mid in selected])
                for step in recovery_steps(group) if selected.intersection(step["members"])]
    actual = [(step["action"], step.get("stage"), step["members"]) for step in policy["recovery_steps"]]
    require(actual == expected, "partial recovery must retain selected full-plan actions and order")
    for step in policy["recovery_steps"]:
        require(all(p.get("id") in checks and p == checks[p["id"]] for p in step.get("checks", [])),
                "partial recovery step checks must match group health checks")


_retain_import_identity(__name__, "inference_guardian.recovery_scope")
