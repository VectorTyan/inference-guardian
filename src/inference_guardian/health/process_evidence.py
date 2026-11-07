"""将已验收进程的消失与字面规则失配区分；不从500或网络超时猜进程死亡。"""
from __future__ import annotations


import copy
import hashlib
import json
import re


def process_identity(info, top, rules, tracked):
    """仅返回PID、规则摘要和容器启动世代，不外发命令行或环境变量。"""
    columns = [str(t).upper() for t in top.get("Titles", [])]
    if "PID" not in columns or not info["State"].get("StartedAt"):
        return {"available": False}
    pi = columns.index("PID")
    ci = max(i for i, c in enumerate(columns) if c in {"COMMAND", "CMD", "ARGS"})
    rows = top["Processes"]
    if any(not isinstance(row[pi], str) or not re.fullmatch(r"[1-9][0-9]{0,9}", row[pi]) for row in rows):
        return {"available": False}
    pids = [int(row[pi]) for row in rows]
    if len(pids) != len(set(pids)) or not pids:
        return {"available": False}
    identities = {}
    for index, rule in enumerate(rules, 1):
        rid = rule.get("id", "process-rule-" + str(index))
        if rid in tracked:
            digest = hashlib.sha256(json.dumps(rule, sort_keys=True).encode()).hexdigest()
            identities[rid] = dict(pids=[pid for pid, row in zip(pids, rows) if rule["pattern"] in row[ci]],
                                   minimum=rule["min_count"], rule_hash=digest)
    return dict(available=True, container_id=info["Id"], started_at=info["State"]["StartedAt"],
                pids=pids, rules=identities)


def valid_identity(value, rule_id):
    if not isinstance(value, dict) or value.get("available") is not True:
        return False
    if (not isinstance(value.get("container_id"), str) or not re.fullmatch(r"[0-9a-f]{64}", value["container_id"])
            or not isinstance(value.get("started_at"), str) or not value["started_at"]):
        return False
    pids = value.get("pids")
    rules = value.get("rules")
    if not isinstance(rules, dict):
        return False
    rule = rules.get(rule_id)
    if not isinstance(pids, list) or not 1 <= len(pids) <= 16384 or any(type(p) is not int or p <= 0 for p in pids):
        return False
    if not isinstance(rule, dict) or type(rule.get("minimum")) is not int or rule["minimum"] <= 0:
        return False
    matches = rule.get("pids")
    return (len(set(pids)) == len(pids) and isinstance(matches, list)
            and all(type(p) is int for p in matches) and len(set(matches)) == len(matches)
            and set(matches) <= set(pids) and isinstance(rule.get("rule_hash"), str)
            and re.fullmatch(r"[0-9a-f]{64}", rule["rule_hash"]) is not None)


def exited_members(group, runtime, statuses, health):
    """本轮同容器/同启动世代/同规则内，已验收PID消失且引擎健康失败的成员。"""
    policy = group.get("process_exit_detection")
    if not policy or len(health) != len(group["health_checks"]):
        return set()
    results = {p["id"]: r for p, r in zip(group["health_checks"], health)}
    failed = set()
    for member, rule in policy["members"].items():
        status = statuses[member]
        current = status.get("process_identity")
        old = runtime.get("process_baselines", {}).get(member)
        rid = rule["rule_id"]
        if (status.get("running") is not True or not valid_identity(current, rid) or not valid_identity(old, rid)
                or current["container_id"] != status.get("container_id")
                or any(current[k] != old[k] for k in ("container_id", "started_at"))):
            continue
        before, after = old["rules"][rid], current["rules"][rid]
        if (before["rule_hash"] != after["rule_hash"] or before["minimum"] != after["minimum"]
                or len(before["pids"]) < before["minimum"] or len(after["pids"]) >= after["minimum"]):
            continue
        unhealthy = any(results[name].state != "pass" and results[name].status not in {401,403,404,429}
                        and results[name].reason != "auth_endpoint_or_capacity" for name in rule["checks"])
        if unhealthy and set(before["pids"]) - set(current["pids"]):
            failed.add(member)
    return failed


def confirmed_exits(group, runtime, statuses, health):
    policy = group.get("process_exit_detection")
    if not policy:
        return set()
    return {mid for mid in exited_members(group, runtime, statuses, health)
            if runtime.get("process_exit_counts", {}).get(mid, 0) >= policy["failure_threshold"]}


def remember_processes(group, runtime, statuses):
    """只在完整健康+canary验收后调用，缺失PID/规则时不凭空建立死亡基线。"""
    policy = group.get("process_exit_detection")
    if not policy:
        return
    baselines = {}
    for member, rule in policy["members"].items():
        identity = statuses[member].get("process_identity")
        rid = rule["rule_id"]
        if (valid_identity(identity, rid) and identity["container_id"] == statuses[member].get("container_id")
                and len(identity["rules"][rid]["pids"]) >= identity["rules"][rid]["minimum"]):
            baselines[member] = copy.deepcopy(identity)
            # 持久化只需已验收的引擎PID；全容器清单仅用于当前“仍存在”复核。
            baselines[member]["pids"] = list(identity["rules"][rid]["pids"])
            baselines[member]["rules"] = {rid: copy.deepcopy(identity["rules"][rid])}
    runtime["process_baselines"] = baselines
    runtime["process_exit_armed"] = len(baselines) == len(policy["members"])
    runtime["process_exit_counts"] = {}


def validate_detection(group, require):
    if "process_exit_detection" not in group:
        return
    policy = group["process_exit_detection"]
    require(isinstance(policy, dict) and set(policy) == {"members", "failure_threshold"}, "invalid process_exit_detection")
    require(type(policy["failure_threshold"]) is int and 2 <= policy["failure_threshold"] <= 20,
            "process exit failure_threshold must be 2..20")
    members = policy["members"]
    require(isinstance(members, dict) and set(members) == {m["id"] for m in group["members"]},
            "process exit detection must cover every member")
    require(all(isinstance(p.get("id"), str) for p in group["health_checks"]), "process exit detection requires named probes")
    checks = {p["id"] for p in group["health_checks"]}
    for value in members.values():
        require(isinstance(value, dict) and set(value) == {"rule_id", "checks"}, "invalid process exit member")
        require(isinstance(value["rule_id"], str) and 0 < len(value["rule_id"]) <= 256, "invalid process exit rule_id")
        names = value["checks"]
        require(isinstance(names, list) and names and all(isinstance(n, str) for n in names)
                and len(names) == len(set(names)) and set(names) <= checks, "invalid process exit check references")
