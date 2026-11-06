"""把逻辑实例、容器成员与恢复步骤分开描述，不按服务器数量猜P/D比例。

一个实例可跨多机，同一宿主也可有多个实例。默认恢复整个组；显式局部策略
在recovery_scope中校验，不能拆开同一实例。本模块不推导HCCL/Mooncake依赖。
"""
from __future__ import annotations

import re

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
ROLES = frozenset({"prefill", "decode", "mixed", "proxy", "stage"})


def recovery_steps(group):
    """统一返回有序start/bootstrap计划，兼容旧的两段配置。

    recovery_steps支持交错步骤，例如D容器start→D脚本→P容器start→P脚本。
    同一步跨Agent并发，同一Agent的动作由Controller串行提交。
    """
    if "recovery_steps" in group:
        return group["recovery_steps"]
    return ([dict(step, action="start") for step in group["start_steps"]]
            + [dict(step, action="bootstrap") for step in group.get("bootstrap_steps", [])])


def canary_specs(group):
    """返回必须全部通过的业务探针；保留单canary兼容入口。"""
    return group["canaries"] if "canaries" in group else [group["canary"]]


def validate_layout(group, members, require, validate_probe):
    """校验实例归属与完整恢复计划；require由配置层提供统一错误类型。"""
    gid = group["id"]
    if "instances" in group:
        instances = group["instances"]
        require(isinstance(instances, list) and 0 < len(instances) <= 1024, f"{gid}: instances must be a nonempty list")
        identities, assigned, roles = set(), [], set()
        for instance in instances:
            require(isinstance(instance, dict), f"{gid}: instance must be an object")
            identifier, role = instance.get("id"), instance.get("role")
            require(isinstance(identifier, str) and _ID.fullmatch(identifier) and identifier not in identities,
                    f"{gid}: instance id invalid or duplicated")
            require(isinstance(role, str) and role in ROLES, f"{gid}: unknown instance role")
            selected = instance.get("members")
            require(isinstance(selected, list) and selected and all(isinstance(mid, str) for mid in selected),
                    f"{gid}: instance members required")
            require(set(selected) <= members, f"{gid}: instance references unknown members")
            identities.add(identifier)
            roles.add(role)
            assigned.extend(selected)
        require(set(assigned) == members and len(assigned) == len(members),
                f"{gid}: instances must cover every member exactly once")
        if group["topology"] == "pd_disaggregated":
            require({"prefill", "decode"} <= roles and "mixed" not in roles,
                    f"{gid}: PD layout requires prefill and decode instances")
        else:
            require(bool(roles & {"mixed", "stage"}) and not roles & {"prefill", "decode"},
                    f"{gid}: mixed layout uses mixed/stage instances, not separate P/D roles")

    if "recovery_steps" in group:
        require("start_steps" not in group and "bootstrap_steps" not in group,
                f"{gid}: recovery_steps cannot be mixed with legacy steps")
    else:
        group.setdefault("start_steps", [{"members": sorted(members)}])
        require(isinstance(group["start_steps"], list) and isinstance(group.get("bootstrap_steps", []), list),
                f"{gid}: startup steps must be lists")
        require(all(isinstance(s, dict) for s in group["start_steps"] + group.get("bootstrap_steps", [])),
                f"{gid}: startup step must be an object")
    steps = recovery_steps(group)
    require(isinstance(steps, list) and 0 < len(steps) <= 256, f"{gid}: recovery steps must be a bounded nonempty list")
    started, dispatched = set(), set()
    for step in steps:
        require(isinstance(step, dict) and not set(step) - {"action", "members", "stage", "checks", "containers_only"},
                f"{gid}: invalid recovery step fields")
        action, selected = step.get("action"), step.get("members")
        require(action in {"start", "bootstrap"}, f"{gid}: unsupported recovery action")
        require(isinstance(selected, list) and selected and all(isinstance(mid, str) for mid in selected),
                f"{gid}: recovery members required")
        require(set(selected) <= members and len(set(selected)) == len(selected), f"{gid}: unknown or repeated recovery member")
        require(type(step.get("containers_only", False)) is bool, f"{gid}: containers_only must be boolean")
        if action == "start":
            require("stage" not in step and not started.intersection(selected), f"{gid}: repeated start or invalid stage")
            started.update(selected)
        else:
            stage = step.get("stage")
            require(isinstance(stage, str) and _ID.fullmatch(stage), f"{gid}: invalid bootstrap stage")
            require(set(selected) <= started, f"{gid}: bootstrap must follow each member's start")
            for mid in selected:
                require((stage, mid) not in dispatched, f"{gid}: repeated bootstrap stage/member")
                dispatched.add((stage, mid))
        require(isinstance(step.get("checks", []), list), f"{gid}: checks must be a list")
        for check in step.get("checks", []):
            validate_probe(check, f"{gid}: recovery check")
    require(started == members, f"{gid}: recovery steps must start every member exactly once")
