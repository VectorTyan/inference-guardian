"""运维显示用探针名称；不改探针地址、重启授权或持久故障计数身份。"""
from __future__ import annotations

import copy

from .health_policy import health_failure_key


def probe_id(spec, index):
    """新配置显式命名；旧配置提供稳定序号回退，不将可能含凭据的URL作为名称。"""
    return spec.get("id") or f"probe-{index + 1:02d}"


def probe_description(spec, index):
    return spec.get("description") or probe_id(spec, index)


def readable_controller_state(state, config):
    """仅转换状态输出副本，原始哈希计数和恢复预算不落盘修改、不丢失未知项。"""
    result = copy.deepcopy(state)
    for group in config["groups"]:
        runtime = result.get("groups", {}).get(group["id"])
        if not isinstance(runtime, dict):
            continue
        counts = runtime.get("health_failure_counts", {})
        names = {health_failure_key(spec, index): probe_id(spec, index)
                 for index, spec in enumerate(group["health_checks"])}
        runtime["health_failure_counts"] = {names.get(key, "unmapped." + key): value for key, value in counts.items()}
    return result
