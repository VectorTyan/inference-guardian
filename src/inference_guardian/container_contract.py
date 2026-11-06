"""生成可用于接管与动作前复核的 Docker 容器配置指纹。

完整 Config、HostConfig 参与计算，Mounts 按下列稳定字段归一化并排序。
顶层容器身份及运行状态不参与：容器 ID、镜像 ID 必须由调用方另行校验。
Env/Cmd 等敏感配置仅参与哈希，不作为返回值、日志或异常详情输出。
"""

from __future__ import annotations

import hashlib
import json
import math
import re


_MOUNT_FIELDS = (
    "Type", "Name", "Source", "Destination", "Driver", "Mode", "RW", "Propagation"
)
_INVALID = "Invalid Docker container configuration metadata"
_SHELLS = {"bash", "sh", "/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"}
_SHELL_LONG_FLAGS = {"--login", "--noprofile", "--norc", "--posix"}


def simple_shell_pid1(info: dict) -> bool:
    """仅识别明确的纯 Bash/sh 入口，供缺失 bootstrap 契约的保护分支使用。

    Entrypoint、Cmd 两字段必须同时存在，null 有效；脚本、-c 命令正文、
    自定义入口或带参数值的选项均不推断为纯 shell。False 只表示未命中
    这条窄规则，不是对自定义入口具备自启能力的证明，也不暴露原 argv。
    """
    config = info.get("Config") if isinstance(info, dict) else None
    if not isinstance(config, dict) or not {"Entrypoint", "Cmd"} <= set(config):
        return False
    argv = []
    for key in ("Entrypoint", "Cmd"):
        value = config[key]
        if value is None:
            continue
        if not isinstance(value, list) or any(not isinstance(arg, str) for arg in value):
            return False
        argv.extend(value)
    if not argv or argv[0] not in _SHELLS:
        return False
    for index, arg in enumerate(argv[1:], 1):
        if arg == "--":
            return index == len(argv) - 1
        # 这里只接受无需后续参数值的短选项；组合选项中也排除 -c、-o、-O。
        if arg not in _SHELL_LONG_FLAGS and not re.fullmatch(r"-[abefhiklmnprstuvxBCEHPT]+", arg):
            return False
    return True


def _validate_json(value: object) -> None:
    """拒绝隐式类型转换、非有限数值及非 JSON 对象，保证指纹可复现。"""
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(_INVALID)
        return
    if type(value) is list:
        for item in value:
            _validate_json(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError(_INVALID)
            _validate_json(item)
        return
    raise ValueError(_INVALID)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def bootstrap_stage_hashes(commands: dict) -> dict[str, str]:
    """返回已归一化静态阶段的命令摘要，不暴露 argv 或工作目录。

    调用方须先通过 Agent 配置校验填入 timeout_seconds、wait_for_exit 等
    默认值；这里不补默认值，也不修改输入。摘要沿用动作台账原有的 JSON
    编码算法，阶段名只作为映射键，不参与命令摘要。空配置返回空映射。
    """
    try:
        if type(commands) is not dict:
            raise ValueError
        result = {}
        for stage, command in commands.items():
            if type(stage) is not str or not stage or type(command) is not dict:
                raise ValueError
            _validate_json(command)
            raw = json.dumps(command, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            result[stage] = hashlib.sha256(raw).hexdigest()
        return result
    except (TypeError, ValueError, RecursionError, OverflowError):
        raise ValueError("Invalid normalized bootstrap commands") from None


def container_config_hash(info: dict) -> str:
    """返回 64 位小写 SHA256；无效元数据只产生不含秘密值的固定异常。

    Config/HostConfig 必须是对象，Mounts 必须是对象列表；挂载的 RW 是
    布尔值，其余选定字段是字符串。缺失字段与空字段有区别，额外挂载字段
    和顶层 State/NetworkSettings 等不参与。仅忽略挂载列表的顺序：
    Config/HostConfig 内部的 Env、argv 等列表仍按原顺序计算。
    """
    try:
        if type(info) is not dict:
            raise ValueError(_INVALID)
        if type(info.get("Config")) is not dict:
            raise ValueError(_INVALID)
        if type(info.get("HostConfig")) is not dict:
            raise ValueError(_INVALID)
        if type(info.get("Mounts")) is not list:
            raise ValueError(_INVALID)
        _validate_json(info["Config"])
        _validate_json(info["HostConfig"])
        mounts = []
        for mount in info["Mounts"]:
            if type(mount) is not dict:
                raise ValueError(_INVALID)
            normalized = {}
            for key in _MOUNT_FIELDS:
                if key in mount:
                    expected = bool if key == "RW" else str
                    if type(mount[key]) is not expected:
                        raise ValueError(_INVALID)
                    normalized[key] = mount[key]
            mounts.append(normalized)
        mounts.sort(key=_canonical)
        contract = {"Config": info["Config"], "HostConfig": info["HostConfig"],
                    "Mounts": mounts}
        encoded = _canonical(contract).encode("utf-8")
    except (TypeError, ValueError, RecursionError, OverflowError):
        # 不拼接原始异常或值：Config.Env、Config.Cmd 中可能存在凭据。
        raise ValueError(_INVALID) from None
    return hashlib.sha256(encoded).hexdigest()


fingerprint_container = container_config_hash
fingerprint = container_config_hash
