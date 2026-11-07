"""Agent配置的复制、校验与默认值规范化，不读取凭据或状态。"""
from __future__ import annotations
import json
from pathlib import PurePosixPath
import re
from ..agent_logging import validate_logging
from ..containers.docker_api import DockerClient

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_ACTION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_CONFIG_HASH = re.compile(r"[0-9a-f]{64}\Z")

def _number(value, name, low, high, *, integer=False):
    allowed = (int,) if integer else (int, float)
    if isinstance(value, bool) or not isinstance(value, allowed) or not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return value


def validate_config(config: dict) -> dict:
    """复制并校验本地配置，固定容器白名单、可选身份约束和启动阶段。

    容器 ID、镜像 ID、配置指纹分别约束实例、镜像和运行配置；通用配置
    允许逐项指定，人工 bootstrap 对账则要求三项齐全。命令只能来自本地
    bootstrap_commands，HTTP 请求只能引用阶段名。
    """
    if not isinstance(config, dict):
        raise ValueError("Node config must be a JSON object")
    config = json.loads(json.dumps(config))
    listen = config.get("listen")
    if not isinstance(listen, dict):
        raise ValueError("listen must be an object")
    if not isinstance(listen.get("host"), str) or not listen["host"] or len(listen["host"]) > 253:
        raise ValueError("listen.host is required")
    _number(listen.get("port"), "listen.port", 0, 65535, integer=True)
    for key in ("token_file",):
        if not isinstance(listen.get(key), str) or not listen[key]:
            raise ValueError(f"listen.{key} is required")
    insecure = listen.get("allow_insecure_http", False)
    if not isinstance(insecure, bool):
        raise ValueError("allow_insecure_http must be a boolean")
    cert, key = listen.get("tls_cert_file"), listen.get("tls_key_file")
    if bool(cert) != bool(key) or (not cert and not insecure):
        raise ValueError("TLS cert and key required unless allow_insecure_http is explicitly true")
    if cert and (not isinstance(cert, str) or not isinstance(key, str)):
        raise ValueError("TLS cert and key must be file paths")
    if not isinstance(config.get("state_dir"), str) or not config["state_dir"]:
        raise ValueError("state_dir is required")
    if "logging" in config:
        validate_logging(config["logging"])
    config.setdefault("docker_socket", "/var/run/docker.sock")
    config.setdefault("docker_api_version", "v1.45")
    config.setdefault("request_timeout_seconds", 15)
    _number(config["request_timeout_seconds"], "request_timeout_seconds", 0.1, 300)
    DockerClient(config["docker_socket"], config["docker_api_version"], config["request_timeout_seconds"])
    containers = config.get("containers")
    if not isinstance(containers, list) or not 1 <= len(containers) <= 256:
        raise ValueError("containers must be a nonempty allowlist of at most 256 entries")
    names = set()
    for item in containers:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not _NAME.fullmatch(item["name"]):
            raise ValueError("Invalid allowlisted container name")
        if item["name"] in names:
            raise ValueError("Duplicate allowlisted container name")
        names.add(item["name"])
        if "expected_image_id" in item and (
            not isinstance(item["expected_image_id"], str) or not _IMAGE.fullmatch(item["expected_image_id"])
        ):
            raise ValueError("expected_image_id must be a full sha256 image ID")
        for field, pattern in (("expected_container_id", _CONTAINER_ID), ("expected_config_hash", _CONFIG_HASH)):
            if field in item and (not isinstance(item[field], str) or not pattern.fullmatch(item[field])):
                raise ValueError(field + " must be a full lowercase SHA256 value")
        # 静态 argv 属于本地配置权限；拒绝未知字段，避免请求层扩展成任意 exec。
        stages = item.get("bootstrap_commands", {})
        if not isinstance(stages, dict) or len(stages) > 32:
            raise ValueError("bootstrap_commands must be an object of at most 32 stages")
        for stage, command in stages.items():
            if not isinstance(stage, str) or not _ACTION_ID.fullmatch(stage):
                raise ValueError("Invalid bootstrap stage ID")
            if (not isinstance(command, dict)
                    or set(command) - {"argv", "working_dir", "timeout_seconds", "wait_for_exit"}):
                raise ValueError("Invalid bootstrap command fields")
            argv = command.get("argv")
            if (not isinstance(argv, list) or not 1 <= len(argv) <= 128
                    or not isinstance(argv[0], str) or not argv[0]
                    or any(not isinstance(arg, str) or len(arg) > 16384 or "\0" in arg for arg in argv)):
                raise ValueError("bootstrap argv must be a bounded nonempty static argument list")
            directory = command.get("working_dir")
            if (not isinstance(directory, str) or not PurePosixPath(directory).is_absolute()
                    or any(char in directory for char in ("\0", "\n", "\r"))):
                raise ValueError("bootstrap working_dir must be an absolute container path")
            command.setdefault("timeout_seconds", 30)
            _number(command["timeout_seconds"], "bootstrap timeout_seconds", 1, 120)
            command.setdefault("wait_for_exit", False)
            if not isinstance(command["wait_for_exit"], bool):
                raise ValueError("bootstrap wait_for_exit must be boolean")
        specs = item.setdefault("required_processes", [])
        if not isinstance(specs, list) or len(specs) > 32:
            raise ValueError("required_processes must be a list of at most 32 entries")
        for spec in specs:
            if not isinstance(spec, dict) or not isinstance(spec.get("pattern"), str) or not 1 <= len(spec["pattern"]) <= 256:
                raise ValueError("Process patterns must be nonempty literal substrings")
            if any(ord(character) < 32 for character in spec["pattern"]):
                raise ValueError("Process patterns cannot contain control characters")
            spec.setdefault("min_count", 1)
            _number(spec["min_count"], "min_count", 1, 4096, integer=True)
            for field in ("id", "description"):
                if field in spec and (not isinstance(spec[field], str) or not 1 <= len(spec[field]) <= 256
                                      or not spec[field].isprintable()):
                    raise ValueError("Invalid process rule " + field)
        if "process_exit_rules" in item:
            tracked = item["process_exit_rules"]
            identifiers = [s.get("id", "process-rule-" + str(i)) for i, s in enumerate(specs, 1)]
            if (not isinstance(tracked, list) or not tracked or not all(isinstance(r, str) for r in tracked)
                    or len(set(tracked)) != len(tracked) or not set(tracked) <= set(identifiers)
                    or len(identifiers) != len(set(identifiers))):
                raise ValueError("process_exit_rules must reference unique required process IDs")
    if "node_id" in config and (not isinstance(config["node_id"], str) or len(config["node_id"]) > 128):
        raise ValueError("node_id must be a short string")
    return config

