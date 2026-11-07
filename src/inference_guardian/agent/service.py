"""执行本地白名单容器操作，并向 Controller 提供有明确证据边界的观测。

真实 Docker socket 需要 Linux。容器、进程存活不等于模型推理就绪；进程
模式仅在 COMMAND 列做区分大小写的字面子串匹配。动作依靠持久台账防止
未知结果被自动重放，不提供任意远程命令执行。诊断快照尽力脱敏，仍可能
包含业务文本，不应作为可公开的日志。
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, wait
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import signal
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..observability.audit import AuditLog
from .logging import AgentLog, validate_logging
from .config import validate_config, _number
from .. import __version__
from ..containers.contract import bootstrap_stage_hashes, container_config_hash, simple_shell_pid1
from ..containers.docker_api import DockerClient, DockerError, MAX_LOG_BYTES
from ..observability.log_format import utc8_timestamp
from .observation import _unknown, _commands, observe_container
from .receipts import completed_stop as _completed_stop_receipt
from .receipts import bootstrap_start_confirmed as _bootstrap_start_confirmed


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_ACTION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_CONFIG_HASH = re.compile(r"[0-9a-f]{64}\Z")
MAX_BODY_BYTES = 8192


class AgentError(Exception):
    """携带面向调用方的 HTTP 状态和受控错误文本，不转发原始 Docker 响应。"""

    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


def _private_directory(path: Path) -> Path:
    """建立私有状态目录并拒绝符号链接，避免台账被写到替换后的目标。"""
    if path.is_symlink():
        raise ValueError("State directories cannot be symlinks")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError("State path must be a directory")
    if os.name == "posix":
        os.chmod(path, 0o700)
    return path.resolve()


def _fsync_directory(directory: Path) -> None:
    if os.name == "posix":
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _atomic_json(path: Path, value: dict) -> None:
    """先同步临时文件，再原子替换并同步目录，供动作派发前持久记录意图。"""
    temporary = path.with_suffix(".tmp")
    if path.is_symlink() or temporary.is_symlink():
        raise OSError("Refusing symlink state file")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


class _StateLease:
    """使同一状态目录仅由一个 Agent 进程持有；这不是跨节点选主锁。"""
    def __init__(self, directory: Path):
        path = directory / "agent.lock"
        if path.is_symlink():
            raise ValueError("Refusing symlink lock file")
        self.handle = open(path, "a+b")
        self.handle.seek(0, os.SEEK_END)
        if self.handle.tell() == 0:
            self.handle.write(b"0")
            self.handle.flush()
        self.handle.seek(0)
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif os.name == "nt":
                import msvcrt
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                raise ValueError("Unsupported platform for state locking")
        except BaseException:
            self.handle.close()
            raise

    def close(self):
        if not self.handle.closed:
            self.handle.close()


def _redact_text(text: str, token: str) -> str:
    """遮蔽已知凭据形式；不保证识别日志中的所有敏感内容或业务文本。"""
    text = text.replace(token, "[REDACTED]")
    text = re.sub(r"(?i)\bBearer\s+[^\s\"',;]+", "Bearer [REDACTED]", text)
    text = re.sub(
        r"(?i)((?:--)?(?:api[_-]?key|access[_-]?token|password|secret|authorization)"
        r"[\"']?\s*(?:[:=]|\s)\s*[\"']?)[^\s\"',;]+", r"\1[REDACTED]", text,
    )
    text = re.sub(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@", r"\1[REDACTED]@", text)
    return text


def _redact(value, token):
    if isinstance(value, str):
        return _redact_text(value, token)
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if re.search(r"(?i)token|password|secret|api.?key|authorization|^env$", key)
                      else _redact(item, token)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, token) for item in value]
    return value


class NodeAgent:
    """负责只读观测与串行动作台账，不自行判定模型就绪或编排全组恢复。

    进程重启后保留 pending/unknown 动作，不自动恢复派发；需要 Controller
    的健康检查、端到端探针和明确的操作对账共同完成恢复。
    """

    def __init__(self, config, docker_client=None):
        self.config = validate_config(config)
        self.timeout = self.config["request_timeout_seconds"]
        token_path = Path(self.config["listen"]["token_file"])
        if os.name == "posix" and token_path.stat().st_mode & 0o077:
            raise ValueError("Token file must not be readable by group or others (chmod 600)")
        with token_path.open("r", encoding="ascii") as handle:
            self.token = handle.read(4097).strip()
        if not 16 <= len(self.token) <= 4096 or any(not 33 <= ord(ch) <= 126 for ch in self.token):
            raise ValueError("Token file must contain 16-4096 printable non-whitespace ASCII characters")
        self.directory = _private_directory(Path(self.config["state_dir"]))
        self.lease = _StateLease(self.directory)
        try:
            self.log = AgentLog(self.directory, self.config.get("node_id"), self.config.get("logging", {}))
            self.started_at = time.monotonic()
            self.log.emit("agent_starting", version=__version__,
                          containers=[item["name"] for item in self.config["containers"]])
            if not self.log.persistence()["persistent_file_ok"]:
                raise OSError("Agent startup log could not be persisted")
            self.close_lock = threading.Lock()
            self.closed = False
            self.observation_lock = threading.Lock()
            self.last_observation = None
            self.actions = _private_directory(self.directory / "actions")
            self.snapshots = _private_directory(self.directory / "snapshots")
            self.docker = docker_client or DockerClient(
                self.config["docker_socket"], self.config["docker_api_version"], self.timeout,
            )
            self.allowlist = {item["name"]: item for item in self.config["containers"]}
            self.audit = AuditLog(self.directory / "audit")
            self.audit_failed = False
            self.lock = threading.Lock()
            self.closing = threading.Event()
            self.status_lock = threading.Lock()
            self.status_pool = ThreadPoolExecutor(max_workers=min(8, len(self.allowlist)), thread_name_prefix="node-status")
            self.records = {}
            self.records_lock = threading.RLock()
            self.active_container = None
            # 启动只加载并验证历史记录，不重放未完成动作；损坏台账直接阻止启动。
            self.generations_path = self.directory / "generations.json"
            self.generations = {}
            if self.generations_path.exists():
                if self.generations_path.is_symlink() or self.generations_path.stat().st_size > 65536:
                    raise ValueError("Invalid generation journal")
                self.generations = json.loads(self.generations_path.read_text(encoding="utf-8"))
                if not isinstance(self.generations, dict):
                    raise ValueError("Invalid generation journal")
                for name, generation in self.generations.items():
                    if name not in self.allowlist:
                        raise ValueError("Generation journal contains a non-allowlisted container")
                    _number(generation, "Persisted generation", 0, 2**63 - 1, integer=True)
            for path in self.actions.glob("*.json"):
                if path.is_symlink() or path.stat().st_size > 1024 * 1024:
                    raise ValueError("Invalid persisted action file")
                record = json.loads(path.read_text(encoding="utf-8"))
                payload = record.get("payload")
                if not isinstance(payload, dict) or record.get("phase") not in ("pending", "unknown", "complete"):
                    raise ValueError("Invalid persisted action record")
                self._validate_payload(payload)
                if path != self._record_path(payload["action_id"]):
                    raise ValueError("Persisted action filename mismatch")
                self.records[payload["action_id"]] = record
        except BaseException as exc:
            if hasattr(self, "log"):
                self.log.emit("agent_startup_failed", level=logging.ERROR, error_type=type(exc).__name__)
                self.log.close()
            if hasattr(self, "status_pool"):
                self.status_pool.shutdown(wait=False, cancel_futures=True)
            self.lease.close()
            raise

    def close(self):
        self.closing.set()
        with self.close_lock:
            if self.closed:
                return True
            self.log.stop_reporting()
            self.log.emit("agent_stopping", **self._journal_summary())
            # Docker变更仍在执行时不得释放跨进程锁或伪造正常退出。
            if not self.lock.acquire(timeout=300):
                self.log.emit("agent_shutdown_incomplete", level=logging.ERROR, reason="action_still_inflight")
                return False
            try:
                self.status_pool.shutdown(wait=True, cancel_futures=True)
                self.log.emit("agent_stopped", **self._journal_summary())
                self.log.close()
                self.lease.close()
                self.closed = True
                return True
            finally:
                self.lock.release()

    def _journal_summary(self):
        with self.records_lock:
            counts = {phase: 0 for phase in ("pending", "unknown", "complete")}
            for record in self.records.values():
                counts[record["phase"]] += 1
            return dict(action_counts=counts, active_container=self.active_container,
                        audit_available=not self.audit_failed)

    def status_summary(self):
        """运维摘要与恢复判定分离；过期/缺失观测不能沿用旧running值。"""
        with self.observation_lock:
            previous = self.last_observation
        age = None if previous is None else max(0, time.monotonic() - previous[0])
        fresh = age is not None and age <= self.log.settings["observation_max_age_seconds"]
        containers = previous[1] if fresh else {name: {"state": "unknown"} for name in self.allowlist}
        journal = self._journal_summary()
        attention = (not journal["audit_available"] or journal["action_counts"]["pending"] > 0
                     or journal["action_counts"]["unknown"] > 0 or not fresh
                     or any(item["state"] != "running" or item.get("process_ok") is False
                            for item in containers.values()) or not self.log.persistence()["persistent_file_ok"])
        return dict(scope="container_observation_not_inference_readiness", containers=containers,
                    uptime_seconds=round(max(0, time.monotonic() - self.started_at), 1),
                    observation_fresh=fresh, observation_age_seconds=None if age is None else round(age, 1),
                    observation_source="latest_agent_status_request", closing=self.closing.is_set(),
                    runtime_logging=self.log.persistence(),
                    attention_required=attention, **journal)

    def _audit(self, event: str, **fields):
        """审计失败即锁存禁用状态；修复存储并重启前，不再批准后续变更。"""
        if self.audit_failed:
            raise AgentError(503, "Audit unavailable; restart agent after repairing audit storage")
        try:
            self.audit.emit(event, **fields)
        except Exception as exc:
            self.audit_failed = True
            self.log.emit("agent_audit_unavailable", level=logging.ERROR, mutations_disabled=True)
            raise AgentError(503, "Audit write failed; mutations disabled") from exc
        # 只镜像审计白名单字段；原argv、Env、reason和Docker结果不进入运行日志。
        safe = {key: fields[key] for key in ("action_id", "container", "action", "generation",
                "recovery_group", "stage", "ok", "progress") if key in fields}
        level = logging.WARNING if "unknown" in event or fields.get("ok") is False else logging.INFO
        self.log.emit(event, level=level, **_redact(safe, self.token))

    def _operation_busy(self, name):
        """同时考虑当前动作和持久未知动作，避免 Agent 重启后误报可操作。

        snapshot 只读取诊断信息，没有晚到模型变更，因此不占用此操作信号。
        """
        with self.records_lock:
            return self.active_container == name or any(
                record["payload"]["container"] == name and record["payload"]["action"] != "snapshot"
                and record["phase"] != "complete" for record in self.records.values())

    def _verify_contract(self, name, info):
        """核对配置中的实例 ID 与指纹；镜像 ID 在状态和变更入口另行校验。"""
        expected = self.allowlist[name]
        if expected.get("expected_container_id") and info.get("Id") != expected["expected_container_id"]:
            raise ValueError("Container ID differs from pinned configuration")
        if expected.get("expected_config_hash") and container_config_hash(info) != expected["expected_config_hash"]:
            raise ValueError("Container configuration differs from pinned fingerprint")

    def status(self) -> dict:
        """在节点采集期限内返回观测；采集忙或超时只能产生 unknown。

        mutation_journal_clear 说明动作台账已无变更不确定性，不代表模型健康。
        本接口既不对账，也不重放任何历史动作。
        """
        started = time.monotonic()
        unavailable = {name: _unknown("Node status collection busy or closing") for name in self.allowlist}
        result = {"containers": unavailable}
        if not self.closing.is_set() and self.status_lock.acquire(blocking=False):
            try:
                if not self.closing.is_set():
                    pending = {name: self.status_pool.submit(self.container_status, name) for name in self.allowlist}
                    wait(pending.values(), timeout=self.timeout)
                    result["containers"] = {}
                    for name, future in pending.items():
                        if future.done() and not future.cancelled():
                            try:
                                result["containers"][name] = future.result()
                            except Exception:
                                result["containers"][name] = _unknown("Node status collection failed")
                        else:
                            future.cancel()
                            result["containers"][name] = _unknown("Node status collection deadline exceeded")
            finally:
                self.status_lock.release()
        if "node_id" in self.config:
            result["node_id"] = self.config["node_id"]
        for name, observed in result["containers"].items():
            observed["operation_busy"] = self._operation_busy(name)
            observed.setdefault("requires_bootstrap", False)
            observed.setdefault("bootstrap_configured", bool(self.allowlist[name].get("bootstrap_commands")))
            # 摘要描述本进程实际加载的静态配置，采集失败时也不能省略或冒充就绪证据。
            observed["bootstrap_stage_hashes"] = bootstrap_stage_hashes(self.allowlist[name].get("bootstrap_commands", {}))
        # 供部署和运维只读检查；取不到动作锁或仍有未知变更时保守阻止后续操作。
        result["mutation_journal_clear"] = False
        if self.lock.acquire(blocking=False):
            try:
                with self.records_lock:
                    result["mutation_journal_clear"] = not self.audit_failed and not self.closing.is_set() and all(
                        record["phase"] == "complete" or record["payload"]["action"] == "snapshot"
                        for record in self.records.values())
            finally:
                self.lock.release()
        # 只缓存受控字段；未知值的false占位符不作为日志中的停止/无故障证据。
        observations = {}
        for name, item in result["containers"].items():
            observations[name] = {"state": item["state"]}
            if item["state"] != "unknown":
                observations[name].update({key: item.get(key) for key in
                                          ("running", "process_ok", "configuration_ok", "oom_killed", "exit_code")})
                observations[name]["process_checks"] = json.loads(json.dumps(item.get("process_checks", [])))
                observations[name]["process_rules_status"] = item.get("process_rules_status", "unavailable")
        with self.observation_lock:
            self.last_observation = (started, observations)
        result["runtime_logging"] = self.log.persistence()
        return result


    def container_status(self, name: str) -> dict:
        """兼容原观测接口；动作忙状态仍由本服务的实时台账提供。"""
        return observe_container(self.docker, name, self.allowlist[name],
                                 self._verify_contract, self._operation_busy)

    def _record_path(self, action_id):
        return self.actions / (hashlib.sha256(action_id.encode("utf-8")).hexdigest() + ".json")

    def _save(self, record):
        """先完成原子落盘，再发布内存副本，避免把尚未持久的阶段当作事实。"""
        action_id = record["payload"]["action_id"]
        try:
            _atomic_json(self._record_path(action_id), record)
        except Exception as exc:
            raise AgentError(503, "Action journal write failed; outcome may be unknown") from exc
        with self.records_lock:
            self.records[action_id] = json.loads(json.dumps(record))

    def _validate_payload(self, body):
        """限定 HTTP 操作字段；只接受白名单阶段名，不接受 argv/env/cwd。

        reason 仅用于显式人工对账，不能借此扩展执行参数。可选 node_id 在
        任何 Docker 调用前核对目标，不写入持久 payload，保持历史动作去重契约。
        """
        if not isinstance(body, dict) or set(body) - {"action_id", "container", "action", "stop_timeout_seconds", "generation", "recovery_group", "stage", "reason", "node_id"}:
            raise AgentError(400, "Invalid action fields")
        if "node_id" in body and (not isinstance(body["node_id"], str) or body["node_id"] != self.config.get("node_id")):
            raise AgentError(409, "Action target node differs from configured node identity")
        if not isinstance(body.get("action_id"), str) or not _ACTION_ID.fullmatch(body["action_id"]):
            raise AgentError(400, "Invalid action_id")
        if not isinstance(body.get("container"), str) or body["container"] not in self.allowlist:
            raise AgentError(403, "Container is not allowlisted")
        if body.get("action") not in ("stop", "start", "snapshot", "bootstrap", "resolve_bootstrap_stopped"):
            raise AgentError(400, "Action is not allowlisted")
        if body["action"] == "bootstrap":
            stage = body.get("stage")
            if not isinstance(stage, str) or stage not in self.allowlist[body["container"]].get("bootstrap_commands", {}):
                raise AgentError(400, "Bootstrap stage is not allowlisted")
        elif "stage" in body:
            raise AgentError(400, "stage is only accepted for bootstrap")
        if body["action"] == "resolve_bootstrap_stopped":
            reason = body.get("reason")
            if (not isinstance(reason, str) or not 1 <= len(reason) <= 256
                    or not reason.strip() or not reason.isprintable()):
                raise AgentError(400, "Manual bootstrap resolution requires a nonempty printable reason of at most 256 characters")
        elif "reason" in body:
            raise AgentError(400, "reason is only accepted for manual bootstrap resolution")
        try:
            _number(body.get("stop_timeout_seconds", 30), "stop_timeout_seconds", 0, 120, integer=True)
            _number(body.get("generation", 0), "generation", 0, 2**63 - 1, integer=True)
        except ValueError as exc:
            raise AgentError(400, str(exc)) from exc
        group = body.get("recovery_group", "")
        if not isinstance(group, str) or (group and not _ACTION_ID.fullmatch(group)):
            raise AgentError(400, "Invalid recovery_group")
        payload = dict(action_id=body["action_id"], container=body["container"], action=body["action"],
                       stop_timeout_seconds=body.get("stop_timeout_seconds", 30),
                       generation=body.get("generation", 0), recovery_group=group)
        if body["action"] == "bootstrap":
            payload["stage"] = body["stage"]
        elif body["action"] == "resolve_bootstrap_stopped":
            payload["reason"] = body["reason"]
        return payload

    def _inspect_for_action(self, payload, *, mutation=True, timeout=None):
        """操作前重新核对容器身份；变更还须满足镜像与生命周期管理约束。"""
        try:
            info = self.docker.inspect(payload["container"], **({"timeout": timeout} if timeout is not None else {}))
        except Exception as exc:
            raise AgentError(503, "Docker inspection unavailable; action not dispatched") from exc
        if not isinstance(info, dict) or not _CONTAINER_ID.fullmatch(str(info.get("Id", ""))):
            raise AgentError(503, "Docker inspection lacks a complete container ID")
        if info.get("Name") != "/" + payload["container"]:
            raise AgentError(409, "Docker name does not match the allowlisted container")
        try:
            self._verify_contract(payload["container"], info)
        except ValueError:
            raise AgentError(409, "Container identity or configuration differs from the pinned contract") from None
        expected = self.allowlist[payload["container"]].get("expected_image_id")
        if mutation:
            # 裸交互 shell 不会自行拉起模型；缺少启动阶段时先拒绝，避免停后无法恢复。
            if (payload["action"] in {"stop", "start"} and simple_shell_pid1(info)
                    and not self.allowlist[payload["container"]].get("bootstrap_commands")):
                raise AgentError(409, "Simple shell container requires configured bootstrap stages before stop/start")
            if expected and info.get("Image") != expected:
                raise AgentError(409, "Image ID differs from pinned configuration")
            host = info.get("HostConfig", {})
            if not isinstance(host, dict) or not isinstance(host.get("AutoRemove"), bool) or not isinstance(host.get("RestartPolicy", {}).get("Name"), str):
                raise AgentError(503, "Docker lifecycle metadata unavailable; action not dispatched")
            if host.get("AutoRemove"):
                raise AgentError(409, "AutoRemove containers cannot be managed with stop/start")
            if host.get("RestartPolicy", {}).get("Name", "no") not in ("", "no"):
                raise AgentError(409, "Docker restart policy must be 'no' for guardian ownership")
        return info

    @staticmethod
    def _target_observed(info, payload):
        """核对普通 stop/start 的容器目标状态，不证明启动脚本或模型已经就绪。"""
        state = info.get("State", {})
        if payload["action"] == "stop":
            return state.get("Running") is False and state.get("Status") in ("exited", "created")
        return (state.get("Running") is True and state.get("Status") == "running"
                and not any(state.get(key) for key in ("Paused", "Restarting", "Dead")))

    def _reconcile(self, record):
        """只读确认同一实例的普通 stop/start 结果，绝不重新派发 Docker 动作。

        容器 Running 不能证明未知 bootstrap 的执行结果；bootstrap 与中断
        snapshot 保留 unknown，前者只能走独立的人工停止后对账流程。
        """
        payload = record["payload"]
        if payload["action"] == "bootstrap":
            result = dict(ok=False, action_id=payload["action_id"], result={
                "state": "unknown", "stage": payload["stage"], "dispatch_confirmed": False,
                "ready": False, "detail": "Bootstrap outcome requires operator investigation; not replayed"})
        elif payload["action"] == "snapshot":
            result = dict(ok=False, action_id=payload["action_id"], result={"state": "unknown", "detail": "Interrupted snapshot; not replayed"})
        else:
            try:
                info = self._inspect_for_action(payload)
                reached = info["Id"] == record.get("container_id") and self._target_observed(info, payload)
            except Exception:
                reached = False
            result = dict(ok=reached, action_id=payload["action_id"], result={
                "state": ("stopped" if payload["action"] == "stop" else "running") if reached else "unknown",
                "reconciled": reached,
                "detail": "Target state observed after interruption" if reached else "Interrupted action outcome unknown; not replayed",
            })
        updated = {**record, "phase": "complete" if result["ok"] else "unknown", "response": result,
                   "http_status": 200 if result["ok"] else 409}
        if result["ok"] and payload["action"] == "start" and isinstance(info["State"].get("StartedAt"), str):
            updated["started_at"] = info["State"]["StartedAt"]
        self._audit("node_action_reconciled", action_id=payload["action_id"], container=payload["container"],
                    action=payload["action"], ok=result["ok"],
                    **({"stage": payload["stage"], "command_hash": record.get("bootstrap", {}).get("command_hash")}
                       if payload["action"] == "bootstrap" else {}))
        self._save(updated)
        return updated["http_status"], result

    @staticmethod
    def _command_hash(command):
        """以静态命令摘要关联台账和审计，避免在审计事件中输出原始参数。"""
        return bootstrap_stage_hashes({"command": command})["command"]

    def _completed_stop(self, payload, container_id):
        """查找同一容器实例、恢复世代和恢复组中已确认成功的最近一次 stop。"""
        return _completed_stop_receipt(self.records.values(), payload, container_id)

    def _bootstrap_preconditions(self, payload, info):
        """要求同世代已完成 stop→start，且 StartedAt 仍是记录中的启动周期。

        同一阶段在一个世代只允许一个动作 ID；更换 ID 不能绕过防重放检查。
        不同阶段可继续执行，但必须共享这一已确认的启动周期。
        """
        started_at = info.get("State", {}).get("StartedAt")
        if not self._target_observed(info, payload) or not isinstance(started_at, str) or not started_at:
            raise AgentError(409, "Bootstrap requires a confirmed running container startup epoch")
        for record in self.records.values():
            previous = record["payload"]
            if (previous["action"] == "bootstrap" and previous["container"] == payload["container"]
                    and previous["generation"] == payload["generation"] and previous["stage"] == payload["stage"]):
                raise AgentError(409, "Bootstrap stage already has an action in this generation; no replay")
        if _bootstrap_start_confirmed(self.records, payload, info["Id"], started_at):
            return started_at
        raise AgentError(409, "Bootstrap requires completed stop then start in the same generation and startup epoch")

    def _bootstrap_progress(self, record, progress, **fields):
        """先审计并持久化阶段再进入下一步；本地台账与 Docker 不构成原子事务。"""
        updated = {**record, "bootstrap": {**record["bootstrap"], "progress": progress, **fields}}
        self._audit("node_bootstrap_progress", action_id=record["payload"]["action_id"],
                    container=record["payload"]["container"], stage=record["payload"]["stage"],
                    command_hash=record["bootstrap"]["command_hash"], progress=progress)
        self._save(updated)
        return updated

    def _bootstrap(self, record, command):
        """单次派发一个静态 exec，并在共享期限内确认，不自动重试 create/start。

        dispatch_confirmed 仅说明已确认执行状态；即使脚本退出 0 也不代表
        推理 ready，后续健康检查和业务探针仍由 Controller 完成。
        """
        payload = record["payload"]
        deadline = time.monotonic() + command["timeout_seconds"]

        def remaining():
            duration = deadline - time.monotonic()
            if duration <= 0 or self.closing.is_set():
                raise DockerError("Bootstrap observation deadline exceeded")
            return min(self.timeout, duration)

        def epoch_matches():
            current = self._inspect_for_action(payload, timeout=remaining())
            remaining()
            if (current["Id"] != record["container_id"]
                    or current.get("State", {}).get("StartedAt") != record["bootstrap"]["started_at"]
                    or not self._target_observed(current, payload)):
                raise DockerError("Container startup epoch changed during bootstrap")

        # 请求前记意图；即使创建响应丢失，也不能再次 create 并假定原请求未执行。
        record = self._bootstrap_progress(record, "create_intent")
        identifier = self.docker.exec_create(record["container_id"], command["argv"], command["working_dir"], timeout=remaining())
        if not isinstance(identifier, str) or not _CONTAINER_ID.fullmatch(identifier):
            raise DockerError("Bootstrap exec ID was not confirmed")
        # exec ID 必须先落盘才能启动；后续未知结果仍保留可供人工调查的对象标识。
        record = self._bootstrap_progress(record, "exec_created", exec_id=identifier)
        epoch_matches()
        # 启动意图与确认分别记录；丢失响应或持久化失败都不能伪造 start_ack。
        record = self._bootstrap_progress(record, "start_intent")
        self.docker.exec_start(identifier, timeout=remaining())
        record = self._bootstrap_progress(record, "start_ack")
        while True:
            observed = self.docker.exec_inspect(identifier, timeout=remaining())
            if (not isinstance(observed, dict) or observed.get("ContainerID") != record["container_id"]
                    or observed.get("ID") != identifier or not isinstance(observed.get("Running"), bool)):
                raise DockerError("Bootstrap exec observation is not bound to the expected container")
            epoch_matches()
            running = observed["Running"]
            exit_code = observed.get("ExitCode")
            if not running and (isinstance(exit_code, bool) or not isinstance(exit_code, int)):
                raise DockerError("Bootstrap exit status was not confirmed")
            if not running or not command["wait_for_exit"]:
                # 明确的非零退出是已知失败；期限或确认异常由上层保存为 unknown。
                ok = running or exit_code == 0
                return record, dict(state="dispatched" if ok else "failed", stage=payload["stage"],
                                    dispatch_confirmed=True, ready=False, exec_id=identifier,
                                    exit_code=None if running else exit_code), ok
            time.sleep(min(0.1, remaining()))

    def _resolution_snapshot(self, payload, resolving_id):
        """人工对账前核对三项固定身份、已停止状态和 restart=no。

        全组维护/停止由调用方确认，本节点拒绝其他未知变更，以防存在晚到的
        start 等操作。只读 snapshot 无此风险，因此保留其记录但不阻塞对账。
        """
        pinned = self.allowlist[payload["container"]]
        if not all(pinned.get(key) for key in ("expected_container_id", "expected_image_id", "expected_config_hash")):
            raise AgentError(409, "Manual resolution requires pinned container ID, image ID, and configuration hash")
        info = self._inspect_for_action(payload)
        state = info.get("State", {})
        if (not isinstance(state, dict) or state.get("Running") is not False
                or state.get("Status") not in {"exited", "created"}
                or any(state.get(key) for key in ("Paused", "Restarting", "Dead"))
                or info["HostConfig"]["RestartPolicy"]["Name"] != "no"):
            raise AgentError(409, "Manual resolution requires a confirmed stopped container with restart policy no")
        unresolved = []
        for identifier, record in self.records.items():
            action = record["payload"]
            if (identifier == resolving_id or action["container"] != payload["container"]
                    or record["phase"] == "complete" or action["action"] == "snapshot"):
                continue
            if action["action"] != "bootstrap":
                raise AgentError(409, "An ordinary or other unresolved node action prevents bootstrap resolution")
            if record.get("container_id") != info["Id"]:
                raise AgentError(409, "Unresolved bootstrap belongs to a different container ID")
            unresolved.append(identifier)
        return info, sorted(unresolved)

    def _resolve_bootstrap_stopped(self, payload, previous=None):
        """仅供人工在全组维护且停止后关闭未知 bootstrap，不执行 Docker 变更。

        本节点复核固定实例并拒绝普通未知动作；保留原 payload、exec ID 和
        阶段记录，以失败且已取消标记结束旧动作，不删除或重新派发。持久化
        中途失败后须先修复存储、重启 Agent，再显式使用相同对账 ID 续办。
        """
        identifier = payload["action_id"]
        info, unresolved = self._resolution_snapshot(payload, identifier)
        reason_hash = hashlib.sha256(payload["reason"].encode("utf-8")).hexdigest()
        pinned = self.allowlist[payload["container"]]
        contract = {key: pinned[key] for key in ("expected_container_id", "expected_image_id", "expected_config_hash")}
        if previous is None:
            record = dict(payload=payload, phase="pending", container_id=info["Id"], created_at=time.time(),
                          resolution={"target_action_ids": unresolved, "reason_hash": reason_hash, "contract": contract})
        else:
            record = json.loads(json.dumps(previous))
            details = record.get("resolution", {})
            targets = details.get("target_action_ids")
            if (record.get("container_id") != info["Id"] or details.get("reason_hash") != reason_hash
                    or details.get("contract") != contract or not isinstance(targets, list)
                    or any(not isinstance(target, str) for target in targets) or len(targets) != len(set(targets))
                    or not set(unresolved) <= set(targets)):
                raise AgentError(409, "Saved manual resolution no longer matches the stopped-container contract")
        targets = record["resolution"]["target_action_ids"]
        for target in targets:
            candidate = self.records.get(target)
            if (not candidate or candidate["payload"]["action"] != "bootstrap"
                    or candidate["payload"]["container"] != payload["container"]
                    or candidate.get("container_id") != info["Id"]
                    or (candidate["phase"] == "complete" and (
                        candidate.get("canceled_by_confirmed_stop") is not True
                        or candidate.get("resolution_action_id") != identifier))):
                raise AgentError(409, "Saved bootstrap target cannot be closed by this manual resolution")
        try:
            self._audit("node_bootstrap_resolution_intent", action_id=identifier, container=payload["container"],
                        container_id=info["Id"], generation=payload["generation"], reason_hash=reason_hash,
                        target_action_ids=targets)
            generations = {**self.generations, payload["container"]: payload["generation"]}
            _atomic_json(self.generations_path, generations)
            self.generations = generations
            # 先固化目标集合，再逐条取消；中途失败只能沿同一人工动作继续。
            self._save(record)
            for target in targets:
                # 每条都重新确认停止，不能把最初检查当作整个对账期间的永久保证。
                current, _ = self._resolution_snapshot(payload, identifier)
                if current["Id"] != record["container_id"]:
                    raise AgentError(409, "Container changed during manual resolution")
                candidate = self.records[target]
                if candidate["phase"] == "complete":
                    continue
                canceled = json.loads(json.dumps(candidate))
                result = {"state": "canceled", "stage": candidate["payload"]["stage"], "ready": False,
                          "dispatch_confirmed": False, "canceled_by_confirmed_stop": True,
                          "resolution_action_id": identifier}
                canceled.update(phase="complete", canceled_by_confirmed_stop=True, resolution_action_id=identifier,
                                response={"ok": False, "action_id": target, "result": result}, http_status=409)
                self._audit("node_bootstrap_cancel_intent", action_id=target, resolution_action_id=identifier,
                            container=payload["container"], stage=candidate["payload"]["stage"],
                            command_hash=candidate.get("bootstrap", {}).get("command_hash"), reason_hash=reason_hash)
                self._save(canceled)
                self._audit("node_bootstrap_canceled", action_id=target, resolution_action_id=identifier,
                            container=payload["container"], reason_hash=reason_hash)
            self._resolution_snapshot(payload, identifier)
            response = {"ok": True, "action_id": identifier, "result": {
                "state": "stopped", "container_id": info["Id"], "resolved_action_ids": targets,
                "resolved_count": len(targets), "canceled_by_confirmed_stop": True}}
            self._audit("node_bootstrap_resolution_completed", action_id=identifier, container=payload["container"],
                        resolved_count=len(targets), reason_hash=reason_hash)
            record.update(phase="complete", response=response, http_status=200)
            self._save(record)
            return 200, response
        except Exception:
            # 部分取消已落盘时不得重新开放派发；统一锁存，等待修复后显式续办。
            self.audit_failed = True
            raise AgentError(503, "Manual resolution incomplete; repair storage, restart Agent, and retry the same resolution action") from None

    def action(self, body):
        """串行执行受控动作，以世代隔离旧请求，并以完整 payload 约束动作 ID。

        已完成的重复 ID 返回历史结果；未知结果只允许读取证据或人工对账，
        不能把网络异常当作重新调用 Docker 的依据。
        """
        payload = self._validate_payload(body)
        if not self.lock.acquire(timeout=self.timeout):
            raise AgentError(503, "Another node action is in progress")
        try:
            with self.records_lock:
                if payload["action"] != "snapshot":
                    self.active_container = payload["container"]
            if self.closing.is_set():
                raise AgentError(503, "Node agent is closing")
            # 更高世代一旦持久化，晚到的旧控制请求不能再驱动容器变更。
            if (payload["action"] != "snapshot"
                    and payload["generation"] < self.generations.get(payload["container"], 0)):
                raise AgentError(409, "Stale recovery generation; action rejected")
            pinned = self.allowlist[payload["container"]]
            if pinned.get("expected_container_id") or pinned.get("expected_config_hash"):
                self._inspect_for_action(payload, mutation=payload["action"] != "snapshot")
            if payload["action"] == "resolve_bootstrap_stopped":
                # 已完成对账仅是历史证据；外部可能已启动容器，缓存响应也须复核停止。
                self._resolution_snapshot(payload, payload["action_id"])
            previous = self.records.get(payload["action_id"])
            if previous:
                if previous["payload"] != payload:
                    raise AgentError(409, "action_id was already used for a different payload")
                if payload["action"] == "bootstrap" and previous.get("bootstrap", {}).get("command_hash") != self._command_hash(
                        pinned["bootstrap_commands"][payload["stage"]]):
                    raise AgentError(409, "Bootstrap configuration changed; prior action cannot be reinterpreted")
                if previous["phase"] == "complete":
                    # 成功和失败都按原结果返回，不因调用方重发而再次执行。
                    return previous["http_status"], previous["response"]
                if payload["action"] == "resolve_bootstrap_stopped":
                    return self._resolve_bootstrap_stopped(payload, previous)
                return self._reconcile(previous)
            if payload["action"] == "resolve_bootstrap_stopped":
                return self._resolve_bootstrap_stopped(payload)
            if payload["action"] != "snapshot":
                # 换一个动作 ID 也不能越过同容器的未知变更，包括未知 bootstrap。
                for record in list(self.records.values()):
                    if (record["payload"]["container"] == payload["container"]
                            and record["payload"]["action"] != "snapshot" and record["phase"] != "complete"):
                        if record["payload"]["action"] == "resolve_bootstrap_stopped":
                            raise AgentError(409, "Pending manual resolution requires the same explicit operator action")
                        status, result = self._reconcile(record)
                        if not result["ok"]:
                            raise AgentError(409, "Prior action outcome unknown; operator reconciliation required")
            info = self._inspect_for_action(payload, mutation=payload["action"] != "snapshot")
            bootstrap = None
            audit_fields = {}
            if payload["action"] == "bootstrap":
                command = pinned["bootstrap_commands"][payload["stage"]]
                bootstrap = {"progress": "prepared", "command_hash": self._command_hash(command),
                             "started_at": self._bootstrap_preconditions(payload, info)}
                audit_fields = {"stage": payload["stage"], "command_hash": bootstrap["command_hash"]}
            self._audit("node_action_intent", action_id=payload["action_id"], container=payload["container"],
                        action=payload["action"], generation=payload["generation"], recovery_group=payload["recovery_group"], **audit_fields)
            # 先审计并持久化世代与 pending 台账，全部成功后才允许调用 Docker。
            if payload["action"] != "snapshot":
                generations = {**self.generations, payload["container"]: payload["generation"]}
                try:
                    _atomic_json(self.generations_path, generations)
                except Exception as exc:
                    raise AgentError(503, "Generation journal write failed; action not dispatched") from exc
                self.generations = generations
            record = dict(payload=payload, phase="pending", container_id=info["Id"], created_at=time.time())
            if bootstrap is not None:
                record["bootstrap"] = bootstrap
            if payload["action"] == "start":
                stop = self._completed_stop(payload, info["Id"])
                if stop:
                    record["preceding_stop_action_id"] = stop["payload"]["action_id"]
            self._save(record)
            try:
                ok = True
                if payload["action"] == "snapshot":
                    outcome = self._snapshot(payload, info)
                elif payload["action"] == "bootstrap":
                    record, outcome, ok = self._bootstrap(record, command)
                else:
                    if payload["action"] == "stop":
                        self.docker.stop(info["Id"], timeout=payload["stop_timeout_seconds"])
                    else:
                        self.docker.start(info["Id"])
                    observed = self.docker.inspect(info["Id"])
                    if observed.get("Id") != info["Id"] or not self._target_observed(observed, payload):
                        raise DockerError("Target state not observed")
                    if payload["action"] == "start" and isinstance(observed["State"].get("StartedAt"), str):
                        record["started_at"] = observed["State"]["StartedAt"]
                    outcome = dict(state="stopped" if payload["action"] == "stop" else "running", container_id=info["Id"])
                response = dict(ok=ok, action_id=payload["action_id"], result=outcome)
                self._audit("node_action_completed", action_id=payload["action_id"], container=payload["container"], action=payload["action"], ok=ok, **audit_fields)
                record.update(phase="complete", response=response, http_status=200 if ok else 502)
            except Exception:
                # 以最后成功落盘的阶段为准；不能把本地临时变量中的确认补成持久事实。
                with self.records_lock:
                    record = json.loads(json.dumps(self.records[payload["action_id"]]))
                response = dict(ok=False, action_id=payload["action_id"], result={"state": "unknown", "detail": "Action outcome unknown; not automatically replayed"})
                if payload["action"] == "bootstrap":
                    response["result"].update(stage=payload["stage"], dispatch_confirmed=False, ready=False)
                record.update(phase="unknown", response=response, http_status=503)
                try:
                    self._audit("node_action_unknown", action_id=payload["action_id"], container=payload["container"],
                                action=payload["action"], **audit_fields)
                except AgentError:
                    pass
            self._save(record)
            return record["http_status"], response
        finally:
            with self.records_lock:
                self.active_container = None
            self.lock.release()

    def _snapshot(self, payload, info):
        """保存有大小限制的本地诊断，只返回路径；尽力脱敏后仍可能含业务文本。"""
        identifier = info["Id"]
        data = {"container": payload["container"], "created_at": time.time(), "notice": "Best-effort redaction; logs may contain business text", "inspect": {
            key: info.get(key) for key in ("Id", "Name", "Image", "State", "RestartCount")
        }}
        data["inspect"]["HostConfig"] = {
            key: info.get("HostConfig", {}).get(key) for key in ("RestartPolicy", "AutoRemove", "NetworkMode")
        }
        try:
            data["top"] = self.docker.top(identifier) if info.get("State", {}).get("Running") else {"unavailable": "Container stopped"}
        except Exception:
            data["top"] = {"unavailable": "Docker top failed"}
        try:
            logs = self.docker.logs(identifier, tail=200)
            if isinstance(logs, bytes):
                logs = logs.decode("utf-8", "replace")
            data["logs"] = str(logs).encode("utf-8")[:MAX_LOG_BYTES].decode("utf-8", "replace")
        except Exception:
            data["logs_unavailable"] = True
        path = self.snapshots / (hashlib.sha256(payload["action_id"].encode()).hexdigest() + ".json")
        _atomic_json(path, _redact(data, self.token))
        return {"snapshot_path": str(path), "redaction": "best_effort", "may_contain_business_text": True}
