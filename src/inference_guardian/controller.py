"""按恢复组采集证据、记录决策并协调既有容器的停止、启动与原脚本阶段。

每组可独立监测，但本进程同一时刻只执行一个组的恢复事务；跨进程唯一
写入者由启动层的持久锁约束，本模块不提供跨宿主领导选举。READY表示配置
的检查通过；外部部署默认不监听业务端口，状态变化不等于原入口已经撤流。
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import copy
import hashlib
import logging
import math
import queue
from pathlib import Path
import threading
import time
import uuid

from .observability.audit import AuditLog, sanitize
from .observability.log_format import utc8_timestamp
from .config import config_hash
from .node_client import NodeClient
from .http_client import file_headers, request
from .health.probes import ProbeResult, run_probe
from .health.policy import (health_failure_counts, management_issue, management_contract_confirmed,
                            inference_healthy, recovery_reason)
from .canary import poll_or_start
from .topology import canary_specs, recovery_steps
from .recovery_scope import select_scope, execution_plan, plan_hash
from .health.process_evidence import exited_members, confirmed_exits, remember_processes
from .storage import atomic_json, read_json

LOG = logging.getLogger(__name__)
ACTIVE_PHASES = {"DRAINING", "SNAPSHOT", "STOPPING", "STARTING", "VALIDATING"}





class RecoveryError(RuntimeError):
    """可记录为恢复未完成并进入维护或退避的异常；持久化等故障仍向外传播。"""

    pass


class Controller:
    """恢复状态机与持久预算的所有者，不承担模型加载或硬件修复。

    生产run为每组创建一个监测线程；耗时canary使用该组唯一的后台任务。
    组内成员可并发执行同一步，组与组之间的恢复由recovery_lock串行化。
"""

    def __init__(self, config, gateway_state, audit=None, node_client=None,
                 probe=run_probe, clock=time.time, sleeper=time.sleep):
        self.config, self.gateway = config, gateway_state
        self.directory = Path(config["state_dir"])
        self.directory.mkdir(parents=True, exist_ok=True)
        self.audit = audit or AuditLog(self.directory / "audit")
        self.nodes = node_client or NodeClient(config["nodes"], config["policy"]["request_timeout_seconds"])
        self.probe, self.clock, self.sleep = probe, clock, sleeper
        self.elapsed_clock = time.monotonic if clock is time.time else clock
        self.policy = config["policy"]
        self.stop_event = threading.Event()
        # 分别约束落盘、状态/路由发布和命令消费；RLock允许内部嵌套调用。
        # persistence_lock只串行化保存动作，不把所有内存状态读取变成事务。
        self.persistence_lock = threading.RLock()
        self.publish_lock = threading.RLock()
        self.commands_lock = threading.RLock()
        # 唯一的组级恢复写入者；此锁不阻塞其他组继续采集健康证据。
        self.recovery_lock = threading.Lock()
        self.worker_errors = []
        self.async_canaries = False
        self.canary_tasks = {}
        self.observation_notices = {}
        self.state_path = self.directory / "state.json"
        self.state = read_json(self.state_path, {"version": 1, "groups": {}, "generation": 0})
        if self.state.get("version") != 1 or not isinstance(self.state.get("groups"), dict):
            raise ValueError("invalid controller state; manual investigation required")
        self.state["config_hash"] = config_hash(config)
        self.state["traffic_control_enabled"] = config.get("gateway", {}).get("enabled", True)
        for group in config["groups"]:
            previous = self.state["groups"].get(group["id"], {})
            interrupted = previous.get("phase") in ACTIVE_PHASES
            previous["recovery_required"] = bool(previous.get("recovery_required") or interrupted
                or previous.get("phase") in {"BACKOFF", "RECOVERY_PENDING"})
            # 重启保留预算/维护/隔离历史，但丢弃就绪证据，重新验收后才能READY。
            previous.update(phase="MAINTENANCE" if previous.get("maintenance") else
                            "QUARANTINED" if previous.get("phase") == "QUARANTINED" else
                            "BACKOFF" if interrupted else "DISCOVERING",
                            failures=0, engine_failures=0, health_failure_counts={}, last_canary=0, canary_ok=False,
                            last_observed_at=0, inference_status="unverified", process_rule_warnings={})
            previous["recovery_inflight"] = False
            if group.get("process_exit_detection"):
                previous["process_exit_counts"] = {}
            # 本进程的在途标记重置，不代表Agent已发送的旧Docker操作已经结束；
            # 后续仍由节点持久台账的operation_busy阻止不确定状态下继续变更。
            previous.setdefault("attempts", [])
            previous.setdefault("incident_attempts", 0)
            previous.setdefault("maintenance", False)
            previous.setdefault("next_retry", 0)
            previous.setdefault("reason", "startup")
            for key in ("ready_since", "changed_at", "generation"):
                previous.setdefault(key, 0)
            previous.setdefault("last_command", "")
            previous.setdefault("canary_revision", 0)
            self.state["groups"][group["id"]] = previous
        self.record("controller_started", mode=config["mode"], config_hash=self.state["config_hash"])
        for gid, incident in self.state.get("recovery_log", {}).items():
            if incident.get("status") == "recovering":
                incident["status"] = "interrupted"
                self.record("recovery_interrupted", group=gid, reason="controller_restarted",
                            generation=incident.get("generation"), result="unconfirmed",
                            summary=copy.deepcopy(incident))
        self.save()
        self.publish()

    @staticmethod
    def _group_log_fields(group):
        """从当前 canary 配置提取 API 模型别名，仅用于运行日志展示。"""
        models = set()
        for spec in canary_specs(group):
            body = spec.get("json")
            model = body.get("model") if isinstance(body, dict) else None
            if isinstance(model, str) and 0 < len(model) <= 256 and model.isprintable():
                models.add(model)
        return dict(group=group["id"], served_models=sorted(models), topology=group["topology"])

    def record(self, event, **fields):
        """先可靠追加原审计，再把同一事件和恢复上下文写入宿主持久运行日志。

        不改变历史审计格式/哈希；日志中只放受控标识与结果，不放请求正文、
        Docker参数或凭据。审计失败继续向上传播，不能以日志成功替代审计。
        """
        checksum = self.audit.emit(event, **fields)
        incident = self.state.get("recovery_log", {}).get(fields.get("group"), {})
        if incident.get("status") == "healthy" and not (
                (event == "canary" and fields.get("state") == "pass")
                or (event == "group_transition" and fields.get("phase") in {"READY", "RAMP_UP"})
                or event == "recovery_validated"):
            # 已结束故障只用于成功观测，不能污染下一次异常或尚未确认的事件。
            incident = {}
        detail = dict(incident, **fields)
        group = next((g for g in self.config["groups"] if g["id"] == fields.get("group")), None)
        if group is not None:
            detail.update(self._group_log_fields(group))
        elif event == "controller_started":
            detail["groups"] = [self._group_log_fields(g) for g in self.config["groups"]]
        detail.update(event=event, time=utc8_timestamp(self.clock()))
        LOG.info("recovery_event %s", json.dumps(sanitize(detail), ensure_ascii=False, sort_keys=True))
        return checksum

    def check_record(self, group, phase, checks, results):
        """记录配置健康点的判定，不复制探针响应正文或认证地址。"""
        self.record("recovery_self_check", group=group["id"], phase=phase,
                    generation=self.state["groups"][group["id"]]["generation"],
                    checks=[dict(id=spec.get("id", "check-" + str(index + 1)),
                                 state=results[index].state if index < len(results) else "not_observed",
                                 status=results[index].status if index < len(results) else None,
                                 reason=results[index].reason if index < len(results) else "members_not_ready")
                            for index, spec in enumerate(checks)])

    def save(self):
        """保存当前状态快照；落盘失败向外传播，不能继续作为已记录的决策执行。"""
        with self.persistence_lock:
            atomic_json(self.state_path, copy.deepcopy(self.state))

    def transition(self, group, phase, reason):
        """串行记录并发布状态转换；维护状态优先于普通恢复阶段。"""
        with self.publish_lock:
            self._transition(group, phase, reason)

    def _transition(self, group, phase, reason):
        runtime = self.state["groups"][group["id"]]
        if runtime["maintenance"]:
            phase, reason = "MAINTENANCE", "operator_maintenance"
        incidents = self.state.setdefault("recovery_log", {})
        incident = incidents.get(group["id"], {})
        if (phase == "SUSPECT" and reason != "canary_pending"
                and (not incident or incident.get("status") == "healthy")):
            incident = incidents[group["id"]] = dict(fault_detected_at=utc8_timestamp(self.clock()),
                                                    detected_timestamp=self.clock(), status="detected", reason=reason)
        invalidate = (phase in {"UNKNOWN", "QUARANTINED"} and runtime.get("phase") != phase) or (
            phase == "SUSPECT" and (runtime.get("phase") in {"READY", "RAMP_UP"}
            or (reason == "health_or_process_failure" and runtime.get("reason") != reason)))
        if invalidate:
            # 一段新异常使之前及在途canary失效；后续必须取得新观测，不能靠旧成功恢复READY。
            runtime["canary_revision"] += 1
            runtime["canary_ok"] = False
        if phase not in {"READY", "RAMP_UP"}:
            runtime["inference_status"] = "unverified"
        if runtime.get("phase") != phase or runtime.get("reason") != reason:
            restoration = {}
            if (phase in {"READY", "RAMP_UP"} and incident and incident.get("status") != "healthy"
                    and not runtime.get("recovery_inflight")):
                # 首次自检通过即记录恢复；后续 READY、重复观测和重启均保留该时间。
                restoration = dict(status="healthy", restored_at=utc8_timestamp(self.clock()),
                                   resolution="observed_healthy")
            self.record("group_transition", group=group["id"], previous=runtime.get("phase"),
                        phase=phase, reason=reason, **restoration)
            LOG.info("group=%s served_models=%s topology=%s phase=%s reason=%s",
                     group["id"], json.dumps(self._group_log_fields(group)["served_models"], ensure_ascii=False),
                     group["topology"], phase, reason)
            runtime.update(phase=phase, reason=reason, changed_at=self.clock())
            incident.update(restoration)
            self.save()
            self.publish()

    def publish(self):
        """发布供可选Gateway读取的状态；GatewayState自身不会绑定业务端口。"""
        with self.publish_lock:
            self._publish()

    def _publish(self):
        # ready同时依赖阶段与canary时效；消费者还需按expires_at拒绝过期证据。
        # 外部模式只保留这份内存状态，不因此控制原Proxy/LB上的业务流量。
        routes = []
        for group in self.config["groups"]:
            runtime = self.state["groups"][group["id"]]
            route = dict(group["route"])
            route["id"] = group["id"]
            route["headers"] = file_headers(group["route"])
            route["ready"] = (runtime["phase"] in {"READY", "RAMP_UP"} and not runtime["maintenance"]
                              and runtime.get("canary_ok", False)
                              and self.clock() - runtime.get("last_canary", 0) <= self.policy["canary_max_age_seconds"]
                              and not self.stop_event.is_set())
            route["expires_at"] = runtime.get("last_observed_at", 0) + self.policy["readiness_ttl_seconds"]
            if runtime["phase"] == "RAMP_UP":
                route["max_inflight"] = 1
            routes.append(route)
        self.gateway.set_routes(routes)

    def statuses(self, group, *, fresh=False):
        """按节点并发取样再映射到组成员；缺少成员数据时保留unknown。"""
        node_ids = sorted({member["node"] for member in group["members"]})
        with ThreadPoolExecutor(max_workers=min(16, len(node_ids))) as pool:
            by_node = dict(zip(node_ids, pool.map(lambda node: self.nodes.status(node, fresh=fresh), node_ids)))
        result = {}
        for member in group["members"]:
            node = by_node[member["node"]]
            observed = node.get(member["container"]) if isinstance(node, dict) else None
            if not isinstance(observed, dict) or observed.get("state") not in {"running", "stopped", "unhealthy", "unknown"}:
                observed = {"state": "unknown"}
            result[member["id"]] = observed
        return result

    def probes(self, checks):
        if not checks:
            return []
        with ThreadPoolExecutor(max_workers=min(16, len(checks))) as pool:
            return list(pool.map(lambda p: self.probe(p, self.policy["request_timeout_seconds"]), checks))

    def commands(self):
        """串行消费人工命令，避免主循环与恢复线程重复处理同一维护指令。"""
        with self.commands_lock, self.publish_lock:
            self._commands()

    def _commands(self):
        queue = self.directory / "commands"
        queue.mkdir(exist_ok=True)
        groups = {g["id"]: g for g in self.config["groups"]}
        for path in sorted(queue.glob("*.json")):
            command = read_json(path)
            gid = command.get("group")
            if gid not in groups or command.get("action") not in {"maintenance_on", "maintenance_off", "unquarantine"}:
                self.record("command_rejected", command_id=path.stem)
                path.rename(path.with_suffix(".rejected"))
                continue
            runtime = self.state["groups"][gid]
            if runtime.get("last_command") == path.stem:
                path.rename(path.with_suffix(".done"))
                continue
            action = command["action"]
            if action in {"maintenance_off", "unquarantine"} and runtime.get("recovery_inflight"):
                self.record("command_rejected", command_id=path.stem, reason="recovery_still_inflight")
                path.rename(path.with_suffix(".rejected"))
                continue
            if action == "unquarantine" and runtime["phase"] != "QUARANTINED":
                self.record("command_rejected", command_id=path.stem, reason="group_not_quarantined")
                path.rename(path.with_suffix(".rejected"))
                continue
            self.record("operator_command", group=gid, command_id=path.stem, action=action)
            # 即使恢复代次未变，维护/解除隔离也必须作废此前启动的canary结果。
            runtime["canary_revision"] += 1
            if action == "maintenance_on":
                runtime.update(maintenance=True, phase="MAINTENANCE", reason="operator_maintenance")
            elif action == "maintenance_off":
                runtime.update(maintenance=False, phase="DISCOVERING", reason="operator_resume", canary_ok=False)
            else:
                # 仅显式unquarantine走人工预算重置；普通进程重启不清恢复历史。
                runtime.update(phase="DISCOVERING", reason="operator_reset", incident_attempts=0,
                               attempts=[], failures=0, next_retry=0, canary_ok=False)
            runtime["last_command"] = path.stem
            self.save()
            self.publish()
            path.rename(path.with_suffix(".done"))

    def critical_fault(self, group):
        """读取可选隔离信号，返回(故障是否存在,本轮证据是否可判定)。"""
        config = group.get("quarantine_probe")
        if not config:
            return False, True
        result = self.probe(config, self.policy["request_timeout_seconds"])
        # 这里的pass表示“配置的故障条件成立”，与普通health的pass含义相反。
        # 条件断言不成立可判定为未发现该故障；探针自身异常则仍是未知。
        return result.state == "pass", result.state != "unknown" and result.reason in {"ok", "result_assertion"}

    def stalled(self, group, canary):
        """只用显式进度适配器的新鲜证据判断停滞，不从长Prefill耗时猜测挂死。

        要求canary未通过、确有待处理请求且无进展时长超过配置阈值；鉴权、端点或
        容量问题不构成停滞证据。阈值与进度信号的可靠性仍须按实际模型校验。
        """
        if (not group.get("stall_probe") or canary.state == "pass" or
                canary.reason == "auth_endpoint_or_capacity"):
            return False
        spec = dict(group["stall_probe"], parse_json=True)
        result = self.probe(spec, self.policy["request_timeout_seconds"])
        data = result.data
        if result.state != "pass" or not isinstance(data, dict):
            return False
        try:
            values = [data[k] for k in ("observed_at", "pending_requests", "seconds_without_progress")]
            if any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values):
                return False
            age = self.clock() - data["observed_at"]
            return (0 <= age <= self.policy["progress_max_age_seconds"] and
                    float(data["pending_requests"]) > 0 and
                    float(data["seconds_without_progress"]) >= self.policy["stall_after_seconds"])
        except (ValueError, KeyError, TypeError):
            return False

    def run_canaries(self, group):
        """串行执行本组全部业务验证；不替现场生成P/D定向路由参数。"""
        result = None
        for spec in canary_specs(group):
            result = self.probe(spec, self.policy["request_timeout_seconds"])
            if result.state != "pass":
                return result
        return result

    def finish_previous_canary(self, group, deadline):
        """等待旧后台请求收敛后再做恢复验收，避免同组并发发送两个canary。"""
        gid = group["id"]
        while gid in self.canary_tasks:
            self.check_continue(group)
            try:
                self.canary_tasks[gid]["results"].get_nowait()
            except queue.Empty:
                if self.elapsed_clock() >= deadline:
                    raise RecoveryError("previous_canary_still_inflight")
                self.interruptible_sleep(min(0.1, max(0, deadline - self.elapsed_clock())))
            else:
                del self.canary_tasks[gid]
                self.record("stale_canary_discarded", group=gid)

    def background_canary(self, group, needed):
        """保留调用接口；任务管理不拥有Controller持久状态或恢复写入权。"""
        return poll_or_start(self.canary_tasks, group, self.state["groups"][group["id"]], needed,
                             self.run_canaries, self.stop_event, self.audit)

    def tick(self, only_group=None):
        """完成一次组观测与证据分类；observe只记录建议，auto才执行恢复。"""
        self.commands()
        for group in self.config["groups"]:
            if only_group is not None and group["id"] != only_group:
                continue
            self._tick_group(group)

    def _observe_canary(self, group, health_ok, hard_failure, now):
        """采集单组业务探针，按维护状态、代次和时效接纳结果。"""
        runtime = self.state["groups"][group["id"]]
        need_canary = (not health_ok or not runtime.get("canary_ok") or
                       now - runtime.get("last_canary", 0) >= self.policy["canary_interval_seconds"])
        canary = None
        if not hard_failure:
            if self.async_canaries:
                canary = self.background_canary(group, need_canary)
            elif need_canary:
                key = (runtime["generation"], runtime["canary_revision"])
                canary = self.run_canaries(group)
                canary._guardian_key = key
        if canary is not None:
            with self.publish_lock:
                current_key = (runtime["generation"], runtime["canary_revision"])
                if runtime["maintenance"] or getattr(canary, "_guardian_key", current_key) != current_key:
                    canary = None
                else:
                    runtime.update(last_canary=self.clock(), canary_ok=canary.state == "pass")
                    self.record("canary", group=group["id"], state=canary.state,
                                    status=canary.status, reason=canary.reason)
        if self.clock() - runtime.get("last_canary", 0) > self.policy["canary_max_age_seconds"]:
            runtime["canary_ok"] = False
        return canary

    def _reset_failure_counts(self, group, *, clear_health):
        """按管理故障分类清理证据；旧配置不新增进程退出计数字段。"""
        runtime = self.state["groups"][group["id"]]
        if group.get("process_exit_detection"):
            runtime["process_exit_counts"] = {}
        if clear_health:
            runtime["engine_failures"] = 0
            runtime["health_failure_counts"] = {}

    def _record_process_warnings(self, group, statuses):
        """仅在进程规则诊断变化时记录，诊断本身不授权重启。"""
        runtime = self.state["groups"][group["id"]]
        mismatches = {member: s.get("process_checks", []) for member, s in statuses.items()
                      if s.get("process_ok") is False}
        runtime["process_rule_warnings"] = mismatches
        notice = json.dumps(mismatches, sort_keys=True)
        if self.observation_notices.get(group["id"]) != notice:
            if mismatches:
                self.record("process_rule_mismatch", group=group["id"], members=mismatches,
                                restart_authorized=False)
                LOG.warning("group=%s served_models=%s topology=%s process_rule_mismatch members=%s; verifying inference independently",
                            group["id"], json.dumps(self._group_log_fields(group)["served_models"], ensure_ascii=False),
                            group["topology"], ",".join(mismatches))
            self.observation_notices[group["id"]] = notice

    def _propose_recovery(self, group, reason, statuses, health):
        """记录 observe 模式的组级恢复建议，保留原范围判定和去重间隔。"""
        runtime = self.state["groups"][group["id"]]
        previous = runtime.get("last_recovery_proposal", {})
        proposal = dict(reason=reason)
        if group.get("partial_recovery"):
            kind, blocked = select_scope(group, runtime, statuses, health, self.policy["failure_threshold"])
            proposal.update(scope=kind, scope_blocked=blocked)
        elif group["topology"] == "multi_node_mixed":
            proposal["scope"] = "full"
        if any(previous.get(k) != v for k, v in proposal.items()) or self.clock() - previous.get("time", 0) >= 60:
            self.record("recovery_proposed", group=group["id"], **proposal)
            runtime["last_recovery_proposal"] = dict(proposal, time=self.clock())

    def _tick_group(self, group):
        """完成一个恢复组的观测与决策，状态和故障证据始终按组保存。"""
        runtime = self.state["groups"][group["id"]]
        if runtime["maintenance"] or runtime["phase"] == "QUARANTINED":
            return
        if runtime.get("recovery_required") and self.clock() < runtime["next_retry"]:
            return
        retry_pending = runtime.get("recovery_required", False)
        statuses = self.statuses(group)
        # 操作未确认、节点不可达都不能推断为已停止；UNKNOWN优先阻断变更。
        # 启动契约缺失或生命周期配置冲突则需要人工处理，进入QUARANTINED。
        issue = management_issue(statuses)
        if issue is not None:
            phase, reason, clear_counts = issue
            self._reset_failure_counts(group, clear_health=clear_counts)
            self.transition(group, phase, reason)
            return
        critical, fault_probe_known = self.critical_fault(group)
        if critical:
            self.transition(group, "QUARANTINED", "configured_critical_fault")
            return
        if not fault_probe_known:
            self._reset_failure_counts(group, clear_health=True)
            self.transition(group, "UNKNOWN", "critical_fault_probe_unavailable")
            return
        # 命令行匹配不到不证明进程死亡（进程可改名）；只认已确认的容器停止。
        # 规则结果作为诊断保留，业务就绪仍须完整健康及真实生成证据。
        hard_failure = any(s.get("state") == "stopped" for s in statuses.values())
        self._record_process_warnings(group, statuses)
        health = self.probes(group["health_checks"])
        health_ok = all(p.state == "pass" for p in health)
        # 只累计显式授权的同一端点连续错误，Proxy/容量503默认只使就绪失败。
        counts = health_failure_counts(group["health_checks"], health, runtime.get("health_failure_counts", {}))
        runtime["health_failure_counts"] = counts
        runtime["engine_failures"] = max(counts.values(), default=0)
        if group.get("process_exit_detection"):
            exited = exited_members(group, runtime, statuses, health)
            old_counts = runtime.get("process_exit_counts", {})
            runtime["process_exit_counts"] = {mid: old_counts.get(mid, 0) + 1 if mid in exited else 0
                for mid in group["process_exit_detection"]["members"]}
        process_dead = confirmed_exits(group, runtime, statuses, health)
        if hard_failure or not health_ok:
            self.transition(group, "SUSPECT", "health_or_process_failure")
        now = self.clock()
        canary = self._observe_canary(group, health_ok, hard_failure, now)
        # 兼容旧Agent明确报告的字面规则失败，不放宽其它unhealthy原因。
        healthy = inference_healthy(statuses, hard_failure, health_ok, runtime.get("canary_ok"))
        runtime["inference_status"] = "verified" if healthy else "unverified"
        if runtime["maintenance"]:
            return
        runtime["last_observed_at"] = self.clock()
        if healthy:
            remember_processes(group, runtime, statuses)
            runtime["failures"] = 0
            runtime["recovery_required"] = False
            if runtime["phase"] not in {"READY", "RAMP_UP"}:
                runtime["ready_since"] = self.clock()
                self.transition(group, "RAMP_UP", "verified")
            elif runtime["phase"] == "RAMP_UP" and now - runtime.get("ready_since", now) >= self.policy["ramp_up_seconds"]:
                self.transition(group, "READY", "ramp_completed")
            if now - runtime.get("ready_since", now) >= self.policy["stable_reset_seconds"]:
                runtime["incident_attempts"] = 0
            self.save()
            self.publish()
            return
        runtime["failures"] += 1
        runtime["canary_ok"] = False
        # SUSPECT只说明尚未满足完整就绪条件，不自动等同于模型已死亡。
        # 已停容器、达到阈值的503、可信停滞或前次恢复未完成，
        # 才进入下面的恢复分支；单次业务失败或单纯探针超时不足以重启。
        self.transition(group, "SUSPECT", "health_or_process_failure" if hard_failure or not health_ok
                        else "canary_pending" if canary is None else "canary_failure")
        explicit_engine_dead = runtime["engine_failures"] >= self.policy["failure_threshold"] or bool(process_dead)
        confirmed_stall = (runtime["failures"] >= self.policy["failure_threshold"] and canary is not None
                           and self.stalled(group, canary))
        # 已知恢复未完成且外观已健康时，先等新canary，避免仅因后台任务尚未返回就再次重启。
        retry_now = retry_pending and not (health_ok and not hard_failure and canary is None)
        reason = recovery_reason(hard_failure, explicit_engine_dead, confirmed_stall, retry_now)
        if process_dead and not hard_failure:
            reason = "confirmed_engine_process_exit"
        if reason is not None:
            if self.config["mode"] == "observe":
                self._propose_recovery(group, reason, statuses, health)
                self.save()
            else:
                self.recover(group, reason)
        else:
            self.save()
        self.publish()

    def interruptible_sleep(self, seconds):
        """分段等待并持续消费维护命令，避免长等待期间失去人工控制。"""
        end = self.elapsed_clock() + seconds
        while self.elapsed_clock() < end:
            if self.stop_event.is_set():
                raise RecoveryError("controller_stopping")
            self.commands()
            self.sleep(min(0.25, max(0, end - self.elapsed_clock())))

    def check_continue(self, group):
        """在发送下一步操作前检查停止与维护屏障；已发送的远端操作不可撤回。"""
        self.commands()
        if self.stop_event.is_set() or self.state["groups"][group["id"]]["maintenance"]:
            raise RecoveryError("recovery_interrupted")

    def actions(self, group, members, action, generation, stage=None):
        """并发发送一个阶段的成员动作，全部收敛后才进入后续阶段或验收。

        动作ID绑定组、代次、阶段和成员，供Agent持久去重；任何成员未确认均使
        本阶段失败，不将其他成员已成功的结果扩展成“整组成功”。
        """
        self.check_continue(group)
        if action != "snapshot":
            observed = self.management_barrier(group)
            if action == "bootstrap" and not all(observed[m["id"]].get("running") is True for m in members):
                raise RecoveryError("bootstrap_members_not_running")
        def call(member):
            aid = f"{group['id']}-{generation}-{action}-{member['id']}"
            if stage is not None:
                token = hashlib.sha256(stage.encode("utf-8")).hexdigest()[:16]
                aid = f"{group['id']}-{generation}-{action}-{token}-{member['id']}"
            self.record("action_intent", group=group["id"], member=member["id"], action=action, action_id=aid,
                            **({"stage": stage} if stage is not None else {}))
            # 审计落盘或其他成员请求期间可能收到维护指令；再检查一次以抑制
            # 尚未发送的操作。已经进入Agent/Docker的请求只能等待其结果收敛。
            self.check_continue(group)
            try:
                if stage is None:
                    result = self.nodes.action(member, action, aid, generation, group["id"], self.policy["stop_timeout_seconds"])
                else:
                    result = self.nodes.action(member, action, aid, generation, group["id"],
                                               self.policy["stop_timeout_seconds"], stage=stage)
            except Exception as exc:
                self.record("action_result", group=group["id"], member=member["id"], action=action,
                                action_id=aid, ok=False, error_type=type(exc).__name__)
                raise RecoveryError("node_action_unconfirmed:" + type(exc).__name__) from None
            self.record("action_result", group=group["id"], member=member["id"], action=action, action_id=aid, ok=True)
            return result
        # Agent以节点级锁保护持久台账。同节点串行、不同节点并行，避免第二个
        # 慢stop/bootstrap争锁超时。需要等待同节点伙伴的脚本必须使用异步启动契约。
        by_node = {}
        for member in members:
            by_node.setdefault(member["node"], []).append(member)
        def call_node(selected):
            for member in selected:
                call(member)
        with ThreadPoolExecutor(max_workers=min(32, len(by_node))) as pool:
            futures = [pool.submit(call_node, selected) for selected in by_node.values()]
            errors = []
            for future in futures:
                try:
                    future.result()
                except RecoveryError as exc:
                    errors.append(str(exc))
            if errors:
                raise RecoveryError("node_action_unconfirmed:" + ",".join(errors))

    def management_barrier(self, group):
        """每个变更阶段前核对全组新鲜管理证据；不要求尚在启动的服务进程就绪。

        分阶段启动期间允许进程规则尚未匹配；身份/配置漂移、未知
        动作或生命周期冲突则必须先阻断，包括当前步骤没有选中的P/D成员。
        """
        statuses = self.statuses(group, fresh=True)
        if not management_contract_confirmed(statuses):
            raise RecoveryError("group_management_contract_unconfirmed")
        runtime = self.state["groups"][group["id"]]
        if (group.get("partial_recovery") and runtime.get("recovery_inflight")
                and runtime.get("recovery_scope", {}).get("kind") == "partial"):
            policy = group["partial_recovery"]
            checks = [p for p in group["health_checks"] if p["id"] in policy["preserved_checks"]]
            if (not all(statuses[mid].get("running") is True for mid in policy["preserved_members"])
                    or not all(p.state == "pass" for p in self.probes(checks))):
                raise RecoveryError("preserved_members_not_confirmed_healthy")
        return statuses

    def wait_checks(self, group, checks, deadline, members=None, containers_only=False):
        """在共享截止时间内等待阶段检查；不把容器Running直接当作模型READY。

        containers_only仅放宽该阶段的必需进程检查，例如engine阶段允许同容器的
        Proxy尚未启动；容器身份、操作台账及本阶段显式健康探针仍必须满足条件。
        """
        results = []
        while self.elapsed_clock() < deadline:
            self.check_continue(group)
            statuses = self.management_barrier(group)
            targets = members or [m["id"] for m in group["members"]]
            if containers_only:
                running = all(statuses[mid].get("running") is True
                              and statuses[mid].get("configuration_ok") is not False
                              and statuses[mid].get("operation_busy") is not True
                              and statuses[mid].get("state") not in {"unknown", "stopped"} for mid in targets)
            else:
                running = all(statuses[mid].get("state") == "running"
                              and statuses[mid].get("operation_busy") is not True for mid in targets)
            results = self.probes(checks) if running else []
            if running and all(r.state == "pass" for r in results):
                self.check_record(group, "stage_ready", checks, results)
                return
            self.interruptible_sleep(min(self.policy["poll_interval_seconds"], max(0, deadline - self.elapsed_clock())))
        self.check_record(group, "stage_timeout", checks, results)
        raise RecoveryError("startup_deadline_exceeded")

    def recover(self, group, reason):
        """争取进程内唯一恢复资格；未取得锁的组保持待恢复状态而不重复写入。"""
        if not self.recovery_lock.acquire(blocking=False):
            self.state["groups"][group["id"]]["recovery_required"] = True
            self.transition(group, "RECOVERY_PENDING", reason)
            return
        try:
            if group.get("partial_recovery"):
                # 新鲜管理/健康证据决定范围；阻断不消耗恢复预算，也不设置重试授权。
                runtime = self.state["groups"][group["id"]]
                try:
                    observed = self.management_barrier(group)
                    kind, blocked = select_scope(group, runtime, observed, self.probes(group["health_checks"]),
                                                 self.policy["failure_threshold"])
                except RecoveryError as exc:
                    kind, blocked = None, str(exc)
                if kind is None:
                    self.transition(group, "UNKNOWN", blocked)
                    return
                runtime["recovery_scope"] = dict(kind=kind, plan_hash=plan_hash(group))
            self.state["groups"][group["id"]]["recovery_inflight"] = True
            self.state["groups"][group["id"]]["recovery_required"] = True
            self.save()
            self._recover(group, reason)
        finally:
            try:
                self.state["groups"][group["id"]]["recovery_inflight"] = False
                self.save()
            finally:
                self.recovery_lock.release()

    def _recover(self, group, reason):
        """按组执行快照、停止确认、容器启动、原脚本阶段与最终canary验收。

        预算在动作前持久化；失败进入线性退避或维护，耗尽预算后隔离。恢复只针对
        配置中已有的容器和静态阶段，不执行模型容器创建、NPU reset或跨主机迁移。
        """
        runtime = self.state["groups"][group["id"]]
        selected, steps = execution_plan(group, runtime)
        now = self.clock()
        runtime["attempts"] = [t for t in runtime["attempts"] if now - t < self.policy["attempt_window_seconds"]]
        if (runtime["incident_attempts"] >= self.policy["max_attempts"] or
                len(runtime["attempts"]) >= self.policy["max_attempts_per_window"]):
            self.transition(group, "QUARANTINED", "recovery_budget_exhausted")
            return
        runtime["incident_attempts"] += 1
        runtime["attempts"].append(now)
        # 代次须跨Controller重启单调递增，Agent据此拒绝迟到的旧stop/start。
        generation = max(self.state.get("generation", 0) + 1, time.time_ns())
        self.state["generation"] = generation
        runtime["generation"] = generation
        incident = self.state.setdefault("recovery_log", {}).setdefault(group["id"],
            dict(fault_detected_at=utc8_timestamp(now), detected_timestamp=now))
        for key in ("restored_at", "recovery_finished_at", "failure_reason", "recovery_elapsed_seconds",
                    "outage_observed_seconds", "resolution"):
            incident.pop(key, None)
        incident.setdefault("fault_reason", reason)
        incident.update(status="recovering", reason=reason, generation=generation,
                        recovery_started_at=utc8_timestamp(now), started_timestamp=now,
                        scope=runtime.get("recovery_scope", {}).get("kind", "full"),
                        members=[m["id"] for m in selected])
        self.record("recovery_started", group=group["id"], reason=reason, generation=generation,
                        attempt=runtime["incident_attempts"], summary=copy.deepcopy(incident),
                        **({"scope": incident["scope"], "members": incident["members"]}
                           if group.get("partial_recovery") or group["topology"] == "multi_node_mixed" else {}))
        self.transition(group, "DRAINING", reason)
        try:
            # 这里只做有界等待，不证明在途请求已全部排空。启用可选Gateway时，
            # 状态发布会停止该组的新准入；默认外部模式不能阻断原入口的业务流量。
            self.interruptible_sleep(self.policy["drain_seconds"])
            self.transition(group, "SNAPSHOT", reason)
            try:
                self.actions(group, group["members"], "snapshot", generation)
            except RecoveryError:
                self.record("snapshot_incomplete", group=group["id"])
            self.check_continue(group)
            self.transition(group, "STOPPING", reason)
            self.actions(group, selected, "stop", generation)
            statuses = self.management_barrier(group)
            # 所选完整实例的旧容器全部停止才启动；局部计划中的D保留运行。
            if not all(statuses[m["id"]].get("state") == "stopped" for m in selected):
                raise RecoveryError("old_members_not_confirmed_stopped")
            self.check_continue(group)
            critical, known = self.critical_fault(group)
            if critical or not known:
                raise RecoveryError("prestart_dependency_check_failed")
            self.transition(group, "STARTING", reason)
            deadline = self.elapsed_clock() + self.policy["startup_timeout_seconds"]
            # start/bootstrap阶段共用就绪截止时间，不为每台重新发放启动预算。
            # 各远端动作和最终canary仍有各自超时，这不是精确的端到端RTO上限。
            by_id = {m["id"]: m for m in group["members"]}
            for step in steps:
                if self.elapsed_clock() >= deadline:
                    raise RecoveryError("startup_deadline_exceeded")
                self.actions(group, [by_id[mid] for mid in step["members"]], step["action"], generation,
                             stage=step.get("stage"))
                if step.get("checks"):
                    self.wait_checks(group, step["checks"], deadline, step["members"],
                                     containers_only=step.get("containers_only", False))
                # 脚本返回与服务就绪分别留证，现场可确认18个API通过后才派发Proxy。
                self.record("recovery_step_ready", group=group["id"], generation=generation,
                                action=step["action"], stage=step.get("stage"), members=step["members"],
                                checks_passed=len(step.get("checks", [])))
            self.transition(group, "VALIDATING", reason)
            # 验收覆盖配置列出的端点与一次业务请求，不代表自动穷举全部P/D组合，
            # 也不能用来宣称NPU释放或真实模型/硬件兼容已经完成现场验证。
            self.wait_checks(group, group["health_checks"], deadline)
            self.check_continue(group)
            self.finish_previous_canary(group, deadline)
            key = (runtime["generation"], runtime["canary_revision"])
            result = self.run_canaries(group)
            self.check_record(group, "canary", [{"id": "aggregate_canary"}], [result])
            self.check_continue(group)
            if key != (runtime["generation"], runtime["canary_revision"]):
                raise RecoveryError("canary_epoch_changed")
            if result.state != "pass":
                raise RecoveryError("canary_validation_failed")
            # 较慢的业务探针返回后再次取样，不能用请求前的进程观测覆盖期间发生的故障。
            observed = self.management_barrier(group)
            post_running = all(item.get("state") == "running" and item.get("configuration_ok") is not False
                               and item.get("operation_busy") is not True for item in observed.values())
            final_health = self.probes(group["health_checks"]) if post_running else []
            self.check_record(group, "post_canary", group["health_checks"], final_health)
            if not post_running or not all(item.state == "pass" for item in final_health):
                raise RecoveryError("post_canary_health_changed")
            self.check_continue(group)
            incident.update(status="healthy", restored_at=utc8_timestamp(self.clock()),
                            recovery_elapsed_seconds=max(0, self.clock() - now),
                            outage_observed_seconds=max(0, self.clock() - incident["detected_timestamp"]))
            self.record("recovery_validated", group=group["id"], generation=generation,
                        summary=copy.deepcopy(incident), self_check="passed")
            remember_processes(group, runtime, observed)
            runtime.update(canary_ok=True, last_canary=self.clock(), ready_since=self.clock(),
                           last_observed_at=self.clock(), failures=0, engine_failures=0,
                           health_failure_counts={}, recovery_required=False)
            self.transition(group, "RAMP_UP", "recovery_validated")
        except RecoveryError as exc:
            incident.update(status="incomplete", recovery_finished_at=utc8_timestamp(self.clock()),
                            recovery_elapsed_seconds=max(0, self.clock() - now), failure_reason=str(exc))
            if runtime["maintenance"]:
                self.transition(group, "MAINTENANCE", "operator_maintenance")
            else:
                runtime["next_retry"] = self.clock() + self.policy["backoff_seconds"] * runtime["incident_attempts"]
                self.transition(group, "BACKOFF", str(exc))
            self.record("recovery_incomplete", group=group["id"], generation=generation, reason=str(exc),
                        summary=copy.deepcopy(incident), self_check="not_passed")
            self.save()
        except Exception as exc:
            # 包括审计落盘异常：保持原异常向上传播，不能尝试重放动作或伪造完成。
            LOG.error("recovery_aborted group=%s served_models=%s topology=%s generation=%s error_type=%s result=unconfirmed",
                      group["id"], json.dumps(self._group_log_fields(group)["served_models"], ensure_ascii=False),
                      group["topology"], generation, type(exc).__name__)
            raise

    def fail_closed(self):
        """停止自动工作并撤销可选网关路由；不会截断默认外部模式的原业务入口。"""
        self.stop_event.set()
        with self.publish_lock:
            self.gateway.set_routes([])

    def run(self):
        """每组一个监测线程，主线程持续处理维护；任一工作异常均停止自动动作。

        慢canary不应阻塞其他组的监测；真正的组恢复仍通过全局recovery_lock串行。
        停止等待有界，未完成的远端操作必须依赖Agent台账继续保持未确认状态。
        """
        self.async_canaries = True
        def monitor(gid):
            try:
                while not self.stop_event.is_set():
                    self.tick(gid)
                    self.stop_event.wait(self.policy["poll_interval_seconds"])
            except BaseException as exc:
                self.worker_errors.append(exc)
                self.fail_closed()
                LOG.exception("controller failed closed")
        threads = [threading.Thread(target=monitor, args=(g["id"],),
                    name="monitor-" + g["id"], daemon=True) for g in self.config["groups"]]
        for thread in threads:
            thread.start()
        while not self.stop_event.wait(0.25):
            try:
                self.commands()
            except BaseException as exc:
                self.worker_errors.append(exc)
                self.fail_closed()
        self.fail_closed()
        for thread in threads:
            thread.join(timeout=self.policy["request_timeout_seconds"] + 1)
        self.gateway.set_routes([])
        if self.worker_errors:
            raise RuntimeError("controller stopped after persistence/audit/worker failure") from self.worker_errors[0]


def queue_command(directory, group, action):
    """原子写入人工命令并返回ID；入队不等于Controller已消费或维护已生效。"""
    # 时间前缀使连续提交的维护命令按提交顺序消费，不再按随机UUID排序。
    command_id = f"{time.time_ns():020d}-{uuid.uuid4()}"
    atomic_json(Path(directory) / "commands" / f"{command_id}.json", {"group": group, "action": action})
    return command_id
