"""本机inspect/top证据采集；不创建台账、不执行容器变更。"""
from __future__ import annotations
from ..containers.contract import bootstrap_stage_hashes, simple_shell_pid1
from ..health.process_evidence import process_identity

def _unknown(detail: str) -> dict:
    # false/0 是兼容字段的占位值，不是已停止或无故障的证据；以 unknown 为准。
    return dict(state="unknown", running=False, process_ok=False, oom_killed=False,
                exit_code=0, restart_policy="unknown", image_id="", health_status="unknown", auto_remove=False, detail=detail)


def _commands(top: dict) -> list[str]:
    """只取 Docker top 的命令列；PID 等其他列不能充当所需进程的匹配证据。"""
    titles = top.get("Titles")
    rows = top.get("Processes")
    if not isinstance(titles, list) or not isinstance(rows, list) or len(rows) > 16384:
        raise ValueError("Invalid Docker top response")
    columns = [str(title).upper() for title in titles]
    command_columns = [index for index, title in enumerate(columns) if title in ("COMMAND", "CMD", "ARGS")]
    if not command_columns:
        raise ValueError("Docker top response lacks a command column")
    index = command_columns[-1]
    commands = []
    for row in rows:
        if not isinstance(row, list) or len(row) != len(titles) or not isinstance(row[index], str):
            raise ValueError("Invalid Docker top process row")
        commands.append(row[index])
    return commands


def observe_container(docker, name, spec, verify_contract, operation_busy):
    """从 inspect/top 汇总容器证据，不将 running 提升为推理 ready。

    只有明确的停止状态或缺失进程等观测才能作为对应故障证据；Docker
    连接失败属于 unknown。Controller 另行判定健康检查与业务探针结果。
    """
    stage_hashes = bootstrap_stage_hashes(spec.get("bootstrap_commands", {}))
    try:
        info = docker.inspect(name)
        state = info["State"]
        if not isinstance(state, dict) or not isinstance(state.get("Running"), bool):
            raise ValueError("Missing Docker running state")
        if info.get("Name") != "/" + name:
            raise ValueError("Docker name does not match allowlisted name")
        host = info["HostConfig"]
        if not isinstance(host.get("AutoRemove"), bool) or not isinstance(host.get("RestartPolicy", {}).get("Name"), str):
            raise ValueError("Missing Docker lifecycle metadata")
        policy = host["RestartPolicy"]["Name"]
        health = state.get("Health", {}).get("Status", "none")
        result = dict(
            state="unknown", running=state["Running"], process_ok=False,
            oom_killed=state.get("OOMKilled", False), exit_code=state.get("ExitCode", 0),
            restart_policy=policy, image_id=info.get("Image", ""), health_status=health,
            auto_remove=host.get("AutoRemove", False), detail="", container_id=info.get("Id", ""),
            configuration_ok=True, bootstrap_stage_hashes=stage_hashes,
        )
        result["bootstrap_configured"] = bool(spec.get("bootstrap_commands"))
        result["requires_bootstrap"] = simple_shell_pid1(info) and not result["bootstrap_configured"]
        expected = spec.get("expected_image_id")
        try:
            verify_contract(name, info)
            contract_ok = True
        except ValueError:
            contract_ok = False
        if not contract_ok:
            result.update(state="unhealthy", configuration_ok=False, detail="Container identity or configuration differs from the pinned contract")
        elif expected and expected != result["image_id"]:
            result.update(state="unhealthy", configuration_ok=False, detail="Image ID differs from pinned configuration")
        elif state.get("Paused") or state.get("Restarting") or state.get("Dead"):
            result.update(state="unhealthy", detail="Container is paused, restarting, or dead")
        elif not result["running"]:
            if state.get("Status") in ("exited", "created"):
                result.update(state="stopped", detail="Docker confirms container stopped")
            else:
                result["detail"] = "Docker state is not a confirmed stopped state"
        elif state.get("Status") != "running":
            result["detail"] = "Docker returned inconsistent running state"
        else:
            # 字面匹配只证明当前命令列满足数量要求，不验证 rank/KV 链路可用。
            top = docker.top(info.get("Id") or name)
            commands = _commands(top)
            if spec.get("process_exit_rules"):
                identity = process_identity(info, top, spec["required_processes"], spec["process_exit_rules"])
                if identity["available"]:
                    after = docker.inspect(info["Id"])
                    if (after.get("Id") != info["Id"] or after.get("State", {}).get("StartedAt") != state["StartedAt"]
                            or after.get("State", {}).get("Running") is not True
                            or after.get("State", {}).get("Status") != "running"
                            or any(after["State"].get(k) for k in ("Paused", "Restarting", "Dead"))):
                        raise ValueError("Container changed during process observation")
                    verify_contract(name, after)
                result["process_identity"] = identity
            result["process_checks"] = [dict(id=spec.get("id", "process-rule-" + str(index)),
                description=spec.get("description", "Configured process rule " + str(index)),
                matched=sum(spec["pattern"] in command for command in commands), minimum=spec["min_count"])
                for index, spec in enumerate(spec["required_processes"], 1)]
            result["process_ok"] = all(item["matched"] >= item["minimum"] for item in result["process_checks"])
            result["process_rules_status"] = "matched" if result["process_ok"] else "mismatch"
            if health == "unhealthy":
                result.update(state="unhealthy", detail="Docker HEALTHCHECK is unhealthy")
            elif health not in ("healthy", "none"):
                result.update(state="unknown", detail="Docker HEALTHCHECK is not ready")
            else:
                result.update(state="running", detail=("Container running; process rules matched; inference not verified"
                    if result["process_ok"] else "Container running; process rule mismatch; inference not verified"))
        result["operation_busy"] = operation_busy(name)
        return result
    except Exception:
        # 无法访问 Docker daemon/top 不等于容器停止，不能据此触发盲目重启。
        return dict(_unknown("Docker inspection or process listing unavailable"), operation_busy=operation_busy(name),
                    requires_bootstrap=False, bootstrap_configured=bool(spec.get("bootstrap_commands")),
                    bootstrap_stage_hashes=stage_hashes)
