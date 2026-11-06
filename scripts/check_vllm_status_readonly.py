"""只读验证Node Agent使用的Docker inspect/top观测链路，不执行恢复。

在模型所在Linux宿主机运行；Python 3.7.9+，不依赖Compose或第三方包。
仅向本机Docker Unix socket发送有期限的GET请求，不调用exec、启停、日志、
健康或推理接口，不读取Token/TLS文件，不创建状态目录，不启动Agent/Controller。
输出只含状态、规则匹配数量和身份摘要，不输出Env或完整进程命令行。

示例（每台主机选择自己的Agent配置，p0如下）：
  python3 scripts/check_vllm_status_readonly.py --agent-config \
    config/manual-profiles/example-pd-dp2tp8/agent-external-p0.json
  python3 scripts/check_vllm_status_readonly.py --self-test

默认只采样一次，最多允许三次、间隔至少五秒。GET仍有少量Docker/CPU管理开销，
通过仅说明当前观测符合规则，不能证明模型可生成、所有rank正常或恢复已验收。
退出码：0=所选规则及生命周期检查通过；1=发现需核对的状态；2=输入或采集未知。
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import http.client
import json
from pathlib import Path
import re
import socket
import sys
import threading
import time
from urllib.parse import urlencode


NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
CID = re.compile(r"[0-9a-f]{64}\Z")
DEFAULT_CONTAINER = "example-model-a"
DEFAULT_PATTERN = "vllm serve /data/models/example-model-a"
# 支持单文件只读工具；随包运行时沿用该发行包的默认服务。
_catalog = Path(__file__).resolve().parents[1] / "deploy/presets.json"
if _catalog.is_file():
    _defaults = json.loads(_catalog.read_text(encoding="utf-8"))
    DEFAULT_CONTAINER = _defaults["LEGACY_CONTAINER"]
    DEFAULT_PATTERN = "vllm serve " + _defaults["MODEL"]
SOCKET = "/var/run/docker.sock"
MAX_BYTES = 4 * 1024 * 1024


class ObservationError(Exception):
    """仅携带固定原因代码；不转发可能包含业务信息的Docker响应正文。"""


class UnixConnection(http.client.HTTPConnection):
    """只连接固定的本机Docker socket，不读取代理或DOCKER_HOST环境变量。"""

    def __init__(self, timeout):
        super().__init__("localhost", timeout=timeout)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(SOCKET)


class ReadOnlyDocker:
    """只提供inspect/top；没有变更请求、重试、容器枚举或脚本执行入口。"""

    def __init__(self, api, timeout, connection_factory=UnixConnection):
        if api not in {"v1.41", "v1.45"} or type(timeout) is not int or not 1 <= timeout <= 5:
            raise ObservationError("invalid_readonly_client_settings")
        self.api, self.timeout = api, timeout
        self.connection_factory = connection_factory
        self.requests = 0

    def _get(self, suffix):
        # 再校验路径，使未来维护也不能把任意Docker接口接入此预检脚本。
        path, _, query = suffix.partition("?")
        if not re.fullmatch(r"/containers/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}/(?:json|top)", path):
            raise ObservationError("readonly_path_rejected")
        if query and (not path.endswith("/top") or query != urlencode({"ps_args": "-ww -eo pid,args"})):
            raise ObservationError("readonly_query_rejected")
        connection = self.connection_factory(self.timeout)
        timer = None
        deadline = time.monotonic() + self.timeout
        try:
            connection.connect()
            transport = connection.sock
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ObservationError("docker_timeout")
            transport.settimeout(remaining)

            def expire():
                # 共享总期限，避免慢速分片使单次读取无限延长；只关闭本次查询连接。
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(remaining, expire)
            timer.daemon = True
            timer.start()
            self.requests += 1
            connection.request("GET", "/" + self.api + suffix)
            response = connection.getresponse()
            if response.status != 200:
                raise ObservationError("docker_http_" + str(response.status))
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ObservationError("docker_response_too_large")
            if time.monotonic() > deadline:
                raise ObservationError("docker_timeout")
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ObservationError("docker_response_not_object")
            return data
        except (OSError, ValueError, http.client.HTTPException):
            raise ObservationError("docker_query_unavailable") from None
        finally:
            if timer is not None:
                timer.cancel()
            connection.close()

    def inspect(self, identifier):
        return self._get("/containers/" + identifier + "/json")

    def top(self, identifier):
        return self._get("/containers/" + identifier + "/top?" + urlencode({"ps_args": "-ww -eo pid,args"}))


def selected_rules(args):
    """仅读配置里的容器名、进程规则及API版本；不解析或执行bootstrap命令。"""
    if args.agent_config and args.pattern:
        raise ObservationError("choose_agent_config_or_patterns")
    if args.agent_config:
        config_path = Path(args.agent_config)
        if not config_path.is_file() or config_path.is_symlink():
            raise ObservationError("regular_config_file_required")
        with config_path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ObservationError("config_too_large")
        config = json.loads(raw)
        if not isinstance(config, dict) or config.get("docker_socket", SOCKET) != SOCKET:
            raise ObservationError("fixed_local_docker_socket_required")
        containers = config.get("containers")
        if not isinstance(containers, list) or not containers or not all(isinstance(c, dict) for c in containers):
            raise ObservationError("invalid_container_config")
        matches = [c for c in containers if args.container is None or c.get("name") == args.container]
        if len(matches) != 1:
            raise ObservationError("select_one_exact_container")
        name = matches[0].get("name")
        rules = matches[0].get("required_processes")
        api = config.get("docker_api_version", "v1.41")
    else:
        name = args.container or DEFAULT_CONTAINER
        rules = [{"pattern": p, "min_count": 1} for p in (args.pattern or [DEFAULT_PATTERN])]
        api = "v1.41"
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ObservationError("invalid_container_name")
    if api not in {"v1.41", "v1.45"}:
        raise ObservationError("unreviewed_docker_api_version")
    if not isinstance(rules, list) or not 1 <= len(rules) <= 32:
        raise ObservationError("nonempty_process_rules_required")
    for rule in rules:
        if (not isinstance(rule, dict) or not isinstance(rule.get("pattern"), str)
                or not 1 <= len(rule["pattern"]) <= 4096
                or not rule["pattern"].strip()
                or type(rule.get("min_count", 1)) is not int
                or not 1 <= rule.get("min_count", 1) <= 4096):
            raise ObservationError("invalid_process_rule")
    return name, rules, api


def process_counts(top, rules):
    """与Node Agent相同：在COMMAND/CMD/ARGS列进行区分大小写的字面子串匹配。"""
    titles, rows = top.get("Titles"), top.get("Processes")
    if not isinstance(titles, list) or not isinstance(rows, list) or len(rows) > 16384:
        raise ObservationError("invalid_process_table")
    columns = [i for i, value in enumerate(titles) if str(value).upper() in {"COMMAND", "CMD", "ARGS"}]
    if not columns:
        raise ObservationError("missing_command_column")
    column = columns[-1]
    if any(not isinstance(row, list) or len(row) != len(titles) or not isinstance(row[column], str) for row in rows):
        raise ObservationError("invalid_process_row")
    # 不输出完整命令行或PID，避免把业务参数、令牌等带入预检报告。
    return [{"rule_index": index, "id": rule.get("id", "process-rule-" + str(index)),
             "description": rule.get("description", "Configured process rule " + str(index)),
             "minimum": rule.get("min_count", 1),
             "matched": sum(rule["pattern"] in row[column] for row in rows)}
            for index, rule in enumerate(rules, 1)]


def inspect_state(info, name):
    state = info.get("State")
    host = info.get("HostConfig")
    if (info.get("Name") != "/" + name or not CID.fullmatch(info.get("Id", ""))
            or not isinstance(state, dict) or not isinstance(host, dict)
            or type(state.get("Running")) is not bool
            or not isinstance(state.get("StartedAt"), str)
            or not isinstance(state.get("Health", {}), dict)):
        raise ObservationError("incomplete_container_metadata")
    return state, host


def sample(client, name, rules):
    """一次至多三个GET；再次inspect确认采集期间同一容器没有改变启动世代或状态。"""
    first = client.inspect(name)
    state, host = inspect_state(first, name)
    health = state.get("Health", {}).get("Status", "none")
    counts = []
    result = "unknown"
    if state.get("Paused") or state.get("Restarting") or state.get("Dead"):
        result = "unhealthy"
    elif state["Running"] is False and state.get("Status") in {"created", "exited"}:
        result = "stopped"
    elif state["Running"] is True and state.get("Status") == "running":
        counts = process_counts(client.top(first["Id"]), rules)
        process_ok = all(row["matched"] >= row["minimum"] for row in counts)
        result = "unhealthy" if health == "unhealthy" else "running" if health in {"none", "healthy"} else "unknown"
    last = client.inspect(first["Id"])
    last_state, _ = inspect_state(last, name)
    # HEALTHCHECK日志正常刷新不代表容器状态变化，只比较其状态值。
    epoch_fields = ("Running", "Status", "StartedAt", "FinishedAt", "Paused", "Restarting", "Dead")
    if (last["Id"] != first["Id"] or any(state.get(key) != last_state.get(key) for key in epoch_fields)
            or health != last_state.get("Health", {}).get("Status", "none")):
        raise ObservationError("container_changed_during_sample")
    restart = host.get("RestartPolicy", {})
    lifecycle_ok = (host.get("AutoRemove") is False and isinstance(restart, dict)
                    and restart.get("Name") in {"no", ""})
    return {"time_utc": datetime.now(timezone.utc).isoformat(), "container": name,
            "container_id_short": first["Id"][:12], "state": result, "running": state["Running"],
            "process_ok": all(row["matched"] >= row["minimum"] for row in counts) if counts else None,
            "process_rules": counts, "docker_health": health,
            "lifecycle_compatible": lifecycle_ok,
            "check_passed": result == "running" and lifecycle_ok and bool(counts)
                            and all(row["matched"] >= row["minimum"] for row in counts)}


def self_test():
    """仅用内存HTTP替身验证请求白名单和分类，不连接Unix socket或现场端点。"""
    rules = [{"pattern": DEFAULT_PATTERN, "min_count": 1}]
    info = {"Id": "a" * 64, "Name": "/" + DEFAULT_CONTAINER,
            "State": {"Running": True, "Status": "running", "StartedAt": "fixture-epoch"},
            "HostConfig": {"AutoRemove": False, "RestartPolicy": {"Name": "no"}}}
    top = {"Titles": ["PID", "COMMAND"], "Processes": [["7", DEFAULT_PATTERN]]}
    cases = []

    def run_responses(payloads, fail_connect=False):
        calls = []

        class Connection:
            def __init__(self, timeout):
                self.sock = self

            def connect(self):
                if fail_connect:
                    raise OSError("simulated unavailable Docker socket")
            def settimeout(self, remaining): pass
            def shutdown(self, mode): pass
            def close(self): pass

            def request(self, method, path):
                assert method == "GET"
                calls.append((method, path))

            def getresponse(self):
                data = payloads.pop(0)
                self.body = json.dumps(data).encode()
                self.status = 200
                return self

            def read(self, size):
                return self.body[:size]

        client = ReadOnlyDocker("v1.41", 3, Connection)
        try:
            value = sample(client, DEFAULT_CONTAINER, rules)
        except ObservationError as exc:
            value = {"state": "unknown", "reason": str(exc)}
        assert len(calls) <= 3
        assert all("/json" in path or "/top?" in path for _, path in calls)
        return value

    assert run_responses([info, top, info])["check_passed"] is True
    cases.append("healthy_process_and_get_only")
    missing = {"Titles": ["PID", "COMMAND"], "Processes": [["1", "bash"]]}
    mismatch = run_responses([info, missing, info])
    assert mismatch["state"] == "running" and mismatch["process_ok"] is False and mismatch["check_passed"] is False
    cases.append("process_rule_mismatch_does_not_claim_inference_failure")
    stopped = copy.deepcopy(info)
    stopped["State"].update(Running=False, Status="exited")
    assert run_responses([stopped, stopped])["state"] == "stopped"
    cases.append("confirmed_stopped")
    changed = copy.deepcopy(info)
    changed["State"]["StartedAt"] = "new-epoch"
    assert run_responses([info, top, changed])["reason"] == "container_changed_during_sample"
    cases.append("concurrent_restart_is_unknown")
    bad_top = {"Titles": ["PID"], "Processes": [["1"]]}
    assert run_responses([info, bad_top])["state"] == "unknown"
    cases.append("unusable_process_table_is_unknown")
    assert run_responses([], fail_connect=True)["reason"] == "docker_query_unavailable"
    cases.append("docker_unavailable_is_unknown_not_stopped")
    misleading = {"Titles": ["COMMAND", "PID"], "Processes": [["bash", DEFAULT_PATTERN]]}
    assert run_responses([info, misleading, info])["process_ok"] is False
    cases.append("only_command_column_can_match")
    try:
        ReadOnlyDocker("v1.41", 3)._get("/containers/any/start")
    except ObservationError as exc:
        assert str(exc) == "readonly_path_rejected"
    else:
        raise AssertionError("unsafe path accepted")
    cases.append("mutation_endpoint_rejected_before_connect")
    return {"self_test": True, "passed": True, "cases": cases, "real_docker_accessed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--agent-config", help="本节点Agent JSON；只读取容器/规则/API，不读取凭据或执行bootstrap")
    parser.add_argument("--container", help="精确容器名；配置含多个容器时必须指定")
    parser.add_argument("--pattern", action="append", help="无Agent配置时的命令子串；可重复，各要求至少一个进程")
    parser.add_argument("--samples", type=int, choices=range(1, 4), default=1)
    parser.add_argument("--interval", type=int, choices=range(5, 31), default=5)
    parser.add_argument("--timeout", type=int, choices=range(1, 6), default=3, help="单次Docker请求期限，1–5秒")
    parser.add_argument("--self-test", action="store_true", help="仅运行内存验证，不访问Docker")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            print(json.dumps(self_test(), ensure_ascii=False, indent=2))
            return 0
        if sys.platform != "linux":
            raise ObservationError("run_live_check_on_linux_model_host")
        name, rules, api = selected_rules(args)
        client = ReadOnlyDocker(api, args.timeout)
        samples = []
        for index in range(args.samples):
            if index:
                time.sleep(args.interval)
            try:
                result = sample(client, name, rules)
            except (ObservationError, TypeError) as exc:
                result = {"state": "unknown", "reason": str(exc) if isinstance(exc, ObservationError) else "invalid_metadata"}
            samples.append(result)
            # 采集未知时立即结束，避免因Daemon故障继续发请求；没有重试或修复动作。
            if result["state"] == "unknown":
                break
        unknown = any(item["state"] == "unknown" for item in samples)
        passed = all(item.get("check_passed") is True for item in samples)
        print(json.dumps({"read_only": True, "scope": "local_docker_container_and_process_observation",
                          "passed": passed, "docker_get_requests": client.requests,
                          "inference_requests": 0, "model_mutations": 0,
                          "not_validated": ["inference_readiness", "all_worker_ranks", "recovery_execution",
                                            "node_agent_action_journal", "pinned_configuration_fingerprint"],
                          "samples": samples}, ensure_ascii=False, indent=2))
        return 2 if unknown else 0 if passed else 1
    except (ObservationError, OSError, ValueError, TypeError):
        print(json.dumps({"read_only": True, "passed": False, "state": "unknown",
                          "reason": "input_or_local_observation_unavailable",
                          "hint": "核对Linux宿主、Docker socket读取权限、精确容器名及JSON配置；不要据此重启模型。"},
                         ensure_ascii=False, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
