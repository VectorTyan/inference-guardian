"""部署后验收：只读管理检查，可选真实生成请求；从不调用Agent action或Docker启停。

在各宿主检查本机组件、基线及审计，在Controller宿主额外检查所有Agent与组就绪。
--canary会消耗推理资源，但不改变Guardian模式、维护状态或执行故障注入。
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[2]
from .deployment import DEFAULT_STATE_ROOT, GuardianDeployment, remap_secrets
from inference_guardian.observability.audit import verify
from inference_guardian.control.config import validate
from inference_guardian.containers.contract import bootstrap_stage_hashes
from inference_guardian.http_client import file_headers, request
from inference_guardian.storage import read_json
from inference_guardian.control.topology import canary_specs
from inference_guardian.health.identity import probe_id, probe_description
from inference_guardian.observability.log_state import file_log_status


def agent_get(spec, path, headers):
    """只允许两个只读Agent端点，不跟随重定向；调用方不保存原始响应正文。"""
    if path not in {"/health", "/v1/status"}:
        raise ValueError("read-only Agent endpoint required")
    status, _, body = request(spec["url"].rstrip("/") + path, headers=headers,
        timeout=spec.get("status_timeout_seconds", 20), ca_file=spec.get("ca_file"),
        cert_file=spec.get("cert_file"), key_file=spec.get("key_file"))
    return status, body


def verify_deployment(deployment, *, with_canary=False):
    """逐项报告pass/fail/skipped；不将没有执行的canary或故障恢复描述为通过。"""
    report = {"time_utc": datetime.now(timezone.utc).isoformat(), "node": deployment.node,
              "scope": "deployed read-only acceptance; optional inference canary",
              "recovery_exercised": False, "canary_requested": with_canary, "checks": [], "warnings": []}
    def check(identifier, operation, description=None):
        item = {"id": identifier}
        if description is not None:
            item["description"] = description
        try:
            if operation() is not True:
                raise ValueError("check did not pass")
            report["checks"].append(dict(item, status="pass"))
            return True
        except Exception as exc:
            # 不回显配置URL、Token、原响应或生成结果；细节通过受保护的现网日志排查。
            report["checks"].append(dict(item, status="fail", error_type=type(exc).__name__))
            return False
    def local_components():
        status = deployment.status()
        return bool(status["components"]) and all(
            isinstance(item, dict) and item.get("running") is True for item in status["components"].values())
    if not check("local.components_and_adoption", local_components):
        report["passed"] = False
        return report
    config = (validate(read_json(deployment.runtime / "controller.json")) if deployment.is_controller
              else deployment.source_controller)
    nodes = config["nodes"] if deployment.is_controller else {deployment.node: config["nodes"][deployment.node]}
    specs = remap_secrets(nodes, {}, directory=deployment.runtime / "secrets")
    headers = {}
    for node, spec in specs.items():
        def load(node=node, spec=spec):
            headers[node] = file_headers(spec)
            return bool(headers[node].get("Authorization"))
        check(f"{node}.credential_readable", load)
    if deployment.is_controller:
        check("tokens.independent", lambda: len(headers) == len(nodes) and
              len({item["Authorization"] for item in headers.values()}) == len(nodes))
    for node, spec in specs.items():
        if node not in headers:
            continue
        check(f"{node}.missing_token_rejected", lambda spec=spec: agent_get(spec, "/health", {})[0] == 401)
        check(f"{node}.wrong_token_rejected", lambda spec=spec: agent_get(spec, "/health",
              {"Authorization": "Bearer " + secrets.token_urlsafe(32)})[0] == 401)
        # 多节点部署同时证明别的节点Token不能访问当前Agent，而不只是随机错误Token被拒绝。
        other = next((value for key, value in headers.items() if key != node), None)
        if other:
            check(f"{node}.other_node_token_rejected", lambda spec=spec, other=other:
                  agent_get(spec, "/health", other)[0] == 401)
        def health(node=node, spec=spec):
            status, body = agent_get(spec, "/health", headers[node])
            data = json.loads(body)
            return status == 200 and data.get("node_id") == node and data.get("ok") is True and data.get("audit_available") is True
        check(f"{node}.agent_health_identity", health)
        def log_persisted(node=node, spec=spec):
            status, body = agent_get(spec, "/health", headers[node])
            data = json.loads(body)
            return (status == 200 and data.get("node_id") == node
                    and data.get("runtime_logging", {}).get("persistent_file_ok") is True)
        check(f"{node}.agent_log_persistence", log_persisted, "Agent确认日志文件仍在写入且未失联/替换")
        def contracts(node=node, spec=spec):
            status, body = agent_get(spec, "/v1/status", headers[node])
            data = json.loads(body)
            expected = {item["name"]: item for item in deployment.agents[node]["containers"]}
            observed = data.get("containers", {})
            if status != 200 or data.get("node_id") != node or data.get("mutation_journal_clear") is not True or set(observed) != set(expected):
                return False
            for name, source in expected.items():
                item = observed[name]
                if (item.get("state") != "running"
                        or item.get("configuration_ok") is not True or item.get("operation_busy") is not False
                        or item.get("restart_policy") not in {"no", ""} or item.get("auto_remove") is not False
                        or item.get("bootstrap_stage_hashes") != bootstrap_stage_hashes(source.get("bootstrap_commands", {}))
                        or (item.get("requires_bootstrap") is True and item.get("bootstrap_configured") is not True)):
                    return False
                if item.get("process_ok") is not True:
                    report["warnings"].append(dict(id=f"{node}.process_rule_mismatch", container=name,
                        description="进程规则待核对；不等同推理故障，业务就绪由Controller健康及生成证据确认",
                        process_checks=item.get("process_checks", [])))
            return True
        check(f"{node}.models_and_startup_contract", contracts)
    report["audit_records"] = {}
    for role in (["agent", "controller"] if deployment.is_controller else ["agent"]):
        def local_log(role=role):
            value = file_log_status(deployment.state / role / "inference-guardian.log")
            report.setdefault("log_files", {})[role] = value
            return value["exists"] and value["bytes"] > 0
        check(f"local.{role}_log_file", local_log, "宿主持久日志文件存在且非空（与动作审计分开）")
        def audit_chain(role=role):
            directory = deployment.state / role / "audit"
            if not directory.is_dir():
                return False
            count = verify(directory)["records"]
            report["audit_records"][role] = count
            # Agent首次observe安装尚未执行动作时合法为空；Controller启动则应留记录。
            return role == "agent" or count > 0
        check(f"local.{role}_audit_chain", audit_chain)
    if deployment.is_controller:
        def fresh():
            deployment.require_fresh_readiness(config)
            return True
        check("controller.fresh_readiness", fresh)
        for group in config["groups"]:
            for index, spec in enumerate(group["health_checks"]):
                check(f"{group['id']}.health.{probe_id(spec, index)}",
                      lambda spec=spec: deployment.probe_passes(spec, config["policy"]["request_timeout_seconds"]),
                      probe_description(spec, index))
            for index, spec in enumerate(canary_specs(group)):
                name = f"{group['id']}.canary.{probe_id(spec, index)}"
                if with_canary:
                    check(name, lambda spec=spec: deployment.probe_passes(spec, config["policy"]["request_timeout_seconds"]),
                          probe_description(spec, index))
                else:
                    report["checks"].append({"id": name, "description": probe_description(spec, index),
                                             "status": "skipped", "reason": "enable --canary to send inference"})
        # 执行业务请求后再采样，避免长canary掩盖期间失效的Controller就绪证据。
        if with_canary:
            check("controller.readiness_after_canary", fresh)
    elif with_canary:
        check("canary.requires_controller_node", lambda: False)
    report["passed"] = all(item["status"] != "fail" for item in report["checks"])
    return report


def main(argv=None):
    """退出码0=已执行检查通过，1=失败；JSON中明确列出跳过项及未验证的恢复能力。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--controller-node")
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
    parser.add_argument("--runtime-dir", type=Path)
    parser.add_argument("--canary", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        deployment = GuardianDeployment(args.profile, args.node, controller_node=args.controller_node,
                                        state_root=args.state_root, runtime_dir=args.runtime_dir)
        report = verify_deployment(deployment, with_canary=args.canary)
        content = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            # 不覆盖既有验收证据，由运维为每轮选新文件名。
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(content)
        print(content)
        return 0 if report["passed"] else 1
    except Exception as exc:
        print("Guardian verification failed: " + type(exc).__name__, file=sys.stderr)
        return 1
