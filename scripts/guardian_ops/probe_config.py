"""从外部探针模板和已审阅启动清单编译健康、恢复等待及进程检查。"""
from __future__ import annotations

import copy
from pathlib import Path
import string
import sys
from urllib.parse import urlsplit

from inference_guardian.control.config import validate_probe
from .mooncake_contract import is_direct_service, is_single, endpoint_counts, validate_manifest, manifest_group_id, SCENARIO, MIXED_SCENARIO


def render(value, context):
    """只允许明确的字段替换，不解释属性、索引、格式表达式或Shell。"""
    if not isinstance(value, str) or not value:
        raise ValueError("probe template must be a nonempty string")
    try:
        for _, field, format_spec, conversion in string.Formatter().parse(value):
            if field is not None and (field not in context or format_spec or conversion):
                raise ValueError("unsupported probe template field")
        return value.format(**context)
    except (KeyError, IndexError, ValueError):
        raise ValueError("invalid probe template; use documented context fields") from None


def build_probe_contract(manifest, settings):
    """端口只取来源清单；名称、路径、说明、断言及进程模板只取外部配置。"""
    nodes = validate_manifest(manifest)
    counts = endpoint_counts(nodes.values())
    direct = is_direct_service(manifest)
    sections = {"engine", "canary"} if direct else {"mooncake", "engine", "proxy", "canary"}
    if (not isinstance(settings, dict) or settings.get("version") != 1
            or set(settings) - {"process_labels", "process_exit_detection"} != sections | {"version", "required_process_patterns"}):
        raise ValueError("probe-settings.json version 1 and all probe sections required")
    patterns = settings["required_process_patterns"]
    if not isinstance(patterns, dict) or set(patterns) != ({"engine"} if direct else {"mooncake", "engine", "proxy"}):
        raise ValueError("all required process patterns must be configured")
    labels = settings.get("process_labels", {})
    if not isinstance(labels, dict) or set(labels) - set(patterns):
        raise ValueError("invalid process label sections")

    def rule(kind, ctx, count):
        value = {"pattern": render(patterns[kind], ctx), "min_count": count}
        if kind in labels:
            if not isinstance(labels[kind], dict) or set(labels[kind]) != {"id", "description"}:
                raise ValueError("process labels require id and description")
            value.update({key: render(template, ctx) for key, template in labels[kind].items()})
        return value

    def context(node, port, rank=None):
        item = nodes[node]
        return dict(node=node, node_label=node.upper(), host=item["host"], port=port,
                    role=item["role"], rank=item["rank"] if rank is None else rank,
                    model=manifest["model_path"] if manifest["version"] == 6 else item["model"], local_dp=item["local_dp"],
                    prefill=counts["prefill"], decode=counts["decode"])

    def probe(section, ctx):
        spec = copy.deepcopy(settings[section])
        if not isinstance(spec, dict):
            raise ValueError("probe settings section must be an object: " + section)
        for field in ("id", "description", "url"):
            spec[field] = render(spec.get(field), ctx)
        if section == "canary" and manifest["version"] == 6:
            if not isinstance(spec.get("json"), dict):
                raise ValueError("service manifest requires a JSON model canary")
            spec["json"]["model"] = manifest["served_model_name"]
        if section == "proxy" and manifest["version"] >= 5:
            # 两项登记数归拓扑所有；其余现场断言、超时及状态码均原样保留。
            for role, count in counts.items():
                path = role + "_instances"
                checks = [c for c in spec.get("json_checks", []) if isinstance(c, dict) and c.get("path") == path]
                if len(checks) != 1 or checks[0].get("op") != "equals":
                    raise ValueError("proxy requires one equals assertion: " + path)
                checks[0]["value"] = count
        # 请求正文不参与模板替换，保留运行时canary的{{nonce}}。
        validate_probe(spec, section)
        endpoint = urlsplit(spec["url"])
        if (endpoint.hostname != ctx["host"] or endpoint.port != ctx["port"]
                or endpoint.scheme not in ({"tcp"} if section == "mooncake" else {"http", "https"})):
            raise ValueError("probe endpoint differs from source manifest: " + section)
        if section != "engine" and spec.get("restart_on_status"):
            raise ValueError("only engine probes may authorize health-status recovery")
        return spec

    if direct:
        ctx = context("p0", manifest["external_port"])
        health, canary = probe("engine", ctx), probe("canary", ctx)
        if not (canary.get("json_any_checks") or canary.get("json_checks") or canary.get("min_response_bytes")):
            raise ValueError("mixed canary must assert generated content")
        endpoint = urlsplit(health["url"])
        if urlsplit(canary["url"]).scheme != endpoint.scheme:
            raise ValueError("health and canary schemes must agree")
        # 每节点脚本各启动一次 vllm serve，headless 节点没有独立 HTTP API。
        processes = {node: [rule("engine", context(node, manifest["external_port"]), 1)] for node in nodes}
        return dict(engine=[health], canary=canary, route=endpoint.scheme + "://" + endpoint.netloc, processes=processes)

    mooncake, engines, processes = [], [], {}
    for node, item in nodes.items():
        mc = context(node, manifest["mooncake"]["listen_port"])
        engine = context(node, item["api_port"])
        master = node in manifest['mooncake']['startup_nodes']
        if master:
            mooncake.append(probe("mooncake", mc))
        engines.extend(probe("engine", context(node, item["api_port"] + i, item["rank"] + i))
                       for i in range(item["local_dp"]))
        processes[node] = ([rule("mooncake", mc, 1)] if master else [])
        processes[node].append(rule("engine", engine, item["local_dp"]))
    proxy_context = context("p0", manifest["external_port"])
    proxy = probe("proxy", proxy_context)
    canary = probe("canary", proxy_context)
    # JSON断言值保持类型；外部配置声明的登记数量必须与清单一致。
    checks = proxy.get("json_checks", [])
    for key in ("prefill", "decode"):
        expected = {"path": key + "_instances", "op": "equals",
                    "value": counts[key]}
        if expected not in checks:
            raise ValueError("proxy probe must assert reviewed backend count: " + key)
    if not (canary.get("json_checks") or canary.get("json_any_checks") or canary.get("min_response_bytes")):
        raise ValueError("canary must assert generated content")
    endpoint = urlsplit(proxy["url"])
    if urlsplit(canary["url"]).scheme != endpoint.scheme:
        raise ValueError("proxy and canary schemes must agree")
    names = [p["id"] for p in mooncake + engines + [proxy]]
    if len(names) != len(set(names)):
        raise ValueError("rendered health probe ids must be unique")
    processes["p0"].append(rule("proxy", proxy_context, 1))
    for items in processes.values():
        if any(not item["pattern"].strip() or not item["pattern"].isprintable() for item in items):
            raise ValueError("required process patterns must be printable and nonempty")
    return dict(mooncake=mooncake, engine=engines, proxy=proxy, canary=canary,
                route=endpoint.scheme + "://" + endpoint.netloc, processes=processes)


def build_partial_recovery(manifest, contract, steps):
    """P组独立恢复仅复用原静态动作；D保持运行时先等全部API，再启动Proxy。"""
    members = [n["id"] for n in manifest["nodes"] if n["role"] == "prefill"]
    preserved = [n["id"] for n in manifest["nodes"] if n["role"] == "decode"]
    hosts = {n["host"] for n in manifest["nodes"] if n["id"] in members}
    plan = []
    for original in steps:
        selected = [mid for mid in original["members"] if mid in members]
        if selected:
            step = copy.deepcopy(original)
            step["members"] = selected
            if step.get("stage") == "prefill":
                step.update(checks=copy.deepcopy(contract["engine"]), containers_only=True)
            plan.append(step)
    return dict(members=members, preserved_members=preserved,
                fault_checks=[p["id"] for p in contract["engine"] if urlsplit(p["url"]).hostname in hosts],
                preserved_checks=[p["id"] for p in contract["engine"] if urlsplit(p["url"]).hostname not in hosts],
                recovery_steps=plan)


def build_exit_detection(manifest, contract, settings):
    option = settings.get("process_exit_detection")
    if option is None:
        return None
    if (not isinstance(option, dict) or set(option) != {"enabled", "failure_threshold"}
            or type(option["enabled"]) is not bool or type(option["failure_threshold"]) is not int
            or not 2 <= option["failure_threshold"] <= 20):
        raise ValueError("invalid configured process exit detection")
    if not option["enabled"]:
        return None
    members = {}
    for item in manifest["nodes"]:
        node = item["id"]
        # 模板中引擎规则位于Master规则之后、Proxy规则之前；名称仍取外部模板。
        index = 1 if not is_direct_service(manifest) and node in manifest["mooncake"]["startup_nodes"] else 0
        rule = contract["processes"][node][index]
        members[node] = dict(rule_id=rule.get("id", "process-rule-" + str(index + 1)),
            checks=[p["id"] for p in contract["engine"] if is_direct_service(manifest) or urlsplit(p["url"]).hostname == item["host"]])
    return dict(members=members, failure_threshold=option["failure_threshold"])


def validate_profile_probes(controller, agents, manifest, settings):
    """接管拒绝模板已改而运行配置未同步的情况，不能沿用旧端口或旧等待门槛。"""
    contract = build_probe_contract(manifest, settings)
    if (controller["gateway"].get("listen_port") != manifest["external_port"]
            or controller["gateway"].get("listen_host") != next(n["host"] for n in manifest["nodes"] if n["id"] == "p0")):
        raise ValueError("gateway endpoint differs from source manifest")
    if len(controller["groups"]) != 1:
        raise ValueError("Mooncake deployment requires one recovery group")
    group = controller["groups"][0]
    if (manifest["version"] == 6 and manifest["scenario"] not in (SCENARIO, MIXED_SCENARIO)
            and group["id"] != manifest_group_id(manifest)):
        raise ValueError("recovery group must match the configured scenario")
    if is_direct_service(manifest):
        expected = mixed_steps(list(validate_manifest(manifest)), contract["engine"])
        topology = 'single_node_mixed' if is_single(manifest) else 'multi_node_mixed'
        if (group["topology"] != topology or group["health_checks"] != contract["engine"]
                or group["recovery_steps"] != expected or "partial_recovery" in group
                or group["canary"] != contract["canary"] or group["route"]["url"] != contract["route"]):
            raise ValueError("mixed recovery plan differs from manifest")
    else:
        _validate_pd_steps(group, manifest, contract)
    for node, patterns in contract["processes"].items():
        containers = agents[node]["containers"]
        if len(containers) != 1 or containers[0]["required_processes"] != patterns:
            raise ValueError("required processes differ from external probe settings: " + node)
    detection = build_exit_detection(manifest, contract, settings)
    if group.get("process_exit_detection") != detection:
        raise ValueError("process exit detection differs from external settings")
    for node in agents:
        expected = [detection["members"][node]["rule_id"]] if detection else None
        if agents[node]["containers"][0].get("process_exit_rules") != expected:
            raise ValueError("Agent process exit tracking differs from external settings")


def mixed_steps(members, checks):
    return [{"action": "start", "members": members, "checks": []},
            {"action": "bootstrap", "stage": "serve", "members": members,
             "checks": copy.deepcopy(checks), "containers_only": True}]


def _validate_pd_steps(group, manifest, contract):
    if (group["health_checks"] != contract["mooncake"] + contract["engine"] + [contract["proxy"]]
            or group.get("canary") != contract["canary"] or group.get("route", {}).get("url") != contract["route"]):
        raise ValueError("probe configuration changed; regenerate external profiles before adoption")
    steps = {s.get("stage"): s for s in group.get("recovery_steps", []) if s.get("action") == "bootstrap"}
    if steps.get('mooncake', {}).get('members') != manifest['mooncake']['startup_nodes']:
        raise ValueError('Mooncake recovery members differ from source manifest startup_nodes')
    for stage, checks in (("mooncake", contract["mooncake"]), ("prefill", []),
                          ("decode", contract["engine"]), ("proxy", [contract["proxy"]])):
        if steps.get(stage, {}).get("checks") != checks:
            raise ValueError("recovery checks differ from external probe settings: " + stage)
    if "partial_recovery" in group and group["partial_recovery"] != build_partial_recovery(
            manifest, contract, group["recovery_steps"]):
        raise ValueError("partial recovery differs from reviewed P/D probes and startup steps")
