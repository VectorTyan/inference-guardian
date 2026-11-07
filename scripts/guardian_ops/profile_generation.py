"""生成当前四机Ascend 1P1D的外部恢复配置，默认observe且关闭业务Gateway。

端口读取source-manifest.json，探针及进程模板读取probe-settings.json。
输出不固定现场CID/image/config PIN，adopt时才读取真实对象；不读写Docker或修改原模型脚本。
"""
from __future__ import annotations

import argparse
import copy
import json
from itertools import chain
from pathlib import Path
from .mooncake_contract import DEPLOYMENT_ID, RETIRED_DEPLOYMENT_IDS, LAYOUT, PROFILE, V4_EXAMPLE, V41_EXAMPLE, node_commands, validate_manifest, path_only_manifest
from .mooncake_contract import MIXED_EXAMPLE, MIXED_ID, MIXED_PROFILE, MIXED_EXAMPLES, manifest_deployment_id, manifest_group_id, is_mixed
from .presets import PACKAGED_EXAMPLES as _PACKAGED_EXAMPLES
from .probe_config import mixed_steps, build_probe_contract, build_partial_recovery, build_exit_detection
from inference_guardian.control.config import validate as validate_controller
from inference_guardian.agent.config import validate_config as validate_agent

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"
FRAMEWORKS = ("vllm-ascend",)
TOPOLOGIES = _PACKAGED_EXAMPLES
DEEPSEEK_PROFILE = PROFILE  # 旧完整 profile 的生成器兼容路径
# 部署身份与接管保护使用共享常量，旧身份只能通过维护迁移更新。
GENERATION = "external-v11-selective-prefill"


def _read(path):
    """以UTF-8读取单个JSON对象；基线缺失或结构错误直接失败。"""
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("profile input must be a JSON object")
    return value


def _agent(node, host, containers, *, api_version, request_timeout):
    """生成HTTP与每节点独立文件Token配置；TLS仍可由现场显式配置启用。"""
    return {"node_id": node,
        "listen": {"host": host, "port": 19090,
                   "token_file": f"/run/secrets/inference-guardian/{node}.token", "allow_insecure_http": True},
        "docker_socket": "/var/run/docker.sock", "docker_api_version": api_version,
        "request_timeout_seconds": request_timeout, "state_dir": "/var/lib/inference-guardian/agent",
        "logging": {"max_bytes": 10485760, "backup_count": 5,
                    "status_interval_seconds": 60, "observation_max_age_seconds": 60},
        "containers": containers}


def _deployment(controller_node, deployment_id):
    """生成安装元数据：控制节点、稳定部署身份、生成批次；不描述推理拓扑。

    deployment_id参与组件名称、状态路径和接管指纹，不能随发布批次更换。
    source_generation仅用于来源说明，不控制容器启动，也不是框架/镜像版本。
    """
    return {"controller_node": controller_node, "deployment_id": deployment_id,
            "source_generation": "external-mixed2node-v1" if deployment_id in MIXED_EXAMPLES else GENERATION}


def _deepseek(examples, directory=None, settings=None, manifest=None, logging_by_node=None):
    """按部署拓扑编译节点白名单、故障证据及恢复阶段。"""
    directory = directory or examples / "vllm-ascend" / DEEPSEEK_PROFILE
    manifest = _read(directory / "source-manifest.json") if manifest is None else manifest
    by_id = validate_manifest(manifest)
    if manifest['version'] not in (4, 5, 6):
        raise ValueError('new deployment requires reviewed v4 manifest or newer with Mooncake only on p0; legacy v3 cannot be regenerated')
    order = tuple(by_id)
    settings = _read(directory / "probe-settings.json") if settings is None else settings
    probes = build_probe_contract(manifest, settings)
    detection = build_exit_detection(manifest, probes, settings)
    members = [{"id": node, "node": node, "container": by_id[node]["container"]} for node in order]
    identifiers = list(order)
    engine_checks, canary = probes["engine"], probes["canary"]
    controller = {"version": 1, "mode": "observe", "state_dir": "/var/lib/inference-guardian/controller",
        "nodes": {node: {"url": f"http://{by_id[node]['host']}:19090", "allow_insecure_http": True,
                         "token_file": f"/run/secrets/inference-guardian/{node}.token",
                         "status_timeout_seconds": 20, "action_timeout_seconds": 120} for node in order},
        "gateway": {"listen_host": by_id["p0"]["host"], "listen_port": manifest["external_port"], "max_inflight": 2,
                    "max_body_bytes": 33554432, "max_output_tokens": 1048576, "default_output_tokens": 1024,
                    "upstream_timeout_seconds": 3600, "allowed_paths": ["/v1/chat/completions", "/v1/completions"],
                    "enabled": False},
        "policy": {"startup_timeout_seconds": 3600, "canary_interval_seconds": 120,
                   "canary_max_age_seconds": 900, "stop_timeout_seconds": 30},
        "groups": []}
    if is_mixed(manifest):
        identity = manifest_deployment_id(manifest)
        group = {"id": manifest_group_id(manifest), "framework": "vllm-ascend", "topology": "multi_node_mixed",
                 "members": members, "instances": [{"id": "model", "role": "mixed", "members": identifiers}],
                 "health_checks": engine_checks, "canary": canary, "route": {"url": probes["route"], "max_inflight": 2},
                 "recovery_steps": mixed_steps(identifiers, engine_checks)}
    else:
        identity = DEPLOYMENT_ID
        mooncake_checks, proxy_check = probes["mooncake"], probes["proxy"]
        group = {"id": manifest_group_id(manifest), "framework": "vllm-ascend", "topology": "pd_disaggregated",
                    "members": members, "instances": [{"id": "prefill", "role": "prefill", "members": ["p0", "p1"]},
                        {"id": "decode", "role": "decode", "members": ["d0", "d1"]}],
                    "health_checks": mooncake_checks + engine_checks + [proxy_check], "canary": canary,
                    "route": {"url": probes["route"], "max_inflight": 2},
                    "recovery_steps": [
                        {"action": "start", "members": identifiers, "checks": []},
                        {"action": "bootstrap", "stage": "mooncake", "members": list(manifest['mooncake']['startup_nodes']),
                         "checks": copy.deepcopy(mooncake_checks), "containers_only": True},
                        # P脚本返回后立即派发D，不能在D启动前等待P权重/通信就绪。
                        {"action": "bootstrap", "stage": "prefill", "members": ["p0", "p1"], "checks": []},
                        {"action": "bootstrap", "stage": "decode", "members": ["d0", "d1"],
                         "checks": copy.deepcopy(engine_checks), "containers_only": True},
                        {"action": "bootstrap", "stage": "proxy", "members": ["p0"],
                         "checks": [copy.deepcopy(proxy_check)], "containers_only": False}]}
        group["partial_recovery"] = build_partial_recovery(manifest, probes, group["recovery_steps"])
    controller["groups"].append(group)
    if detection:
        group["process_exit_detection"] = detection
    files = {directory / "controller-external.json": controller,
             directory / "deployment-external.json": _deployment("p0", identity)}
    for node in order:
        container = {"name": by_id[node]["container"],
                     "required_processes": probes["processes"][node],
                     "bootstrap_commands": node_commands(manifest, node)}
        if detection:
            container["process_exit_rules"] = [detection["members"][node]["rule_id"]]
        path = directory / f"agent-external-{node}.json"
        value = _agent(
            node, by_id[node]["host"], [container], api_version="v1.41", request_timeout=5)
        # logging是运维输入；重生成模型契约时保留已配置值，随后按Agent规则校验。
        if path.is_symlink():
            raise ValueError("Agent profile cannot be a symlink")
        if logging_by_node is not None:
            if node in logging_by_node:
                value["logging"] = logging_by_node[node]
        elif path.is_file():
            existing = _read(path)
            if "logging" in existing:
                value["logging"] = existing["logging"]
        files[path] = value
    # 所有输出先校验再写入，错误模板不会部分覆盖现场配置。
    validate_controller(controller)
    for path, value in files.items():
        if path.name.startswith("agent-external-"):
            validate_agent(value)
    return files


def compile_service_manifest(directory, manifest_bytes, base, settings_bytes=None):
    """把单份v6输入编译为既有部署快照；仅从已核验的基线继承探针策略和日志参数。"""
    manifest = json.loads(manifest_bytes)
    if manifest.get("version") != 6:
        raise ValueError("standalone service manifest requires version 6")
    if settings_bytes is None and base is None:
        raise ValueError("probe defaults required for first installation")
    settings = json.loads(base["probe-settings.json"] if settings_bytes is None else settings_bytes)
    logging = {}
    if base is not None:
        for node in validate_manifest(manifest):
            agent = json.loads(base[f"agent-external-{node}.json"])
            if "logging" in agent:
                logging[node] = agent["logging"]
    outputs = _deepseek(EXAMPLES, directory, settings=settings, manifest=manifest, logging_by_node=logging)
    group = outputs[directory / "controller-external.json"]["groups"][0]
    if not is_mixed(manifest):
        settings["proxy"]["json_checks"] = copy.deepcopy(group["health_checks"][-1]["json_checks"])
    settings["canary"]["json"] = copy.deepcopy(group["canary"]["json"])
    raw = {path.name: (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode() for path, value in outputs.items()}
    raw["source-manifest.json"] = manifest_bytes
    raw["probe-settings.json"] = (json.dumps(settings, ensure_ascii=False, indent=2) + "\n").encode()
    return raw


def _example_snapshots(examples):
    snapshots = {}
    for name in TOPOLOGIES:
        directory = examples / "vllm-ascend" / name
        path = directory / "source-manifest.json"
        policy = directory / "probe-settings.json"
        if not policy.exists() and not policy.is_symlink():
            policy = directory.parent / "probe-settings.json"
        if (directory.is_symlink() or path.is_symlink() or not path.is_file()
                or policy.is_symlink() or not policy.is_file()):
            raise ValueError("regular model manifest and probe policy required: " + name)
        if any(directory.glob("*-external*.json")):
            raise ValueError("model examples must not mix manifests and compiled configurations: " + name)
        snapshots[name] = compile_service_manifest(directory, path.read_bytes(), None, policy.read_bytes())
    return snapshots


def build_profiles(examples=EXAMPLES):
    """返回生成文件的路径和配置，不向单清单示例目录写入文件。"""
    examples = Path(examples).resolve()
    if any((examples/"vllm-ascend"/name).exists() for name in TOPOLOGIES):
        return {examples/"vllm-ascend"/model/name: json.loads(data)
                for model, raw in _example_snapshots(examples).items() for name, data in raw.items()
                if name not in ("source-manifest.json", "probe-settings.json")}
    return _deepseek(examples)


def check_profile(directory):
    """校验一个独立profile目录，冻结快照无需复制examples层级。"""
    for path, value in _deepseek(EXAMPLES, Path(directory)).items():
        if not path.is_file() or _read(path) != value:
            raise ValueError("generated external profile is out of date: " + path.name)


def _check_generated(outputs, snapshot):
    for path, following in outputs.items():
        previous = json.loads(snapshot[path.name])
        left, right = copy.deepcopy(previous), copy.deepcopy(following)
        if path.name == "controller-external.json":
            for old, new in zip(left["groups"], right["groups"]):
                for key in ("partial_recovery", "process_exit_detection"):
                    if key in old and old[key] != new.get(key):
                        raise ValueError("upgrade would change existing policy: " + key)
                    old.pop(key, None)
                    new.pop(key, None)
        elif path.name == "deployment-external.json":
            left.pop("source_generation", None)
            right.pop("source_generation", None)
        else:
            for old, new in zip(left["containers"], right["containers"]):
                if "process_exit_rules" in old and old["process_exit_rules"] != new.get("process_exit_rules"):
                    raise ValueError("upgrade would change process_exit_rules: " + path.name)
                old.pop("process_exit_rules", None)
                new.pop("process_exit_rules", None)
        if left != right:
            raise ValueError("upgrade would reset custom settings: " + path.name)


def upgrade_profile(directory, *, previous_manifests=(), add_missing_exit_policy=True):
    """返回兼容迁移后的配置字节，不改写输入、凭据或运行状态。

    仅补充本场景新增策略；其余生成参数必须与旧输入一致。现场手改的
    非生成参数不能静默归零，旧v3启动契约仍须明确维护迁移。
    """
    directory = Path(directory)
    names = ['source-manifest.json', 'probe-settings.json', 'controller-external.json', 'deployment-external.json']
    if (directory / "source-manifest.json").is_symlink():
        raise ValueError("upgrade input cannot be a symlink")
    names += ['agent-external-' + node + '.json' for node in validate_manifest(_read(directory / 'source-manifest.json'))]
    if any((directory / name).is_symlink() for name in names):
        raise ValueError("upgrade input cannot be a symlink")
    snapshot = {name: (directory / name).read_bytes() for name in names}
    settings = _read(directory / "probe-settings.json")
    old_outputs = _deepseek(EXAMPLES, directory)
    try:
        _check_generated(old_outputs, snapshot)
    except ValueError as original:
        # 可编辑副本可能还带上一拓扑的六份输出。只接受整套可重现的旧输出，
        # 比较时仅替换四个并行字段，不能借拓扑迁移覆盖自定义命令、策略或端口。
        target = _read(directory / "source-manifest.json")
        if target["version"] != 5:
            raise
        keys = ("dp", "tp", "local_dp", "rank")
        default = {node: dict(zip(keys, layout[2:6])) for node, layout in LAYOUT.items()}
        for prior_nodes in chain((default,), map(validate_manifest, previous_manifests)):
            old_layout = copy.deepcopy(target)
            for n in old_layout["nodes"]:
                for key in keys:
                    n[key] = prior_nodes[n["id"]][key]
            if old_layout == target:
                continue
            try:
                candidate = _deepseek(EXAMPLES, directory, settings=settings, manifest=old_layout)
                _check_generated(candidate, snapshot)
            except ValueError:
                continue
            break
        else:
            raise original
    # 缺省旧配置补齐退出检测；显式禁用/阈值属于现场选择，必须保留。
    if add_missing_exit_policy:
        settings.setdefault("process_exit_detection", {"enabled": True, "failure_threshold": 3})
    manifest = path_only_manifest(_read(directory / "source-manifest.json"))
    outputs = _deepseek(EXAMPLES, directory, settings=settings, manifest=manifest)
    group = outputs[directory / "controller-external.json"]["groups"][0]
    if not is_mixed(manifest):
        settings["proxy"]["json_checks"] = copy.deepcopy(group["health_checks"][-1]["json_checks"])
    raw = {path.name: (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
           for path, value in outputs.items()}
    raw["source-manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    raw["probe-settings.json"] = (json.dumps(settings, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    # 不改变已经迁移完成的字节，保证重试/切模式时仍命中同一冻结配置。
    for name in raw:
        path = directory / name
        if json.loads(raw[name]) == _read(path):
            raw[name] = path.read_bytes()
    if any((directory / name).is_symlink() or (directory / name).read_bytes() != value
           for name, value in snapshot.items()):
        raise ValueError("profile changed during migration; no candidate may be published")
    return raw


def generate(examples=EXAMPLES, *, check=False, output_root=None):
    """按固定JSON格式重生成全部配置；check模式只比较，发现差异时报错而不覆盖。"""
    # 拒绝过期目录和PD的中性节点文件，避免生成后留下两套可被误用的配置。
    obsolete = [examples / framework / name for framework in FRAMEWORKS
                for name in ("pd_1p1d", "pd_2p1d", "pd_disaggregated", "multi_node_mixed", "single_node_mixed", DEPLOYMENT_ID, *RETIRED_DEPLOYMENT_IDS)
                if (examples / framework / name).exists()]
    obsolete += [path for framework in FRAMEWORKS for name in ("pd_1p1d_4node",)
                 for path in (examples / framework / name).glob("agent-external-n*.json")]
    # mixed_4node空目录可留作占位，但不允许混部配置残留或再次进入交付。
    obsolete += [path for framework in FRAMEWORKS for path in (examples / framework / "mixed_4node").glob("*")]
    # 已停用框架不得在当前交付中悄悄重新出现。
    obsolete += [path for path in examples.iterdir() if path.is_dir() and path.name not in FRAMEWORKS]
    if obsolete:
        raise ValueError("retired profile or PD node filenames found; review migration before generation: "
                         + ", ".join(str(path) for path in obsolete))
    if any((examples / "vllm-ascend" / name).exists() for name in TOPOLOGIES):
        snapshots = _example_snapshots(examples)
        # 只在显式指定外部目录时生成文件；先检查所有目标，避免覆盖运维输入。
        missing = {}
        if output_root is not None:
            output_root = Path(output_root).resolve()
            if output_root == examples.resolve() or examples.resolve() in output_root.parents:
                raise ValueError("export outside the example tree")
            for name, raw in snapshots.items():
                target = output_root / name
                if target.resolve() != target:
                    raise ValueError("export directory traverses a symlink: " + str(target))
                for filename, data in raw.items():
                    path = target / filename
                    if path.is_symlink() or (path.exists() and path.read_bytes() != data):
                        raise ValueError("existing exported file differs: " + str(path))
                    if not path.exists():
                        if check:
                            raise ValueError("exported file is missing: " + str(path))
                        missing[path] = data
            for path, data in missing.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as stream:
                    stream.write(data)
        return {"source_generation": GENERATION, "profiles": len(snapshots),
                "files": sum(len(raw)-2 for raw in snapshots.values()),
                "changed": [str(p) for p in missing], "checked_only": check or output_root is None}
    if output_root is not None:
        raise ValueError("output-root requires the named service manifest examples")
    outputs = build_profiles(examples)
    # 交付目录只保留统一命名；旧配置可能已被用户修改，不能替用户覆盖或删除。
    legacy = [path.with_name(f"agent-{value['node_id']}.json") for path, value in outputs.items()
              if path.name.startswith("agent-external-")
              and path.with_name(f"agent-{value['node_id']}.json").exists()]
    if legacy:
        raise ValueError("legacy Agent filenames found; review and rename to agent-external-<node>.json before generation: "
                         + ", ".join(str(path) for path in legacy))
    changed = []
    for path, value in outputs.items():
        content = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        if not path.is_file() or path.read_text(encoding="utf-8") != content:
            changed.append(str(path))
            if not check:
                path.parent.mkdir(parents=True, exist_ok=True)
                # Path.write_text的newline参数在宿主Python3.7中不可用。
                with path.open("w", encoding="utf-8", newline="\n") as stream:
                    stream.write(content)
    if check and changed:
        raise ValueError("generated external profiles are missing or out of date: " + ", ".join(changed))
    return {"source_generation": GENERATION, "profiles": 1, "files": len(outputs),
            "changed": changed, "checked_only": check}


def main(argv=None):
    """提供重生成及只读--check入口，输出差异列表供维护审阅。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--examples-root", type=Path, default=EXAMPLES)
    parser.add_argument("--output-root", type=Path, help="可选：在示例目录外导出供手工CLI使用的完整profile")
    parser.add_argument("--check", action="store_true", help="Verify generation without writing any file")
    args = parser.parse_args(argv)
    print(json.dumps(generate(args.examples_root, check=args.check, output_root=args.output_root), ensure_ascii=False, indent=2))
