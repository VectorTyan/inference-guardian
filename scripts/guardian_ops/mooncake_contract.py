"""四节点启动路径契约；旧摘要格式仅用于读取既有配置及升级识别。"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
import shlex

from .presets import (
    DEPLOYMENT_ID, LAYOUT, MIXED_EXAMPLE, MIXED_EXAMPLES, MIXED_ID, MIXED_PROFILE,
    MIXED_SCENARIO, MIXED_W8A8_EXAMPLE, MIXED_W8A8_ID, MODEL, PROFILE,
    RETIRED_DEPLOYMENT_IDS, SCENARIO, SCRIPT_DIRECTORY, SUPPORTED_DEPLOYMENTS,
    V4_EXAMPLE, V41_EXAMPLE, LEGACY_CONTAINER as _LEGACY_CONTAINER, LEGACY_GROUP as _LEGACY_GROUP,
)


def is_mixed(manifest):
    nodes = manifest.get("nodes")
    return (manifest.get("scenario") == MIXED_SCENARIO
            or (manifest.get("version") == 6 and isinstance(nodes, list) and len(nodes) == 2
                and all(isinstance(n, dict) and n.get("role") == "mixed" for n in nodes)))


def manifest_deployment_id(manifest):
    """旧两机清单保持 W4A8 身份，新部署由清单显式选择稳定身份。"""
    return manifest.get("deployment_id", MIXED_ID) if is_mixed(manifest) else DEPLOYMENT_ID


def manifest_group_id(manifest):
    """旧场景值保留历史组 ID；v6 自定义场景直接作为恢复组 ID。"""
    if manifest["version"] < 6:
        return _LEGACY_GROUP
    scenario = manifest["scenario"]
    if scenario in (SCENARIO, MIXED_SCENARIO):
        return manifest_deployment_id(manifest)
    return scenario


def text_hash(raw):
    """只统一换行，不折叠空白、不忽略注释或改写JSON。"""
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()


def set_hash(hashes):
    return hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def source_files(node, manifest=None):
    if manifest is not None and manifest["version"] == 6:
        entries = list(_stage_scripts(manifest, node).values()) + manifest["required_files"]
        if node == "p0" and not is_mixed(manifest):
            entries += manifest["proxy"]["required_files"]
        return list(dict.fromkeys(entries))
    files = ["start_mooncake.sh", f"start_{node}.sh", "launch_online_dp.py", "run_dp_template.sh", "mooncake.json"]
    # 无manifest的旧调用保留v3文件集合；v4非Master节点不依赖未执行的Master脚本。
    if manifest is not None and node not in manifest['mooncake']['startup_nodes']:
        files.remove('start_mooncake.sh')
    return files + (["proxy.sh", "load_balance_proxy_server_example.py"] if node == "p0" else [])


def endpoint_counts(nodes):
    return {role: sum(n["local_dp"] for n in nodes if n["role"] == role)
            for role in ("prefill", "decode")}


def _check_parallelism(nodes):
    # 当前启动器在每台8卡机器上为每个本地DP rank分配连续tp张卡。
    for role in ("prefill", "decode"):
        group = sorted((n for n in nodes if n["role"] == role), key=lambda n: n["rank"])
        dp, tp = group[0]["dp"], group[0]["tp"]
        end = 0
        for n in group:
            if (n["dp"] != dp or n["tp"] != tp or n["local_dp"] * tp > 8
                    or n["rank"] != end):
                raise ValueError("inconsistent DP/TP, overlapping/gapped ranks or more than 8 local cards: " + n["id"])
            end += n["local_dp"]
        if end != dp:
            raise ValueError("local ranks must cover the group DP size: " + role)


def _v6_name(value, *, script=False):
    if (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value)
            or value.lower() == "start_container.sh" or (script and not value.endswith(".sh"))):
        raise ValueError("expected a local service filename, not a container creation script or command")


def _v6_path(value, root):
    if (not isinstance(value, str) or not value.startswith(root + "/")
            or not all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", part)
                       for part in value[len(root)+1:].split("/"))):
        raise ValueError("absolute path under " + root + " required")


def _stage_scripts(manifest, node):
    item = next(n for n in manifest["nodes"] if n["id"] == node)
    if is_mixed(manifest):
        return {"serve": item["startup_script"]}
    scripts = ({"mooncake": manifest["mooncake"]["startup_script"]}
               if node in manifest["mooncake"]["startup_nodes"] else {})
    scripts[item["role"]] = item["startup_script"]
    if node == "p0":
        scripts["proxy"] = manifest["proxy"]["startup_script"]
    return scripts


def _validate_mixed(manifest):
    """两机共用一个 API；第二台只参与分布式推理。"""
    from ipaddress import IPv4Address
    if (manifest.get("version") != 6 or set(manifest) - {"deployment_id"} != {
            "version", "scenario", "script_directory", "model_path", "served_model_name",
            "required_files", "nodes", "external_port"}):
        raise ValueError("invalid mixed service manifest")
    if manifest_deployment_id(manifest) not in tuple(MIXED_EXAMPLES):
        raise ValueError("unsupported mixed deployment_id")
    _v6_path(manifest["script_directory"], "/data/scripts")
    _v6_path(manifest["model_path"], "/data/models")
    _v6_name(manifest["served_model_name"])
    if not isinstance(manifest["required_files"], list):
        raise ValueError("required_files must be a list")
    for name in manifest["required_files"]:
        _v6_name(name)
    port = manifest["external_port"]
    if type(port) is not int or not 1 <= port <= 65535 or port == 19090:
        raise ValueError("invalid mixed service API port")
    nodes = manifest["nodes"]
    if (not isinstance(nodes, list) or len(nodes) != 2 or
            [n.get("id") for n in nodes if isinstance(n, dict)] != ["p0", "p1"]):
        raise ValueError("mixed layout requires API p0 and headless p1, in rank order")
    end = 0
    hosts = set()
    for n in nodes:
        if set(n) != {"id", "host", "container", "startup_script", "dp", "tp", "local_dp", "rank", "role"} or n["role"] != "mixed":
            raise ValueError("invalid mixed node fields")
        _v6_name(n["container"])
        _v6_name(n["startup_script"], script=True)
        hosts.add(str(IPv4Address(n["host"])))
        if (not isinstance(n["host"], str) or type(n["rank"]) is not int or n["rank"] != end or
                any(type(n[k]) is not int or n[k] <= 0 for k in ("dp", "tp", "local_dp")) or
                n["dp"] != nodes[0]["dp"] or n["tp"] != nodes[0]["tp"] or n["local_dp"] * n["tp"] > 8):
            raise ValueError("invalid mixed DP/TP or start rank")
        end += n["local_dp"]
    if end != nodes[0]["dp"] or len(hosts) != 2:
        raise ValueError("mixed DP ranks must span two distinct hosts")
    return {n["id"]: n for n in nodes}


def validate_manifest(manifest):
    """核对布局、名称和路径；旧版本摘要只维持既有配置身份兼容。"""
    if isinstance(manifest, dict) and manifest.get("version") == 6:
        scenario = manifest.get("scenario")
        if not isinstance(scenario, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", scenario):
            raise ValueError("scenario must be a safe group identifier of 1..80 characters")
        if scenario == SCENARIO and is_mixed(manifest):
            raise ValueError("legacy four-node scenario cannot describe mixed nodes")
    if isinstance(manifest, dict) and is_mixed(manifest):
        return _validate_mixed(manifest)
    if (not isinstance(manifest, dict) or manifest.get("version") not in (3, 4, 5, 6)
            or (manifest["version"] < 6 and manifest.get("scenario") != SCENARIO)):
        raise ValueError("reviewed four-node Mooncake manifest required")
    configurable = manifest["version"] == 6
    if configurable:
        if set(manifest) != {"version", "scenario", "script_directory", "model_path", "served_model_name",
                             "required_files", "nodes", "mooncake", "proxy", "external_port"}:
            raise ValueError("invalid service manifest fields")
        _v6_path(manifest.get("script_directory"), "/data/scripts")
        _v6_path(manifest.get("model_path"), "/data/models")
        _v6_name(manifest.get("served_model_name"))
        for name in ("mooncake", "proxy"):
            section = manifest.get(name)
            if not isinstance(section, dict):
                raise ValueError("missing stage: " + name)
            _v6_name(section.get("startup_script"), script=True)
        if (set(manifest["proxy"]) != {"startup_script", "required_files"}
                or set(manifest["mooncake"]) != {"startup_nodes", "startup_script", "listen_port"}
                or manifest["proxy"]["startup_script"] == manifest["mooncake"]["startup_script"]):
            raise ValueError("invalid shared service stage configuration")
        for section in (manifest, manifest["proxy"]):
            if not isinstance(section.get("required_files"), list):
                raise ValueError("required_files must be a list of local dependency names")
            for name in section["required_files"]:
                _v6_name(name)
    elif manifest.get("script_directory") != SCRIPT_DIRECTORY:
        raise ValueError("legacy source manifest requires the reviewed script directory")
    startup_nodes = list(LAYOUT) if manifest['version'] == 3 else ['p0']
    if manifest.get('mooncake', {}).get('startup_nodes') != startup_nodes:
        raise ValueError('Mooncake startup_nodes differs from reviewed manifest version')
    nodes = manifest.get("nodes")
    if (not isinstance(nodes, list) or len(nodes) != 4 or not all(isinstance(n, dict) for n in nodes)
            or {n.get("id") for n in nodes} != set(LAYOUT)):
        raise ValueError("Mooncake manifest requires exactly p0/p1/d0/d1")
    by_id = {node: next(n for n in nodes if n["id"] == node) for node in LAYOUT}
    def port(value):
        return type(value) is int and 1 <= value <= 65535
    expected_files = set()
    for node, expected in LAYOUT.items():
        item = by_id[node]
        layout = tuple(item.get(key) for key in ("role", "host", "dp", "tp", "local_dp", "rank", "master"))
        if (layout[:2] != expected[:2] or layout[-1] != expected[-1]
                or (manifest["version"] < 5 and layout != expected)):
            raise ValueError("Mooncake node layout differs from reviewed scripts: " + node)
        if (not all(type(i) is int and i > 0 for i in layout[2:5])
                or type(layout[5]) is not int or layout[5] < 0):
            raise ValueError("positive integer dp/tp/local_dp and nonnegative rank required: " + node)
        directory = f"{item['role']}/{node}-{item['host']}"
        if configurable:
            if set(item) != {"id", "role", "host", "master", "rpc_port", "api_port", "dp", "tp",
                             "local_dp", "rank", "container", "startup_script"}:
                raise ValueError("invalid node fields: " + node)
            _v6_name(item.get("container"))
            _v6_name(item.get("startup_script"), script=True)
            if item["startup_script"] in (manifest["proxy"]["startup_script"], manifest["mooncake"]["startup_script"]):
                raise ValueError("model and shared service scripts must be distinct: " + node)
        elif (item.get("source_directory") != directory or item.get("startup_script") != f"start_{node}.sh"
                or item.get("model") != MODEL or item.get("container") != _LEGACY_CONTAINER):
            raise ValueError("Mooncake script/model baseline differs: " + node)
        if (not port(item.get("api_port")) or not port(item.get("rpc_port"))
                or item["api_port"] + item["local_dp"] - 1 > 65535):
            raise ValueError("Mooncake script/model/port baseline differs: " + node)
        expected_files.update(directory + "/" + name for name in source_files(node, manifest))
    _check_parallelism(by_id.values())
    legacy_hashes = (("sources_sha256", "source_set_sha256"),
                     ("sources_text_sha256", "source_text_set_sha256")) if manifest['version'] < 5 else ()
    for field, checksum in legacy_hashes:
        hashes = manifest.get(field)
        if (not isinstance(hashes, dict) or set(hashes) != expected_files
                or not all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in hashes.values())
                or manifest.get(checksum) != set_hash(hashes)):
            raise ValueError("complete reviewed Mooncake file hashes required: " + field)
    mooncake = manifest.get("mooncake", {})
    if (not port(manifest.get("external_port"))
            or (manifest["version"] < 5 and manifest.get("proxy_registered_endpoints") != endpoint_counts(nodes))
            or not port(mooncake.get("listen_port"))
            or (not configurable and mooncake.get("client_config", {}).get("master_server_address")
                != f"{by_id['p0']['host']}:{mooncake['listen_port']}")):
        raise ValueError("Mooncake/Proxy endpoints differ from reviewed scripts")
    for node, item in by_id.items():
        if item["rpc_port"] != by_id["p0" if item["role"] == "prefill" else "d0"]["rpc_port"]:
            raise ValueError("group members must share the reviewed RPC port")
        listeners = ([mooncake["listen_port"]] if node in startup_nodes else [])
        listeners += list(range(item["api_port"], item["api_port"] + item["local_dp"]))
        if node == "p0":
            listeners.append(manifest["external_port"])
        if len(listeners) != len(set(listeners)):
            raise ValueError("reviewed model service ports overlap on node: " + node)
    return by_id


def node_hashes(manifest, node):
    spec = next(item for item in manifest["nodes"] if item["id"] == node)
    prefix = spec["source_directory"] + "/"
    return {name: manifest["sources_text_sha256"][prefix + name] for name in source_files(node, manifest)}


def _legacy_hash_guard(expected):
    """重建旧命令文本以核对历史身份；迁移时不执行或读取现场文件。"""
    code = ("import hashlib,pathlib,sys\nexpected=" + repr(expected) + "\n"
            "bad=[name for name,digest in expected.items() if "
            "hashlib.sha256(pathlib.Path(name).read_bytes().replace(b'\\r\\n',b'\\n')).hexdigest()!=digest]\n"
            "if bad: sys.exit('startup source differs from reviewed manifest: '+','.join(bad))\n")
    return "python -c " + shlex.quote(code)


def bootstrap_guard(manifest, node):
    """新配置仅检查依赖文件存在，不读取内容、不要求摘要同步。"""
    if manifest['version'] < 5:
        return _legacy_hash_guard(node_hashes(manifest, node))
    return ' && '.join('test -f ' + shlex.quote('./' + name) for name in source_files(node, manifest))


def path_only_manifest(manifest):
    """在既有升级入口移除文件摘要元数据，保留现场布局和端口等参数。"""
    validate_manifest(manifest)
    if manifest["version"] == 6:
        return copy.deepcopy(manifest)
    if manifest['version'] not in (4, 5):
        raise ValueError('path-only upgrade requires p0-only Mooncake v4 manifest or v5')
    result = copy.deepcopy(manifest)
    result['version'] = 5
    # 仅更新冻结清单的派生说明；不改现场KV配置、模型脚本或输入文件。
    result["proxy_registered_endpoints"] = endpoint_counts(result["nodes"])
    parallel = {n["role"]: (n["dp"], n["tp"]) for n in result["nodes"]}
    for node in result["nodes"]:
        extra = node.get("kv", {}).get("kv_connector_extra_config", {})
        for role, (dp, tp) in parallel.items():
            if role in extra:
                extra[role].update(dp_size=dp, tp_size=tp)
    for key in ('sources_sha256', 'source_set_sha256', 'sources_text_sha256',
                'source_text_set_sha256', 'execution_hash_normalization'):
        result.pop(key, None)
    # 保留目录修正历史，移除不再维护的文件内容摘要。
    for change in result.get('transformations', []):
        for item in change.get('files', []):
            item.pop('before_sha256', None)
            item.pop('after_sha256', None)
    return result


def path_only_command_upgrade(previous, following, manifest, node):
    """迁移旧摘要前缀及非p0的旧Mooncake阶段，保留其它路径/命令契约。"""
    if manifest['version'] != 5 or following != node_commands(manifest, node):
        return False
    # 现场可能已更新p0的配置，而工作节点仍加载四机Mooncake时期的运行配置。
    # 目标必须是已确认的p0单启动配置；旧工作节点阶段只从配置移除，不执行脚本。
    worker = node not in manifest['mooncake']['startup_nodes']
    stages = set(following)
    if set(previous) not in (stages, stages | {'mooncake'} if worker else stages):
        return False
    for stage, command in previous.items():
        target = following.get(stage)
        if target is None:
            target = bootstrap_command('start_mooncake.sh', manifest, node)
        if command == target:
            continue
        try:
            argv = command['argv']
            tokens = shlex.split(argv[2])
            # 只解析字面量；即使旧文本被修改也不执行Python或Shell。
            if len(tokens) != 9 or tokens[:5] != ['cd', SCRIPT_DIRECTORY, '&&', 'python', '-c']:
                return False
            tree = ast.parse(tokens[5])
            expected = ast.literal_eval(tree.body[1].value)
            files = set(source_files(node, manifest))
            if (not isinstance(expected, dict)
                    or set(expected) not in (files, files | {'start_mooncake.sh'} if worker else files)
                    or not all(isinstance(v, str) and re.fullmatch(r'[0-9a-f]{64}', v) for v in expected.values())):
                return False
            candidate = copy.deepcopy(target)
            script = shlex.split(candidate['argv'][2])[-1]
            candidate['argv'][2] = f'cd {SCRIPT_DIRECTORY} && {_legacy_hash_guard(expected)} && bash {script}'
            if command != candidate:
                return False
        except (KeyError, IndexError, TypeError, ValueError, SyntaxError, AttributeError):
            return False
    return True


def bootstrap_command(script, manifest, node):
    """固定工作目录与原脚本；30秒包含文件存在检查和启动壳返回。"""
    directory = manifest["script_directory"]
    return {"argv": ["bash", "-ic", f"cd {shlex.quote(directory)} && {bootstrap_guard(manifest, node)} && bash {shlex.quote('./'+script)}"],
            "working_dir": directory, "timeout_seconds": 30, "wait_for_exit": True}


def node_commands(manifest, node):
    """接管、升级与启动复用同一阶段及路径定义。"""
    if manifest["version"] == 6:
        return {stage: bootstrap_command(script, manifest, node)
                for stage, script in _stage_scripts(manifest, node).items()}
    scripts = {"mooncake": "start_mooncake.sh"} if node in manifest['mooncake']['startup_nodes'] else {}
    scripts["prefill" if node.startswith("p") else "decode"] = f"start_{node}.sh"
    if node == "p0":
        scripts["proxy"] = "proxy.sh"
    return {stage: bootstrap_command(script, manifest, node) for stage, script in scripts.items()}
