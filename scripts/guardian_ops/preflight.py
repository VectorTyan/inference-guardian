"""只读核对启动文件名称、路径及容器挂载；不读取文件内容、不执行模型。"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path, PurePosixPath
import shlex
import subprocess
from .mooncake_contract import V4_EXAMPLE, source_files, validate_manifest, is_single

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "examples/vllm-ascend" / V4_EXAMPLE


def script_option(contents, name):
    """只解析显式Shell参数，不执行脚本或展开变量；重复/缺失参数不能通过。"""
    tokens = shlex.split(contents.replace("\\\n", " "), comments=True)
    option = "--" + name
    found = []
    for index, token in enumerate(tokens):
        if token.startswith(option + "="):
            found.append([token[len(option) + 1:]])
        elif token == option:
            values = []
            for value in tokens[index + 1:]:
                if value.startswith(("--", ">", "<")) or value in {"&", ";", "|", "&&"}:
                    break
                values.append(value)
            found.append(values)
    if len(found) != 1:
        raise ValueError("one explicit startup parameter required: " + option)
    return found[0]


def check_local(info, node, manifest):
    """只读检查路径及文件存在；不解析脚本参数，不证明模型服务可用。"""
    by_id = validate_manifest(manifest)
    by_id[node]  # 拒绝未知节点，避免漏查其启动入口。
    directory = Path(manifest["script_directory"])
    mounts = info.get("Mounts", [])
    bind_target = '/data'
    if is_single(manifest):
        mount = manifest['script_mount'];bind_target = mount['target']
        matching = [m for m in mounts if m.get('Destination') == bind_target]
        if (len(matching) != 1 or matching[0].get('Type') != 'bind' or matching[0].get('Source') != mount['source']
                or matching[0].get('RW') is not True):
            raise ValueError('model container script bind differs from manifest')
        relative = PurePosixPath(manifest['script_directory']).relative_to(bind_target)
        directory = Path(mount['source']).joinpath(*relative.parts)
        devices = info.get('HostConfig', {}).get('Devices', [])
        expected = {'/dev/davinci' + str(number) for number in by_id[node]['npu_devices']}
        compute = [d for d in devices if re.fullmatch(r'/dev/davinci[0-9]+', d.get('PathOnHost', ''))]
        if ({d['PathOnHost'] for d in compute} != expected or len(compute) != len(expected)
                or any(d.get('PathInContainer') != d['PathOnHost'] for d in compute)):
            raise ValueError('model container NPU devices differ from manifest')
    elif not any(m.get("Type") == "bind" and m.get("Source") == "/data"
               and m.get("Destination") == "/data" and m.get("RW") is True for m in mounts):
        raise ValueError("model container requires the confirmed read-write /data:/data bind")
    if info.get("HostConfig", {}).get("NetworkMode") != "host":
        raise ValueError("model container must use the reviewed host network")
    files = source_files(node, manifest)
    for mount in mounts:
        target = PurePosixPath(mount.get("Destination", "/"))
        if target == PurePosixPath(bind_target):
            continue
        for name in files:
            path = PurePosixPath(manifest["script_directory"]) / name
            if target == path or (target != PurePosixPath("/") and target in path.parents):
                raise ValueError("nested mount shadows the confirmed script bind")
    missing = [name for name in files if not (directory / name).is_file()]
    if missing:
        raise ValueError("required startup file missing: " + ','.join(missing))
    result = {"node": node, "passed": True, "model_mutations": 0,
            "scope": "file names, paths and Docker mounts only; no content validation or model execution",
            "script_directory": manifest['script_directory'], "required_files": files}
    if is_single(manifest):
        result['scope'] = 'file names, paths, Docker mounts and NPU devices only; no content validation or model execution'
        result.update(host_script_directory=str(directory), npu_devices=by_id[node]['npu_devices'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=PROFILE)
    parser.add_argument("--node", required=True, choices=("p0", "p1", "d0", "d1"))
    args = parser.parse_args()
    manifest = json.loads((args.profile / "source-manifest.json").read_text(encoding="utf-8"))
    spec = next(item for item in manifest["nodes"] if item["id"] == args.node)
    result = subprocess.run(["docker", "--host", "unix:///var/run/docker.sock", "container", "inspect", spec["container"]],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=20)
    inspected = json.loads(result.stdout)
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise ValueError("one exact model container required")
    print(json.dumps(check_local(inspected[0], args.node, manifest), ensure_ascii=False, indent=2))
