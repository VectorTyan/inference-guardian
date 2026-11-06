"""在Linux/WSL制作tar.gz源码包；目录0755、文件0644，不含模型、凭据或运行状态。"""
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from inference_guardian import read_source_version
ROOT_FILES = ("README.md", ".dockerignore", "pyproject.toml")
DEPLOY_FILES = ("deploy/Dockerfile", "deploy/site.example.json",
                "deploy/python-3.12-slim-bookworm-arm64.tar.xz")
# 部署工具和现场文档显式列出；新增开发工具/规则/审查稿不会自动进入交付。
SCRIPT_FILES = tuple("scripts/" + name + ".py" for name in (
    "check_mooncake_preflight", "check_vllm_status_readonly", "generate_external_profiles",
    "generate_node_tokens", "guardian_deploy", "guardian_schema", "mooncake_contract", "probe_config", "verify_guardian",
    "install_guardian", "guardian_rollout", "rollout_node", "rollout_state", "recommission", "guardian_inspect"))
HOST_MODULES = ('__init__', 'deployment', 'components', 'rollout', 'node_release', 'release_state', 'inspection', 'verification', 'recommission', 'probe_config', 'mooncake_contract', 'profile_generation', 'preflight', 'tokens')
HOST_MODULES += ('release_files', 'site', 'credentials', 'profile', 'transport', 'image', 'presets')
HOST_MODULES += ('uninstall',)
SCRIPT_FILES += tuple("scripts/guardian_ops/" + name + ".py" for name in HOST_MODULES)
DOC_FILES = tuple("docs/" + name for name in (
    "operations.md", "recovery.md", "delivery.md", "image-distribution.md", "release-notes.md"))
TREES = {"src": {".py"}, "examples/vllm-ascend": {".md", ".json"}}
EXCLUDE = {".demo", ".runtime", "dist", "state", "reports", "archive", "tests", "__pycache__", ".git", ".pytest_cache"}


def project_version(root):
    """从项目元数据读取发行版本，包名和MANIFEST共用同一来源。"""
    return read_source_version(root)


def require_release_notes(root, version):
    """每次版本更新都必须有非空修改说明，缺失时在创建任何交付产物前失败。"""
    path = Path(root) / "docs" / "release-notes.md"
    if not path.is_file():
        raise ValueError("docs/release-notes.md is required for every release")
    content = path.read_text(encoding="utf-8")
    entries = list(re.finditer(r"^##[ \t]+([^\n]+)$", content, re.MULTILINE))
    matches = [index for index, entry in enumerate(entries)
               if re.match(re.escape(version) + r"(?:[ \t]|$)", entry.group(1))]
    if len(matches) != 1:
        raise ValueError("exactly one release-notes entry required for version " + version)
    index = matches[0]
    end = entries[index + 1].start() if index + 1 < len(entries) else len(content)
    if not content[entries[index].end():end].strip():
        raise ValueError("current release-notes entry must describe the changes")


def release_stem(name):
    """限制归档文件名，拒绝目录穿越和旧ZIP格式。"""
    if not re.fullmatch(r"inference-guardian-source-[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*\.tar\.gz", name):
        raise ValueError("name must follow inference-guardian-source-{version}.tar.gz")
    return name[:-7]


def collect_files(root):
    """白名单收集当前交付文件；不跟随符号链接，不遍历运行目录或历史归档。"""
    root = Path(root).resolve()
    found = []
    for name in (*ROOT_FILES, *DEPLOY_FILES, *SCRIPT_FILES, *DOC_FILES):
        path = root / name
        if path.is_symlink() or not path.is_file() or path.resolve().parent != path.parent:
            raise ValueError(f"missing or unsafe required source file: {name}")
        found.append(path)
    for name, suffixes in TREES.items():
        base = root / name
        if base.is_symlink() or not base.is_dir() or base.resolve() != base:
            raise ValueError(f"missing or unsafe source directory: {name}")
        for folder, directories, files in os.walk(base, followlinks=False):
            directories[:] = sorted(item for item in directories if item not in EXCLUDE and not item.startswith('.'))
            for item in directories:
                if (Path(folder) / item).is_symlink():
                    raise ValueError("source directory symlinks are not packaged")
            for item in sorted(files):
                path = Path(folder) / item
                if item.startswith(('.', 'test_')) or path.suffix not in suffixes:
                    continue
                if path.is_symlink() or not path.is_file():
                    raise ValueError("source file symlinks are not packaged")
                found.append(path)
    return sorted(found, key=lambda path: path.relative_to(root).as_posix())


def verify_archive(archive, manifest):
    """独立读取tar成员，验证无链接/越界、权限、所有者及逐文件内容。"""
    expected = {"inference-guardian/" + item["path"]: item for item in manifest["files"]}
    seen, regular = set(), set()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            parts = member.name.split("/")
            if (member.name in seen or parts[0] != "inference-guardian" or ".." in parts
                    or member.uid != 0 or member.gid != 0 or not (member.isdir() or member.isfile())):
                raise ValueError("unsafe or duplicate archive member")
            seen.add(member.name)
            if member.mode != (0o755 if member.isdir() else 0o644):
                raise ValueError("archive permissions differ from delivery contract")
            if member.isfile():
                regular.add(member.name)
                data = bundle.extractfile(member).read()
                if member.name == "inference-guardian/MANIFEST.json":
                    if json.loads(data) != manifest:
                        raise ValueError("embedded manifest differs")
                else:
                    entry = expected.get(member.name)
                    if (not entry or len(data) != entry["bytes"]
                            or hashlib.sha256(data).hexdigest() != entry["sha256"]):
                        raise ValueError("archive content differs from manifest")
    if regular != set(expected) | {"inference-guardian/MANIFEST.json"}:
        raise ValueError("archive files missing")
    return {"source_files": len(expected), "members": len(seen), "hashes_verified": True,
            "permissions_verified": True, "links_absent": True, "uid_gid": "0:0"}


def build(root, name):
    """在独立Linux暂存区chmod后调用tar；不会chmod宿主运行配置或凭据。

    Python脚本以python3执行，无需执行位。uid/gid统一为0，现场以
    --no-same-owner解压；文件清单覆盖所有内容，MANIFEST自身由归档SHA256保护。
    """
    stem = release_stem(name)
    if os.name != "posix":
        raise ValueError("run this packager in Linux/WSL to apply POSIX permissions")
    root = Path(root).resolve()
    version = project_version(root)
    require_release_notes(root, version)
    if name != f"inference-guardian-source-{version}.tar.gz":
        raise ValueError("archive name must match project.version in pyproject.toml")
    files = collect_files(root)
    destination = root / "dist"
    if destination.is_symlink():
        raise ValueError("dist must not be a symlink")
    destination.mkdir(exist_ok=True)
    archive = destination / name
    targets = [archive, destination / (stem + ".SHA256SUMS"), destination / "install_guardian.py"]
    if any(path.is_symlink() or path.exists() for path in targets):
        raise ValueError("release outputs already exist; review/archive them before packaging again")
    with tempfile.TemporaryDirectory(prefix="inference-guardian-bundle-") as temporary:
        staging = Path(temporary) / "inference-guardian"
        staging.mkdir()
        entries = []
        for source in files:
            relative = source.relative_to(root)
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            entries.append({"path": relative.as_posix(), "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                            "bytes": target.stat().st_size, "mode": "0644"})
        manifest = {"version": version, "release_name": name,
                    "created_utc": datetime.now(timezone.utc).isoformat(),
                    "scope": "Inference Guardian service, deployment examples and operations documentation",
                    "permissions": {"directories": "0755", "files": "0644", "archive_uid": 0, "archive_gid": 0},
                    "files": entries}
        content = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
        (staging / "MANIFEST.json").write_text(content, encoding="utf-8")
        subprocess.run(["find", str(staging), "-type", "d", "-exec", "chmod", "0755", "{}", "+"], check=True)
        subprocess.run(["find", str(staging), "-type", "f", "-exec", "chmod", "0644", "{}", "+"], check=True)
        subprocess.run(["tar", "--format=posix", "--sort=name", "--owner=0", "--group=0", "--numeric-owner",
                        "-czf", str(archive), "-C", temporary, "inference-guardian"], check=True)
        shutil.copyfile(staging / "scripts" / "install_guardian.py", targets[2])
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    verified = verify_archive(archive, manifest)
    verified.update(archive=name, sha256=checksum, platform="Linux/WSL", docker_image_built=False)
    targets[1].write_text(f"{checksum}  {archive.name}\n", encoding="ascii")
    subprocess.run(["chmod", "0644", *(str(path) for path in targets)], check=True)
    return {"archive": str(archive), "sha256": checksum, "files": len(entries), "directory_mode": "0755", "file_mode": "0644", "verification": verified}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", help="Optional; must match inference-guardian-source-{project.version}.tar.gz")
    args = parser.parse_args(argv)
    try:
        name = args.name or f"inference-guardian-source-{project_version(ROOT)}.tar.gz"
        result = build(ROOT, name)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
