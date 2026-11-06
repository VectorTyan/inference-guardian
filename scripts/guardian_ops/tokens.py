"""生成每节点独立的256位随机Token；重部署仅补齐缺失文件，不打印或覆盖已有凭据。

仅在Controller宿主执行一次，再经受控通道把各文件分发到对应节点。
部分写入失败时保留已生成文件并返回失败，禁止通过重新生成覆盖现场已分发Token。
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
from inference_guardian.config import validate
from .deployment import DEFAULT_SECRETS_DIR


def generate(profile, output, *, missing_only=False):
    """校验标准映射并排他发布；missing_only供重部署补齐，CLI默认仍拒绝覆盖。"""
    config = validate(json.loads((Path(profile) / "controller-external.json").read_text(encoding="utf-8")))
    output = Path(output)
    if output.is_symlink():
        raise ValueError("output must not be a symbolic link")
    names = []
    for node, spec in config["nodes"].items():
        expected = f"{node}.token"
        if spec.get("token_file") != f"/run/secrets/inference-guardian/{expected}" or PurePosixPath(expected).name != expected:
            raise ValueError("expected the standard per-node token_file mapping")
        names.append(expected)
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    existing = {name for name in names if (output / name).exists()}
    if any((output / name).is_symlink() or ((output / name).exists() and not (output / name).is_file()) for name in names):
        raise ValueError("token must be a regular file")
    if existing and not missing_only:
        raise ValueError("token already exists; refusing to overwrite or rotate credentials")
    if os.name == "posix":
        output.chmod(0o700)
    generated = {(output / name).read_bytes().strip() for name in existing}
    created = []
    for name in names:
        if name in existing:
            continue
        token = secrets.token_urlsafe(32)
        while token.encode('ascii') in generated:
            token = secrets.token_urlsafe(32)
        generated.add(token.encode('ascii'))
        # 完整写入再排他发布；失败不留下空Token，已发布文件在重试时直接复用。
        fd, temporary = tempfile.mkstemp(prefix='.token-', dir=str(output))
        try:
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                stream.write(token + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, str(output / name))
            created.append(name)
        finally:
            os.unlink(temporary)
    return {"created_files": created, "count": len(created), "secret_values_printed": False}


def main(argv=None):
    """仅输出文件名；异常信息不带Token，失败返回1。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_SECRETS_DIR,
                        help="Token source directory (default: /data/scripts/inference-guardian/secrets)")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(generate(args.profile, args.output_dir), ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("Token generation refused: " + type(exc).__name__, file=sys.stderr)
        return 1
