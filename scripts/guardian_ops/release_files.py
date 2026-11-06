"""受管理发布文件：摘要、路径校验、快照及排他写入；不操作容器。"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

INSTALL_ROOT = Path('/data/scripts/inference-guardian')

def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def safe_directory(path, root=INSTALL_ROOT):
    """所有受管理目录必须在指定根内；逐层拒绝符号链接。"""
    path, root = Path(os.path.abspath(str(path))), Path(os.path.abspath(str(root)))
    if path != root and root not in path.parents:
        raise ValueError('path is outside the managed installation root')
    for entry in (path, *path.parents):
        if entry.is_symlink():
            raise ValueError('managed paths cannot traverse symlinks')
    return path


def digest(value):
    """对配置对象规范序列化后计算SHA-256，不包含文件中未进入对象的注释或格式。"""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def private_dir(path):
    """创建部署私有目录并拒绝符号链接；POSIX固定0700，不修改其它目录权限。"""
    if path.is_symlink():
        raise ValueError("deployment directories may not be symlinks")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        path.chmod(0o700)


def tree_manifest(directory):
    """快照普通文件和空目录；拒绝链接、socket等特殊文件。"""
    directory = Path(directory)
    result = {}
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('snapshot requires a real directory')
    for path in sorted(directory.rglob('*')):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('snapshot contains unsafe file types')
        result[path.relative_to(directory).as_posix()] = file_hash(path) if path.is_file() else None
    return result


def snapshot(source, target):
    expected = tree_manifest(source)
    if Path(target).exists():
        raise ValueError('backup target already exists')
    shutil.copytree(str(source), str(target), copy_function=shutil.copy2)
    if tree_manifest(source) != expected or tree_manifest(target) != expected:
        raise ValueError('source changed or backup verification failed')
    return expected


def write_private(path, data):
    """既有凭据只允许字节一致；新文件先写同目录临时文件后排他发布。"""
    path = Path(path)
    safe_directory(path)
    private_dir(path.parent)
    if path.exists():
        if not path.is_file() or path.read_bytes() != data:
            raise ValueError('existing private file differs; automatic replacement forbidden')
        return
    descriptor, temporary = tempfile.mkstemp(prefix='.transfer-', dir=str(path.parent))
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, str(path))
    finally:
        os.unlink(temporary)
