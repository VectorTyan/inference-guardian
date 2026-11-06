"""凭据引用、内容校验与只读挂载重映射；不轮换凭据。"""
from pathlib import Path, PurePosixPath
import re
import ssl

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
SECRET_ROOT = "/run/secrets/inference-guardian/"
FILE_KEYS = {"token_file", "ca_file", "cert_file", "key_file", "tls_cert_file", "tls_key_file",
             "client_token_file", "upstream_token_file", "tokenizer_token_file"}

def remap_secrets(value, references, *, directory=None):
    """递归收集本角色引用的最小凭据集，并重映射到只读凭据挂载。

    按basename检查冲突，避免不同源文件在挂载内互相覆盖；references由本函数累计。
    """
    def map_file(path, kind):
        if not isinstance(path, str) or not path:
            raise ValueError("credential references must be nonempty paths")
        name = PurePosixPath(path.replace("\\", "/")).name
        if not NAME.fullmatch(name) or name in {".", ".."}:
            raise ValueError("credential filename is invalid")
        previous = references.get(name)
        if previous and previous["source"] != path:
            raise ValueError("credential basenames must be unique")
        references.setdefault(name, {"source": path, "kinds": set()})["kinds"].add(kind)
        return str(directory / name) if directory is not None else SECRET_ROOT + name
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in FILE_KEYS and item is not None:
                result[key] = map_file(item, key)
            elif key == "header_files":
                result[key] = {header: map_file(path, "header") for header, path in item.items()}
            else:
                result[key] = remap_secrets(item, references, directory=directory)
        return result
    if isinstance(value, list):
        return [remap_secrets(item, references, directory=directory) for item in value]
    return value


def credentials(directory, references, agent):
    """读取精确引用的本地普通凭据文件，检查大小、Token格式和证书可加载性。

    返回原始字节供受限目录落盘；不打印内容，也不证明现场SAN、期限及网络已通过验收。
    """
    data = {}
    directory = directory.resolve()
    for name, reference in references.items():
        path = directory / name
        if path.is_symlink() or path.resolve().parent != directory:
            raise ValueError("credential files must be local regular files")
        value = path.read_bytes()
        if not value or len(value) > 1024 * 1024:
            raise ValueError("credential file is empty or too large")
        if any(kind.endswith("token_file") for kind in reference["kinds"]):
            token = value.strip()
            if not 16 <= len(token) <= 4096 or any(byte < 33 or byte > 126 for byte in token):
                raise ValueError("tokens require 16-4096 printable non-whitespace ASCII bytes")
        data[name] = value
    listen = agent["listen"]
    try:
        if listen.get("tls_cert_file"):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(directory / PurePosixPath(listen["tls_cert_file"]).name),
                                    str(directory / PurePosixPath(listen["tls_key_file"]).name))
        for name, reference in references.items():
            if "ca_file" in reference["kinds"]:
                ssl.create_default_context(cafile=str(directory / name))
    except (OSError, ssl.SSLError):
        raise ValueError("TLS certificate/key or CA could not be loaded") from None
    return data
