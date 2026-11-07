"""兼容原公开导入；实现位于 containers.docker_api。"""
import sys as _sys
from .containers import docker_api as _implementation

_sys.modules[__name__] = _implementation
