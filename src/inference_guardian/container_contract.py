"""兼容原公开导入；实现位于 containers.contract。"""
import sys as _sys
from .containers import contract as _implementation

_sys.modules[__name__] = _implementation
