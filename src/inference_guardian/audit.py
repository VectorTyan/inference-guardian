"""兼容原公开导入；实现位于 observability.audit。"""
import sys as _sys
from .observability import audit as _implementation

_sys.modules[__name__] = _implementation
