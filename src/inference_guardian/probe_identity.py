"""兼容原公开导入；实现位于 health.identity。"""
import sys as _sys
from .health import identity as _implementation

_sys.modules[__name__] = _implementation
