"""兼容原公开导入；实现位于 health.policy。"""
import sys as _sys
from .health import policy as _implementation

_sys.modules[__name__] = _implementation
