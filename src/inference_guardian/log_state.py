"""兼容原公开导入；实现位于 observability.log_state。"""
import sys as _sys
from .observability import log_state as _implementation

_sys.modules[__name__] = _implementation
