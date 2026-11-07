"""兼容原公开导入；实现位于 control.recovery_scope。"""
import sys as _sys
from .control import recovery_scope as _implementation

_sys.modules[__name__] = _implementation
