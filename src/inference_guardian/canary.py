"""兼容原公开导入；实现位于 control.canary。"""
import sys as _sys
from .control import canary as _implementation

_sys.modules[__name__] = _implementation
