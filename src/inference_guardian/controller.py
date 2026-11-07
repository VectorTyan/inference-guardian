"""兼容原公开导入；实现位于 control.service。"""
import sys as _sys
from .control import service as _implementation

_sys.modules[__name__] = _implementation
