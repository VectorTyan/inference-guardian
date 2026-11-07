"""兼容原公开导入；实现位于 agent.client。"""
import sys as _sys
from .agent import client as _implementation

_sys.modules[__name__] = _implementation
