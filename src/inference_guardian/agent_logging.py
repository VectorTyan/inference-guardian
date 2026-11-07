"""兼容原公开导入；实现位于 agent.logging。"""
import sys as _sys
from .agent import logging as _implementation

_sys.modules[__name__] = _implementation
