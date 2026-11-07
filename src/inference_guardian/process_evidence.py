"""兼容原公开导入；实现位于 health.process_evidence。"""
import sys as _sys
from .health import process_evidence as _implementation

_sys.modules[__name__] = _implementation
