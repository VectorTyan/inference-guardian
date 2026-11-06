"""兼容原脚本路径与导入名称；实现位于guardian_ops。"""
from pathlib import Path as _Path
import sys as _sys

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "src"))
from guardian_ops.mooncake_contract import *
from guardian_ops import mooncake_contract as _implementation


def __getattr__(name):
    return getattr(_implementation, name)
