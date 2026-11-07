"""保留迁移模块的公开身份，使旧导入和新实现共享依赖及类型。"""
import sys as _sys
from types import FunctionType as _FunctionType


def _retain_import_identity(implementation_name, public_name):
    """实现初始化完成后保留历史类型身份，再发布共享模块的旧入口。

    提前发布别名会绕过实现模块的导入锁，初始化失败时还会留下不完整缓存。
    调用必须是实现模块的最后一步；只修改本模块定义的对象，保留外部类型。
    """
    module = _sys.modules[implementation_name]
    for value in vars(module).values():
        if not isinstance(value, (_FunctionType, type)) or value.__module__ != implementation_name:
            continue
        value.__module__ = public_name
        if isinstance(value, type):
            for member in vars(value).values():
                if isinstance(member, (staticmethod, classmethod)):
                    member = member.__func__
                if isinstance(member, _FunctionType) and member.__module__ == implementation_name:
                    member.__module__ = public_name
    module.__name__ = public_name
    _sys.modules[public_name] = module
    parent, _, name = public_name.rpartition(".")
    setattr(_sys.modules[parent], name, module)
