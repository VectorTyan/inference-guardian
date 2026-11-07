"""保留迁移模块的公开身份，使旧导入和新实现共享依赖及类型。"""
import sys as _sys


def _retain_import_identity(implementation_name, public_name):
    """在定义类型前绑定旧名称，保留 pickle、依赖替换和日志分类语义。"""
    module = _sys.modules[implementation_name]
    _sys.modules[public_name] = module
    parent, _, name = public_name.rpartition(".")
    setattr(_sys.modules[parent], name, module)
    module.__name__ = public_name
