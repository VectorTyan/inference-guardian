"""Agent公共兼容入口；观测、动作事务和HTTP实现按职责组织。"""
from .agent.service import *
from .agent import service as _service
from .agent.http import create_server, main, _Server, _Handler
from .agent.config import validate_config, _number
from .agent.observation import _unknown, _commands


def __getattr__(name):
    return getattr(_service, name)


if __name__ == "__main__":
    main()
