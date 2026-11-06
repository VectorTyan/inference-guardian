"""面向已明确配置的推理恢复组提供外部监测、恢复和审计。

仅导出版本信息；模型镜像与模型容器入口不由本包修改。
"""

from pathlib import Path as _Path
import re as _re


def read_source_version(root):
    """读取项目约定的[project]单行version字段，只用通用标准库。

    这是本项目版本字段的窄读取器，不是通用TOML解析器。仅接受单/双引号
    包围的major.minor.patch及Docker标签可用后缀；允许空白和行尾注释。
    缺失、重复、非字面量或不安全值均失败，不猜测版本、不回退旧标签。
    """
    lines = (_Path(root) / "pyproject.toml").read_text(encoding="utf-8").splitlines()
    in_project, sections, versions = False, 0, []
    for line in lines:
        if line.lstrip().startswith("["):
            section = _re.fullmatch(r"\s*\[([^\[\]]+)\]\s*(?:#.*)?", line)
            in_project = bool(section and section.group(1).strip() == "project")
            sections += int(in_project)
        elif in_project and _re.match(r"\s*version\s*=", line):
            match = _re.fullmatch(
                r'''\s*version\s*=\s*(['"])([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.-]*)\1\s*(?:#.*)?''',
                line,
            )
            if not match or len(match.group(2)) > 128:
                raise ValueError("project.version must be a quoted Docker-tag-compatible major.minor.patch version")
            versions.append(match.group(2))
    if sections != 1 or len(versions) != 1:
        raise ValueError("exactly one [project] section and literal version field are required")
    return versions[0]

# 源码和守护镜像都携带同一份pyproject.toml；安装为wheel时使用发行元数据。
# 不维护第二份版本常量，避免升级后包名、镜像标签与运行时代码版本不一致。
_source_metadata = _Path(__file__).resolve().parents[2] / "pyproject.toml"
if _source_metadata.is_file():
    __version__ = read_source_version(_source_metadata.parent)
else:
    from importlib.metadata import version as _installed_version
    __version__ = _installed_version("inference-guardian")
