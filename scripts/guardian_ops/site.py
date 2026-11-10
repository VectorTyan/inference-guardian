"""site.json版本与发布参数校验，不执行发布。"""
import copy
from pathlib import Path
import re
from inference_guardian.storage import read_json
from .mooncake_contract import MIXED_EXAMPLE

from .presets import LEGACY_MIXED_EXAMPLE as _LEGACY_MIXED_EXAMPLE
from .presets import PACKAGED_EXAMPLES

SOURCE = Path(__file__).resolve().parents[2]

def load_site(path, mode=None):
    value = copy.deepcopy(path) if isinstance(path, dict) else read_json(path)
    keys = {'version', 'mode', 'profile_directory', 'ssh', 'image', 'readiness_timeout_seconds'}
    if isinstance(value, dict) and 'profile' in value:
        name = value['profile']
        if name == _LEGACY_MIXED_EXAMPLE:
            name = MIXED_EXAMPLE
        if name not in PACKAGED_EXAMPLES or set(value) - (keys - {'profile_directory'} | {'profile'}):
            raise ValueError('select one packaged profile by name, or use the existing profile_directory configuration')
        defaults = read_json(SOURCE / 'deploy/site.example.json')
        for key, setting in value.items():
            if key in ('ssh', 'image') and isinstance(setting, dict):
                defaults[key].update(setting)
            elif key != 'profile':
                defaults[key] = setting
        defaults['profile_directory'] = str(SOURCE / 'examples/vllm-ascend' / name)
        value = defaults
    if not isinstance(value, dict) or set(value) != keys or value['version'] != 1:
        raise ValueError('use deploy/site.example.json schema version 1')
    value = copy.deepcopy(value)
    if mode is not None:
        value['mode'] = mode
    if value['mode'] not in {'observe', 'recovery'}:
        raise ValueError('deployment mode must be observe or recovery')
    ssh = value['ssh']
    if (not isinstance(ssh, dict) or set(ssh) != {'user', 'port', 'identity_file', 'connect_timeout_seconds'}
            or ssh['user'] != 'root' or type(ssh['port']) is not int or not 1 <= ssh['port'] <= 65535
            or type(ssh['connect_timeout_seconds']) is not int or not 1 <= ssh['connect_timeout_seconds'] <= 60):
        raise ValueError('SSH requires root, a valid port and bounded timeout')
    for item in (ssh['identity_file'], value['profile_directory']):
        if item is not None and (not isinstance(item, str) or not Path(item).is_absolute()):
            raise ValueError('optional local paths must be absolute')
    image = value['image']
    if not isinstance(image, dict) or set(image) != {'source', 'base_image', 'archive', 'sha256'}:
        raise ValueError('invalid image configuration')
    if image['source'] == 'build':
        if not isinstance(image['base_image'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:@-]{0,255}', image['base_image']):
            raise ValueError('invalid local base image reference')
        if image['archive'] is not None or image['sha256'] is not None:
            raise ValueError('build and imported-image settings cannot be mixed')
    elif image['source'] == 'archive':
        if (not isinstance(image['archive'], str) or not Path(image['archive']).is_absolute()
                or not re.fullmatch(r'[0-9a-f]{64}', image['sha256'] or '')):
            raise ValueError('imported image requires an absolute tar path and SHA256')
    else:
        raise ValueError('image.source must be build or archive')
    if type(value['readiness_timeout_seconds']) is not int or not 30 <= value['readiness_timeout_seconds'] <= 7200:
        raise ValueError('readiness timeout must be 30..7200 seconds')
    return value


def site_for_manifest(manifest, config=None):
    """仅在内存选择清单；现场 SSH/镜像设置来自显式配置或标准默认值。"""
    manifest = Path(manifest).absolute()
    if (manifest.name != "source-manifest.json" or manifest.is_symlink()
            or not manifest.is_file() or any(p.is_symlink() for p in manifest.parents)):
        raise ValueError("--manifest requires a regular source-manifest.json file")
    from .mooncake_contract import validate_manifest
    validate_manifest(read_json(manifest))
    site = load_site(config if config is not None else SOURCE / "deploy/site.example.json")
    site["profile_directory"] = str(manifest.parent.resolve())
    return site
