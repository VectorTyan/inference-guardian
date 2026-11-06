# 手工首次部署

在复制源码到安装根目录前于 Bash 中执行以下检查。已有部署使用统一升级入口。

```bash
set -eu
test ! -L /data/scripts/inference-guardian
if test -e /data/scripts/inference-guardian; then test -d /data/scripts/inference-guardian; fi
for IG_ENTRY in src scripts docs examples deploy README.md pyproject.toml MANIFEST.json .dockerignore runtime state; do
  test ! -e "/data/scripts/inference-guardian/$IG_ENTRY"
  test ! -L "/data/scripts/inference-guardian/$IG_ENTRY"
done
```
