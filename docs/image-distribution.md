# 镜像分发

常规安装器会在主控构建并分发 Guardian 镜像。手工操作时，先在主控按受管目录准备经核验的镜像归档、完整镜像 ID 和 SHA256SUMS。

## 3 p0分发

各节点先解压同一源码包。p0重新读取源码版本，使用与构建时相同的目录；目标目录须尚不存在。

```bash
set -euo pipefail
cd /data/scripts/inference-guardian
if [[ -z "${IG_PROFILE:-}" ]]; then
  configs=("$PWD"/config/manual-profiles/*/controller-external.json)
  [[ ${#configs[@]} -eq 1 && -f "${configs[0]}" ]] || { echo "请指定四节点配置目录 IG_PROFILE" >&2; exit 1; }
  IG_PROFILE=$(dirname "${configs[0]}")
fi
IG_VERSION=$(PYTHONPATH=src python3 -c 'from inference_guardian import __version__; print(__version__)')
[[ "$IG_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.-]*$ ]]
test "${#IG_VERSION}" -le 128
IG_IMAGES="/data/scripts/inference-guardian/images/${IG_VERSION}"
cd "$IG_IMAGES"
sha256sum --check SHA256SUMS
for IG_NODE in p1 d0 d1; do
  IG_TARGET=$(python3 -c 'import json,sys; from urllib.parse import urlsplit; print(urlsplit(json.load(open(sys.argv[1]))["nodes"][sys.argv[2]]["url"]).hostname)' "$IG_PROFILE/controller-external.json" "$IG_NODE")
  [[ "$IG_TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
  ssh "root@$IG_TARGET" "mkdir -p /data/scripts/inference-guardian/images && mkdir -m 700 '$IG_IMAGES'"
  scp "inference-guardian-${IG_VERSION}-arm64.tar" "inference-guardian-${IG_VERSION}-arm64.image-id" source-manifest.sha256 \
    build.log smoke.log SHA256SUMS "root@$IG_TARGET:$IG_IMAGES/"
  ssh "root@$IG_TARGET" "cd '$IG_IMAGES' && sha256sum --check SHA256SUMS"
done
```

远端命令中的目录由p0从源码读取并校验后的版本派生。保留SSH主机密钥检查；中断后补传并重新校验，不重建已有目录。

## 4 工作节点导入

校验 SHA256SUMS 后用 docker load 导入，检查版本标签是否指向主控记录的完整镜像 ID。
