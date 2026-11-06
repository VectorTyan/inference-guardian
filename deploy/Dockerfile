# 基础镜像直接定义于此；在ARM64宿主使用docker build构建。
ARG BASE_IMAGE=python:3.12-slim-bookworm
FROM ${BASE_IMAGE}
ARG RELEASE_SHA256=manual-build
LABEL org.opencontainers.image.title="inference-guardian" \
      guardian.external-contract="1" \
      guardian.release-sha256="${RELEASE_SHA256}"
WORKDIR /opt/inference-guardian
COPY src/ /opt/inference-guardian/src/
COPY pyproject.toml /opt/inference-guardian/pyproject.toml
ENV PYTHONPATH=/opt/inference-guardian/src PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
# No pip/apt/model downloads at runtime.
# 服务名称为inference-guardian；Python包名使用下划线，与现有模块及部署器契约一致。
ENTRYPOINT ["python", "-m", "inference_guardian"]
