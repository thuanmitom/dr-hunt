# syntax=docker/dockerfile:1.7
# One image, three roles (api / worker / beat) selected by the compose `command`.
# The base image is pinned by digest (D-59): rebuilds use the same OS layer until the pin is changed on purpose.

FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
# requirements.txt is hash-locked (uv pip compile --generate-hashes): every artifact is verified.
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install --require-hashes -r requirements.txt

FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache
RUN groupadd --system --gid 10001 hc \
 && useradd --system --uid 10001 --gid hc --no-create-home --shell /usr/sbin/nologin hc
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=hc:hc alembic.ini ./
COPY --chown=hc:hc app ./app
COPY --chown=hc:hc migrations ./migrations
COPY --chown=hc:hc scripts ./scripts
COPY --chown=hc:hc contracts ./contracts
USER hc
EXPOSE 8000
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
