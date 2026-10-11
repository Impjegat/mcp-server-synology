# Dockerfile for the Synology MCP server: three images from one file, chosen with
# --target.
#
#   adapter  The credential-free local server an AI application launches over stdio.
#            It forwards to the broker and holds no NAS credential, so the image has
#            none of the NAS client code and none of its libraries.
#   broker   The protected process that holds the DSM sessions and serves the tools
#            over HTTPS. It runs on its own host (see docs/MANUAL_AUTHENTICATION.md).
#   legacy   The original single-process server that logs in with a password it is
#            given. The last stage, so a plain `docker build .` and docker-compose.yml
#            keep building it.
#
#   docker build --target adapter -t synology-mcp-adapter .
#   docker build --target broker  -t synology-mcp-broker  .
#
# In every image the code and its dependencies are owned by root and are not writable
# by the account the process runs as, nothing is run as root, and no secret is baked in
# (.dockerignore keeps credentials, tokens, keys and local configuration out of the
# build context, and no stage copies more than the files it names).

# ---------------------------------------------------------------- dependencies
# Built where a compiler is available, and copied as a finished virtual environment
# so that no runtime image carries one.
FROM python:3.13-slim AS build-adapter
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*
COPY requirements-adapter.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements-adapter.txt

FROM python:3.13-slim AS build-server
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ------------------------------------------------------------------- the base
FROM python:3.13-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PATH=/opt/venv/bin:$PATH
WORKDIR /app

# -------------------------------------------------------------------- adapter
FROM runtime AS adapter
COPY --from=build-adapter /opt/venv /opt/venv
COPY adapter_main.py ./
COPY src/adapter/ ./src/adapter/
# Its logging masks the broker token with the project's redaction filter, which is
# standalone (standard library only). Nothing else under src/ is copied.
COPY src/utils/redact.py ./src/utils/redact.py
# A system account with no login, no home and no write access to anything above.
RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin mcp
USER mcp
# Pass --config PATH (or set SYNOLOGY_ADAPTER_CONFIG) and mount the config and the
# broker token file read-only. The adapter refuses to start if a NAS password, code or
# device token is in its environment.
ENTRYPOINT ["python", "adapter_main.py"]

# --------------------------------------------------------------------- broker
FROM runtime AS broker
COPY --from=build-server /opt/venv /opt/venv
COPY main.py broker_main.py ./
COPY src/ ./src/
COPY docker/broker_healthcheck.py /opt/broker_healthcheck.py
RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin mcp
USER mcp
# Settings (NAS endpoints, no passwords) and the policy are read from here; the compose
# template in deploy/broker mounts them read-only.
ENV XDG_CONFIG_HOME=/config
EXPOSE 8443 8444
# Ready is not the same as signed in: a broker nobody has signed in to is healthy.
HEALTHCHECK --interval=30s --timeout=6s --start-period=20s --retries=3 \
    CMD ["python", "/opt/broker_healthcheck.py"]
ENTRYPOINT ["python", "broker_main.py"]
# With no arguments, print the usage. The broker refuses to start without TLS and a
# policy, so there is deliberately no default `serve` here.
CMD ["--help"]

# --------------------------------------------------------------------- legacy
FROM runtime AS legacy
COPY --from=build-server /opt/venv /opt/venv
COPY src/ ./src/
COPY main.py ./
# The only writable place under /app is the log directory (docker-compose.yml mounts
# ./logs over it). Home and config are for settings.json, which this mode reads.
RUN useradd -m -u 1000 mcpuser \
    && mkdir -p /app/logs \
    && chown mcpuser:mcpuser /app/logs
USER mcpuser
# Default command - stdio MCP server for Claude/Cursor
CMD ["python", "main.py"]
