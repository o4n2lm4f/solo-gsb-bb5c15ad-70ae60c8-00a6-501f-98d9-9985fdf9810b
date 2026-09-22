#!/bin/sh
# Dependencies are installed at container start, immediately before the
# service is launched ("依赖随启动安装").  Set SKIP_PIP_INSTALL=1 to skip.
set -eu

APP_HOST="${APP_HOST:-0.0.0.0}"
APP_PORT="${APP_PORT:-8000}"
REQUIREMENTS_FILE="${REQUIREMENTS_FILE:-/app/requirements.txt}"

if [ "${SKIP_PIP_INSTALL:-0}" != "1" ]; then
    echo "[entrypoint] Installing dependencies from ${REQUIREMENTS_FILE} ..."
    python -m pip install --no-cache-dir -r "${REQUIREMENTS_FILE}"
else
    echo "[entrypoint] Skipping dependency installation (SKIP_PIP_INSTALL=1)."
fi

echo "[entrypoint] Starting uvicorn on ${APP_HOST}:${APP_PORT}"
exec python -m uvicorn app.main:app --host "${APP_HOST}" --port "${APP_PORT}"
