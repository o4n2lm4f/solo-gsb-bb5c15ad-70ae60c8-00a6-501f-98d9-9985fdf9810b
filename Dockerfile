FROM python:3.11-slim

# Runtime environment ------------------------------------------------------
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_HOST=0.0.0.0 \
    APP_PORT=8000 \
    DEFAULT_PROOF_MODE=standard

WORKDIR /app

# Requirements are copied first so they can be bind-mounted over in dev.
# Dependencies themselves are installed at container startup by
# docker-entrypoint.sh ("依赖随启动安装"), keeping the image itself thin.
COPY requirements.txt /app/requirements.txt
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Application source (in the default Compose setup this directory is
# bind-mounted from the host, so this copy mainly serves non-Compose runs).
COPY app /app/app

EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]
