# syntax=docker/dockerfile:1
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
FROM postgres:16-bookworm@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4 AS postgres-tools
FROM ${PYTHON_IMAGE} AS build
ENV UV_PROJECT_ENVIRONMENT=/opt/venv UV_LINK_MODE=copy
RUN pip install --no-cache-dir uv==0.13.1
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project --python /usr/local/bin/python

FROM build AS test-deps
RUN uv sync --frozen --no-install-project --python /usr/local/bin/python

FROM ${PYTHON_IMAGE} AS base
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH=/opt/venv/bin:$PATH
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git openssh-client openssl libpq5 liblz4-1 libzstd1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home app \
    && mkdir -p /srv/inventory /srv/artifacts /run/cert-keys \
    && chown app:app /srv/inventory /srv/artifacts /run/cert-keys \
    && chmod 0700 /run/cert-keys
WORKDIR /app
COPY --from=postgres-tools /usr/lib/postgresql/16/bin/pg_dump /usr/lib/postgresql/16/bin/pg_restore /usr/lib/postgresql/16/bin/psql /usr/local/bin/
COPY --chown=app:app app ./app
COPY --chown=app:app --chmod=0755 app/migrations/init_roles.sh ./app/migrations/init_roles.sh
USER 10001:10001

FROM base AS test
COPY --from=test-deps /opt/venv /opt/venv
COPY --chown=app:app tests ./tests
COPY --chown=app:app pyproject.toml docker-compose*.yml .gitattributes .dockerignore ./
CMD ["pytest", "-q", "-p", "no:cacheprovider"]

FROM base AS runtime
COPY --from=build /opt/venv /opt/venv
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
