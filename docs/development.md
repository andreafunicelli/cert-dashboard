# Development and container setup

Python 3.12 and uv 0.13.1 run the pinned dependencies in `uv.lock`.

```sh
uv sync --frozen
uv run ruff check .
docker compose -f docker-compose.test.yml pull db
docker build --target test -t cert-dashboard:test .
uv run pytest -q --cov=app --cov-report=term-missing --cov-report=json
uv run coverage report --fail-under=85 --include='app/crypto/*'
uv run pip-audit
docker compose -f docker-compose.test.yml config --quiet
docker run --rm cert-dashboard:test
docker build -t cert-dashboard:local .
```

On Windows, use WSL's Linux Docker engine for authoritative tests. Keep its uv
environment outside the Windows checkout so Linux and Windows venvs stay distinct:

```sh
cd /mnt/c/Users/afunicelli/cert-dashboard
UV_PROJECT_ENVIRONMENT="$HOME/.venvs/cert-dashboard" uv run pytest -q
```

Host tests exercise Docker Compose rendering and isolated container permissions;
they require the test image built above. Those four Docker-CLI tests skip inside
the application test image, which has no host Docker socket or CLI. Unit tests do
not contact network services. Prepare images/dependencies before running tests.

This scaffold does not yet implement `app.main` or the worker loop. Application
startup and database schema validation arrive in later reviewed plan tasks.

## Linux deployment secrets

Provision canonical files beneath `/etc/cert-dashboard/secrets` through the
operator's normal secure process: `master_key`, `session_secret`, `db_password`,
and a distinct `db_owner_password`. Never commit them. Worker credentials
`ansible_ssh_key`, `ansible_vault_password`, `inventory_git_token`, `smtp_password`
are optional; mount only the ones provisioned using the credentials override.

An administrator runs the following as root on the deployment host (the agent does
not elevate or touch production secrets):

```sh
sh scripts/install-secrets.sh /etc/cert-dashboard/secrets
```

The installer changes ownership/modes only, reads no values, and creates no copies:

| Object | Owner | Mode |
| --- | --- | --- |
| Secret directory | root:root | 0711 |
| App/worker secrets | 10001:10001 | 0400 |
| Shared `db_password` | 10001:999 | 0440 |
| `db_owner_password` | 999:999 | 0400 |

The directory permits traversal of known filenames, but not listing. Compose file
secrets are read-only bind mounts preserving these numeric owners/modes; `mode:`
does not remap them outside Swarm. The pinned Debian PostgreSQL 16 image uses
postgres UID/GID 999. The application runs as 10001; its one-shot migration override
runs as 999 with only DB configuration needed. Inherited app-owned secret files
remain unreadable to that migration UID. Normal web/worker never mount the owner
password. Rotate a secret by replacing it, reapplying the installer, then restarting
the affected service. Keep the master-key backup copies separate from DB backups.

After the schema task is implemented, migrations use:

```sh
docker compose -f docker-compose.yml -f docker-compose.migrate.yml run --rm web alembic upgrade head
```

Use the credentials override only after provisioning its entries and
`/etc/cert-dashboard/known_hosts`; remove unused optional mounts first. SSH host
keys are pinned and strict checking is enabled.

The offline htmx asset is upstream v2.0.8 from
`https://github.com/bigskysoftware/htmx/tree/v2.0.8`, with its upstream license in
`app/static/htmx.LICENSE`; the bundled JS SHA-256 is
`22283ef68cb7545914f0a88a1bdedc7256a703d1d580c1d255217d0a50d31313`.
