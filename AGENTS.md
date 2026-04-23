## Scope

This repository collects the tooling and dashboards for the CELINE project. All Python code lives in a single package (`celine-dashboards`) under `./src/celine/**`, with optional extras grouping functionality by service.

## Structure

Sources are namespaced under `celine.*`:

- `src/celine/superset` (`celine.superset`) — SSO plugin for Superset (Keycloak JWT auth, org-aware role mapping)
- `src/celine/superset/cli` (`celine.superset.cli`) — management CLI for Superset (import/export, governance sync). Exposed as `celine-superset` console script.
    - `src/celine/superset/cli/openapi/superset_client` is generated and read-only (regenerate via `openapi-python-client`).
- `src/celine/jupyter` (`celine.jupyter`) — JWT authorizer for Jupyter

Tests live under `./tests/**` mirroring the source layout.

### pyproject extras

Install via `uv sync --all-extras` or pick a subset:

- `[superset]` — pulls `cryptography`, `psycopg2-binary`, `requests`
- `[cli]` — pulls `httpx`, `typer`, `pydantic`, `rich`, `pyyaml`, etc.
- `[jupyter]` — header-only (`pyjwt` from base deps)
- `[all]` — all of the above

### CLI

`instances.example.yaml` at the repo root is the template for per-instance Superset config consumed by `celine-superset`. Copy to `instances.yaml` (gitignored) and edit. Commands:

- `bootstrap` — default to local env and configure database
- `chart` / `dashboard` — `import` / `export` per env
- `governance sync` — reconcile dataset governance; see `task governance:sync`

### Superset stack

- `config/superset` — Superset config and bootstrap scripts, mounted into the image
- `version.txt` — Superset image version (format `6.0.0-1.0.0`)

### Jupyter stack

- `config/jupyter/jupyterhub_config.py` — Jupyter auth config
- `version.jupyter.txt` — Jupyter image version (format `lab-4.4.7-1.0.0`)
