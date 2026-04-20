## Scope

This repository collects the tooling and dashboards for the CELINE project, `packages/**` may have an AGENTS.md to load too depending on the task.

## Structure

### Superset

- `packages/celine-superset` python package (`celine.superset`) to handle SSO via Keycloak in superset
- `config/superset` superset config mounted in docker image
- `version.txt` tracks the superset version and SSO login version eg `6.0.0-1.0.0`

- `packages/celine-superset-cli` python package (`celine.superset.cli`) provides a CLI to interact with superset via API (eg import, export)

### Jupyter

- `packages/jupyter_jwt_auth` python package (`celine.jupyter`) to handle SSO via Jupyter
- `config/jupyter` integrate the SSO in `jupyterhub_config.py`
- `version.jupyter.txt` tracks the jupyter version and SSO login version eg `lab-4.4.7-1.0.0`

