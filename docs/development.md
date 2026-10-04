# Development

## Prerequisites

- Docker and Docker Compose
- Task (https://taskfile.dev)

## Setup

```bash
# 1. Initialize environment files (generates secrets, writes .env files)
task ensure-env

# 2. Start the full stack
docker compose up -d

# 3. Access services
#   Superset:  http://superset.celine.localhost
#   Jupyter:   http://jupyter.celine.localhost
#   SSO:       http://sso.celine.localhost
#   Keycloak:  http://keycloak.celine.localhost
```

On first run the realm is provisioned by `celine-policies`, not from a file here. Demo users come with it.

## Stopping and Resetting

```bash
# Stop all services
docker compose down

# Stop and remove all data volumes (full reset)
docker compose down -v
```

## Rebuilding Images

```bash
# Rebuild the Superset image
docker compose build superset

# Rebuild the Jupyter image
docker compose build jupyter
```

## Service URLs

| Service | Local URL |
|---|---|
| Superset | http://superset.celine.localhost |
| Jupyter | http://jupyter.celine.localhost |
| oauth2-proxy | http://sso.celine.localhost |
| Keycloak Admin | http://keycloak.celine.localhost/admin |

## Adding a New Service

To add a new service behind the SSO boundary:

1. Add the service to `docker-compose.yaml`.
2. Add a Caddy virtual host using `forward_auth` to oauth2-proxy. The Caddyfile belongs to the integration workspace, not to this repository.
3. Configure the service to read identity from the injected headers (`X-Auth-Request-User`, `X-Auth-Request-Access-Token`).
4. Implement authorization logic using the JWT claims: the realm role `platform-admin` (`realm_access.roles`) for platform-wide access, and `organization.<alias>.groups` only for the organisation a request concerns. Never read the top-level `groups` claim.

## Changing the Role Mapping

Edit `packages/celine-superset/src/celine/superset/auth/groups.py` to modify Superset role mappings. In the compose stack the plugin source is mounted, so a restart picks it up.

Jupyter access is `platform-admin` only, in `packages/celine-jupyter/src/celine/jupyter/jwt_authorizer.py`.
The server reads `~/.jupyter/jupyter_server_config.py` (the compose stack mounts
`config/jupyter/jupyter_server_config.py` there) and needs `CELINE_JUPYTER_JWT_ISSUER`; see
[Services](services.md#jupyter).

## Tests

```bash
uv run --package celine-superset pytest packages/celine-superset/tests -q
# celine-jupyter is not a workspace member (it needs celine-sdk>=2.0.0 and jupyter-server):
cd packages/celine-jupyter && uv run pytest -q
```

The Jupyter startup tests (`tests/test_serverapp.py`) start real servers in subprocesses, both
`jupyter celine-server` and a stock `jupyter server` with the shipped configuration file, and
send them RS256 tokens of a local test issuer.

`tests/**/integration/` hold real-token tests against a local Keycloak (dev realm, `oauth2_proxy`
client, dev users `admin` and `org-admin`). They skip when Keycloak does not answer. The
legacy-realm-group case also needs `LEGACY_GROUP_TOKEN`, a token minted from a client that
still maps realm groups.

## CI and Image Publishing

Docker images are built and published automatically via GitHub Actions when source or configuration files change. Image versions are controlled by `version.txt` (Superset) and `version.jupyter.txt` (Jupyter).
