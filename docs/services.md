# Services

## Superset

### Authentication

Superset uses `AUTH_REMOTE_USER` mode. Login and logout are fully delegated to oauth2-proxy — Superset never handles credentials directly.

The custom `OAuth2ProxySecurityManager` (in `packages/celine-superset/src/celine/superset/`) extends Superset's `RemoteUserSecurityManager`:

- Reads the `X-Auth-Request-Access-Token` header on each request
- Validates the JWT signature against the Keycloak JWKS endpoint
- Extracts user identity and group memberships from the token claims
- Auto-creates users on first login
- Synchronizes Superset roles on every login based on current group membership

### Group-to-Role Mapping

Keycloak groups are mapped to Superset roles in `packages/celine-superset/src/celine/superset/auth/groups.py`:

| Keycloak group | Superset role |
|---|---|
| realm `admin(s)`, `manager(s)` | `Admin` |
| realm `editor(s)` | `celine:managers` (cross-org) |
| any other realm group, including `/viewers` | none |
| org `admins`, `managers`, `editors` | `org:<slug>:<level>` |
| org `viewers`, any other org group, or org membership alone | `org:<slug>:viewers` |

Users with no mapped role cannot access Superset.

### Dataset Access

`celine-superset governance sync` tags every dataset in the synced schema with `extra.celine_access`, resolved from `governance.yaml` (file defaults and deployer overlays included):

| Tag | Who can read the dataset |
|---|---|
| `open` | any Superset user |
| `org` | cross-org roles (`celine:*`), and `org:<slug>:*` for a slug in `extra.org_slugs` |
| `operators` | `Admin` only |

Datasets classified `pii`, with `row_filters` or `consent_required`, `secret`, without an owner that has a Keycloak organization, or without a governance entry are tagged `operators`. A dataset the sync has not tagged is also `Admin` only.

### Docker Image

```
ghcr.io/celine-eu/superset:<version>
ghcr.io/celine-eu/superset:latest
```

Version is defined in `version.txt`.

---

## Jupyter

### Authentication

Jupyter has no local passwords or tokens. All access control is enforced by the custom JWT authorizer in `packages/celine-jupyter/src/celine/jupyter/`.

The authorizer:
- Reads the `Authorization: Bearer <token>` header (injected by oauth2-proxy via Caddy)
- Validates the JWT signature against Keycloak JWKS
- Checks the user's group memberships from the token claims
- Grants access only to users in the configured allowed groups (default: `/admins`)

### Access Control

Edit the allowed groups in the Jupyter configuration:

```python
# config/jupyter/jupyter_server_config.py
c.JWTAuthenticator.allowed_groups = ["/admins", "/managers"]
```

### Docker Image

```
ghcr.io/celine-eu/jupyter:<version>
ghcr.io/celine-eu/jupyter:latest
```

Version is defined in `version.jupyter.txt`.

---

## Caddy

Caddy handles TLS termination and reverse proxying via virtual hosts and `forward_auth`.

Configuration lives in the integration workspace rather than here. Key patterns:

- All `*.celine.localhost` traffic is routed through oauth2-proxy's `forward_auth` directive before proxying to the target service.
- The SSO endpoint (`sso.celine.localhost`) is proxied directly to oauth2-proxy for the login/callback flow.
- Keycloak (`keycloak.celine.localhost`) is proxied without auth to allow the OIDC discovery and JWKS endpoints to be reachable.
