# Services

## Superset

### Authentication

Superset uses `AUTH_REMOTE_USER` mode. Login and logout are fully delegated to oauth2-proxy — Superset never handles credentials directly.

The custom `OAuth2ProxySecurityManager` (in `packages/celine-superset/src/celine/superset/`) extends Superset's `RemoteUserSecurityManager`:

- Reads the `X-Auth-Request-Access-Token` header on each request
- Validates the JWT signature against the Keycloak JWKS endpoint
- Extracts user identity, realm roles and organisation groups from the token claims
- Auto-creates users on first login
- Synchronizes Superset roles on every login

### Role Mapping

There are exactly two levels, mapped in `packages/celine-superset/src/celine/superset/auth/groups.py`:

| Token claim | Superset role |
|---|---|
| realm role `platform-admin` (`realm_access.roles`) | `Admin` |
| org `admins`, `managers`, `editors` (`organization.<slug>.groups`) | `org:<slug>:<level>` |
| org `viewers`, any other org group, or org membership alone | `org:<slug>:viewers` |
| a realm group (top-level `groups`, e.g. `/admins`), any other realm role | none |

An organisation's group is valid only in that organisation: `admins` in one organisation is
not `Admin`, and reaches no other organisation. There is no cross-organisation role; the
`celine:*` roles are permission templates that `governance sync` copies onto `org:<slug>:*`
roles, and nobody is granted one at login.

Users with no mapped role cannot access Superset.

### Dataset Access

`celine-superset governance sync` tags every dataset in the synced schema with `extra.celine_access`, resolved from `governance.yaml` (file defaults and deployer overlays included):

| Tag | Who can read the dataset |
|---|---|
| `open` | any Superset user |
| `org` | `Admin`, and `org:<slug>:*` for a slug in `extra.org_slugs` |
| `operators` | `Admin` only |

Datasets classified `pii`, with `row_filters` or `consent_required`, `secret`, without an owner that has a Keycloak organization, or without a governance entry are tagged `operators`. A dataset the sync has not tagged is also `Admin` only.

### Access Audit

Who read which dashboard, chart, dataset or SQL Lab query, and who was refused, is logged on
`celine.audit` in the platform's record shape, one JSON line per request, naming the caller by
token `sub` only. See the [plugin README](../packages/celine-superset/README.md#access-audit)
and [ADR-0004](decisions/ADR-0004-superset-audits-the-request-in-the-platform-record.md).

The API description (`/swagger/v1`, `/api/v1/_openapi`) is served in dev only, unless
`CELINE_PUBLIC_DOCS=true`.

### Docker Image

```
ghcr.io/celine-eu/superset:<version>
ghcr.io/celine-eu/superset:latest
```

Version is defined in `version.txt`.

---

## Jupyter

### Authentication

Jupyter has no server token, no password and no login page. Every request is identified from
the access token it carries, and only a platform administrator's token identifies anyone. The
code is in `packages/celine-jupyter/src/celine/jupyter/`:

- `identity.py`: `JWTIdentityProvider` reads `X-Forwarded-Access-Token` (oauth2-proxy), then
  `Authorization: Bearer <token>`; any other scheme, Jupyter's own `token` included, is no
  token. It checks the token's `iss` against the one trusted issuer **before** fetching any
  key, then verifies the RS256 signature against that issuer's JWKS, `exp`, and `aud` when an
  audience is configured. A request whose token is missing, invalid or not a platform
  administrator's has no user, and Jupyter answers 403.
- `jwt_authorizer.py`: `JWTAuthorizer` allows every action, terminals included, exactly when
  the verified token carries the realm role `platform-admin` (`realm_access.roles`, read with
  `celine.sdk.auth.is_platform_admin`), and nothing otherwise.
- `serverapp.py`: `jupyter celine-server`, the image's command, is Jupyter Server with both
  built in. After loading its configuration it exits instead of serving if either was
  replaced, if unauthenticated access or the XSRF check was switched back on, or if no
  issuer is set. The same check runs as a server extension, which the shipped
  `config/jupyter/jupyter_server_config.py` enables, so a stock `jupyter lab` / `jupyter
  server` given that file is closed the same way. That file exits the process if
  `celine.jupyter` cannot be imported: Jupyter logs an error in a configuration file and
  starts anyway with its own random token, so a configuration file alone cannot fail closed.

A server token set anyway (`JUPYTER_TOKEN`, `IdentityProvider.token`, `ServerApp.token`) is
dropped. A bearer token sent by the caller skips Jupyter's XSRF check, as Jupyter's own token
would; a token forwarded by the proxy stands for a browser session and keeps it.

| Variable | Meaning |
|---|---|
| `CELINE_JUPYTER_JWT_ISSUER` | Required. The trusted issuer, the realm URL exactly as in the tokens' `iss` (e.g. `https://keycloak.example.org/realms/celine`). |
| `CELINE_JUPYTER_JWKS_URL` | Optional. The issuer's JWKS URL, when its discovery document is not reachable from the server. |
| `CELINE_JUPYTER_JWT_AUDIENCE` | Optional. When set, the token's `aud` must contain it. |

### Access Control

Access is not configurable: only platform administrators use Jupyter. An organisation's
`admins` group and a realm group such as `/admins` grant nothing.

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
