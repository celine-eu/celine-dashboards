# Authentication

## Keycloak Realm Configuration

The Keycloak realm is **not defined in this repository**. Realm, clients and scopes are reconciled by the `celine-policies` CLI from its own declarations; this repository only consumes the resulting identity.

**Realm:** `celine`

**Clients:**

| Client | Purpose |
|---|---|
| `oauth2_proxy` | Browser SSO flows |
| `celine-cli` | Service and CLI token issuance |

**Authority — exactly two levels:**

| Level | Carried by | Grants here |
|---|---|---|
| platform | realm role `platform-admin`, in `realm_access.roles` | Superset `Admin`; Jupyter access |
| organisation | the organisation's `admins`, `managers`, `editors`, `viewers` groups, in `organization.<alias>.groups` | Superset `org:<alias>:<level>`, in that organisation only |

There are no realm groups. A realm group still present in a token (`groups: ["/admins"]`)
grants nothing, and neither does any realm role other than `platform-admin`.
`realm_access.roles` is in the **access token** only, which is the token oauth2-proxy
forwards; the `oauth2_proxy` client needs the `roles` client scope for it.

The dev realm (from `celine-policies`) has demo users: `admin` holds `platform-admin`,
`org-admin` is an `example_rec` admin, `org-viewer` an `example_rec` viewer.

## oauth2-proxy Setup

oauth2-proxy is the single authentication gateway for all browser sessions.

Key configuration, which lives with the deployment rather than in this repository:

| Setting | Value |
|---|---|
| Provider | `keycloak-oidc` |
| Client ID | `oauth2_proxy` |
| Cookie domain | `.celine.localhost` |
| Cookie secret | Set via `OAUTH2_PROXY_COOKIE_SECRET` env var |
| `skip_jwt_bearer_tokens` | `true` — allows service tokens to bypass browser SSO |
| `oidc_issuer_url` | `http://keycloak:8080/realms/celine` |

Cookie sharing across `*.celine.localhost` means a single login grants access to all subdomains.

## JWT Validation

Each application validates the access token locally, against **one configured issuer**
(the realm URL). A token's `iss` is compared with that issuer before any key is fetched, and
the keys come from the configuration (or the configured issuer's discovery document), never
from the token: a validly signed token of any other issuer, another realm of the same
Keycloak included, is refused. Signatures must be RS256; `exp` and `iss` are required.

| | Superset (`celine-superset`) | Jupyter (`celine-jupyter`) |
|---|---|---|
| trusted issuer | `CUSTOM_SECURITY_MANAGER_KEYCLOAK_ISSUER` | `CELINE_JUPYTER_JWT_ISSUER` |
| JWKS URL (optional; default: from the issuer's discovery document) | `CUSTOM_SECURITY_MANAGER_KEYCLOAK_JWKS_URL` | `CELINE_JUPYTER_JWKS_URL` |
| audience (optional; comma-separated for Superset) | `CUSTOM_SECURITY_MANAGER_KEYCLOAK_AUDIENCE` | `CELINE_JUPYTER_JWT_AUDIENCE` |
| no issuer configured | does not start, unless `CELINE_ENV=dev` (then the local realm `http://keycloak.celine.localhost/realms/celine`) | does not start |
| decision | [ADR-0003](decisions/ADR-0003-superset-trusts-one-configured-issuer.md) | [ADR-0002](decisions/ADR-0002-jupyter-fails-closed-and-trusts-one-issuer.md) |

The posture signal for Superset is `CELINE_ENV`, then `ENVIRONMENT`; only the value `dev`
relaxes, and unset is hardened (the platform rule of `celine.sdk.posture`). Superset's own
`SUPERSET_ENV` plays no part. Keys are fetched on first use and cached per key id.

## Service / CLI Tokens

Non-browser clients (scripts, pipelines) can use client credentials tokens from the `celine-cli` client:

```bash
curl -s http://keycloak.celine.localhost/realms/celine/protocol/openid-connect/token \
  -d "grant_type=client_credentials&client_id=celine-cli&client_secret=<secret>" \
  | jq .access_token
```

Pass the token as `Authorization: Bearer <token>`. oauth2-proxy will skip session validation for requests with a valid Bearer token.
