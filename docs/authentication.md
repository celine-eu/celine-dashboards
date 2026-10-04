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

Each application validates JWTs locally using the Keycloak JWKS endpoint:

```
http://keycloak:8080/realms/celine/protocol/openid-connect/certs
```

The JWKS is fetched once at startup and cached. JWT signatures use RS256.

## Service / CLI Tokens

Non-browser clients (scripts, pipelines) can use client credentials tokens from the `celine-cli` client:

```bash
curl -s http://keycloak.celine.localhost/realms/celine/protocol/openid-connect/token \
  -d "grant_type=client_credentials&client_id=celine-cli&client_secret=<secret>" \
  | jq .access_token
```

Pass the token as `Authorization: Bearer <token>`. oauth2-proxy will skip session validation for requests with a valid Bearer token.
