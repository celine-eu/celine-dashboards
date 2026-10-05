# celine-superset

CELINE Superset SSO plugin and management CLI.

## SSO plugin: configuration

The plugin (`OAuth2ProxySecurityManager`, `CUSTOM_SECURITY_MANAGER` in `superset_config.py`)
identifies every request from the Keycloak access token oauth2-proxy forwards
(`X-Auth-Request-Access-Token`, `X-Forwarded-Access-Token` or `Authorization: Bearer`).

| variable | required | meaning |
|---|---|---|
| `CUSTOM_SECURITY_MANAGER_KEYCLOAK_ISSUER` | **yes**, outside `CELINE_ENV=dev` | the one issuer whose tokens are trusted: the realm URL, e.g. `https://keycloak.example.org/realms/celine` |
| `CUSTOM_SECURITY_MANAGER_KEYCLOAK_JWKS_URL` | no | the issuer's JWKS URL, when its discovery document is not reachable from Superset; default: `jwks_uri` of `<issuer>/.well-known/openid-configuration` |
| `CUSTOM_SECURITY_MANAGER_KEYCLOAK_AUDIENCE` | no | comma-separated; when set, the token's `aud` must contain one of them |
| `CUSTOM_SECURITY_MANAGER_SKIP_SSL_VERIFY` | no | `true` skips TLS verification of the discovery and JWKS fetches (self-signed issuers only) |
| `CELINE_ENV` (then `ENVIRONMENT`) | no | posture; only `dev` relaxes, unset is hardened |
| `CELINE_PUBLIC_DOCS` | no | `true` serves the API description (`/swagger/v1`, `/api/v1/_openapi`) outside dev; off by default (`FAB_API_SWAGGER_UI`) |
| `CELINE_AUDIT_PSEUDONYM_KEY` | no | keys the hash that stands in for a personal identifier in an audit record |

Behaviour ([ADR-0003](../../docs/decisions/ADR-0003-superset-trusts-one-configured-issuer.md)):

- A token's `iss` is compared with the configured issuer **before** any key is fetched; a
  token of any other issuer, another realm of the same Keycloak included, is refused.
- Keys come from the configuration or the configured issuer's discovery document (whose
  `issuer` must match), never from the token. RS256 only; `exp` and `iss` are required.
- Without an issuer, Superset does not start (`InsecureConfiguration` when the security
  manager is built: web server, workers and CLI alike), unless `CELINE_ENV=dev`, where the
  issuer defaults to the local realm `http://keycloak.celine.localhost/realms/celine`.

## Access audit

Every request the plugin identifies gets at most one record on the logger `celine.audit`, in
the platform's shape (`celine.sdk.audit`: `event`, `service`, `sub`, `client_id`,
`service_account`, `action`, `method`, `route`, `resource`, `outcome`, `reason`, `request_id`,
`trace_id`, `ts`), one JSON object per line, written once the response status is known
([ADR-0004](../../docs/decisions/ADR-0004-superset-audits-the-request-in-the-platform-record.md)):

| The request | Record |
|---|---|
| a read listed in `plugin/audit.py` `READS` (dashboard, chart and chart data, explore, dataset, SQL Lab, saved query, export), answered below 400 | `access`, `allowed` |
| any request answered 401 or 403 by a verified caller | `denied`, at `WARNING` |
| a token that fails verification, or a caller granted no role | `denied`, reason `invalid_token` / `no_role` |
| a listed read answered with another error | `access`, `error`, reason `http <status>` |

- The caller is the token's `sub` and `azp`, never the Superset username (the token's
  `preferred_username` or email). A request without a token is not recorded.
- `resource` is a Superset id with its kind: `dashboard:12`, `chart:5`, `dataset:7`,
  `query:<client id>`. A refusal by the dataset tag carries `reason=not_in_organisation`.
- SQL Lab is recorded as `database:<id>/sql:<16 hex>`, the SHA-256 of the statement: the SQL
  text is never in a record.
- `route` is the Flask rule (`/api/v1/dashboard/<id_or_slug>`), never the path or query.
- Superset's own event log (the `logs` table) is unchanged.
- `service_account` is the plugin's reading of the token: true for a client-credentials token
  (`preferred_username` `service-account-…`, `gty`, a `client_id` with no person behind it,
  Keycloak's grant in `jti`), false for a person's. The plugin cannot install `celine-sdk`
  (Superset pins `cryptography<45`), so the record is written by its own copy of the emitter.

## Log lines

The plugin's operational log lines (`celine.superset.plugin.security_manager`,
`celine.superset.auth.user`: sign-in, user creation, the dataset filter, the access checks) name
the caller by the token's `sub`, the value the audit record carries, at every level. The
Superset username (the token's `preferred_username`, often an email address), the email and the
given and family names are never in a log line; a new user is logged with its `sub` and roles.

Their level and handler are Superset's (`LOG_LEVEL`, from `SUPERSET_LOG_LEVEL`, default
`INFO`). At `INFO` the plugin logs a sign-in (`Authenticated sub=… azp=…`), a refusal and a
failed check (`WARNING` and above); the per-request access traces (the dataset filter,
`raise_for_access`, `datasource_access`, a check that passed) are `DEBUG` and appear only when
`SUPERSET_LOG_LEVEL=debug`. Who read what is the audit record, held at `INFO` whatever the level.

## Tests

```bash
../../.venv/bin/pytest -q
```

`tests/superset/integration` uses real tokens from the local Keycloak and is skipped when it
does not answer. The case for another realm's token needs a master-realm user in
`KEYCLOAK_MASTER_USER` / `KEYCLOAK_MASTER_PASSWORD`; without them it is skipped.
