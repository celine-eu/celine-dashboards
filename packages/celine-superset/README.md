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

Behaviour ([ADR-0003](../../docs/decisions/ADR-0003-superset-trusts-one-configured-issuer.md)):

- A token's `iss` is compared with the configured issuer **before** any key is fetched; a
  token of any other issuer, another realm of the same Keycloak included, is refused.
- Keys come from the configuration or the configured issuer's discovery document (whose
  `issuer` must match), never from the token. RS256 only; `exp` and `iss` are required.
- Without an issuer, Superset does not start (`InsecureConfiguration` when the security
  manager is built: web server, workers and CLI alike), unless `CELINE_ENV=dev`, where the
  issuer defaults to the local realm `http://keycloak.celine.localhost/realms/celine`.

## Tests

```bash
../../.venv/bin/pytest -q
```

`tests/superset/integration` uses real tokens from the local Keycloak and is skipped when it
does not answer. The case for another realm's token needs a master-realm user in
`KEYCLOAK_MASTER_USER` / `KEYCLOAK_MASTER_PASSWORD`; without them it is skipped.
