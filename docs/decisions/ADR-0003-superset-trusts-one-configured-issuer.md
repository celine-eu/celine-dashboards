# ADR-0003 — Superset trusts one configured issuer and does not start without it outside dev

**Date:** 2026-10-05
**Status:** accepted

## Context

Superset identifies every request from the access token oauth2-proxy forwards, and the realm
role `platform-admin` in that token makes the user Superset `Admin` (ADR-0001). So the question
"which issuer's tokens count" decides who is an administrator, and it has to be answered by the
deployment, not by the token: a signature check against keys located through the token's own
claims proves only that *some* issuer signed it. The verifier had no setting for the trusted
issuer, only an optional JWKS URL, and fell back to locating keys through the token.

ADR-0002 closed the same gap for Jupyter. Superset differs in one respect: it runs in its own
interpreter (`apache/superset`, Python 3.10) with only the `[plugin]` dependencies, so it does
not import `celine-sdk` and its `celine.sdk.posture`.

## Decision

- One issuer is trusted, `CUSTOM_SECURITY_MANAGER_KEYCLOAK_ISSUER` (the realm URL). A token's
  `iss` is compared with it before any key is fetched; another issuer's token is refused.
- Keys come from `CUSTOM_SECURITY_MANAGER_KEYCLOAK_JWKS_URL` when set, else from the
  configured issuer's discovery document, whose own `issuer` must match. Never from the token.
- RS256 only; `exp` and `iss` required; the audience is checked when
  `CUSTOM_SECURITY_MANAGER_KEYCLOAK_AUDIENCE` is set.
- Posture is the platform rule, mirrored in the plugin rather than imported: `CELINE_ENV`, then
  `ENVIRONMENT`; only `dev` relaxes, unset is hardened. In dev an unset issuer defaults to the
  local stack's realm, still one issuer. Anywhere else the security manager refuses to be built,
  so the web server, the workers and the Superset CLI do not start; a request that reached the
  verifier without an issuer would be refused.

## Consequences

- Every deployment must set `CUSTOM_SECURITY_MANAGER_KEYCLOAK_ISSUER` before running an image
  with this change, or Superset (web, worker, beat, init) exits at start.
- A local stack that runs Superset must pass either the issuer or `CELINE_ENV=dev`.
- `CUSTOM_SECURITY_MANAGER_SKIP_SSL_VERIFY` still applies to the discovery and JWKS fetches;
  with the issuer fixed it no longer chooses whose keys are used, but it still lets whoever is
  on that path supply them.
- The posture rule exists twice (here and in `celine.sdk.posture`). A change to the rule must
  be made in both; depending on the SDK from the plugin would remove the copy.
- Loosening any of this (an issuer taken from the token, a list of issuers, a hardened default
  issuer, logging instead of refusing to start) reopens what this record closes and needs a new
  ADR that supersedes this one.
