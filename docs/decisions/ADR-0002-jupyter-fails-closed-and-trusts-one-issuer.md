# ADR-0002 — Jupyter fails closed: its own server command, one trusted issuer, no server token

**Date:** 2026-10-04
**Status:** accepted

## Context

The Jupyter image put its configuration at `~/.jupyter/jupyterhub_config.py`, a file that
`jupyter lab` never reads. The JWT authorizer was therefore never loaded: the server ran with
Jupyter's own token (random and printed in the log, or `JUPYTER_TOKEN`), which opened
everything, terminals included, to whoever held it. Nothing failed, so nothing showed it.

Renaming the file is not enough on its own. Jupyter logs an error raised in a configuration
file and starts anyway with its own token; a server extension that fails to load is a
warning; a missing configuration file is no error at all. Each of these turns "the
authorizer could not be loaded" back into "the server token opens the server".

The authorizer also took the issuer from the unverified token and fetched that issuer's keys,
so a validly signed token from any other issuer (another realm of the same Keycloak
included) was accepted.

## Decision

- The image runs `jupyter celine-server` (`celine.jupyter.serverapp`): Jupyter Server whose
  identity provider and authorizer are the CELINE ones by default, and which exits instead of
  serving if either was replaced, if unauthenticated access or the XSRF check was switched
  back on, or if no trusted issuer is configured.
- The shipped `jupyter_server_config.py` installs the same settings and enables the same check
  as a server extension, and raises `SystemExit` (the one thing Jupyter does not swallow) when
  `celine.jupyter` cannot be imported, so a stock `jupyter lab` given that file fails closed too.
- Authentication is an identity provider, not only an authorizer: a request without a
  platform administrator's token has no user. There is no server token (any configured one is
  dropped), no password and no login page.
- One issuer is trusted, `CELINE_JUPYTER_JWT_ISSUER`. A token's `iss` is compared with it
  before any key is fetched.

## Consequences

- A deployment must set `CELINE_JUPYTER_JWT_ISSUER`, or the container exits at start.
- The image cannot be opened for local debugging with a token or password; that needs a
  platform administrator's access token from the configured issuer.
- A stock `jupyter lab` started **without** the shipped configuration file is not protected by
  anything here; only `jupyter celine-server` carries the protection without a file.
- Upgrades of jupyter-server must keep `ServerApp.identity_provider_class`,
  `authorizer_class` and `allow_unauthenticated_access`; the startup tests fail when they change.
- Loosening any of this "for convenience" (a token, a fallback issuer, logging instead of
  exiting) reopens the hole this record closes and needs a new ADR that supersedes this one.
