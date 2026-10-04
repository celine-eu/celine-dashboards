# celine-jupyter

The CELINE Jupyter server: only a platform administrator's access token opens it.

- `jupyter celine-server`: Jupyter Server with `JWTIdentityProvider` and `JWTAuthorizer` built
  in; it refuses to start without `CELINE_JUPYTER_JWT_ISSUER` or when configuration replaces them.
- `celine.jupyter.serverapp.configure(c)`: the same settings for a stock server's
  `jupyter_server_config.py`, plus the startup check as a server extension.

See the repository's `docs/services.md` (Jupyter).
