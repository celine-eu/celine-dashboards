# Jupyter Server configuration of the CELINE Jupyter image (~/.jupyter/jupyter_server_config.py).
#
# The image runs `jupyter celine-server` (celine.jupyter.serverapp), which has the CELINE
# authentication built in and refuses to start without it; this file only repeats it, so that
# a stock `jupyter lab` / `jupyter server` given this file is closed the same way.
#
# Access: a platform administrator's access token (realm role platform-admin) from the issuer
# in $CELINE_JUPYTER_JWT_ISSUER, sent as X-Forwarded-Access-Token (oauth2-proxy) or
# Authorization: Bearer. Nothing else: no server token, no password, no login form.

c = get_config()  # type: ignore  # noqa: F821

try:
    from celine.jupyter.serverapp import configure
except BaseException as exc:  # noqa: BLE001
    # Jupyter logs an error in a configuration file and starts anyway, with its own random
    # token. SystemExit is the one thing it does not swallow: no CELINE authentication, no server.
    raise SystemExit(f"celine-jupyter: cannot load the CELINE authentication ({exc!r}); not starting")

configure(c)

c.ServerApp.trust_xheaders = True
c.ServerApp.root_dir = "/home/jovyan/notebooks"
