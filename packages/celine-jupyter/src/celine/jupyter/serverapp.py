"""The CELINE Jupyter server: opened only by a platform administrator's access token, or not started.

``jupyter celine-server`` (the image's command) is Jupyter Server with
:class:`~celine.jupyter.identity.JWTIdentityProvider` and
:class:`~celine.jupyter.jwt_authorizer.JWTAuthorizer` built in, and a check after the
configuration is loaded: if anything replaced them, re-enabled unauthenticated access or the
XSRF check, or left the trusted issuer empty, the server exits instead of serving.

That check is the point. Jupyter swallows errors in its configuration files and in server
extensions, and a missing configuration file is no error at all; either way the stock server
comes up with its own random token. Fail-closed therefore cannot live in a configuration file
alone.

The same check also runs as a server extension (``celine.jupyter.serverapp``), which
:func:`configure` enables, so a stock ``jupyter lab`` / ``jupyter server`` started with the
shipped configuration file refuses to serve too. A server extension that fails is normally
only a warning; this one ends the process.
"""

from __future__ import annotations

import sys
from typing import Any

from jupyter_server.auth.authorizer import Authorizer
from jupyter_server.auth.identity import IdentityProvider
from jupyter_server.serverapp import ServerApp
from traitlets import Type, default

from celine.jupyter.identity import ISSUER_ENV, JWTIdentityProvider
from celine.jupyter.jwt_authorizer import JWTAuthorizer

EXTENSION = "celine.jupyter.serverapp"


def configure(c: Any) -> None:
    """Put the CELINE authentication into a Jupyter config object (``c = get_config()``)."""
    c.ServerApp.identity_provider_class = JWTIdentityProvider
    c.ServerApp.authorizer_class = JWTAuthorizer
    c.ServerApp.allow_unauthenticated_access = False
    c.ServerApp.disable_check_xsrf = False
    c.IdentityProvider.token = ""
    c.ServerApp.jpserver_extensions.update({EXTENSION: True})


def security_problems(app: ServerApp) -> list[str]:
    """Why ``app`` (initialised) would let in anyone but a platform administrator. Empty when sound."""
    problems = []
    identity = getattr(app, "identity_provider", None)
    if not isinstance(identity, JWTIdentityProvider):
        problems.append(f"identity provider is {type(identity).__name__}, not JWTIdentityProvider")
    else:
        if not identity.issuer:
            problems.append(f"no trusted issuer (set ${ISSUER_ENV} or JWTIdentityProvider.issuer)")
        if identity.token:
            problems.append("a server token is set")
    if not isinstance(getattr(app, "authorizer", None), JWTAuthorizer):
        problems.append(f"authorizer is {type(getattr(app, 'authorizer', None)).__name__}, not JWTAuthorizer")
    if getattr(app, "allow_unauthenticated_access", True) is not False:
        problems.append("unauthenticated access is allowed")
    if getattr(app, "disable_check_xsrf", True) is not False:
        problems.append("the XSRF check is disabled")
    return problems


def refuse_unless_sound(app: ServerApp) -> None:
    """Exit the process (``SystemExit``, which Jupyter does not swallow) unless ``app`` is sound."""
    problems = security_problems(app)
    if problems:
        message = "celine-jupyter refuses to start: " + "; ".join(problems)
        app.log.critical(message)
        raise SystemExit(message)
    if getattr(app, "_celine_authentication_announced", False):
        return  # celine-server with the shipped config checks twice; say it once
    app._celine_authentication_announced = True
    app.log.info(
        "Only platform administrators' access tokens from %s open this server",
        app.identity_provider.issuer,
    )


# --- server extension: the same check for a stock `jupyter lab` / `jupyter server` ---------


def _jupyter_server_extension_points() -> list[dict[str, str]]:
    return [{"module": EXTENSION}]


def _load_jupyter_server_extension(serverapp: ServerApp) -> None:
    refuse_unless_sound(serverapp)


# --- the server itself ------------------------------------------------------------------------


class CelineServerApp(ServerApp):
    """Jupyter Server that only a platform administrator's access token opens."""

    description = __doc__

    identity_provider_class = Type(
        default_value=JWTIdentityProvider,
        klass=IdentityProvider,
        config=True,
        help="Must stay celine.jupyter.identity.JWTIdentityProvider (or a subclass): the server refuses to start otherwise.",
    )

    authorizer_class = Type(
        default_value=JWTAuthorizer,
        klass=Authorizer,
        config=True,
        help="Must stay celine.jupyter.jwt_authorizer.JWTAuthorizer (or a subclass): the server refuses to start otherwise.",
    )

    @default("allow_unauthenticated_access")
    def _no_unauthenticated_access(self) -> bool:
        return False

    @default("default_url")
    def _default_url_lab(self) -> str:
        return "/lab"

    def init_configurables(self) -> None:
        super().init_configurables()
        refuse_unless_sound(self)


main = launch_new_instance = CelineServerApp.launch_instance

if __name__ == "__main__":
    sys.exit(main())
