"""Who is calling the Jupyter server: a platform administrator's verified access token, or nobody.

There is no other way in. No server token (the random ``?token=`` Jupyter prints at start),
no password, no login form and no login cookie: every request is identified again from the
access token it carries, and a request without a valid one has no user at all, so Jupyter
refuses it (403) before any handler runs.

The token is trusted only from the one configured issuer. Its ``iss`` is compared with that
issuer *before* anything is fetched, so a token signed by any other issuer, even another
realm of the same Keycloak, is refused without being looked at further.
"""

from __future__ import annotations

import os
from typing import Any

import jwt
import requests
from celine.sdk.auth import is_platform_admin
from jupyter_server.auth.decorator import allow_unauthenticated
from jupyter_server.auth.identity import IdentityProvider, User
from jupyter_server.base.handlers import JupyterHandler
from jwt import PyJWKClient
from tornado import web
from traitlets import Unicode, default, validate

ISSUER_ENV = "CELINE_JUPYTER_JWT_ISSUER"
JWKS_URL_ENV = "CELINE_JUPYTER_JWKS_URL"
AUDIENCE_ENV = "CELINE_JUPYTER_JWT_AUDIENCE"

ALGORITHMS = ["RS256"]
DISCOVERY_TIMEOUT = 5

# Per-request cache, so the identity provider and the authorizer verify a token once.
_CLAIMS_ATTR = "_celine_platform_admin_claims"


def request_token(handler: web.RequestHandler) -> str | None:
    """The access token a request carries, or None.

    ``X-Forwarded-Access-Token`` (oauth2-proxy) first, then ``Authorization: Bearer``.
    Any other ``Authorization`` scheme, including Jupyter's own ``token``, is not a token here.
    """
    headers = handler.request.headers
    forwarded = (headers.get("X-Forwarded-Access-Token") or "").strip()
    if forwarded:
        return forwarded
    scheme, _, value = (headers.get("Authorization") or "").strip().partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    return None


class NoLoginHandler(JupyterHandler):
    """``/login`` answers 403: there is nothing to log in with."""

    @allow_unauthenticated
    def get(self) -> None:
        raise web.HTTPError(403)

    @allow_unauthenticated
    def post(self) -> None:
        raise web.HTTPError(403)


class JWTIdentityProvider(IdentityProvider):
    """A user exists only for a request carrying a platform administrator's access token."""

    issuer = Unicode(
        config=True,
        help=f"""The one issuer whose access tokens are trusted (the realm URL, e.g.
        https://keycloak.example.org/realms/celine). Required: without it nobody gets in and
        the CELINE server refuses to start. Default: ${ISSUER_ENV}.""",
    )

    jwks_url = Unicode(
        config=True,
        help=f"""JWKS URL of the issuer, when the issuer's own discovery document is not
        reachable from the server. Default: ${JWKS_URL_ENV}, else discovered from `issuer`.""",
    )

    audience = Unicode(
        config=True,
        help=f"""When set, the token's `aud` must contain it. Default: ${AUDIENCE_ENV}.""",
    )

    @default("issuer")
    def _issuer_default(self) -> str:
        return os.environ.get(ISSUER_ENV, "").strip()

    @default("jwks_url")
    def _jwks_url_default(self) -> str:
        return os.environ.get(JWKS_URL_ENV, "").strip()

    @default("audience")
    def _audience_default(self) -> str:
        return os.environ.get(AUDIENCE_ENV, "").strip()

    # --- no server token -------------------------------------------------------------
    # The base class generates a random token (or takes $JUPYTER_TOKEN) that opens the
    # whole server. Here the token is always empty, whatever is configured.

    @default("token")
    def _token_default(self) -> str:
        self.token_generated = False
        return ""

    @validate("token")
    def _never_a_token(self, proposal: Any) -> str:
        if proposal["value"]:
            self.log.warning("A Jupyter server token is configured and ignored: only access tokens open this server")
        return ""

    @property
    def auth_enabled(self) -> bool:
        return True

    @property
    def login_available(self) -> bool:
        return False

    @property
    def logout_available(self) -> bool:
        return False

    def get_handlers(self) -> list[tuple[str, object]]:
        return [(r"/login", NoLoginHandler)]

    def is_token_authenticated(self, handler: web.RequestHandler) -> bool:
        """True for a platform administrator's token sent by the caller itself (``Authorization``).

        Jupyter skips its XSRF and origin checks for such requests, as it does for its own
        token. A token forwarded by the proxy (``X-Forwarded-Access-Token``) stands for a
        browser session cookie, so those requests keep both checks.
        """
        if (handler.request.headers.get("X-Forwarded-Access-Token") or "").strip():
            return False
        return self.platform_admin_claims(handler) is not None

    # --- identity ----------------------------------------------------------------------

    def get_user(self, handler: web.RequestHandler) -> User | None:
        claims = self.platform_admin_claims(handler)
        if claims is None:
            return None
        username = str(claims.get("preferred_username") or claims.get("sub") or "platform-admin")
        return User(username=username, name=str(claims.get("name") or username))

    def platform_admin_claims(self, handler: web.RequestHandler) -> dict[str, Any] | None:
        """The verified claims of the request's token if it is a platform administrator's, else None."""
        if _CLAIMS_ATTR in getattr(handler, "__dict__", {}):
            return handler.__dict__[_CLAIMS_ATTR]
        claims = self._platform_admin_claims(handler)
        try:
            setattr(handler, _CLAIMS_ATTR, claims)
        except AttributeError:
            pass
        return claims

    def _platform_admin_claims(self, handler: web.RequestHandler) -> dict[str, Any] | None:
        token = request_token(handler)
        if not token:
            return None
        try:
            claims = self.verify(token)
        except Exception as exc:  # any failure to verify is a refusal, never an error page
            self.log.warning("Access token refused: %s", exc)
            return None
        if not is_platform_admin(claims):
            return None
        return claims

    # --- verification ------------------------------------------------------------------

    _jwk_client: PyJWKClient | None = None

    def verify(self, token: str) -> dict[str, Any]:
        """Verified claims of a token from the configured issuer; raises otherwise."""
        issuer = self.issuer.rstrip("/")
        if not issuer:
            raise jwt.InvalidIssuerError(f"no trusted issuer configured (${ISSUER_ENV})")
        unverified = jwt.decode(token, options={"verify_signature": False})
        token_issuer = unverified.get("iss")
        if not isinstance(token_issuer, str) or token_issuer.rstrip("/") != issuer:
            raise jwt.InvalidIssuerError(f"untrusted issuer {token_issuer!r}")
        key = self._jwks().get_signing_key_from_jwt(token).key
        return jwt.decode(
            token,
            key,
            algorithms=ALGORITHMS,
            issuer=token_issuer,
            audience=self.audience or None,
            options={"require": ["exp", "iss"], "verify_aud": bool(self.audience)},
        )

    def _jwks(self) -> PyJWKClient:
        if self._jwk_client is None:
            url = self.jwks_url or self._discover_jwks_url()
            self.log.info("Verifying access tokens of %s against %s", self.issuer, url)
            self._jwk_client = PyJWKClient(url)
        return self._jwk_client

    def _discover_jwks_url(self) -> str:
        issuer = self.issuer.rstrip("/")
        resp = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=DISCOVERY_TIMEOUT)
        resp.raise_for_status()
        document = resp.json()
        if str(document.get("issuer", "")).rstrip("/") != issuer:
            raise jwt.InvalidIssuerError(f"discovery document names issuer {document.get('issuer')!r}")
        return document["jwks_uri"]
