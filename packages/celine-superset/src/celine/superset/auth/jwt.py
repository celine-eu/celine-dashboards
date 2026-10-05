"""Verification of the access token oauth2-proxy forwards to Superset.

One issuer is trusted: ``CUSTOM_SECURITY_MANAGER_KEYCLOAK_ISSUER``, the realm URL. A token's
``iss`` is compared with it *before* anything is fetched, and the signing keys come from the
configuration (``CUSTOM_SECURITY_MANAGER_KEYCLOAK_JWKS_URL``, else the configured issuer's own
discovery document), never from the token. A token signed by any other issuer, another realm
of the same Keycloak included, is refused without being looked at further.

Posture follows the platform rule (``celine.sdk.posture``, mirrored here because the plugin runs
in Superset's own interpreter and does not depend on the SDK): the signal is ``CELINE_ENV``,
then ``ENVIRONMENT``, and only the value ``dev`` relaxes. In dev an unset issuer defaults to the
local stack's realm (:data:`DEV_ISSUER`). Anywhere else, unset included, an unset issuer is a
configuration error: :func:`check_configuration` raises, and the security manager calls it when
Superset builds the app, so Superset does not start. Should a request reach the verifier anyway,
it is refused.
"""

import json
import logging
import os
from functools import lru_cache

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import RSAAlgorithm
from werkzeug.datastructures import Headers

logger = logging.getLogger(__name__)

ISSUER_ENV = "CUSTOM_SECURITY_MANAGER_KEYCLOAK_ISSUER"
JWKS_URL_ENV = "CUSTOM_SECURITY_MANAGER_KEYCLOAK_JWKS_URL"
# Comma-separated expected audiences. Empty = audience not checked.
AUDIENCE_ENV = "CUSTOM_SECURITY_MANAGER_KEYCLOAK_AUDIENCE"
SKIP_SSL_VERIFY_ENV = "CUSTOM_SECURITY_MANAGER_SKIP_SSL_VERIFY"

#: The posture signal, read in this order; the first non-empty value wins.
POSTURE_ENV_VARS = ("CELINE_ENV", "ENVIRONMENT")
#: The only posture value that relaxes anything.
DEV = "dev"
#: The issuer trusted in dev when none is configured: the local stack's realm.
DEV_ISSUER = "http://keycloak.celine.localhost/realms/celine"

ALGORITHMS = ["RS256"]
HTTP_TIMEOUT = 5


class InsecureConfiguration(RuntimeError):
    """Raised at startup when no trusted issuer is configured outside dev."""


def current_env() -> str:
    """The posture signal, stripped and lowercased; ``""`` when unset."""
    for name in POSTURE_ENV_VARS:
        value = os.environ.get(name)
        if value is not None and value.strip():
            return value.strip().lower()
    return ""


def is_dev() -> bool:
    """True only when the signal says exactly ``dev``. Unset is hardened."""
    return current_env() == DEV


def trusted_issuer() -> str:
    """The one issuer whose tokens are accepted; ``""`` when there is none (outside dev)."""
    issuer = os.environ.get(ISSUER_ENV, "").strip().rstrip("/")
    if issuer:
        return issuer
    return DEV_ISSUER if is_dev() else ""


def check_configuration() -> str:
    """The trusted issuer, or :class:`InsecureConfiguration` when there is none.

    Called when Superset builds its security manager, so a hardened deployment without an
    issuer fails at start instead of refusing every request.
    """
    issuer = trusted_issuer()
    if not issuer:
        env = current_env() or "<unset>"
        raise InsecureConfiguration(
            f"{ISSUER_ENV} is not set and the environment is not dev "
            f"(CELINE_ENV/ENVIRONMENT={env}). Set it to the realm URL whose tokens Superset "
            f"trusts; only CELINE_ENV=dev defaults it to {DEV_ISSUER}."
        )
    if os.environ.get(ISSUER_ENV, "").strip():
        logger.info("Trusting access tokens of %s only", issuer)
    else:
        logger.warning(
            "%s not set: trusting the dev issuer %s (CELINE_ENV=dev)",
            ISSUER_ENV,
            issuer,
        )
    return issuer


def _verify_ssl() -> bool:
    return os.environ.get(SKIP_SSL_VERIFY_ENV, "false").strip().lower() != "true"


def _audiences() -> list[str]:
    return [a.strip() for a in os.environ.get(AUDIENCE_ENV, "").split(",") if a.strip()]


@lru_cache(maxsize=8)
def get_jwks_uri(issuer: str) -> str:
    """JWKS URL of the trusted issuer: the configured one, else its discovery document's."""
    configured = os.environ.get(JWKS_URL_ENV, "").strip()
    if configured:
        return configured
    resp = requests.get(
        f"{issuer}/.well-known/openid-configuration",
        verify=_verify_ssl(),
        timeout=HTTP_TIMEOUT,
    )
    resp.raise_for_status()
    document = resp.json()
    if str(document.get("issuer", "")).rstrip("/") != issuer:
        raise jwt.InvalidIssuerError(
            f"discovery document names issuer {document.get('issuer')!r}"
        )
    return document["jwks_uri"]


@lru_cache(maxsize=32)
def get_public_key(jwks_url: str, kid: str) -> RSAPublicKey:
    """The RSA key ``kid`` of the JWKS at ``jwks_url`` (cached per key)."""
    resp = requests.get(jwks_url, verify=_verify_ssl(), timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    jwks = resp.json()

    for key_data in jwks.get("keys", []):
        if key_data.get("kid") == kid:
            public_key = RSAAlgorithm.from_jwk(json.dumps(key_data))
            if not isinstance(public_key, RSAPublicKey):
                raise TypeError("Expected RSAPublicKey from JWK")
            return public_key

    raise ValueError(f"No matching JWK for kid={kid}")


def verify_token(token: str) -> dict:
    """Verified claims of a token from the trusted issuer; ``jwt.InvalidTokenError`` otherwise."""
    issuer = trusted_issuer()
    if not issuer:
        raise jwt.InvalidIssuerError(f"no trusted issuer configured (${ISSUER_ENV})")

    # The issuer is decided on before any key is fetched.
    unverified = jwt.decode(token, options={"verify_signature": False})
    token_issuer = unverified.get("iss")
    if not isinstance(token_issuer, str) or token_issuer.rstrip("/") != issuer:
        raise jwt.InvalidIssuerError(f"untrusted issuer {token_issuer!r}")

    kid = jwt.get_unverified_header(token).get("kid")
    if not kid:
        raise jwt.InvalidTokenError("JWT header missing kid")

    public_key = get_public_key(get_jwks_uri(issuer), kid)

    audiences = _audiences()
    return jwt.decode(
        token,
        public_key,
        algorithms=ALGORITHMS,
        issuer=token_issuer,
        audience=audiences or None,
        options={"require": ["exp", "iss"], "verify_aud": bool(audiences)},
    )


def extract_jwt_claims(headers: Headers) -> dict | None:
    """Extract and verify the Keycloak access token of an incoming request."""
    auth = headers.get("Authorization", "")
    token = (
        headers.get("X-Auth-Request-Access-Token")
        or headers.get("X-Forwarded-Access-Token")
        or (
            auth.split(" ", 1)[1].strip()
            if auth.lower().startswith("bearer ")
            else None
        )
    )

    if not token:
        return None

    try:
        return verify_token(token)

    except jwt.ExpiredSignatureError:
        logger.info("JWT expired — user must re-authenticate")
        return None

    except jwt.InvalidTokenError as e:
        logger.warning("Invalid JWT: %s", e)
        return None
