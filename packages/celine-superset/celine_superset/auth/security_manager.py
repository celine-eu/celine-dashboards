import requests
import json
import logging
import jwt
import os
from functools import lru_cache
from werkzeug.datastructures.headers import Headers
from superset.security import SupersetSecurityManager
from flask_login import current_user, login_user
from flask import current_app, g, request
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from celine_superset.auth.roles import GROUP_TO_SUPERSET_ROLE, DEFAULT_ROLE
from celine_superset.auth.views import (
    OAuth2ProxyAuthRemoteUserView,
)


# Set up detailed logging
logging.basicConfig(level=os.getenv("CUSTOM_SECURITY_MANAGER_LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

JWKS_URL = os.getenv("CUSTOM_SECURITY_MANAGER_KEYCLOAK_JWKS_URL", None)

JWT_AUDIENCE = os.getenv(
    "CUSTOM_SECURITY_MANAGER_KEYCLOAK_AUDIENCE", "oauth2_proxy,celine-cli"
)

SSO_BASE_URL = os.getenv("CUSTOM_SECURITY_MANAGER_SSO_BASE_URL", "")
VERIFY_SSL = (
    os.getenv("CUSTOM_SECURITY_MANAGER_SKIP_SSL_VERIFY", "false").lower() != "true"
)


@lru_cache(maxsize=1)
def _extract_audience():
    audiences = JWT_AUDIENCE.split(",")
    for i, aud in enumerate(audiences):
        audiences[i] = aud.strip(" ")
    return audiences


@lru_cache(maxsize=1)
def get_jwks_uri_from_jwt(token):
    if JWKS_URL:
        return JWKS_URL
    # Decode the JWT headers (not the payload, don't verify yet)
    unverified_claims = jwt.decode(token, options={"verify_signature": False})
    issuer = unverified_claims["iss"]
    well_known_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    resp = requests.get(well_known_url, verify=VERIFY_SSL)
    resp.raise_for_status()
    jwks_uri = resp.json()["jwks_uri"]
    return jwks_uri


@lru_cache(maxsize=1)
def get_public_key(jwks_url: str, token: str) -> RSAPublicKey:
    resp = requests.get(jwks_url, verify=VERIFY_SSL)
    resp.raise_for_status()
    jwks = resp.json()

    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")

    if not kid:
        raise ValueError("JWT header missing kid")

    for key_data in jwks.get("keys", []):
        if key_data.get("kid") == kid:
            public_key = RSAAlgorithm.from_jwk(json.dumps(key_data))
            if not isinstance(public_key, RSAPublicKey):
                raise TypeError("Expected RSAPublicKey from JWK")
            return public_key

    raise ValueError(f"No matching JWK found for kid={kid}")


def extract_jwt_claims_from_request(headers: Headers) -> dict | None:
    token = (
        headers.get("X-Auth-Request-Access-Token")
        or headers.get("X-Forwarded-Access-Token")
        or (
            headers.get("Authorization", "").split(" ", 1)[1].strip()
            if headers.get("Authorization", "").lower().startswith("bearer ")
            else None
        )
    )

    if not token:
        return None

    try:
        jwks_url = get_jwks_uri_from_jwt(token)
        public_key = get_public_key(jwks_url, token)
        audiences = _extract_audience()

        return jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=audiences,
        )

    except jwt.ExpiredSignatureError:
        logger.info("JWT expired — user must re-authenticate")
        return None

    except jwt.InvalidTokenError as e:
        logger.warning("Invalid JWT: %s", e)
        return None


def resolve_superset_user(sm: SupersetSecurityManager, claims: dict):
    username = claims.get("preferred_username") or claims.get("email")
    if not username:
        return None

    user = sm.find_user(username=username)

    # --- roles ---
    mapped_roles = set()
    groups = claims.get("groups", [])
    if isinstance(groups, str):
        groups = [groups]

    for group in groups:
        group_name = group.strip("/").split("/")[0]
        role_name = GROUP_TO_SUPERSET_ROLE.get(group_name)
        if role_name:
            role = sm.find_role(role_name)
            if role:
                mapped_roles.add(role)

    if not mapped_roles:
        default_role = sm.find_role(DEFAULT_ROLE)
        if default_role:
            mapped_roles.add(default_role)

    roles = list(mapped_roles)

    if user:
        if sm.auth_roles_sync_at_login:
            user.roles = roles
            sm.update_user(user)

        sm.update_user_auth_stat(user)
        return user

    if not sm.auth_user_registration:
        return None

    user = sm.add_user(
        username=username,
        first_name=claims.get("given_name", "User"),
        last_name=claims.get("family_name", "Name"),
        email=claims.get("email", f"{username}@local"),
        role=roles,
    )

    if user:
        sm.update_user_auth_stat(user)

    return user


class OAuth2ProxySecurityManager(SupersetSecurityManager):

    authremoteuserview = OAuth2ProxyAuthRemoteUserView

    @staticmethod
    def before_request():
        """
        Handle JWT based authentication
        """

        # public paths
        if request.path.startswith(("/health", "/static", "/favicon.ico")):
            g.user = current_user
            return

        sm: SupersetSecurityManager = current_app.appbuilder.sm  # type: ignore

        # already authenticated
        if not current_user.is_anonymous:
            g.user = current_user
            return

        try:
            claims = extract_jwt_claims_from_request(request.headers)
            if not claims:
                # leave anonymous — Superset will redirect later
                g.user = current_user
                return

            user = resolve_superset_user(sm, claims)
            if not user:
                g.user = current_user
                return

            # bind session
            login_user(user, remember=False)
            g.user = user

            # expose identity for downstream code
            request.environ["REMOTE_USER"] = user.username
            request.environ["JWT_CLAIMS"] = json.dumps(claims)

            logger.debug("Authenticated user=%s", user.username)

        except Exception:
            logger.exception("Authentication error")
            g.user = current_user
