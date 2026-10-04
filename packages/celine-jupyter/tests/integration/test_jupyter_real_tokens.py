"""Real-token tests: signed access tokens from a local Keycloak, verified by the identity provider
itself (pinned issuer, OIDC discovery + JWKS), decided by the authorizer.

Dev users (password = username) on the dev realm's `oauth2_proxy` client:

  admin       holds the realm role platform-admin
  org-admin   example_rec admins, not a platform admin
  org-viewer  example_rec viewers

A token that still carries a legacy realm group (`groups: ["/admins", ...]`) cannot be
minted from a converged realm. Mint one from a client that still maps realm groups and
pass it in `LEGACY_GROUP_TOKEN`; without it that case is skipped.

Environment (dev defaults): KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_USER_CLIENT_ID,
KEYCLOAK_USER_CLIENT_SECRET. Every test is skipped when Keycloak does not answer.
"""

import os
from types import SimpleNamespace

import pytest
import requests
from jupyter_server.auth.identity import User

from celine.jupyter.identity import JWTIdentityProvider
from celine.jupyter.jwt_authorizer import JWTAuthorizer

pytestmark = pytest.mark.integration

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak.celine.localhost").rstrip("/")
REALM = os.getenv("KEYCLOAK_REALM", "celine")
CLIENT_ID = os.getenv("KEYCLOAK_USER_CLIENT_ID", "oauth2_proxy")
CLIENT_SECRET = os.getenv("KEYCLOAK_USER_CLIENT_SECRET", "oauth2_proxy")
ISSUER = f"{KEYCLOAK_URL}/realms/{REALM}"
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"


@pytest.fixture(scope="module")
def keycloak():
    try:
        requests.get(ISSUER, timeout=3).raise_for_status()
    except requests.RequestException as exc:
        pytest.skip(f"local Keycloak not reachable at {KEYCLOAK_URL}: {exc}")


@pytest.fixture
def identity() -> JWTIdentityProvider:
    return JWTIdentityProvider(issuer=ISSUER)


@pytest.fixture
def authorizer(identity) -> JWTAuthorizer:
    return JWTAuthorizer(identity_provider=identity)


def _user_token(username: str) -> str:
    resp = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "username": username,
            "password": username,
            "scope": "openid email profile organization:*",
        },
        timeout=10,
    )
    if resp.status_code != 200:
        pytest.skip(f"cannot mint a token for {username!r}: HTTP {resp.status_code} {resp.text[:200]}")
    return resp.json()["access_token"]


def _authorized(identity, authorizer, token: str) -> bool:
    handler = SimpleNamespace(request=SimpleNamespace(headers={"X-Forwarded-Access-Token": token}))
    if identity.get_user(handler) is None:  # Jupyter answers 403 before any authorizer call
        return False
    # The authorizer must agree on its own, even for a user Jupyter would let through.
    return authorizer.is_authorized(handler, User(username="someone"), "execute", "terminals")


def test_platform_admin_holder_is_authorized(keycloak, identity, authorizer):
    token = _user_token("admin")
    assert "platform-admin" in identity.verify(token)["realm_access"]["roles"]
    assert _authorized(identity, authorizer, token) is True


@pytest.mark.parametrize("username,group", [("org-admin", "/admins"), ("org-viewer", "/viewers")])
def test_organisation_member_is_not_authorized(keycloak, identity, authorizer, username, group):
    token = _user_token(username)
    claims = identity.verify(token)  # verifies: denied on the claims, not on verification
    assert group in claims["organization"]["example_rec"]["groups"]
    assert "platform-admin" not in claims.get("realm_access", {}).get("roles", [])
    assert _authorized(identity, authorizer, token) is False


def test_legacy_realm_group_grants_nothing(keycloak, identity, authorizer):
    token = os.getenv("LEGACY_GROUP_TOKEN")
    if not token:
        pytest.skip("LEGACY_GROUP_TOKEN not set: no token carrying a legacy realm group")
    claims = identity.verify(token)
    assert "/admins" in (claims.get("groups") or []), "LEGACY_GROUP_TOKEN carries no realm /admins"
    assert _authorized(identity, authorizer, token) is False


def test_another_issuer_is_refused(keycloak):
    other = JWTIdentityProvider(issuer=f"{KEYCLOAK_URL}/realms/another-realm")
    with pytest.raises(Exception, match="untrusted issuer"):
        other.verify(_user_token("admin"))
