"""Real-token tests: signed access tokens from a local Keycloak, verified against its JWKS.

The tokens come from the dev realm's `oauth2_proxy` client, the one whose access token
oauth2-proxy forwards to Superset. Dev users (password = username):

  admin       holds the realm role platform-admin (and org admins in example_rec)
  org-admin   example_rec admins, not a platform admin

A token that still carries a legacy realm group (`groups: ["/admins", "admins"]`) cannot
be minted from a converged realm. Mint one from a client that still maps realm groups and
pass it in `LEGACY_GROUP_TOKEN`; without it that case is skipped.

Environment (dev defaults): KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_USER_CLIENT_ID,
KEYCLOAK_USER_CLIENT_SECRET. Every test is skipped when Keycloak does not answer.
"""
import os
from unittest.mock import Mock

import pytest
import requests
from werkzeug.datastructures import Headers

from celine.superset.auth.groups import resolve_access
from celine.superset.auth.jwt import extract_jwt_claims
from celine.superset.auth.user import resolve_superset_user

pytestmark = pytest.mark.integration

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak.celine.localhost").rstrip("/")
REALM = os.getenv("KEYCLOAK_REALM", "celine")
CLIENT_ID = os.getenv("KEYCLOAK_USER_CLIENT_ID", "oauth2_proxy")
CLIENT_SECRET = os.getenv("KEYCLOAK_USER_CLIENT_SECRET", "oauth2_proxy")
TOKEN_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"


@pytest.fixture(scope="module")
def keycloak():
    try:
        requests.get(f"{KEYCLOAK_URL}/realms/{REALM}", timeout=3).raise_for_status()
    except requests.RequestException as exc:
        pytest.skip(f"local Keycloak not reachable at {KEYCLOAK_URL}: {exc}")


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


def _verified_claims(token: str) -> dict:
    claims = extract_jwt_claims(Headers({"X-Auth-Request-Access-Token": token}))
    assert claims is not None, "token did not verify against the realm's JWKS"
    return claims


def _roles_requested(claims: dict) -> list[str]:
    requested: list[str] = []

    def _find_role(name):
        requested.append(name)
        return Mock(name=name)

    sm = Mock()
    sm.auth_user_registration = True
    sm.auth_roles_sync_at_login = True
    sm.find_user.return_value = None
    sm.find_role.side_effect = _find_role
    resolve_superset_user(sm, claims)
    return requested


def test_platform_admin_holder_is_superset_admin(keycloak):
    claims = _verified_claims(_user_token("admin"))
    assert "platform-admin" in claims["realm_access"]["roles"]

    result = resolve_access(claims)

    assert result.superset_roles == ["Admin"]
    assert "Admin" in _roles_requested(claims)


def test_organisation_admins_member_is_not_superset_admin(keycloak):
    claims = _verified_claims(_user_token("org-admin"))
    assert "/admins" in claims["organization"]["example_rec"]["groups"]

    result = resolve_access(claims)

    assert result.superset_roles == []
    assert result.org_role_names == ["org:example_rec:admins"]
    assert _roles_requested(claims) == ["org:example_rec:admins"]


def test_legacy_realm_group_grants_nothing(keycloak):
    token = os.getenv("LEGACY_GROUP_TOKEN")
    if not token:
        pytest.skip("LEGACY_GROUP_TOKEN not set: no token carrying a legacy realm group")
    claims = _verified_claims(token)
    assert "/admins" in (claims.get("groups") or []), "LEGACY_GROUP_TOKEN carries no realm /admins"

    result = resolve_access(claims)

    assert "Admin" not in result.superset_roles
    assert not [name for name in result.superset_roles if name.startswith("celine:")]
    assert "Admin" not in _roles_requested(claims)
