"""JWTAuthorizer: everything for a platform administrator, nothing for anyone else."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from conftest import LEGACY_REALM_ADMIN, ORG_ADMIN, ORG_VIEWER, PLATFORM_ADMIN
from jupyter_server.auth.identity import IdentityProvider, User

from celine.jupyter.identity import JWTIdentityProvider
from celine.jupyter.jwt_authorizer import JWTAuthorizer

USER = User(username="someone")
ACTIONS = [("read", "contents"), ("write", "contents"), ("execute", "kernels"), ("execute", "terminals")]


def handler(headers: dict[str, str] | None = None) -> SimpleNamespace:
    return SimpleNamespace(request=SimpleNamespace(headers=headers or {}))


@pytest.fixture
def identity(issuer) -> JWTIdentityProvider:
    return JWTIdentityProvider(issuer=issuer.issuer)


@pytest.fixture
def authorizer(identity) -> JWTAuthorizer:
    return JWTAuthorizer(identity_provider=identity)


def authorized(authorizer, token: str, action: str = "read", resource: str = "contents") -> bool:
    return authorizer.is_authorized(handler({"X-Forwarded-Access-Token": token}), USER, action, resource)


class TestPlatformAdminOnly:
    @pytest.mark.parametrize("action,resource", ACTIONS)
    def test_platform_admin_role_grants_everything(self, authorizer, issuer, action, resource):
        assert authorized(authorizer, issuer.sign(PLATFORM_ADMIN), action, resource) is True

    @pytest.mark.parametrize("claims", [ORG_ADMIN, ORG_VIEWER, LEGACY_REALM_ADMIN], ids=["org-admin", "org-viewer", "legacy"])
    @pytest.mark.parametrize("action,resource", ACTIONS)
    def test_nobody_else(self, authorizer, issuer, claims, action, resource):
        assert authorized(authorizer, issuer.sign(claims), action, resource) is False

    @pytest.mark.parametrize("claims", [
        {"groups": ["/admins"]},
        {"groups": ["platform-admin"]},
        {"roles": ["platform-admin"]},
        {"resource_access": {"oauth2_proxy": {"roles": ["platform-admin"]}}},
        {"organization": {"example_rec": {"groups": ["/platform-admin"]}}},
        {"realm_access": {"roles": ["admin", "manager"]}},
        {"realm_access": {"roles": "platform-admin"}},
        {"realm_access": ["platform-admin"]},
        {},
    ])
    def test_platform_admin_only_from_realm_access_roles(self, authorizer, issuer, claims):
        assert authorized(authorizer, issuer.sign(claims)) is False

    def test_platform_admin_with_a_legacy_group_is_still_admin(self, authorizer, issuer):
        claims = {**LEGACY_REALM_ADMIN, "realm_access": {"roles": ["platform-admin"]}}
        assert authorized(authorizer, issuer.sign(claims)) is True

    def test_bearer_header(self, authorizer, issuer):
        h = handler({"Authorization": "Bearer " + issuer.sign(PLATFORM_ADMIN)})
        assert authorizer.is_authorized(h, USER, "read", "contents") is True

    def test_no_token_denied(self, authorizer):
        assert authorizer.is_authorized(handler(), USER, "read", "contents") is False

    def test_platform_admin_of_another_issuer_denied(self, authorizer, issuer, other_key):
        token = issuer.sign(PLATFORM_ADMIN, iss="https://evil.example.org/realms/celine", key=other_key)
        assert authorized(authorizer, token) is False

    def test_no_user_denied_even_with_a_platform_admin_token(self, authorizer, issuer):
        h = handler({"X-Forwarded-Access-Token": issuer.sign(PLATFORM_ADMIN)})
        assert authorizer.is_authorized(h, None, "read", "contents") is False


class TestNeedsTheIdentityProvider:
    def test_stock_identity_provider_refuses_everything(self, issuer):
        authorizer = JWTAuthorizer(identity_provider=IdentityProvider())
        authorizer.log = MagicMock()
        assert authorized(authorizer, issuer.sign(PLATFORM_ADMIN)) is False
        authorizer.log.error.assert_called_once()

    def test_decision_comes_from_the_identity_provider(self, authorizer, identity):
        h = handler({"X-Forwarded-Access-Token": "tok"})
        with patch.object(identity, "platform_admin_claims", return_value=None) as claims:
            assert authorizer.is_authorized(h, USER, "read", "contents") is False
        claims.assert_called_once_with(h)
        with patch.object(identity, "platform_admin_claims", return_value={"realm_access": {"roles": ["platform-admin"]}}):
            assert authorizer.is_authorized(h, USER, "read", "contents") is True
