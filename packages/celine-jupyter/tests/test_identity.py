"""JWTIdentityProvider: who is calling — a platform administrator's verified access token, or nobody."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import jwt
import pytest
from conftest import LEGACY_REALM_ADMIN, ORG_ADMIN, ORG_VIEWER, PLATFORM_ADMIN

from celine.jupyter.identity import JWTIdentityProvider, request_token


def handler(headers: dict[str, str] | None = None) -> SimpleNamespace:
    return SimpleNamespace(request=SimpleNamespace(headers=headers or {}))


@pytest.fixture
def provider(issuer, monkeypatch) -> JWTIdentityProvider:
    monkeypatch.delenv("JUPYTER_TOKEN", raising=False)
    return JWTIdentityProvider(issuer=issuer.issuer)


class TestRequestToken:
    def test_forwarded_access_token_first(self):
        h = handler({"X-Forwarded-Access-Token": "fwd", "Authorization": "Bearer bear"})
        assert request_token(h) == "fwd"

    def test_bearer(self):
        assert request_token(handler({"Authorization": "Bearer bear"})) == "bear"
        assert request_token(handler({"Authorization": "bearer  bear "})) == "bear"

    @pytest.mark.parametrize("value", ["token abc", "Basic YTpi", "Bearer", "Bearer   ", "abc", ""])
    def test_no_other_scheme_is_a_token(self, value):
        # `Authorization: token <x>` is Jupyter's own server token: not a token here.
        assert request_token(handler({"Authorization": value})) is None

    def test_none(self):
        assert request_token(handler()) is None


class TestVerify:
    def test_valid_token_of_the_issuer(self, provider, issuer):
        claims = provider.verify(issuer.sign(PLATFORM_ADMIN))
        assert claims["realm_access"] == {"roles": ["platform-admin"]}

    def test_trailing_slash_of_the_configured_issuer_is_ignored(self, issuer):
        p = JWTIdentityProvider(issuer=issuer.issuer + "/")
        assert p.verify(issuer.sign(PLATFORM_ADMIN))["preferred_username"] == "admin"

    def test_no_issuer_configured_trusts_nothing(self, issuer, monkeypatch):
        monkeypatch.delenv("CELINE_JUPYTER_JWT_ISSUER", raising=False)
        p = JWTIdentityProvider()
        assert p.issuer == ""
        with pytest.raises(jwt.InvalidIssuerError, match="no trusted issuer"):
            p.verify(issuer.sign(PLATFORM_ADMIN))

    def test_issuer_from_environment(self, issuer, monkeypatch):
        monkeypatch.setenv("CELINE_JUPYTER_JWT_ISSUER", f"  {issuer.issuer}  ")
        assert JWTIdentityProvider().issuer == issuer.issuer

    @pytest.mark.parametrize("foreign", [
        "https://evil.example.org/realms/celine",
        "http://127.0.0.1:1/realms/example",
        "",
    ])
    def test_foreign_issuer_refused_before_any_fetch(self, provider, issuer, other_key, foreign):
        token = issuer.sign(PLATFORM_ADMIN, iss=foreign, key=other_key)
        with patch("celine.jupyter.identity.requests.get") as get, \
             patch("celine.jupyter.identity.PyJWKClient") as jwk_client:
            with pytest.raises(jwt.InvalidIssuerError, match="untrusted issuer"):
                provider.verify(token)
        get.assert_not_called()
        jwk_client.assert_not_called()

    def test_another_realm_of_the_same_host_is_foreign(self, provider, issuer, other_key):
        sibling = issuer.issuer.rsplit("/", 1)[0] + "/other-realm"
        with pytest.raises(jwt.InvalidIssuerError):
            provider.verify(issuer.sign(PLATFORM_ADMIN, iss=sibling, key=other_key))

    def test_right_issuer_wrong_key_refused(self, provider, issuer, other_key):
        with pytest.raises(jwt.InvalidSignatureError):
            provider.verify(issuer.sign(PLATFORM_ADMIN, key=other_key))

    def test_unknown_kid_refused(self, provider, issuer, other_key):
        with pytest.raises(jwt.PyJWKClientError):
            provider.verify(issuer.sign(PLATFORM_ADMIN, key=other_key, kid="unknown"))

    def test_expired_refused(self, provider, issuer):
        with pytest.raises(jwt.ExpiredSignatureError):
            provider.verify(issuer.sign(PLATFORM_ADMIN, lifetime=-60))

    def test_missing_exp_refused(self, provider, issuer):
        token = jwt.encode({**PLATFORM_ADMIN, "iss": issuer.issuer}, issuer.key, algorithm="RS256",
                           headers={"kid": "test-key"})
        with pytest.raises(jwt.MissingRequiredClaimError):
            provider.verify(token)

    def test_symmetric_token_refused(self, provider, issuer):
        token = jwt.encode({**PLATFORM_ADMIN, "iss": issuer.issuer, "exp": 4102444800}, "secret" * 8,
                           algorithm="HS256", headers={"kid": "test-key"})
        with pytest.raises(jwt.PyJWTError):
            provider.verify(token)

    def test_unsigned_token_refused(self, provider, issuer):
        token = jwt.encode({**PLATFORM_ADMIN, "iss": issuer.issuer, "exp": 4102444800}, None, algorithm="none")
        with pytest.raises(jwt.PyJWTError):
            provider.verify(token)

    def test_garbage_refused(self, provider):
        with pytest.raises(jwt.DecodeError):
            provider.verify("not-a-jwt")

    def test_audience_checked_when_configured(self, issuer):
        p = JWTIdentityProvider(issuer=issuer.issuer, audience="svc-jupyter")
        assert p.verify(issuer.sign(PLATFORM_ADMIN, aud=["svc-jupyter", "svc-x"]))
        with pytest.raises(jwt.InvalidAudienceError):
            p.verify(issuer.sign(PLATFORM_ADMIN, aud=["svc-x"]))
        with pytest.raises(jwt.MissingRequiredClaimError):
            p.verify(issuer.sign(PLATFORM_ADMIN))

    def test_discovery_naming_another_issuer_refused(self, issuer):
        p = JWTIdentityProvider(issuer=issuer.issuer)
        with patch("celine.jupyter.identity.requests.get") as get:
            get.return_value.json.return_value = {"issuer": "https://evil.example.org", "jwks_uri": "https://evil.example.org/k"}
            with pytest.raises(jwt.InvalidIssuerError, match="discovery document"):
                p.verify(issuer.sign(PLATFORM_ADMIN))

    def test_discovery_once_then_cached(self, issuer):
        p = JWTIdentityProvider(issuer=issuer.issuer)
        before = [r for r in issuer.requests if r.endswith("openid-configuration")]
        for _ in range(3):
            p.verify(issuer.sign(PLATFORM_ADMIN))
        after = [r for r in issuer.requests if r.endswith("openid-configuration")]
        assert len(after) - len(before) == 1

    def test_configured_jwks_url_skips_discovery(self, issuer):
        p = JWTIdentityProvider(issuer=issuer.issuer, jwks_url=issuer.issuer + "/protocol/openid-connect/certs")
        with patch("celine.jupyter.identity.requests.get") as get:
            assert p.verify(issuer.sign(PLATFORM_ADMIN))
        get.assert_not_called()


class TestIdentity:
    def test_platform_admin_is_a_user(self, provider, issuer):
        user = provider.get_user(handler({"X-Forwarded-Access-Token": issuer.sign(PLATFORM_ADMIN)}))
        assert user is not None and user.username == "admin"

    def test_platform_admin_bearer_is_a_user(self, provider, issuer):
        user = provider.get_user(handler({"Authorization": "Bearer " + issuer.sign(PLATFORM_ADMIN)}))
        assert user is not None and user.username == "admin"

    @pytest.mark.parametrize("claims", [ORG_ADMIN, ORG_VIEWER, LEGACY_REALM_ADMIN], ids=["org-admin", "org-viewer", "legacy"])
    def test_everyone_else_is_nobody(self, provider, issuer, claims):
        assert provider.get_user(handler({"X-Forwarded-Access-Token": issuer.sign(claims)})) is None
        assert provider.get_user(handler({"Authorization": "Bearer " + issuer.sign(claims)})) is None

    def test_no_token_is_nobody(self, provider):
        assert provider.get_user(handler()) is None

    def test_invalid_token_is_nobody_not_an_error(self, provider, issuer, other_key):
        assert provider.get_user(handler({"Authorization": "Bearer " + issuer.sign(PLATFORM_ADMIN, key=other_key)})) is None
        assert provider.get_user(handler({"Authorization": "Bearer garbage"})) is None

    def test_token_verified_once_per_request(self, provider, issuer):
        h = handler({"X-Forwarded-Access-Token": issuer.sign(PLATFORM_ADMIN)})
        with patch.object(provider, "verify", wraps=provider.verify) as verify:
            provider.get_user(h)
            provider.platform_admin_claims(h)
            provider.is_token_authenticated(h)
        assert verify.call_count == 1

    def test_bearer_is_token_authenticated_forwarded_is_not(self, provider, issuer):
        token = issuer.sign(PLATFORM_ADMIN)
        # A caller's own bearer token: Jupyter skips XSRF as for its own token.
        assert provider.is_token_authenticated(handler({"Authorization": "Bearer " + token})) is True
        # The proxy's forwarded token stands for a browser session: XSRF stays on.
        assert provider.is_token_authenticated(handler({"X-Forwarded-Access-Token": token})) is False
        assert provider.is_token_authenticated(handler({"Authorization": "Bearer " + issuer.sign(ORG_ADMIN)})) is False
        assert provider.is_token_authenticated(handler()) is False


class TestNoServerToken:
    def test_no_token_generated(self, provider):
        assert provider.token == ""
        assert provider.token_generated is False

    def test_jupyter_token_environment_ignored(self, issuer, monkeypatch):
        monkeypatch.setenv("JUPYTER_TOKEN", "leaked")
        assert JWTIdentityProvider(issuer=issuer.issuer).token == ""

    def test_configured_token_ignored(self, issuer):
        p = JWTIdentityProvider(issuer=issuer.issuer, token="configured")
        assert p.token == ""
        p.token = "later"
        assert p.token == ""

    def test_server_token_is_not_a_user(self, issuer, monkeypatch):
        monkeypatch.setenv("JUPYTER_TOKEN", "leaked")
        p = JWTIdentityProvider(issuer=issuer.issuer)
        for headers in ({"Authorization": "token leaked"}, {"Authorization": "Bearer leaked"},
                        {"X-Forwarded-Access-Token": "leaked"}):
            assert p.get_user(handler(headers)) is None

    def test_auth_always_on_no_login(self, provider):
        assert provider.auth_enabled is True
        assert provider.login_available is False
        assert provider.logout_available is False
        assert [pattern for pattern, _ in provider.get_handlers()] == [r"/login"]
