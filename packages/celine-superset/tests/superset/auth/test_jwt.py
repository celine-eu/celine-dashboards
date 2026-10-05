"""Access-token verification (ADR-0003): one configured issuer, keys from configuration, fail closed.

Tokens here are really signed (RSA keys made per test session); only HTTP is faked, and every
fetch is recorded, so a test can also say that a refused token caused no fetch at all.
"""

import json
import time

import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from werkzeug.datastructures import Headers

import celine.superset.auth.jwt as jwt_mod

TRUSTED = "https://kc.example.org/realms/celine"
OTHER = "https://kc.example.org/realms/other"  # another realm of the same Keycloak
DEV_ISSUER = "http://keycloak.celine.localhost/realms/celine"
TRUSTED_JWKS = f"{TRUSTED}/protocol/openid-connect/certs"
OTHER_JWKS = f"{OTHER}/protocol/openid-connect/certs"
DEV_JWKS = f"{DEV_ISSUER}/protocol/openid-connect/certs"

ISSUER_ENV = "CUSTOM_SECURITY_MANAGER_KEYCLOAK_ISSUER"
JWKS_URL_ENV = "CUSTOM_SECURITY_MANAGER_KEYCLOAK_JWKS_URL"
AUDIENCE_ENV = "CUSTOM_SECURITY_MANAGER_KEYCLOAK_AUDIENCE"
ENV_VARS = (
    "CELINE_ENV",
    "ENVIRONMENT",
    ISSUER_ENV,
    JWKS_URL_ENV,
    AUDIENCE_ENV,
    "CUSTOM_SECURITY_MANAGER_SKIP_SSL_VERIFY",
)


class _Resp:
    def __init__(self, payload=None, exc=None):
        self._payload = payload or {}
        self._exc = exc

    def raise_for_status(self):
        if self._exc:
            raise self._exc

    def json(self):
        return self._payload


class _Realm:
    """An issuer with its own signing key, discovery document and JWKS."""

    def __init__(self, issuer: str, jwks_url: str, kid: str):
        self.issuer = issuer
        self.jwks_url = jwks_url
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwk(self) -> dict:
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update(kid=self.kid, use="sig", alg="RS256")
        return jwk

    def token(self, **claims) -> str:
        now = int(time.time())
        payload = {
            "iss": self.issuer,
            "sub": "user-1",
            "preferred_username": "alice",
            "azp": "oauth2_proxy",
            "aud": ["oauth2_proxy"],
            "iat": now,
            "exp": now + 300,
            "realm_access": {"roles": ["platform-admin"]},
        }
        payload.update(claims)
        return jwt.encode(
            payload, self.key, algorithm="RS256", headers={"kid": self.kid}
        )


@pytest.fixture(scope="session")
def realms():
    return {
        "trusted": _Realm(TRUSTED, TRUSTED_JWKS, "trusted-kid"),
        "other": _Realm(OTHER, OTHER_JWKS, "other-kid"),
        "dev": _Realm(DEV_ISSUER, DEV_JWKS, "dev-kid"),
    }


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    jwt_mod.get_jwks_uri.cache_clear()
    jwt_mod.get_public_key.cache_clear()
    yield
    jwt_mod.get_jwks_uri.cache_clear()
    jwt_mod.get_public_key.cache_clear()


@pytest.fixture
def http(monkeypatch, realms):
    """Serves every realm's discovery document and JWKS; records each URL fetched."""
    fetched: list[str] = []
    routes = {}
    for realm in realms.values():
        routes[f"{realm.issuer}/.well-known/openid-configuration"] = {
            "issuer": realm.issuer,
            "jwks_uri": realm.jwks_url,
        }
        routes[realm.jwks_url] = {"keys": [realm.jwk()]}

    def fake_get(url, *args, **kwargs):
        fetched.append(url)
        if url not in routes:
            return _Resp(exc=requests.HTTPError(f"404 {url}"))
        return _Resp(payload=routes[url])

    monkeypatch.setattr(jwt_mod.requests, "get", fake_get)
    return fetched


def _claims(token: str):
    return jwt_mod.extract_jwt_claims(Headers({"X-Auth-Request-Access-Token": token}))


# --- one issuer is trusted -----------------------------------------------------------------


def test_the_configured_issuers_token_is_accepted(monkeypatch, realms, http):
    monkeypatch.setenv(ISSUER_ENV, TRUSTED)

    claims = _claims(realms["trusted"].token())

    assert claims is not None
    assert claims["iss"] == TRUSTED
    assert http == [f"{TRUSTED}/.well-known/openid-configuration", TRUSTED_JWKS]


def test_another_issuers_validly_signed_token_is_refused_before_any_fetch(
    monkeypatch, realms, http
):
    monkeypatch.setenv(ISSUER_ENV, TRUSTED)

    assert _claims(realms["other"].token()) is None
    assert http == [], "nothing may be fetched for a token of an untrusted issuer"


def test_another_issuers_token_is_refused_after_a_trusted_one(
    monkeypatch, realms, http
):
    """Same with warm caches: a trusted token first, then another issuer's."""
    monkeypatch.setenv(ISSUER_ENV, TRUSTED)
    assert _claims(realms["trusted"].token()) is not None

    assert _claims(realms["other"].token()) is None
    assert (
        OTHER_JWKS not in http
        and f"{OTHER}/.well-known/openid-configuration" not in http
    )


def test_a_token_naming_the_trusted_issuer_but_signed_by_another_key_is_refused(
    monkeypatch, realms, http
):
    monkeypatch.setenv(ISSUER_ENV, TRUSTED)
    token = jwt.encode(
        {"iss": TRUSTED, "sub": "x", "exp": int(time.time()) + 300},
        realms["other"].key,
        algorithm="RS256",
        headers={"kid": "trusted-kid"},
    )

    assert _claims(token) is None


def test_the_issuer_comparison_ignores_a_trailing_slash(monkeypatch, realms, http):
    monkeypatch.setenv(ISSUER_ENV, TRUSTED + "/")

    assert _claims(realms["trusted"].token()) is not None


def test_a_token_without_an_issuer_is_refused(monkeypatch, realms, http):
    monkeypatch.setenv(ISSUER_ENV, TRUSTED)
    now = int(time.time())
    token = jwt.encode(
        {"sub": "x", "iat": now, "exp": now + 300},
        realms["trusted"].key,
        algorithm="RS256",
        headers={"kid": "trusted-kid"},
    )

    assert _claims(token) is None
    assert http == []


def test_the_configured_jwks_url_is_used_without_discovery(monkeypatch, realms, http):
    monkeypatch.setenv(ISSUER_ENV, TRUSTED)
    monkeypatch.setenv(JWKS_URL_ENV, TRUSTED_JWKS)

    assert _claims(realms["trusted"].token()) is not None
    assert http == [TRUSTED_JWKS]


def test_a_discovery_document_naming_another_issuer_is_refused(monkeypatch, realms):
    monkeypatch.setenv(ISSUER_ENV, TRUSTED)
    monkeypatch.setattr(
        jwt_mod.requests,
        "get",
        lambda url, *a, **k: _Resp(payload={"issuer": OTHER, "jwks_uri": OTHER_JWKS}),
    )

    assert _claims(realms["trusted"].token()) is None


def test_only_rs256_is_accepted(monkeypatch, http):
    monkeypatch.setenv(ISSUER_ENV, TRUSTED)
    token = jwt.encode(
        {"iss": TRUSTED, "sub": "x", "exp": int(time.time()) + 300},
        "a-shared-secret-that-is-long-enough-for-hs256",
        algorithm="HS256",
        headers={"kid": "trusted-kid"},
    )

    assert _claims(token) is None


def test_the_audience_is_checked_when_configured(monkeypatch, realms, http):
    monkeypatch.setenv(ISSUER_ENV, TRUSTED)
    monkeypatch.setenv(AUDIENCE_ENV, "superset, oauth2_proxy")

    assert _claims(realms["trusted"].token()) is not None
    assert _claims(realms["trusted"].token(aud=["someone-else"])) is None


def test_an_expired_token_is_refused(monkeypatch, realms, http):
    monkeypatch.setenv(ISSUER_ENV, TRUSTED)

    assert _claims(realms["trusted"].token(exp=int(time.time()) - 60)) is None


# --- posture: only CELINE_ENV=dev relaxes --------------------------------------------------


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"CELINE_ENV": ""},
        {"CELINE_ENV": "prod"},
        {"CELINE_ENV": "staging"},
        {"CELINE_ENV": "development"},
        {"ENVIRONMENT": "production"},
        {"CELINE_ENV": "staging", "ENVIRONMENT": "dev"},
    ],
)
def test_no_issuer_outside_dev_refuses_to_start(monkeypatch, env):
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    with pytest.raises(jwt_mod.InsecureConfiguration, match=ISSUER_ENV):
        jwt_mod.check_configuration()


def test_no_issuer_outside_dev_refuses_every_token(monkeypatch, realms, http):
    """Should a request reach the verifier anyway, nothing is trusted, not even the dev realm."""
    monkeypatch.setenv("CELINE_ENV", "staging")

    assert _claims(realms["dev"].token()) is None
    assert _claims(realms["other"].token()) is None
    assert http == []


def test_a_configured_issuer_starts_outside_dev(monkeypatch):
    monkeypatch.setenv("CELINE_ENV", "prod")
    monkeypatch.setenv(ISSUER_ENV, TRUSTED + "/")

    assert jwt_mod.check_configuration() == TRUSTED


@pytest.mark.parametrize(
    "env", [{"CELINE_ENV": "dev"}, {"CELINE_ENV": " DEV "}, {"ENVIRONMENT": "dev"}]
)
def test_dev_without_an_issuer_trusts_the_local_realm_only(
    monkeypatch, realms, http, env
):
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    assert jwt_mod.check_configuration() == DEV_ISSUER
    assert _claims(realms["dev"].token()) is not None
    assert _claims(realms["other"].token()) is None
    assert OTHER_JWKS not in http


def test_dev_does_not_widen_a_configured_issuer(monkeypatch, realms, http):
    monkeypatch.setenv("CELINE_ENV", "dev")
    monkeypatch.setenv(ISSUER_ENV, TRUSTED)

    assert _claims(realms["trusted"].token()) is not None
    assert _claims(realms["dev"].token()) is None


# --- token extraction ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    ["X-Auth-Request-Access-Token", "X-Forwarded-Access-Token", "Authorization"],
)
def test_the_token_is_read_from_each_supported_header(
    monkeypatch, realms, http, header
):
    monkeypatch.setenv(ISSUER_ENV, TRUSTED)
    token = realms["trusted"].token()
    value = f"Bearer {token}" if header == "Authorization" else token

    claims = jwt_mod.extract_jwt_claims(Headers({header: value}))

    assert claims is not None and claims["preferred_username"] == "alice"


def test_no_token_is_no_identity():
    assert jwt_mod.extract_jwt_claims(Headers()) is None


def test_a_token_without_kid_is_refused(monkeypatch, realms, http):
    monkeypatch.setenv(ISSUER_ENV, TRUSTED)
    token = jwt.encode(
        {"iss": TRUSTED, "sub": "x", "exp": int(time.time()) + 300},
        realms["trusted"].key,
        algorithm="RS256",
    )

    assert _claims(token) is None
    assert http == []


# --- key lookup ----------------------------------------------------------------------------


def test_get_public_key_type_error(monkeypatch):
    monkeypatch.setattr(
        jwt_mod.requests,
        "get",
        lambda url, **kw: _Resp(payload={"keys": [{"kid": "k1"}]}),
    )
    monkeypatch.setattr(
        jwt_mod.RSAAlgorithm, "from_jwk", lambda j: object()
    )  # not RSAPublicKey
    with pytest.raises(TypeError, match="Expected RSAPublicKey"):
        jwt_mod.get_public_key("https://jwks", "k1")


def test_get_public_key_unknown_kid(monkeypatch):
    monkeypatch.setattr(
        jwt_mod.requests, "get", lambda url, **kw: _Resp(payload={"keys": []})
    )
    with pytest.raises(ValueError, match="No matching JWK"):
        jwt_mod.get_public_key("https://jwks", "k1")


def test_get_jwks_uri_http_error(monkeypatch):
    monkeypatch.setattr(
        jwt_mod.requests, "get", lambda url, **kw: _Resp(exc=requests.HTTPError("boom"))
    )
    with pytest.raises(requests.HTTPError):
        jwt_mod.get_jwks_uri(TRUSTED)
