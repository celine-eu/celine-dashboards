import pytest
import requests
from werkzeug.datastructures import Headers

import celine.superset.auth.jwt as jwt_mod


class _Resp:
    def __init__(self, payload=None, exc=None):
        self._payload = payload or {}
        self._exc = exc

    def raise_for_status(self):
        if self._exc:
            raise self._exc

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def clear_caches():
    jwt_mod.get_jwks_uri.cache_clear()
    jwt_mod.get_public_key.cache_clear()
    jwt_mod._audiences.cache_clear()
    yield
    jwt_mod.get_jwks_uri.cache_clear()
    jwt_mod.get_public_key.cache_clear()
    jwt_mod._audiences.cache_clear()


# --- get_jwks_uri ---

def test_get_jwks_uri_happy(monkeypatch):
    monkeypatch.setattr(jwt_mod.jwt, "decode", lambda token, options: {"iss": "https://kc.example"})

    def fake_get(url, **kw):
        assert "/.well-known/openid-configuration" in url
        return _Resp(payload={"jwks_uri": "https://kc.example/jwks"})

    monkeypatch.setattr(jwt_mod.requests, "get", fake_get)
    assert jwt_mod.get_jwks_uri("tok") == "https://kc.example/jwks"


def test_get_jwks_uri_uses_env(monkeypatch):
    monkeypatch.setattr(jwt_mod, "JWKS_URL", "https://fixed/jwks")
    assert jwt_mod.get_jwks_uri("any") == "https://fixed/jwks"


def test_get_jwks_uri_http_error(monkeypatch):
    monkeypatch.setattr(jwt_mod.jwt, "decode", lambda t, options: {"iss": "https://kc"})
    monkeypatch.setattr(jwt_mod.requests, "get", lambda url, **kw: _Resp(exc=requests.HTTPError("boom")))
    with pytest.raises(requests.HTTPError):
        jwt_mod.get_jwks_uri("tok")


# --- get_public_key ---

def test_get_public_key_type_error(monkeypatch):
    monkeypatch.setattr(jwt_mod.requests, "get", lambda url, **kw: _Resp(payload={"keys": [{"kid": "k1"}]}))
    monkeypatch.setattr(jwt_mod.jwt, "get_unverified_header", lambda t: {"kid": "k1"})
    monkeypatch.setattr(jwt_mod.RSAAlgorithm, "from_jwk", lambda j: object())  # not RSAPublicKey
    with pytest.raises(TypeError, match="Expected RSAPublicKey"):
        jwt_mod.get_public_key("https://jwks", "tok")


def test_get_public_key_missing_kid(monkeypatch):
    monkeypatch.setattr(jwt_mod.requests, "get", lambda url, **kw: _Resp(payload={"keys": []}))
    monkeypatch.setattr(jwt_mod.jwt, "get_unverified_header", lambda t: {})
    with pytest.raises(ValueError, match="missing kid"):
        jwt_mod.get_public_key("https://jwks", "tok")


# --- extract_jwt_claims ---

def test_extract_from_bearer(monkeypatch):
    headers = Headers({"Authorization": "Bearer tok"})
    monkeypatch.setattr(jwt_mod, "get_jwks_uri", lambda t: "url")
    monkeypatch.setattr(jwt_mod, "get_public_key", lambda u, t: object())
    monkeypatch.setattr(jwt_mod.jwt, "decode", lambda *a, **k: {"sub": "alice"})
    assert jwt_mod.extract_jwt_claims(headers) == {"sub": "alice"}


def test_extract_from_x_auth_header(monkeypatch):
    headers = Headers({"X-Auth-Request-Access-Token": "tok"})
    monkeypatch.setattr(jwt_mod, "get_jwks_uri", lambda t: "url")
    monkeypatch.setattr(jwt_mod, "get_public_key", lambda u, t: object())
    monkeypatch.setattr(jwt_mod.jwt, "decode", lambda *a, **k: {"sub": "bob"})
    assert jwt_mod.extract_jwt_claims(headers)["sub"] == "bob"


def test_extract_no_token():
    assert jwt_mod.extract_jwt_claims(Headers()) is None


def test_extract_expired(monkeypatch):
    headers = Headers({"X-Auth-Request-Access-Token": "tok"})
    monkeypatch.setattr(jwt_mod, "get_jwks_uri", lambda t: "url")
    monkeypatch.setattr(jwt_mod, "get_public_key", lambda u, t: object())
    monkeypatch.setattr(
        jwt_mod.jwt, "decode",
        lambda *a, **k: (_ for _ in ()).throw(jwt_mod.jwt.ExpiredSignatureError()),
    )
    assert jwt_mod.extract_jwt_claims(headers) is None
