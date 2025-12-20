import pytest
import requests
import celine_superset.auth.security_manager as sm


class DummyResp:
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
    sm.get_jwks_uri_from_jwt.cache_clear()
    sm.get_public_key.cache_clear()
    yield
    sm.get_jwks_uri_from_jwt.cache_clear()
    sm.get_public_key.cache_clear()


def test_get_jwks_uri_from_jwt_happy(monkeypatch):
    monkeypatch.setattr(
        sm.jwt, "decode", lambda token, options: {"iss": "https://issuer.example"}
    )

    def fake_get(url, **kwargs):
        assert url.endswith("/.well-known/openid-configuration")
        return DummyResp(payload={"jwks_uri": "https://issuer.example/jwks"})

    monkeypatch.setattr(sm.requests, "get", fake_get)

    assert sm.get_jwks_uri_from_jwt("dummy.token") == "https://issuer.example/jwks"


def test_get_jwks_uri_from_jwt_http_error(monkeypatch):
    monkeypatch.setattr(
        sm.jwt, "decode", lambda token, options: {"iss": "https://issuer.example"}
    )

    def fake_get(url, **kwargs):
        return DummyResp(exc=requests.HTTPError("boom"))

    monkeypatch.setattr(sm.requests, "get", fake_get)

    with pytest.raises(requests.HTTPError):
        sm.get_jwks_uri_from_jwt("dummy.token")


def test_get_public_key_type_error(monkeypatch):
    def fake_get(url, **kwargs):
        return DummyResp(
            payload={
                "keys": [
                    {
                        "kid": "abc",
                        "kty": "RSA",
                        "n": "00",
                        "e": "AQAB",
                    }
                ]
            }
        )

    monkeypatch.setattr(sm.requests, "get", fake_get)
    monkeypatch.setattr(sm.jwt, "get_unverified_header", lambda token: {"kid": "abc"})
    monkeypatch.setattr(sm.RSAAlgorithm, "from_jwk", lambda jwk: object())

    with pytest.raises(TypeError, match="Expected RSAPublicKey"):
        sm.get_public_key("https://issuer/jwks", "dummy.token")
