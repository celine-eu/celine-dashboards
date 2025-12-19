import json
import types
import pytest
import requests

import celine_superset.auth.security_manager as sm


class DummyResp:
    def __init__(self, status=200, payload=None, raise_for_status_exc=None):
        self.status_code = status
        self._payload = payload or {}
        self._exc = raise_for_status_exc

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
    # jwt.decode(token, options={"verify_signature": False}) -> {"iss": ...}
    monkeypatch.setattr(
        sm.jwt, "decode", lambda token, options: {"iss": "https://issuer.example"}
    )

    def fake_get(url, *args, **kwargs):
        assert url == "https://issuer.example/.well-known/openid-configuration"
        return DummyResp(payload={"jwks_uri": "https://issuer.example/jwks"})

    monkeypatch.setattr(sm.requests, "get", fake_get)

    assert sm.get_jwks_uri_from_jwt("dummy.token") == "https://issuer.example/jwks"


def test_get_jwks_uri_from_jwt_http_error(monkeypatch):
    monkeypatch.setattr(
        sm.jwt, "decode", lambda token, options: {"iss": "https://issuer.example"}
    )

    def fake_get(url, *args, **kwargs):
        return DummyResp(raise_for_status_exc=requests.HTTPError("boom"))

    monkeypatch.setattr(sm.requests, "get", fake_get)

    with pytest.raises(requests.HTTPError):
        sm.get_jwks_uri_from_jwt("dummy.token")


def test_get_public_key_type_error(monkeypatch):
    # mock requests.get correctly
    def fake_get(url, *args, **kwargs):
        class DummyResp:
            def raise_for_status(self):
                pass

            def json(self):
                return {"keys": [{"kty": "RSA"}]}

        return DummyResp()

    monkeypatch.setattr(sm.requests, "get", fake_get)

    # force from_jwk to return a non-RSAPublicKey
    monkeypatch.setattr(sm.RSAAlgorithm, "from_jwk", lambda jwk: object())

    with pytest.raises(TypeError, match=r"Expected RSAPublicKey"):
        sm.get_public_key("https://issuer.example/jwks")
