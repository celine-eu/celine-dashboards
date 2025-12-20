import jwt
from werkzeug.datastructures import Headers
import celine_superset.auth.security_manager as sm


def test_extract_jwt_claims_from_bearer(monkeypatch):
    headers = Headers({"Authorization": "Bearer token123"})

    monkeypatch.setattr(sm, "get_jwks_uri_from_jwt", lambda t: "jwks")
    monkeypatch.setattr(sm, "get_public_key", lambda u, t: object())
    monkeypatch.setattr(sm.jwt, "decode", lambda *a, **k: {"sub": "user"})

    claims = sm.extract_jwt_claims_from_request(headers)

    assert claims is not None
    assert claims["sub"] == "user"


def test_extract_jwt_claims_missing_token():
    headers = Headers()
    assert sm.extract_jwt_claims_from_request(headers) is None


def test_extract_jwt_claims_expired(monkeypatch):
    headers = Headers({"X-Auth-Request-Access-Token": "tok"})

    monkeypatch.setattr(sm, "get_jwks_uri_from_jwt", lambda t: "jwks")
    monkeypatch.setattr(sm, "get_public_key", lambda u, t: object())
    monkeypatch.setattr(
        sm.jwt,
        "decode",
        lambda *a, **k: (_ for _ in ()).throw(jwt.ExpiredSignatureError()),
    )

    assert sm.extract_jwt_claims_from_request(headers) is None
