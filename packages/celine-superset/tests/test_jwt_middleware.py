import json
import pytest
import requests

import celine_superset.auth.security_manager as sm


def ok_app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"OK"]


@pytest.fixture(autouse=True)
def clear_caches():
    sm.get_jwks_uri_from_jwt.cache_clear()
    sm.get_public_key.cache_clear()
    yield
    sm.get_jwks_uri_from_jwt.cache_clear()
    sm.get_public_key.cache_clear()


def test_health_path_passthrough(start_response):
    mw = sm.JWTRemoteUserMiddleware(ok_app)
    environ = {"PATH_INFO": "/health"}
    body = mw(environ, start_response)
    assert start_response.status == "200 OK"
    assert b"".join(body) == b"OK"


def test_missing_token_redirects(start_response, caplog, monkeypatch):
    monkeypatch.setattr(sm, "SSO_BASE_URL", "https://sso.example")
    mw = sm.JWTRemoteUserMiddleware(ok_app)

    environ = {"PATH_INFO": "/"}
    body = mw(environ, start_response)

    assert start_response.status == "302 Found"
    assert "Location" in start_response.headers
    assert start_response.headers["Location"].startswith(
        "https://sso.example/oauth2/sign_in"
    )
    assert b"Redirecting" in b"".join(body)
    assert any("JWT header missing" in r.message for r in caplog.records)


def test_invalid_token_redirects(start_response, caplog, monkeypatch):
    mw = sm.JWTRemoteUserMiddleware(ok_app)
    environ = {
        "PATH_INFO": "/",
        "HTTP_X_AUTH_REQUEST_ACCESS_TOKEN": "bad.token",
        "HTTP_HOST": "superset.local",
        "wsgi.url_scheme": "https",
    }

    # avoid network: return fixed jwks url + public key
    monkeypatch.setattr(sm, "JWKS_URL", "https://issuer/jwks")
    monkeypatch.setattr(
        sm, "get_public_key", lambda url: object()
    )  # key value not used since decode fails
    monkeypatch.setattr(
        sm.jwt,
        "decode",
        lambda *a, **k: (_ for _ in ()).throw(sm.jwt.InvalidTokenError("nope")),
    )

    body = mw(environ, start_response)

    assert start_response.status == "302 Found"
    assert any("JWT decode error" in r.message for r in caplog.records)
    assert b"Redirecting" in b"".join(body)
    assert "REMOTE_USER" not in environ
    assert "JWT_CLAIMS" not in environ


def test_expired_token_redirects(start_response, caplog, monkeypatch):
    mw = sm.JWTRemoteUserMiddleware(ok_app)
    environ = {"PATH_INFO": "/", "HTTP_X_AUTH_REQUEST_ACCESS_TOKEN": "expired.token"}

    monkeypatch.setattr(sm, "JWKS_URL", "https://issuer/jwks")
    monkeypatch.setattr(sm, "get_public_key", lambda url: object())
    monkeypatch.setattr(
        sm.jwt,
        "decode",
        lambda *a, **k: (_ for _ in ()).throw(sm.jwt.ExpiredSignatureError("expired")),
    )

    body = mw(environ, start_response)

    assert start_response.status == "302 Found"
    assert any("has expired" in r.message for r in caplog.records)
    assert b"Redirecting" in b"".join(body)


def test_missing_username_claims_returns_unauthorized(start_response, monkeypatch):
    mw = sm.JWTRemoteUserMiddleware(ok_app)
    environ = {"PATH_INFO": "/", "HTTP_X_AUTH_REQUEST_ACCESS_TOKEN": "ok.token"}

    monkeypatch.setattr(sm, "JWKS_URL", "https://issuer/jwks")
    monkeypatch.setattr(sm, "get_public_key", lambda url: object())
    monkeypatch.setattr(
        sm.jwt, "decode", lambda *a, **k: {"sub": "123"}
    )  # no preferred_username/email

    body = mw(environ, start_response)

    assert start_response.status == "401 Unauthorized"
    assert b"Username missing in token" in b"".join(body)
    assert "REMOTE_USER" not in environ


def test_happy_path_sets_remote_user_and_calls_app(start_response, monkeypatch):
    mw = sm.JWTRemoteUserMiddleware(ok_app)
    environ = {"PATH_INFO": "/", "HTTP_X_AUTH_REQUEST_ACCESS_TOKEN": "ok.token"}

    monkeypatch.setattr(sm, "JWKS_URL", "https://issuer/jwks")
    monkeypatch.setattr(sm, "get_public_key", lambda url: object())
    monkeypatch.setattr(
        sm.jwt,
        "decode",
        lambda *a, **k: {"preferred_username": "alice", "groups": ["/admins"]},
    )

    body = mw(environ, start_response)

    assert environ["REMOTE_USER"] == "alice"
    assert json.loads(environ["JWT_CLAIMS"])["preferred_username"] == "alice"
    assert start_response.status == "200 OK"
    assert b"".join(body) == b"OK"


def test_network_error_redirects(start_response, caplog, monkeypatch):
    mw = sm.JWTRemoteUserMiddleware(ok_app)
    environ = {"PATH_INFO": "/", "HTTP_X_AUTH_REQUEST_ACCESS_TOKEN": "ok.token"}

    monkeypatch.setattr(sm, "JWKS_URL", None)
    sm.get_jwks_uri_from_jwt.cache_clear()

    # get_jwks_uri_from_jwt triggers requests.get inside; easiest is to raise RequestException from it
    monkeypatch.setattr(
        sm,
        "get_jwks_uri_from_jwt",
        lambda token: (_ for _ in ()).throw(requests.RequestException("down")),
    )

    body = mw(environ, start_response)

    assert start_response.status == "302 Found"
    assert any("HTTP error while resolving JWKS" in r.message for r in caplog.records)
    assert b"Redirecting" in b"".join(body)
