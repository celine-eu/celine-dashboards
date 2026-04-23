import pytest
import respx
import httpx

from celine.superset.cli.client import SupersetClient, KcTokenProvider
from celine.superset.cli.config import Settings


@pytest.fixture
def settings():
    return Settings(
        url="http://superset.test",
        kc_issuer_url="http://kc.test/realms/celine",
        kc_client_id="celine-cli",
        kc_client_secret="celine-cli",
    )


@pytest.fixture
def client(settings):
    with respx.mock:
        _mock_kc()
        return SupersetClient(settings)


def _mock_kc(token: str = "kc-token-abc"):
    respx.get("http://kc.test/realms/celine/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json={"token_endpoint": "http://kc.test/token"})
    )
    respx.post("http://kc.test/token").mock(
        return_value=httpx.Response(200, json={"access_token": token, "expires_in": 300})
    )


# --- KcTokenProvider ---

@respx.mock
def test_kc_token_fetched_via_discovery(settings):
    _mock_kc("my-jwt")
    provider = KcTokenProvider(settings)
    assert provider.get_token() == "my-jwt"


@respx.mock
def test_kc_token_cached(settings):
    _mock_kc()
    provider = KcTokenProvider(settings)
    provider.get_token()
    provider.get_token()
    assert respx.calls.call_count == 2  # discovery + token


@respx.mock
def test_kc_discovery_error_propagates(settings):
    respx.get("http://kc.test/realms/celine/.well-known/openid-configuration").mock(
        return_value=httpx.Response(500)
    )
    provider = KcTokenProvider(settings)
    with pytest.raises(httpx.HTTPStatusError):
        provider.get_token()


# --- SupersetClient ---

@respx.mock
def test_bearer_header_set_on_get(settings):
    _mock_kc("jwt-abc")
    c = SupersetClient(settings)
    respx.get("http://superset.test/api/v1/dashboard/").mock(
        return_value=httpx.Response(200, json={"result": []})
    )
    c.get("/api/v1/dashboard/")
    req = respx.calls.last.request
    assert req.headers["Authorization"] == "Bearer jwt-abc"


@respx.mock
def test_csrf_fetched_before_mutation(settings):
    _mock_kc()
    c = SupersetClient(settings)
    respx.get("http://superset.test/api/v1/security/csrf_token/").mock(
        return_value=httpx.Response(200, json={"result": "csrf-xyz"})
    )
    respx.post("http://superset.test/api/v1/dashboard/import/").mock(
        return_value=httpx.Response(200, json={"message": "OK"})
    )
    c.import_zip("dashboard", b"PKzip")
    req = respx.calls.last.request
    assert req.headers.get("X-CSRFToken") == "csrf-xyz"


@respx.mock
def test_csrf_not_refetched_on_second_mutation(settings):
    _mock_kc()
    c = SupersetClient(settings)
    csrf_route = respx.get("http://superset.test/api/v1/security/csrf_token/").mock(
        return_value=httpx.Response(200, json={"result": "tok"})
    )
    respx.post("http://superset.test/api/v1/dashboard/import/").mock(
        return_value=httpx.Response(200, json={})
    )
    c.import_zip("dashboard", b"a")
    c.import_zip("dashboard", b"b")
    assert csrf_route.call_count == 1


@respx.mock
def test_302_raises_not_follows(settings):
    _mock_kc()
    c = SupersetClient(settings)
    respx.get("http://superset.test/api/v1/dataset/").mock(
        return_value=httpx.Response(302, headers={"Location": "http://sso/login"})
    )
    with pytest.raises(httpx.HTTPStatusError):
        c.get("/api/v1/dataset/")


@respx.mock
def test_export_returns_zip_bytes(settings):
    _mock_kc()
    c = SupersetClient(settings)
    respx.get("http://superset.test/api/v1/dashboard/export/").mock(
        return_value=httpx.Response(200, content=b"PKdata")
    )
    assert c.export("dashboard", [1, 2]) == b"PKdata"
