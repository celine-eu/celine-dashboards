import jwt as pyjwt
import pytest
from unittest.mock import MagicMock, patch

from celine.jupyter.jwt_authorizer import JWTAuthorizer


@pytest.fixture(autouse=True)
def _clear_jwk_cache():
    JWTAuthorizer._jwk_clients = {}


@pytest.fixture
def authorizer():
    auth = JWTAuthorizer()
    auth.log = MagicMock()
    return auth


@pytest.fixture
def handler():
    h = MagicMock()
    h.request.headers = {}
    return h


class TestIsAuthorized:
    def test_admin_group_grants_access(self, authorizer, handler):
        handler.request.headers = {"X-Forwarded-Access-Token": "tok"}
        with patch.object(authorizer, "_decode_token", return_value={"groups": ["/admins"]}):
            assert authorizer.is_authorized(handler, "user", "read", "contents") is True

    def test_non_admin_denied(self, authorizer, handler):
        handler.request.headers = {"X-Forwarded-Access-Token": "tok"}
        with patch.object(authorizer, "_decode_token", return_value={"groups": ["/users"]}):
            assert authorizer.is_authorized(handler, "user", "read", "contents") is False

    def test_empty_groups_denied(self, authorizer, handler):
        handler.request.headers = {"X-Forwarded-Access-Token": "tok"}
        with patch.object(authorizer, "_decode_token", return_value={"groups": []}):
            assert authorizer.is_authorized(handler, "user", "read", "contents") is False

    def test_no_token_denied(self, authorizer, handler):
        assert authorizer.is_authorized(handler, "user", "read", "contents") is False

    def test_invalid_token_denied_and_logged(self, authorizer, handler):
        handler.request.headers = {"Authorization": "Bearer bad"}
        with patch.object(authorizer, "_decode_token", side_effect=ValueError("bad")):
            assert authorizer.is_authorized(handler, "user", "read", "contents") is False
        authorizer.log.warning.assert_called_once()

    def test_forwarded_header_takes_precedence(self, authorizer, handler):
        handler.request.headers = {
            "X-Forwarded-Access-Token": "forwarded",
            "Authorization": "Bearer bearer",
        }
        with patch.object(authorizer, "_decode_token", return_value={"groups": []}) as mock:
            authorizer.is_authorized(handler, "user", "read", "contents")
            mock.assert_called_once_with("forwarded")

    def test_bearer_prefix_stripped(self, authorizer, handler):
        handler.request.headers = {"Authorization": "Bearer my-token"}
        with patch.object(authorizer, "_decode_token", return_value={"groups": []}) as mock:
            authorizer.is_authorized(handler, "user", "read", "contents")
            mock.assert_called_once_with("my-token")

    def test_no_groups_claim_denied(self, authorizer, handler):
        handler.request.headers = {"X-Forwarded-Access-Token": "tok"}
        with patch.object(authorizer, "_decode_token", return_value={"sub": "user"}):
            assert authorizer.is_authorized(handler, "user", "read", "contents") is False


class TestDecodeToken:
    def test_missing_issuer_raises(self, authorizer):
        token = pyjwt.encode({"sub": "user"}, "secret", algorithm="HS256")
        with pytest.raises(ValueError, match="missing 'iss' claim"):
            authorizer._decode_token(token)

    def test_oidc_discovery_and_jwk_caching(self, authorizer):
        issuer = "https://auth.example.com/realms/test"
        token = pyjwt.encode({"iss": issuer, "sub": "user"}, "secret", algorithm="HS256")
        jwks_uri = f"{issuer}/protocol/openid-connect/certs"

        mock_jwk_client = MagicMock()
        mock_jwk_client.get_signing_key_from_jwt.return_value.key = "k"

        with patch("celine.jupyter.jwt_authorizer.requests.get") as mock_get, \
             patch("celine.jupyter.jwt_authorizer.PyJWKClient", return_value=mock_jwk_client), \
             patch("celine.jupyter.jwt_authorizer.jwt.decode") as mock_decode:

            mock_get.return_value.json.return_value = {"jwks_uri": jwks_uri}
            mock_decode.side_effect = [
                {"iss": issuer},
                {"iss": issuer, "groups": ["/admins"]},
            ]
            authorizer._decode_token(token)
            mock_get.assert_called_once_with(
                f"{issuer}/.well-known/openid-configuration", timeout=5,
            )

            mock_decode.side_effect = [
                {"iss": issuer},
                {"iss": issuer, "groups": []},
            ]
            authorizer._decode_token(token)
            assert mock_get.call_count == 1  # no second OIDC fetch
