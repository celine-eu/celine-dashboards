import jwt
import requests
from jwt import PyJWKClient
from jupyter_server.auth.authorizer import Authorizer


JWT_GROUPS_CLAIM = "groups"


class JWTAuthorizer(Authorizer):
    """Role-based access control using JWT and cached OIDC discovery."""

    _jwk_clients = {}  # class-level cache: {issuer -> PyJWKClient}

    def _decode_token(self, token):
        # Step 1. Peek at unverified claims to get issuer
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            issuer = unverified.get("iss")
            if not issuer:
                raise ValueError("JWT missing 'iss' claim")
        except Exception as e:
            raise ValueError(f"Failed to parse JWT for issuer: {e}")

        # Step 2. Reuse cached JWK client if available
        if issuer not in self._jwk_clients:
            oidc_config_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
            resp = requests.get(oidc_config_url, timeout=5)
            resp.raise_for_status()
            jwks_uri = resp.json()["jwks_uri"]

            self.log.info(f"Caching JWKS client for issuer {issuer}")
            self._jwk_clients[issuer] = PyJWKClient(jwks_uri)

        jwk_client = self._jwk_clients[issuer]

        # Step 3. Verify signature against JWKS
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )

    def is_authorized(self, handler, user, action, resource):
        token = handler.request.headers.get(
            "X-Forwarded-Access-Token"
        ) or handler.request.headers.get("Authorization", "").replace("Bearer ", "")

        groups = []
        if token:
            try:
                payload = self._decode_token(token)
                groups = payload.get(JWT_GROUPS_CLAIM, [])
            except Exception as e:
                self.log.warning(f"JWT verification failed: {e}")

        # Admins: full access (including terminals)
        if "/admins" in groups:
            return True

        # No access for others
        return False
