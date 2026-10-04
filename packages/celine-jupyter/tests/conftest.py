"""Shared fixtures: a local OIDC issuer (discovery + JWKS over HTTP) that signs real RS256 tokens,
and an isolated Jupyter environment (config, data and runtime directories of the test's own)."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

REALM_PATH = "/realms/example"
KID = "test-key"

# Access-token claim shapes (Keycloak, dev realm), without the registered claims.
PLATFORM_ADMIN = {
    "azp": "oauth2_proxy",
    "preferred_username": "admin",
    "realm_access": {"roles": ["platform-admin"]},
}
ORG_ADMIN = {
    "azp": "oauth2_proxy",
    "preferred_username": "org-admin",
    "realm_access": {"roles": ["default-roles-celine", "offline_access", "uma_authorization"]},
    "organization": {"example_rec": {"type": ["rec"], "groups": ["/admins"]}},
}
ORG_VIEWER = {
    "azp": "oauth2_proxy",
    "preferred_username": "org-viewer",
    "realm_access": {"roles": ["default-roles-celine", "offline_access", "uma_authorization"]},
    "organization": {"example_rec": {"type": ["rec"], "groups": ["/viewers"]}},
}
# The old oauth2_proxy token of a realm-/admins member: both group forms, and the retired
# realm role `admin` the group mapped to.
LEGACY_REALM_ADMIN = {
    "azp": "oauth2_proxy",
    "preferred_username": "legacy-admin",
    "groups": ["/admins", "admins"],
    "realm_access": {"roles": ["admin"]},
    "organization": {"example-rec": {"type": ["rec"], "groups": ["/admins"]}},
}


def _jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


@dataclass
class Issuer:
    """A running local issuer. ``issuer`` is its URL; ``requests`` counts the HTTP requests it answered."""

    issuer: str
    key: rsa.RSAPrivateKey
    requests: list[str]

    def sign(
        self,
        claims: dict[str, Any],
        *,
        iss: str | None = None,
        key: rsa.RSAPrivateKey | None = None,
        kid: str = KID,
        lifetime: int = 300,
        **registered: Any,
    ) -> str:
        now = int(time.time())
        payload = {"iss": iss if iss is not None else self.issuer, "sub": claims.get("preferred_username", "u"),
                   "iat": now, "exp": now + lifetime, **registered, **claims}
        return jwt.encode(payload, key or self.key, algorithm="RS256", headers={"kid": kid})


@pytest.fixture(scope="session")
def issuer() -> Issuer:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    seen: list[str] = []
    documents: dict[str, Any] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            seen.append(self.path)
            body = documents.get(self.path)
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base = f"http://127.0.0.1:{server.server_address[1]}{REALM_PATH}"
    documents[f"{REALM_PATH}/.well-known/openid-configuration"] = {
        "issuer": base,
        "jwks_uri": f"{base}/protocol/openid-connect/certs",
    }
    documents[f"{REALM_PATH}/protocol/openid-connect/certs"] = {"keys": [_jwk(key, KID)]}
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield Issuer(issuer=base, key=key, requests=seen)
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="session")
def other_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def jupyter_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Jupyter config/data/runtime directories of this test only; returns the config directory."""
    for name in ("config", "data", "runtime", "root"):
        (tmp_path / name).mkdir()
    monkeypatch.setenv("JUPYTER_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("JUPYTER_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("JUPYTER_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.delenv("JUPYTER_CONFIG_PATH", raising=False)
    monkeypatch.delenv("JUPYTER_TOKEN", raising=False)
    monkeypatch.delenv("JUPYTER_SERVER_ALLOW_UNAUTHENTICATED_ACCESS", raising=False)
    monkeypatch.delenv("CELINE_JUPYTER_JWKS_URL", raising=False)
    monkeypatch.delenv("CELINE_JUPYTER_JWT_AUDIENCE", raising=False)
    return tmp_path / "config"
