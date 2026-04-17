"""
Superset REST API client built on the generated openapi/superset_client.

Auth flow:
  1. KC client credentials grant  → KC access token (JWT)
  2. AuthenticatedClient injects Authorization: Bearer <token> on every request.
     oauth2_proxy forwards requests bearing a valid KC JWT without SSO redirect
     (skip-jwt-bearer-tokens=true).
  3. CSRF token (for mutations): fetched once via the generated security API and
     stored on the underlying httpx session.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from io import BytesIO

import httpx

from celine.superset.cli.config import Settings
from celine.superset.cli.openapi.superset_client import AuthenticatedClient
from celine.superset.cli.openapi.superset_client.api.security import (
    get_api_v1_security_csrf_token,
)
from celine.superset.cli.openapi.superset_client.models.post_api_v1_chart_import_body import (
    PostApiV1ChartImportBody,
)
from celine.superset.cli.openapi.superset_client.models.post_api_v1_dashboard_import_body import (
    PostApiV1DashboardImportBody,
)
from celine.superset.cli.openapi.superset_client.models.post_api_v1_dataset_import_body import (
    PostApiV1DatasetImportBody,
)
from celine.superset.cli.openapi.superset_client.types import File, Unset


@dataclass
class _Token:
    access_token: str
    expires_at: float

    def is_valid(self, leeway: int = 30) -> bool:
        return time.time() < (self.expires_at - leeway)


class KcTokenProvider:
    """Sync KC client credentials token provider."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._token: _Token | None = None
        self._token_endpoint: str | None = None

    def _resolve_token_endpoint(self) -> str:
        if self._token_endpoint:
            return self._token_endpoint
        url = f"{self._settings.kc_issuer_url}/.well-known/openid-configuration"
        resp = httpx.get(url, verify=self._settings.verify_ssl, timeout=10)
        resp.raise_for_status()
        self._token_endpoint = resp.json()["token_endpoint"]
        return self._token_endpoint

    def get_token(self) -> str:
        if self._token and self._token.is_valid():
            return self._token.access_token

        endpoint = self._resolve_token_endpoint()
        resp = httpx.post(
            endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": self._settings.kc_client_id,
                "client_secret": self._settings.kc_client_secret,
            },
            verify=self._settings.verify_ssl,
            timeout=10,
        )
        resp.raise_for_status()
        payload = resp.json()
        self._token = _Token(
            access_token=payload["access_token"],
            expires_at=time.time() + float(payload.get("expires_in", 300)),
        )
        return self._token.access_token


class SupersetClient:
    def __init__(self, settings: Settings):
        self._kc = KcTokenProvider(settings)
        self._settings = settings
        self._api_client: AuthenticatedClient | None = None

    def _get_api_client(self) -> AuthenticatedClient:
        if self._api_client is None:
            self._api_client = AuthenticatedClient(
                base_url=self._settings.url,
                token=self._kc.get_token(),
                verify_ssl=self._settings.verify_ssl,
                timeout=httpx.Timeout(30),
                follow_redirects=False,
                raise_on_unexpected_status=True,
            )
        return self._api_client

    def _ensure_csrf(self) -> None:
        client = self._get_api_client()
        http = client.get_httpx_client()
        if "X-CSRFToken" in http.headers:
            return
        resp = get_api_v1_security_csrf_token.sync_detailed(client=client)
        if resp.parsed is None or isinstance(resp.parsed.result, Unset):
            raise RuntimeError(f"Failed to fetch CSRF token: HTTP {resp.status_code}")
        http.headers["X-CSRFToken"] = resp.parsed.result

    # ------------------------------------------------------------------
    # Listing helpers
    # ------------------------------------------------------------------

    def list_ids(self, resource: str) -> list[dict]:
        http = self._get_api_client().get_httpx_client()
        resp = http.get(f"/api/v1/{resource}/", params={"q": "(page_size:200)"})
        resp.raise_for_status()
        return [
            {
                "id": r["id"],
                "name": (
                    r.get("dashboard_title")
                    or r.get("slice_name")
                    or r.get("table_name", "")
                ),
            }
            for r in resp.json().get("result", [])
        ]

    # ------------------------------------------------------------------
    # Export (ZIP bundle)
    # ------------------------------------------------------------------

    def export(self, resource: str, ids: list[int]) -> bytes:
        http = self._get_api_client().get_httpx_client()
        params = [("q", f"ids:[{','.join(str(i) for i in ids)}]")]
        resp = http.get(f"/api/v1/{resource}/export/", params=params)
        resp.raise_for_status()
        return resp.content

    # ------------------------------------------------------------------
    # Import (ZIP bundle)
    # ------------------------------------------------------------------

    def import_zip(
        self, resource: str, zip_bytes: bytes, *, overwrite: bool = True
    ) -> dict:
        self._ensure_csrf()
        http = self._get_api_client().get_httpx_client()
        body = _build_import_body(resource, zip_bytes, overwrite)
        resp = http.post(
            f"/api/v1/{resource}/import/",
            files=body.to_multipart(),
        )
        resp.raise_for_status()
        return resp.json()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self._api_client is not None:
            self._api_client.get_httpx_client().close()


def _build_import_body(resource: str, zip_bytes: bytes, overwrite: bool):
    file = File(payload=BytesIO(zip_bytes), file_name="bundle.zip", mime_type="application/zip")
    if resource == "dashboard":
        return PostApiV1DashboardImportBody(form_data=file, overwrite=overwrite)
    if resource == "chart":
        return PostApiV1ChartImportBody(form_data=file, overwrite=overwrite)
    if resource == "dataset":
        return PostApiV1DatasetImportBody(form_data=file, overwrite=overwrite)
    raise ValueError(f"Unknown resource: {resource!r}")
