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

import json
import time
from dataclasses import dataclass
from io import BytesIO

import httpx

from celine.superset.cli.config import Settings
from celine.superset.cli.openapi.superset_client import AuthenticatedClient
from celine.superset.cli.openapi.superset_client.api.charts import get_api_v1_chart_export, get_api_v1_chart
from celine.superset.cli.openapi.superset_client.api.dashboards import get_api_v1_dashboard_export, get_api_v1_dashboard
from celine.superset.cli.openapi.superset_client.api.datasets import (
    get_api_v1_dataset_export,
    get_api_v1_dataset,
    post_api_v1_dataset,
)
from celine.superset.cli.openapi.superset_client.api.importexport import post_api_v1_assets_import
from celine.superset.cli.openapi.superset_client.models.post_api_v1_assets_import_body import PostApiV1AssetsImportBody
from celine.superset.cli.openapi.superset_client.models.post_api_v1_assets_import_response_200 import PostApiV1AssetsImportResponse200
from celine.superset.cli.openapi.superset_client.api.database import (
    get_api_v1_database,
    get_api_v1_database_pk_tables,
    post_api_v1_database,
)
from celine.superset.cli.openapi.superset_client.api.security import (
    get_api_v1_security_csrf_token,
)
from celine.superset.cli.openapi.superset_client.models.get_api_v1_database_response_200 import GetApiV1DatabaseResponse200
from celine.superset.cli.openapi.superset_client.models.post_api_v1_database_response_201 import PostApiV1DatabaseResponse201
from celine.superset.cli.openapi.superset_client.models.post_api_v1_dataset_response_201 import PostApiV1DatasetResponse201
from celine.superset.cli.openapi.superset_client.models.database_rest_api_post import DatabaseRestApiPost
from celine.superset.cli.openapi.superset_client.models.dataset_rest_api_post import DatasetRestApiPost
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
        api_client = self._get_api_client()
        list_module = _list_module(resource)
        kwargs = list_module._get_kwargs()
        kwargs.setdefault("params", {})["q"] = "(page_size:200)"
        raw = api_client.get_httpx_client().request(**kwargs)
        resp = list_module._build_response(client=api_client, response=raw)
        if raw.is_error:
            msg = getattr(resp.parsed, "message", raw.text)
            raise RuntimeError(f"list {resource} failed: HTTP {resp.status_code} — {msg}")
        return [
            {
                "id": r["id"],
                "name": (
                    r.get("dashboard_title")
                    or r.get("slice_name")
                    or r.get("table_name", "")
                ),
            }
            for r in raw.json().get("result", [])
        ]

    # ------------------------------------------------------------------
    # Export (ZIP bundle)
    # ------------------------------------------------------------------

    def export(self, resource: str, ids: list[int]) -> bytes:
        # Superset export endpoint uses Rison array syntax: !(1,2,3)
        # The `q` param is not in the OpenAPI spec, so we inject it manually
        # on top of the generated _get_kwargs() infrastructure.
        api_client = self._get_api_client()
        module = _export_module(resource)
        kwargs = module._get_kwargs()
        kwargs.setdefault("params", {})["q"] = f"!({','.join(str(i) for i in ids)})"
        raw = api_client.get_httpx_client().request(**kwargs)
        resp = module._build_response(client=api_client, response=raw)
        if raw.is_error:
            msg = getattr(resp.parsed, "message", raw.text)
            raise RuntimeError(f"export {resource} failed: HTTP {resp.status_code} — {msg}")
        return raw.content

    # ------------------------------------------------------------------
    # Import (ZIP bundle) — type-agnostic assets endpoint
    # ------------------------------------------------------------------

    def import_assets(self, zip_bytes: bytes, passwords: dict[str, str] | None = None) -> str:
        """Import any Superset asset bundle. passwords keys are ZIP-relative DB paths."""
        self._ensure_csrf()
        api_client = self._get_api_client()
        file = File(payload=BytesIO(zip_bytes), file_name="bundle.zip", mime_type="application/zip")
        body = PostApiV1AssetsImportBody(
            bundle=file,
            passwords=json.dumps(passwords) if passwords else UNSET,
        )
        resp = post_api_v1_assets_import.sync_detailed(client=api_client, body=body)
        if not isinstance(resp.parsed, PostApiV1AssetsImportResponse200):
            msg = getattr(resp.parsed, "message", resp.content.decode())
            raise RuntimeError(f"import assets failed: HTTP {resp.status_code} — {msg}")
        return resp.parsed.message if not isinstance(resp.parsed.message, Unset) else "ok"

    # ------------------------------------------------------------------
    # Bootstrap helpers
    # ------------------------------------------------------------------

    def ensure_database(self, db_name: str, sqlalchemy_uri: str) -> int:
        """Return existing DB ID matched by name, or create it and return the new ID."""
        api_client = self._get_api_client()
        list_resp = get_api_v1_database.sync_detailed(client=api_client)
        if isinstance(list_resp.parsed, GetApiV1DatabaseResponse200) and not isinstance(list_resp.parsed.result, Unset):
            for db in list_resp.parsed.result:
                if db.database_name == db_name and not isinstance(db.id, Unset):
                    return db.id
        self._ensure_csrf()
        body = DatabaseRestApiPost(
            database_name=db_name,
            sqlalchemy_uri=sqlalchemy_uri,
            expose_in_sqllab=True,
        )
        resp = post_api_v1_database.sync_detailed(client=api_client, body=body)
        if not isinstance(resp.parsed, PostApiV1DatabaseResponse201):
            raise RuntimeError(
                f"Failed to create database {db_name!r}: HTTP {resp.status_code} — {resp.content.decode()}"
            )
        if isinstance(resp.parsed.id, Unset):
            raise RuntimeError(f"No id in create-database response for {db_name!r}")
        return int(resp.parsed.id)

    def list_schema_tables(self, db_id: int, schema: str) -> list[str]:
        """Return table names visible in the given schema.

        schema_name is not in the OpenAPI spec so we pass it via the underlying
        authenticated httpx session to keep the same auth/session state.
        """
        api_client = self._get_api_client()
        kwargs = get_api_v1_database_pk_tables._get_kwargs(pk=db_id)
        kwargs.setdefault("params", {})["q"] = f"(schema_name:{schema},force:!f)"
        raw = api_client.get_httpx_client().request(**kwargs)
        if raw.is_error:
            raise RuntimeError(
                f"list_schema_tables failed: HTTP {raw.status_code} — {raw.text}"
            )
        # Use raw JSON: generated from_dict crashes on null `extra` fields
        return [r["value"] for r in raw.json().get("result", []) if r.get("value")]

    def list_schema_datasets(self, schema: str) -> set[str]:
        """Return table names that already have a dataset registered in the given schema."""
        http = self._get_api_client().get_httpx_client()
        resp = http.get("/api/v1/dataset/", params={"q": "(page_size:1000)"})
        if resp.is_error:
            raise RuntimeError(f"list_schema_datasets failed: HTTP {resp.status_code} — {resp.text}")
        # Use raw JSON: generated from_dict is fragile on certain field shapes
        return {r["table_name"] for r in resp.json().get("result", []) if r.get("schema") == schema}

    def create_dataset(self, db_id: int, schema: str, table: str) -> int:
        """Create a dataset for a table and return its Superset ID."""
        self._ensure_csrf()
        api_client = self._get_api_client()
        body = DatasetRestApiPost(database=db_id, schema=schema, table_name=table)
        resp = post_api_v1_dataset.sync_detailed(client=api_client, body=body)
        if resp.status_code != 201 or not isinstance(resp.parsed, PostApiV1DatasetResponse201):
            raise RuntimeError(
                f"Failed to create dataset {schema}.{table}: HTTP {resp.status_code} — {resp.content.decode()}"
            )
        created = resp.parsed
        if isinstance(created.id, Unset):
            raise RuntimeError(f"No id in create-dataset response for {schema}.{table}")
        return int(created.id)

    # ------------------------------------------------------------------
    # Governance: groups
    # ------------------------------------------------------------------

    def list_groups(self) -> list[dict]:
        """Return all Superset security groups as raw dicts."""
        http = self._get_api_client().get_httpx_client()
        resp = http.get("/api/v1/security/groups/", params={"q": "(page_size:1000)"})
        if resp.is_error:
            raise RuntimeError(f"list_groups failed: HTTP {resp.status_code} — {resp.text}")
        return resp.json().get("result", [])

    def ensure_group(
        self,
        name: str,
        label: str | None = None,
        description: str | None = None,
    ) -> tuple[int, bool]:
        """Return (group_id, was_created). Idempotent — skips creation if name already exists."""
        for g in self.list_groups():
            if g.get("name") == name:
                return int(g["id"]), False
        self._ensure_csrf()
        payload: dict = {"name": name}
        if label:
            payload["label"] = label
        if description:
            payload["description"] = description
        http = self._get_api_client().get_httpx_client()
        resp = http.post("/api/v1/security/groups/", json=payload)
        if resp.is_error:
            raise RuntimeError(
                f"Failed to create group {name!r}: HTTP {resp.status_code} — {resp.text}"
            )
        return int(resp.json()["id"]), True

    def update_group_roles(self, group_id: int, role_ids: list[int]) -> None:
        """Replace the role list on an existing group."""
        http = self._get_api_client().get_httpx_client()
        info = http.get(f"/api/v1/security/groups/{group_id}")
        if info.is_error:
            raise RuntimeError(f"get group {group_id} failed: HTTP {info.status_code}")
        name = info.json()["result"]["name"]
        self._ensure_csrf()
        resp = http.put(f"/api/v1/security/groups/{group_id}", json={"name": name, "roles": role_ids})
        if resp.is_error:
            raise RuntimeError(
                f"update_group_roles group={group_id} failed: HTTP {resp.status_code} — {resp.text}"
            )

    # ------------------------------------------------------------------
    # Governance: roles
    # ------------------------------------------------------------------

    def list_roles(self) -> list[dict]:
        """Return all Superset roles as raw dicts [{id, name}]."""
        http = self._get_api_client().get_httpx_client()
        resp = http.get("/api/v1/security/roles/", params={"q": "(page_size:1000)"})
        if resp.is_error:
            raise RuntimeError(f"list_roles failed: HTTP {resp.status_code} — {resp.text}")
        return resp.json().get("result", [])

    def delete_role(self, role_id: int) -> None:
        """Delete a role by id."""
        self._ensure_csrf()
        http = self._get_api_client().get_httpx_client()
        resp = http.delete(f"/api/v1/security/roles/{role_id}")
        if resp.is_error:
            raise RuntimeError(f"delete_role {role_id} failed: HTTP {resp.status_code} — {resp.text}")

    def ensure_role(self, name: str) -> tuple[int, bool]:
        """Return (role_id, was_created). Idempotent."""
        for r in self.list_roles():
            if r.get("name") == name:
                return int(r["id"]), False
        self._ensure_csrf()
        http = self._get_api_client().get_httpx_client()
        resp = http.post("/api/v1/security/roles/", json={"name": name})
        if resp.is_error:
            raise RuntimeError(
                f"Failed to create role {name!r}: HTTP {resp.status_code} — {resp.text}"
            )
        return int(resp.json()["id"]), True

    # ------------------------------------------------------------------
    # Governance: datasets + permissions
    # ------------------------------------------------------------------

    def list_datasets_full(self) -> list[dict]:
        """Return [{id, table_name, schema}] for all registered datasets."""
        http = self._get_api_client().get_httpx_client()
        resp = http.get("/api/v1/dataset/", params={"q": "(page_size:1000)"})
        if resp.is_error:
            raise RuntimeError(f"list_datasets_full failed: HTTP {resp.status_code} — {resp.text}")
        return [
            {"id": r["id"], "table_name": r.get("table_name", ""), "schema": r.get("schema", "")}
            for r in resp.json().get("result", [])
        ]

    def update_dataset_extra(self, dataset_id: int, extra_update: dict) -> None:
        """Merge extra_update into the dataset's existing extra JSON and PUT it back."""
        http = self._get_api_client().get_httpx_client()
        info = http.get(f"/api/v1/dataset/{dataset_id}")
        if info.is_error:
            raise RuntimeError(f"get dataset {dataset_id} failed: HTTP {info.status_code}")
        raw_extra = info.json().get("result", {}).get("extra") or "{}"
        try:
            current_extra = json.loads(raw_extra)
        except (json.JSONDecodeError, TypeError):
            current_extra = {}
        current_extra.update(extra_update)
        self._ensure_csrf()
        resp = http.put(f"/api/v1/dataset/{dataset_id}", json={"extra": json.dumps(current_extra)})
        if resp.is_error:
            raise RuntimeError(
                f"update_dataset_extra dataset={dataset_id} failed: HTTP {resp.status_code} — {resp.text}"
            )

    # ------------------------------------------------------------------
    # Governance: role permissions
    # ------------------------------------------------------------------

    def get_role_permission_ids(self, role_id: int) -> list[int]:
        """Return PVM ids assigned to a role."""
        http = self._get_api_client().get_httpx_client()
        resp = http.get(f"/api/v1/security/roles/{role_id}/permissions/")
        if resp.is_error:
            raise RuntimeError(f"get_role_permissions {role_id} failed: HTTP {resp.status_code} — {resp.text}")
        return [item["id"] for item in resp.json().get("result", [])]

    def set_role_permissions(self, role_id: int, perm_ids: list[int]) -> None:
        """Replace the permission set on a role."""
        self._ensure_csrf()
        http = self._get_api_client().get_httpx_client()
        resp = http.post(
            f"/api/v1/security/roles/{role_id}/permissions",
            json={"permission_view_menu_ids": perm_ids},
        )
        if resp.is_error:
            raise RuntimeError(f"set_role_permissions {role_id} failed: HTTP {resp.status_code} — {resp.text}")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self._api_client is not None:
            self._api_client.get_httpx_client().close()


def _export_module(resource: str):
    if resource == "dashboard":
        return get_api_v1_dashboard_export
    if resource == "chart":
        return get_api_v1_chart_export
    if resource == "dataset":
        return get_api_v1_dataset_export
    raise ValueError(f"Unknown resource: {resource!r}")


def _list_module(resource: str):
    if resource == "dashboard":
        return get_api_v1_dashboard
    if resource == "chart":
        return get_api_v1_chart
    if resource == "dataset":
        return get_api_v1_dataset
    raise ValueError(f"Unknown resource: {resource!r}")


