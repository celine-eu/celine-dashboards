"""
celine-superset CLI

Auth: KC client credentials → Bearer on every request (oauth2_proxy bypass).
Superset's before_request hook validates the KC JWT and logs in the service
account with Admin role (requires CUSTOM_SECURITY_MANAGER_CLI_ADMIN_AZP=celine-cli).

Examples:
  celine-superset dashboard list
  celine-superset dashboard export 12 34 --output prod-dashboards.zip
  celine-superset dashboard import prod-dashboards.zip

  celine-superset generate --output-path ./superset-client

  # Override target instance
  SUPERSET_URL=https://superset.prod \\
  SUPERSET_KC_CLIENT_SECRET=xxx \\
    celine-superset dashboard list

Environment variables (or ~/.config/celine-superset/config.yaml):
  SUPERSET_URL                default: http://superset.celine.localhost
  SUPERSET_KC_ISSUER_URL      default: http://keycloak.celine.localhost/realms/celine
  SUPERSET_KC_CLIENT_ID       default: celine-cli
  SUPERSET_KC_CLIENT_SECRET   default: celine-cli
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console

from celine.superset.cli.client import KcTokenProvider, SupersetClient
from celine.superset.cli.config import Settings, get_settings
from celine.superset.cli.resources import charts, dashboards, datasets

app = typer.Typer(
    name="celine-superset",
    help="Import/export Superset resources across environments.",
    no_args_is_help=True,
)

app.add_typer(dashboards.app, name="dashboard")
app.add_typer(charts.app, name="chart")
app.add_typer(datasets.app, name="dataset")

_console = Console()


@app.callback()
def main(
    ctx: typer.Context,
    url: Optional[str] = typer.Option(None, "--url", envvar="SUPERSET_URL"),
    kc_issuer_url: Optional[str] = typer.Option(None, "--kc-issuer-url", envvar="SUPERSET_KC_ISSUER_URL"),
    kc_client_id: Optional[str] = typer.Option(None, "--kc-client-id", envvar="SUPERSET_KC_CLIENT_ID"),
    kc_client_secret: Optional[str] = typer.Option(None, "--kc-client-secret", envvar="SUPERSET_KC_CLIENT_SECRET"),
    no_verify_ssl: bool = typer.Option(False, "--no-verify-ssl", help="Disable TLS verification"),
):
    settings = get_settings()
    if url:
        settings.url = url
    if kc_issuer_url:
        settings.kc_issuer_url = kc_issuer_url
    if kc_client_id:
        settings.kc_client_id = kc_client_id
    if kc_client_secret:
        settings.kc_client_secret = kc_client_secret
    if no_verify_ssl:
        settings.verify_ssl = False

    ctx.ensure_object(dict)
    ctx.obj = SupersetClient(settings)
    ctx.meta["settings"] = settings


_OPENAPI_DIR = Path(__file__).parent / "openapi"


@app.command()
def generate(
    ctx: typer.Context,
    overwrite: bool = typer.Option(True, "--overwrite/--no-overwrite", help="Overwrite existing generated client."),
):
    """Fetch the Superset OpenAPI spec and regenerate the typed client in openapi/superset_client/."""
    settings: Settings = ctx.meta["settings"]

    _console.print(f"[bold]Authenticating[/bold] against {settings.kc_issuer_url} …")
    kc = KcTokenProvider(settings)
    token = kc.get_token()
    auth_headers = {"Authorization": f"Bearer {token}"}

    superset_version = _fetch_superset_version(settings, auth_headers)
    _console.print(f"Superset version: [cyan]{superset_version}[/cyan]")

    spec_url = f"{settings.url}/api/v1/_openapi"
    _console.print(f"[bold]Fetching OpenAPI spec[/bold] from {spec_url} …")
    resp = httpx.get(spec_url, headers=auth_headers, verify=settings.verify_ssl, timeout=30)
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        _console.print(f"[red]Failed to fetch OpenAPI spec:[/red] {exc}")
        raise typer.Exit(1) from exc

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
        json.dump(resp.json(), tmp)
        tmp_path = tmp.name

    # Superset's spec has duplicate timezone enum values (e.g. GMT0);
    # literal_enums emits Literal["GMT0"] instead of a deduped Enum class.
    with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as cfg:
        cfg.write("literal_enums: true\n")
        cfg_path = cfg.name

    with tempfile.TemporaryDirectory() as gen_dir:
        cmd = [
            "openapi-python-client",
            "generate",
            "--path", tmp_path,
            "--config", cfg_path,
            "--output-path", gen_dir,
            "--overwrite",
        ]
        _console.print("[bold]Generating client[/bold] …")
        result = subprocess.run(cmd, capture_output=False)
        if result.returncode != 0:
            raise typer.Exit(result.returncode)

        # Copy only the generated package into openapi/superset_client/,
        # leaving openapi/__init__.py and _superset_version.txt untouched.
        src_pkg = Path(gen_dir) / "superset_client"
        dst_pkg = _OPENAPI_DIR / "superset_client"
        if dst_pkg.exists() and overwrite:
            shutil.rmtree(dst_pkg)
        shutil.copytree(src_pkg, dst_pkg)

    _OPENAPI_DIR.mkdir(parents=True, exist_ok=True)
    init = _OPENAPI_DIR / "__init__.py"
    if not init.exists():
        init.write_text("")
    (_OPENAPI_DIR / "_superset_version.txt").write_text(f"{superset_version}\n")
    _console.print(f"[green]Client generated at[/green] {_OPENAPI_DIR / 'superset_client'} (Superset {superset_version})")


def _fetch_superset_version(settings: Settings, headers: dict) -> str:
    try:
        resp = httpx.get(
            f"{settings.url}/api/v1/",
            headers=headers,
            verify=settings.verify_ssl,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("version", "unknown")
    except Exception:
        return "unknown"


if __name__ == "__main__":
    app()
