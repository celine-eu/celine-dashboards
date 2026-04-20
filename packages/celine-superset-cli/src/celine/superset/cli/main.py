"""
celine-superset CLI

Auth: KC client credentials → Bearer on every request (oauth2_proxy bypass).

Examples:
  celine-superset --env=dev list dashboard
  celine-superset --env=staging export dashboard 1 2
  celine-superset --env=dev import data/staging/dashboard_1_2.zip

  celine-superset --env=dev bootstrap
  celine-superset generate

Environment / instances.yaml:
  Run `celine-superset bootstrap` to initialise instances.yaml for an env.
  Copy instances.example.yaml → instances.yaml and fill in secrets.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from enum import Enum
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich import print as rprint

from celine.superset.cli.client import KcTokenProvider, SupersetClient

from celine.superset.cli.config import (
    INSTANCES_FILE,
    InstanceConfig,
    Settings,
    get_instance_settings,
    write_instance,
)
from celine.superset.cli.governance import (
    OwnersRegistry,
    collect_sources,
    expand_globs,
    load_governance_file,
    load_owners_yaml,
    parse_source_key,
)

app = typer.Typer(
    name="celine-superset",
    help="Manage Superset resources across environments.",
    no_args_is_help=True,
)

_console = Console()


class Resource(str, Enum):
    dashboard = "dashboard"
    chart = "chart"
    dataset = "dataset"


@app.callback()
def main(
    ctx: typer.Context,
    env: str = typer.Option("dev", "--env", envvar="SUPERSET_ENV", help="Target instance from instances.yaml"),
    no_verify_ssl: bool = typer.Option(False, "--no-verify-ssl", help="Disable TLS verification"),
):
    settings, passwords = get_instance_settings(env)
    if no_verify_ssl:
        settings = settings.model_copy(update={"verify_ssl": False})
    ctx.ensure_object(dict)
    ctx.obj = SupersetClient(settings)
    ctx.meta["settings"] = settings
    ctx.meta["passwords"] = passwords
    ctx.meta["env"] = env


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@app.command("list")
def list_resources(
    ctx: typer.Context,
    resource: Resource = typer.Argument(..., help="Resource type to list"),
):
    """List available resources on the target instance."""
    client: SupersetClient = ctx.obj
    items = client.list_ids(resource.value)
    for item in items:
        rprint(f"[cyan]{item['id']:>5}[/cyan]  {item['name']}")


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

@app.command("export")
def export_resources(
    ctx: typer.Context,
    resource: Resource = typer.Argument(..., help="Resource type"),
    ids: list[int] = typer.Argument(..., help="Resource IDs to export"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Override output path"),
):
    """Export resources to a ZIP bundle.

    Default output: data/{env}/{resource}_{ids}.zip
    """
    client: SupersetClient = ctx.obj
    env: str = ctx.meta["env"]
    if output is None:
        ids_str = "_".join(str(i) for i in ids)
        output = Path("data") / env / f"{resource.value}_{ids_str}.zip"
    output.parent.mkdir(parents=True, exist_ok=True)
    data = client.export(resource.value, ids)
    output.write_bytes(data)
    rprint(f"[green]Exported {len(ids)} {resource.value}(s) → {output}[/green]")


# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------

@app.command(name="import")
def import_bundle(
    ctx: typer.Context,
    bundle: Path = typer.Argument(..., help="ZIP bundle to import"),
):
    """Import an asset bundle into the target instance.

    Database passwords are read from instances.yaml for the target env.
    """
    client: SupersetClient = ctx.obj
    passwords: dict[str, str] = ctx.meta["passwords"]
    msg = client.import_assets(bundle.read_bytes(), passwords or None)
    rprint(f"[green]Imported {bundle.name}:[/green] {msg}")


# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------

@app.command("bootstrap")
def bootstrap(
    ctx: typer.Context,
    db_name: Optional[str] = typer.Option(None, "--db-name", envvar="SUPERSET_BOOTSTRAP_DB_NAME"),
    db_uri: Optional[str] = typer.Option(None, "--db-uri", envvar="SUPERSET_BOOTSTRAP_DB_URI"),
    db_schema: Optional[str] = typer.Option(None, "--db-schema", envvar="SUPERSET_BOOTSTRAP_DB_SCHEMA"),
    write_config: bool = typer.Option(True, "--write-config/--no-write-config",
                                      help="Write/update instances.yaml for this env"),
):
    """Idempotently configure Superset and write the instance config.

    Steps:
      1. Create (or locate) the database connection.
      2. Scan all tables in the target schema.
      3. Register each table as a dataset (skips existing).
      4. Write/update instances.yaml for this env.
    """
    client: SupersetClient = ctx.obj
    settings: Settings = ctx.meta["settings"]
    env: str = ctx.meta["env"]

    resolved_db_name = db_name or settings.bootstrap_db_name
    resolved_db_uri = db_uri or settings.bootstrap_db_uri
    schema = db_schema or settings.bootstrap_db_schema

    _console.print(
        f"[bold]Bootstrap[/bold] env=[cyan]{env}[/cyan] "
        f"db=[cyan]{resolved_db_name}[/cyan] schema=[cyan]{schema}[/cyan]"
    )

    db_id = client.ensure_database(resolved_db_name, resolved_db_uri)
    _console.print(f"  Database id=[green]{db_id}[/green]")

    tables = client.list_schema_tables(db_id, schema)
    if not tables:
        _console.print(f"[yellow]No tables found in schema [bold]{schema}[/bold].[/yellow]")
        raise typer.Exit(0)

    _console.print(f"  Found [cyan]{len(tables)}[/cyan] table(s) in [bold]{schema}[/bold]")

    existing = client.list_schema_datasets(schema)
    created = skipped = 0
    for table in tables:
        if table in existing:
            _console.print(f"    [dim]skip[/dim]  {table}")
            skipped += 1
        else:
            client.create_dataset(db_id, schema, table)
            _console.print(f"    [green]add[/green]   {table}")
            created += 1

    _console.print(f"\n[bold]Done:[/bold] {created} created, {skipped} already existed")

    if write_config:
        cfg = InstanceConfig(
            url=settings.url,
            kc_issuer_url=settings.kc_issuer_url,
            kc_client_id=settings.kc_client_id,
            kc_client_secret=settings.kc_client_secret,
            verify_ssl=settings.verify_ssl if not settings.verify_ssl else None,
            bootstrap_db_name=resolved_db_name,
            bootstrap_db_uri=resolved_db_uri,
            bootstrap_db_schema=schema,
        )
        write_instance(env, cfg)
        _console.print(f"[dim]Instance '{env}' written to {INSTANCES_FILE}[/dim]")


# ---------------------------------------------------------------------------
# generate (OpenAPI client regeneration)
# ---------------------------------------------------------------------------

_OPENAPI_DIR = Path(__file__).parent / "openapi"


@app.command()
def generate(
    ctx: typer.Context,
    overwrite: bool = typer.Option(True, "--overwrite/--no-overwrite"),
):
    """Fetch the Superset OpenAPI spec and regenerate the typed client."""
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
        _console.print(f"[red]Failed to fetch OpenAPI spec:[/red] {exc}\n{exc.response.text}")
        raise typer.Exit(1) from exc

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
        json.dump(resp.json(), tmp)
        tmp_path = tmp.name

    with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as cfg:
        cfg.write("literal_enums: true\n")
        cfg_path = cfg.name

    with tempfile.TemporaryDirectory() as gen_dir:
        cmd = [
            "openapi-python-client", "generate",
            "--path", tmp_path,
            "--config", cfg_path,
            "--output-path", gen_dir,
            "--overwrite",
        ]
        _console.print("[bold]Generating client[/bold] …")
        result = subprocess.run(cmd, capture_output=False)
        if result.returncode != 0:
            raise typer.Exit(result.returncode)

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


# ---------------------------------------------------------------------------
# governance sub-app
# ---------------------------------------------------------------------------

_governance_app = typer.Typer(
    name="governance",
    help="Sync governance.yaml / owners.yaml rules to Superset.",
    no_args_is_help=True,
)
app.add_typer(_governance_app)


_ORG_LEVELS = ("viewers", "editors", "managers", "admins")

# celine:* base role → (built-in seed role, description)
_CELINE_BASE_ROLES: dict[str, tuple[str, str]] = {
    "celine:viewers":  ("Gamma", "read-only dashboard browsing"),
    "celine:editors":  ("Alpha", "edit existing dashboards/charts"),
    "celine:managers": ("Alpha", "create/delete dashboards/charts"),
    "celine:admins":   ("Alpha", "all of above + dataset management"),
}

# org level suffix → celine:* base role
_LEVEL_TO_BASE: dict[str, str] = {
    "viewers": "celine:viewers",
    "editors": "celine:editors",
    "managers": "celine:managers",
    "admins": "celine:admins",
}


def _sync_celine_roles_and_org_permissions(
    client,
    org_slugs: list[str],
    dry_run: bool = False,
) -> None:
    """Seed celine:* base roles and propagate permissions to org:<slug>:* roles.

    Idempotent: celine:* roles that already have permissions are left untouched so
    that manually-tuned permission sets survive re-runs.
    """
    all_roles = {r["name"]: r["id"] for r in client.list_roles()}
    gamma_id = all_roles.get("Gamma")
    alpha_id = all_roles.get("Alpha")
    if gamma_id is None or alpha_id is None:
        _console.print("[yellow]  warn: Gamma/Alpha roles not found — skipping permission seeding[/yellow]")
        return

    seed_perms = {"Gamma": client.get_role_permission_ids(gamma_id),
                  "Alpha": client.get_role_permission_ids(alpha_id)}

    celine_perm_ids: dict[str, list[int]] = {}
    for role_name, (seed_role, desc) in _CELINE_BASE_ROLES.items():
        rid, created = client.ensure_role(role_name)
        existing = client.get_role_permission_ids(rid)
        if existing:
            celine_perm_ids[role_name] = existing
            tag = "[green]created[/green]" if created else "[dim]exists [/dim]"
            _console.print(f"    {tag}  {role_name}  ({desc})")
        else:
            perms = seed_perms[seed_role]
            celine_perm_ids[role_name] = perms
            if dry_run:
                _console.print(f"    [dim]dry-run[/dim]  {role_name}  ← {len(perms)} pvm(s) from {seed_role}")
            else:
                client.set_role_permissions(rid, perms)
                _console.print(f"    [green]seeded [/green]  {role_name}  {len(perms)} pvm(s)  ({desc})")

    if not org_slugs:
        return

    # Re-fetch roles after potential creation above
    all_roles_fresh = {r["name"]: r["id"] for r in client.list_roles()}
    for slug in sorted(org_slugs):
        for level, base_role in _LEVEL_TO_BASE.items():
            role_name = f"org:{slug}:{level}"
            rid = all_roles_fresh.get(role_name)
            if rid is None:
                continue
            perm_ids = celine_perm_ids[base_role]
            if dry_run:
                _console.print(f"    [dim]dry-run[/dim]  {role_name}  ← {len(perm_ids)} pvm(s) from {base_role}")
            else:
                client.set_role_permissions(rid, perm_ids)
                _console.print(f"    [dim]propagated[/dim]  {role_name}  {len(perm_ids)} pvm(s)")


@_governance_app.command("sync")
def governance_sync(
    ctx: typer.Context,
    paths: list[str] = typer.Option(
        ...,
        "--path",
        help="Glob pattern(s) for governance.yaml files. Repeatable.",
    ),
    owners_paths: Optional[list[str]] = typer.Option(
        None,
        "--owners",
        help="Path(s) to owners.yaml files for alias resolution. Repeatable.",
    ),
    filter_pattern: Optional[str] = typer.Option(
        None,
        "--filter",
        help="fnmatch pattern applied to governance source keys (e.g. 'ds_dev_gold.*').",
    ),
    cleanup: bool = typer.Option(True, "--cleanup/--no-cleanup",
                                  help="Remove stale org:* roles not in the current managed set."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print plan without making changes."),
):
    """Sync governance.yaml ownership blocks to Superset groups, roles, and dataset tags.

    For every unique owner alias found in filtered governance sources:
      1. Ensures a Superset security group exists (named by owner alias).
      2. Ensures four org-level roles: org:<alias>:viewer/editor/manager/admin.
      3. Links all four roles to the group.
      4. Tags each dataset's extra.org_slugs so datasource_access can enforce access.

    access_level mapping:
      open       → dataset tagged org_slugs=[] — any authenticated user sees it
      internal   → dataset tagged org_slugs=[owner] — only that org's members see it
      restricted → same as internal
      secret     → skipped entirely

    Run `governance setup-permissions` afterwards to assign Superset feature permissions
    to the org-level roles based on Gamma (viewer) and Alpha (editor/manager/admin).

    Example:
      celine-superset governance sync \\
        --path '../**/governance.yaml' \\
        --path '../../../../**/governance.yaml' \\
        --owners owners.local.yaml \\
        --filter 'ds_dev_gold.*'
    """
    from pathlib import Path as _Path

    client: SupersetClient = ctx.obj

    # 1. Expand governance globs and load files
    gov_files = expand_globs(paths)
    if not gov_files:
        _console.print("[yellow]No governance.yaml files matched the given patterns.[/yellow]")
        raise typer.Exit(0)
    _console.print(f"Found [cyan]{len(gov_files)}[/cyan] governance file(s).")

    configs = []
    for gf in gov_files:
        try:
            configs.append(load_governance_file(gf))
            _console.print(f"  [dim]loaded[/dim] {gf}")
        except Exception as exc:
            _console.print(f"  [red]error[/red] loading {gf}: {exc}")

    # 2. Collect matching sources
    sources = collect_sources(configs, filter_pattern)
    if not sources:
        _console.print("[yellow]No sources matched the filter.[/yellow]")
        raise typer.Exit(0)
    _console.print(
        f"Matched [cyan]{len(sources)}[/cyan] source(s)"
        + (f" with filter [bold]{filter_pattern}[/bold]" if filter_pattern else "")
        + "."
    )

    # 3. Collect unique owner aliases → source keys + whether they own any restricted data
    owner_sources: dict[str, set[str]] = {}
    owner_has_restricted: set[str] = set()
    for key, rule in sources.items():
        level = rule.access_level or "internal"
        for owner in rule.ownership:
            owner_sources.setdefault(owner.name, set()).add(key)
            if level in ("internal", "restricted"):
                owner_has_restricted.add(owner.name)

    if not owner_sources:
        _console.print("[yellow]No ownership blocks found in matched sources.[/yellow]")
        raise typer.Exit(0)

    # 4. Load owners registry for label resolution
    registry = OwnersRegistry([])
    if owners_paths:
        for op in expand_globs(owners_paths):
            try:
                registry = load_owners_yaml(_Path(op))
                _console.print(f"  [dim]owners[/dim]  {op}")
                break
            except Exception as exc:
                _console.print(f"  [yellow]warn[/yellow] could not load {op}: {exc}")

    # 5. Sync groups + four org-level roles per owner
    _console.print(
        f"\n{'[dim][dry-run][/dim] ' if dry_run else ''}"
        f"[bold]Syncing [cyan]{len(owner_sources)}[/cyan] owner(s)[/bold]"
    )

    groups_created = roles_created = 0

    for alias in sorted(owner_sources):
        entry = registry.by_id(alias)
        label = entry.name if entry else None
        description = entry.url if entry else None
        is_open_only = alias not in owner_has_restricted

        if dry_run:
            if is_open_only:
                _console.print(
                    f"  [dim]dry-run[/dim]  [dim]{alias}[/dim]  (open-only — no roles)"
                    + (f"  ({label})" if label else "")
                )
            else:
                role_names = [f"org:{alias}:{lvl}" for lvl in _ORG_LEVELS]
                _console.print(
                    f"  [dim]dry-run[/dim]  group=[bold]{alias}[/bold]"
                    f"  roles={role_names}"
                    + (f"  ({label})" if label else "")
                    + f"  ← {len(owner_sources[alias])} source(s)"
                )
        else:
            if is_open_only:
                _console.print(f"  [dim]skip roles[/dim]  [bold]{alias}[/bold]  (open-only)")
                continue
            gid, g_new = client.ensure_group(alias, label=label, description=description)
            level_ids: list[int] = []
            for level in _ORG_LEVELS:
                rid, r_new = client.ensure_role(f"org:{alias}:{level}")
                level_ids.append(rid)
                if r_new:
                    roles_created += 1
            client.update_group_roles(gid, level_ids)
            g_tag = "[green]created[/green]" if g_new else "[dim]exists [/dim]"
            _console.print(
                f"  group {g_tag} [bold]{alias}[/bold] id={gid}"
                f"  roles={[f'org:{alias}:{lvl}' for lvl in _ORG_LEVELS]}"
                + (f"  ({label})" if label else "")
            )
            if g_new:
                groups_created += 1

    # 6. Remove stale org:* roles not in the current managed set
    _VALID_ORG_LEVELS = frozenset(_ORG_LEVELS)
    expected_org_roles: set[str] = {
        f"org:{alias}:{lvl}"
        for alias in owner_sources
        if alias in owner_has_restricted
        for lvl in _ORG_LEVELS
    }

    if cleanup:
        roles_deleted = 0
        if dry_run:
            _console.print("\n[bold]Stale org:* roles (dry-run):[/bold]")
        else:
            _console.print("\n[bold]Cleaning up stale org:* roles…[/bold]")
        for role in client.list_roles():
            name = role["name"]
            parts = name.split(":")
            if not (len(parts) == 3 and parts[0] == "org" and parts[2] in _VALID_ORG_LEVELS):
                continue
            if name in expected_org_roles:
                continue
            if dry_run:
                _console.print(f"  [dim]would delete[/dim]  {name}")
            else:
                client.delete_role(int(role["id"]))
                _console.print(f"  [red]deleted[/red]  {name}")
                roles_deleted += 1
        if not dry_run and roles_deleted == 0:
            _console.print("  [dim]nothing to clean up[/dim]")

    # 7. Tag datasets with org_slugs for datasource_access enforcement
    level_counts: dict[str, int] = {}
    for rule in sources.values():
        lvl = rule.access_level or "internal"
        level_counts[lvl] = level_counts.get(lvl, 0) + 1

    level_summary = "  ".join(
        f"[cyan]{count}[/cyan] {lvl}" for lvl, count in sorted(level_counts.items())
    )
    _console.print(f"\n[bold]Tagging datasets…[/bold]  ({level_summary})")

    if dry_run:
        for source_key, rule in sorted(sources.items()):
            level = rule.access_level or "internal"
            if level == "secret":
                continue
            owners_list = [o.name for o in rule.ownership]
            _console.print(
                f"  [dim]{level:10}[/dim]  {source_key}"
                + (f"  owners={owners_list}" if owners_list else "  [yellow](no owners)[/yellow]")
            )
        _console.print(f"\n[dim][dry-run] no changes made.[/dim]")
        return

    all_datasets = client.list_datasets_full()
    dataset_map: dict[tuple[str, str], int] = {
        (d["schema"], d["table_name"]): d["id"] for d in all_datasets
    }

    # dataset_id → org_slugs ([] = open, [...] = org-restricted)
    dataset_org_slugs: dict[int, list[str]] = {}
    unmatched_count = 0

    for source_key, rule in sorted(sources.items()):
        level = rule.access_level or "internal"
        if level == "secret":
            continue

        parsed = parse_source_key(source_key)
        if parsed is None:
            continue
        schema, table = parsed

        dataset_id = dataset_map.get((schema, table))
        if dataset_id is None:
            unmatched_count += 1
            _console.print(f"  [yellow]skip[/yellow]  {source_key}  — not found in Superset (run bootstrap)")
            continue

        if level == "open":
            dataset_org_slugs.setdefault(dataset_id, [])
            continue

        for owner in rule.ownership:
            slugs = dataset_org_slugs.setdefault(dataset_id, [])
            if owner.name not in slugs:
                slugs.append(owner.name)

    extra_updated = 0
    for ds_id, org_slugs in dataset_org_slugs.items():
        try:
            client.update_dataset_extra(ds_id, {"org_slugs": org_slugs})
            extra_updated += 1
        except Exception as exc:
            _console.print(f"  [yellow]warn:[/yellow] could not tag dataset id={ds_id}: {exc}")

    if unmatched_count:
        _console.print(f"  [yellow]warn:[/yellow] {unmatched_count} source(s) had no matching dataset.")

    # 8. Seed celine:* base roles and propagate to all org roles created above
    managed_org_slugs = sorted(a for a in owner_sources if a in owner_has_restricted)
    _console.print(f"\n[bold]Seeding celine:* base roles and propagating to org roles…[/bold]")
    _sync_celine_roles_and_org_permissions(client, managed_org_slugs, dry_run=dry_run)

    _console.print(
        f"\n[bold]Done:[/bold] {groups_created} group(s) created, {roles_created} role(s) created, "
        f"{extra_updated} dataset(s) tagged"
    )


@_governance_app.command("setup-permissions")
def governance_setup_permissions(
    ctx: typer.Context,
    org_slugs: list[str] = typer.Option(
        [],
        "--org",
        help="Org alias to configure. Repeatable. Use '*' to target all discovered orgs.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print plan without making changes."),
):
    """Seed celine:* base roles and propagate permissions to org-level roles.

    Normally called automatically by `governance sync`. Run manually to re-seed
    after customising celine:* permissions in the Superset UI.

    Step 1 — ensure celine:viewers/editors/managers/admins exist, seeded from
    built-in Gamma (viewers) or Alpha (editors/managers/admins). Already-customised
    roles are left untouched.

    Step 2 — copy each celine:<level> permission set to every matching org:<slug>:<level>
    role. Pass --org <slug> (repeatable) or --org '*' to target all discovered orgs.

    Example:
      celine-superset governance setup-permissions
      celine-superset governance setup-permissions --org '*'
      celine-superset governance setup-permissions --org greenland --org set
    """
    client: SupersetClient = ctx.obj

    resolved_slugs: list[str] = []
    if "*" in org_slugs:
        for role in client.list_roles():
            parts = role["name"].split(":")
            if len(parts) == 3 and parts[0] == "org" and parts[2] == "viewers":
                if parts[1] not in resolved_slugs:
                    resolved_slugs.append(parts[1])
        _console.print(f"Auto-discovered [cyan]{len(resolved_slugs)}[/cyan] org(s): {resolved_slugs}")
    else:
        resolved_slugs = [s for s in org_slugs if s != "*"]

    if org_slugs and not resolved_slugs:
        _console.print("[yellow]No org roles found — run governance sync first.[/yellow]")
        return

    _console.print("[bold]Seeding celine:* base roles and propagating to org roles…[/bold]")
    _sync_celine_roles_and_org_permissions(client, resolved_slugs, dry_run=dry_run)
    if dry_run:
        _console.print("\n[dim][dry-run] no changes made.[/dim]")
    else:
        _console.print("\n[bold]Done.[/bold]")


def _fetch_superset_version(settings: Settings, headers: dict) -> str:
    try:
        resp = httpx.get(f"{settings.url}/api/v1/", headers=headers, verify=settings.verify_ssl, timeout=10)
        resp.raise_for_status()
        return resp.json().get("version", "unknown")
    except Exception:
        return "unknown"


if __name__ == "__main__":
    app()
