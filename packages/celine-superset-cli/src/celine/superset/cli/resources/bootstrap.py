from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from celine.superset.cli.client import SupersetClient
from celine.superset.cli.config import Settings

_console = Console()


def bootstrap(
    ctx: typer.Context,
    db_name: Optional[str] = typer.Option(
        None,
        "--db-name",
        envvar="SUPERSET_BOOTSTRAP_DB_NAME",
        help="Superset display name for the database connection.",
    ),
    db_uri: Optional[str] = typer.Option(
        None,
        "--db-uri",
        envvar="SUPERSET_BOOTSTRAP_DB_URI",
        help="SQLAlchemy URI for the database (overrides default dev URI).",
    ),
    db_schema: Optional[str] = typer.Option(
        None,
        "--db-schema",
        envvar="SUPERSET_BOOTSTRAP_DB_SCHEMA",
        help="Datasource tables are scanned from this schema.",
    ),
):
    """
    Idempotently configure Superset for local development.

    Steps:
      1. Create (or locate) the database connection.
      2. Scan all tables in the {ds_dev}_gold schema.
      3. Register each table as a Superset dataset (skips existing ones).

    Defaults target the local dev stack. Override via CLI options or env vars:
      SUPERSET_BOOTSTRAP_DB_NAME, SUPERSET_BOOTSTRAP_DB_URI, SUPERSET_BOOTSTRAP_DS_DEV
    """
    client: SupersetClient = ctx.obj
    settings: Settings = ctx.meta["settings"]

    resolved_db_name = db_name or settings.bootstrap_db_name
    resolved_db_uri = db_uri or settings.bootstrap_db_uri
    schema = db_schema or settings.bootstrap_db_schema

    _console.print(
        f"[bold]Bootstrap[/bold] → database [cyan]{resolved_db_name}[/cyan], schema [cyan]{schema}[/cyan]"
    )

    db_id = client.ensure_database(resolved_db_name, resolved_db_uri)
    _console.print(f"  Database id=[green]{db_id}[/green]")

    tables = client.list_schema_tables(db_id, schema)
    if not tables:
        _console.print(
            f"[yellow]No tables found in schema [bold]{schema}[/bold] — nothing to import.[/yellow]"
        )
        raise typer.Exit(0)

    _console.print(
        f"  Found [cyan]{len(tables)}[/cyan] table(s) in [bold]{schema}[/bold]"
    )

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
