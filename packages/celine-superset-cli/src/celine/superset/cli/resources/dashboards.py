from pathlib import Path
import typer
from rich import print as rprint

from celine.superset.cli.client import SupersetClient

app = typer.Typer(help="Manage dashboards")
RESOURCE = "dashboard"


@app.command("list")
def list_dashboards(ctx: typer.Context):
    """List available dashboards."""
    client: SupersetClient = ctx.obj
    items = client.list_ids(RESOURCE)
    for item in items:
        rprint(f"[cyan]{item['id']:>5}[/cyan]  {item['name']}")


@app.command("export")
def export_dashboard(
    ctx: typer.Context,
    ids: list[int] = typer.Argument(..., help="Dashboard IDs to export"),
    output: Path = typer.Option(Path("dashboards.zip"), "--output", "-o"),
):
    """Export dashboards (with linked charts + datasets) to a ZIP bundle."""
    client: SupersetClient = ctx.obj
    data = client.export(RESOURCE, ids)
    output.write_bytes(data)
    rprint(f"[green]Exported {len(ids)} dashboard(s) → {output}[/green]")


@app.command("import")
def import_dashboard(
    ctx: typer.Context,
    bundle: Path = typer.Argument(..., help="ZIP bundle to import"),
    overwrite: bool = typer.Option(True, help="Overwrite existing dashboards"),
):
    """Import dashboards from a ZIP bundle (charts + datasets included)."""
    client: SupersetClient = ctx.obj
    result = client.import_zip(RESOURCE, bundle.read_bytes(), overwrite=overwrite)
    rprint(f"[green]Import result:[/green] {result}")
