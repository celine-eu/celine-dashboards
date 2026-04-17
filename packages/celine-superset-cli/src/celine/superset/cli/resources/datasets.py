from pathlib import Path
import typer
from rich import print as rprint

from celine.superset.cli.client import SupersetClient

app = typer.Typer(help="Manage datasets")
RESOURCE = "dataset"


@app.command("list")
def list_datasets(ctx: typer.Context):
    """List available datasets."""
    client: SupersetClient = ctx.obj
    items = client.list_ids(RESOURCE)
    for item in items:
        rprint(f"[cyan]{item['id']:>5}[/cyan]  {item['name']}")


@app.command("export")
def export_dataset(
    ctx: typer.Context,
    ids: list[int] = typer.Argument(..., help="Dataset IDs to export"),
    output: Path = typer.Option(Path("datasets.zip"), "--output", "-o"),
):
    """Export datasets to a ZIP bundle."""
    client: SupersetClient = ctx.obj
    data = client.export(RESOURCE, ids)
    output.write_bytes(data)
    rprint(f"[green]Exported {len(ids)} dataset(s) → {output}[/green]")


@app.command("import")
def import_dataset(
    ctx: typer.Context,
    bundle: Path = typer.Argument(..., help="ZIP bundle to import"),
    overwrite: bool = typer.Option(True, help="Overwrite existing datasets"),
):
    """Import datasets from a ZIP bundle."""
    client: SupersetClient = ctx.obj
    result = client.import_zip(RESOURCE, bundle.read_bytes(), overwrite=overwrite)
    rprint(f"[green]Import result:[/green] {result}")
