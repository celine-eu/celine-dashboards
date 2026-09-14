"""`governance sync` end to end against an in-memory Superset client."""
from pathlib import Path
from textwrap import dedent

import pytest
from typer.testing import CliRunner

import celine.superset.cli.main as main


class FakeClient:
    def __init__(self, datasets, fail_ids=()):
        self.datasets = datasets
        self.fail_ids = set(fail_ids)
        self.extra: dict[int, dict] = {}
        self.roles: dict[str, int] = {"Gamma": 1, "Alpha": 2}

    # datasets
    def list_datasets_full(self):
        return [dict(d) for d in self.datasets]

    def update_dataset_extra(self, dataset_id, extra_update):
        if dataset_id in self.fail_ids:
            raise RuntimeError("HTTP 500")
        self.extra.setdefault(dataset_id, {}).update(extra_update)

    # groups and roles
    def ensure_group(self, name, label=None, description=None):
        return 1, False

    def ensure_role(self, name):
        created = name not in self.roles
        self.roles.setdefault(name, len(self.roles) + 1)
        return self.roles[name], created

    def update_group_roles(self, group_id, role_ids):
        pass

    def list_roles(self):
        return [{"id": rid, "name": name} for name, rid in self.roles.items()]

    def delete_role(self, role_id):
        pass

    def get_role_permission_ids(self, role_id):
        return [1]

    def get_role_permissions_full(self, role_id):
        return [{"id": 1, "permission_name": "can_read"}]

    def set_role_permissions(self, role_id, perm_ids):
        pass


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(text))
    return path


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no instances.yaml → Settings defaults
    _write(tmp_path / "pipelines/apps/rec_metering/governance.yaml", """
        defaults:
          access_level: internal
          ownership: [rec]
        sources:
          datasets.ds_dev_gold.meters_data_15m:
            classification: pii
            row_filters:
              - handler: rec_registry
                args: {}
          datasets.ds_dev_gold.meters_summary: {}
    """)
    _write(tmp_path / "pipelines/apps/weather/governance.yaml", """
        sources:
          datasets.ds_dev_gold.weather_hourly:
            access_level: open
            ownership: [mt]
          datasets.ds_dev_gold.weather_secret:
            access_level: secret
            ownership: [mt]
    """)
    _write(tmp_path / "deployment/governance/governance.rec_metering.yaml", """
        defaults:
          ownership: [greenland]
    """)
    _write(tmp_path / "owners.yaml", """
        owners:
          - id: greenland
            organization: {create: true}
          - id: mt
            organization: {create: false}
    """)
    return tmp_path


DATASETS = [
    {"id": 1, "schema": "ds_dev_gold", "table_name": "meters_data_15m"},
    {"id": 2, "schema": "ds_dev_gold", "table_name": "meters_summary"},
    {"id": 3, "schema": "ds_dev_gold", "table_name": "weather_hourly"},
    {"id": 4, "schema": "ds_dev_gold", "table_name": "weather_secret"},
    {"id": 5, "schema": "ds_dev_gold", "table_name": "made_by_hand"},
    {"id": 6, "schema": "ds_dev_silver", "table_name": "meters_data_15m"},
]


def _run(monkeypatch, client, *extra_args):
    monkeypatch.setattr(main, "SupersetClient", lambda settings: client)
    return CliRunner().invoke(main.app, [
        "governance", "sync",
        "--path", "pipelines/apps/*/governance.yaml",
        "--overlay-dir", "deployment/governance",
        "--owners", "owners.yaml",
        "--filter", "ds_dev_gold.*",
        "--schema", "ds_dev_gold",
        *extra_args,
    ])


def test_every_dataset_in_schema_gets_an_explicit_decision(workspace, monkeypatch):
    client = FakeClient(DATASETS)

    result = _run(monkeypatch, client)

    assert result.exit_code == 0, result.output
    assert client.extra == {
        1: {"celine_access": "operators", "org_slugs": []},              # pii + row filter
        2: {"celine_access": "org", "org_slugs": ["greenland"]},          # owner from overlay
        3: {"celine_access": "open", "org_slugs": []},
        4: {"celine_access": "operators", "org_slugs": []},              # secret
        5: {"celine_access": "operators", "org_slugs": []},              # no governance entry
    }
    assert 6 not in client.extra                                          # other schema untouched
    assert "org:greenland:viewers" in client.roles


def test_overwrites_stale_tags(workspace, monkeypatch):
    client = FakeClient(DATASETS)
    client.extra[1] = {"org_slugs": [], "celine_access": "open"}

    _run(monkeypatch, client)

    assert client.extra[1]["celine_access"] == "operators"


def test_dry_run_writes_nothing(workspace, monkeypatch):
    client = FakeClient(DATASETS)

    result = _run(monkeypatch, client, "--dry-run")

    assert result.exit_code == 0, result.output
    assert client.extra == {}
    assert "made_by_hand" in result.output
    assert "no governance entry" in result.output


def test_failed_tag_write_exits_non_zero(workspace, monkeypatch):
    client = FakeClient(DATASETS, fail_ids={3})

    result = _run(monkeypatch, client)

    assert result.exit_code == 1
    assert 1 in client.extra and 3 not in client.extra


def test_no_matching_files_exits_non_zero(workspace, monkeypatch):
    monkeypatch.setattr(main, "SupersetClient", lambda settings: FakeClient(DATASETS))
    result = CliRunner().invoke(main.app, ["governance", "sync", "--path", "nowhere/**/governance.yaml"])
    assert result.exit_code == 1


def test_conflicting_entries_are_operators_and_printed(workspace, monkeypatch):
    _write(workspace / "pipelines/apps.legacy/weather/governance.yaml", """
        sources:
          datasets.ds_dev_gold.weather_hourly:
            access_level: internal
            ownership: [greenland]
    """)
    client = FakeClient(DATASETS)
    monkeypatch.setattr(main, "SupersetClient", lambda settings: client)

    result = CliRunner().invoke(main.app, [
        "governance", "sync",
        "--path", "pipelines/**/governance.yaml",
        "--owners", "owners.yaml",
        "--schema", "ds_dev_gold",
    ])

    assert result.exit_code == 0, result.output
    assert client.extra[3] == {"celine_access": "operators", "org_slugs": []}
    assert "conflicting governance entries" in result.output
    assert "['greenland']" in result.output
