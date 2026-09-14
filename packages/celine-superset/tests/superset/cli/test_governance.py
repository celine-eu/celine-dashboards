from pathlib import Path
from textwrap import dedent

import pytest

from celine.governance import GovernanceRule, OwnerEntry, OwnersRegistry
from celine.superset.cli.governance import (
    AccessDecision,
    collect_sources,
    decide_dataset,
    decide_rule,
    expand_globs,
    load_governance_file,
    matching_rules,
)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(text))
    return path


def _rule(**fields) -> GovernanceRule:
    return GovernanceRule.model_validate(fields)


REGISTRY = OwnersRegistry([
    OwnerEntry.model_validate({"id": "greenland", "aliases": ["rec"], "organization": {"create": True}}),
    OwnerEntry.model_validate({"id": "set", "aliases": ["dso"], "organization": {"create": True}}),
    OwnerEntry.model_validate({"id": "dwd", "organization": {"create": False}}),
])


# ---------------------------------------------------------------------------
# load_governance_file — defaults and overlays
# ---------------------------------------------------------------------------

def test_sources_inherit_file_defaults(tmp_path):
    """The defect: collect_sources returned rules as declared, so inherited owners vanished."""
    f = _write(tmp_path / "apps/rec_metering/governance.yaml", """
        defaults:
          access_level: internal
          classification: pii
          ownership: [rec]
        sources:
          datasets.ds_dev_gold.meters_data_15m:
            title: Meters
    """)
    gf = load_governance_file(f)
    sources = collect_sources([gf.config], "ds_dev_gold.*")

    rule = sources["datasets.ds_dev_gold.meters_data_15m"]
    assert [o.name for o in rule.ownership] == ["rec"]
    assert rule.classification == "pii"


def test_overlay_dir_is_merged(tmp_path):
    base = _write(tmp_path / "pipelines/apps/rec_metering/governance.yaml", """
        defaults:
          access_level: internal
          ownership: [rec]
        sources:
          datasets.ds_dev_gold.meters_data_1h: {}
    """)
    overlay_dir = tmp_path / "deployment/governance"
    _write(overlay_dir / "governance.rec_metering.yaml", """
        defaults:
          ownership:
            - name: greenland
              type: DATA_OWNER
    """)

    gf = load_governance_file(base, (overlay_dir,))

    assert gf.overlays == (overlay_dir / "governance.rec_metering.yaml",)
    rule = collect_sources([gf.config], None)["datasets.ds_dev_gold.meters_data_1h"]
    assert [o.name for o in rule.ownership] == ["greenland"]


def test_sibling_overlay_is_merged(tmp_path):
    base = _write(tmp_path / "apps/grid/governance.yaml", """
        sources:
          datasets.ds_dev_gold.grid_shapes:
            access_level: internal
            ownership: [dso]
    """)
    _write(tmp_path / "apps/grid/governance.grid.yaml", """
        sources:
          datasets.ds_dev_gold.grid_shapes:
            access_level: open
    """)

    gf = load_governance_file(base)

    assert gf.overlays == (tmp_path / "apps/grid/governance.grid.yaml",)
    assert gf.config.sources["datasets.ds_dev_gold.grid_shapes"].access_level == "open"


def test_overlay_for_another_app_is_ignored(tmp_path):
    base = _write(tmp_path / "apps/grid/governance.yaml", """
        sources:
          datasets.ds_dev_gold.grid_shapes: {access_level: internal, ownership: [dso]}
    """)
    overlay_dir = tmp_path / "overlays"
    _write(overlay_dir / "governance.rec_it.yaml", "defaults: {access_level: open}\n")

    gf = load_governance_file(base, (overlay_dir,))

    assert gf.overlays == ()


# ---------------------------------------------------------------------------
# matching_rules
# ---------------------------------------------------------------------------

def test_matching_rules_exact_beats_glob_and_resolves_defaults(tmp_path):
    f = _write(tmp_path / "apps/a/governance.yaml", """
        defaults:
          ownership: [rec]
        sources:
          datasets.*_gold.meters: {access_level: open}
          datasets.ds_dev_gold.meters: {access_level: internal}
    """)
    gf = load_governance_file(f)

    [(path, key, rule)] = matching_rules([gf], "ds_dev_gold", "meters")

    assert key == "datasets.ds_dev_gold.meters"
    assert rule.access_level == "internal"
    assert [o.name for o in rule.ownership] == ["rec"]


def test_matching_rules_glob_matches_schema_segment(tmp_path):
    f = _write(tmp_path / "apps/a/governance.yaml", """
        sources:
          datasets.*_gold.pv_overture_buildings: {access_level: open}
    """)
    gf = load_governance_file(f)

    [(_, key, _)] = matching_rules([gf], "ds_prod_gold", "pv_overture_buildings")
    assert key == "datasets.*_gold.pv_overture_buildings"
    assert matching_rules([gf], "ds_prod_silver", "pv_overture_buildings") == []


def test_matching_rules_respects_filter(tmp_path):
    f = _write(tmp_path / "apps/a/governance.yaml", """
        sources:
          datasets.ds_dev_gold.t: {access_level: open}
    """)
    gf = load_governance_file(f)
    assert matching_rules([gf], "ds_dev_gold", "t", "ds_dev_silver.*") == []


# ---------------------------------------------------------------------------
# decide_rule — fail closed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fields,reason", [
    ({"access_level": "open", "classification": "pii", "ownership": ["rec"]}, "classification pii"),
    ({"access_level": "internal", "classification": "PII", "ownership": ["rec"]}, "classification pii"),
    ({"access_level": "internal", "ownership": ["rec"],
      "row_filters": [{"handler": "rec_registry", "args": {}}]}, "row_filters cannot be enforced"),
    ({"access_level": "internal", "ownership": ["rec"],
      "dataspace": {"consent_required": True}}, "consent_required cannot be enforced"),
    ({"access_level": "secret", "ownership": ["rec"]}, "access_level secret"),
    ({"access_level": "internal"}, "no owner with a Keycloak organization"),
    ({"access_level": "internal", "ownership": ["dwd"]}, "no owner with a Keycloak organization"),
    ({"access_level": "public", "ownership": ["rec"]}, "unknown access_level 'public'"),
])
def test_decide_rule_operators_only(fields, reason):
    decision = decide_rule(_rule(**fields), REGISTRY)
    assert decision == AccessDecision("operators", (), reason)


def test_decide_rule_open():
    assert decide_rule(_rule(access_level="open"), REGISTRY).as_extra() == {
        "celine_access": "open",
        "org_slugs": [],
    }


@pytest.mark.parametrize("level", ["internal", "restricted", None])
def test_decide_rule_org_resolves_aliases(level):
    decision = decide_rule(_rule(access_level=level, ownership=["rec", "dso", "dwd"]), REGISTRY)
    assert decision.access == "org"
    assert decision.org_slugs == ("greenland", "set")


def test_decide_rule_unregistered_owner_uses_alias():
    decision = decide_rule(_rule(access_level="internal", ownership=["acme"]), REGISTRY)
    assert decision.as_extra() == {"celine_access": "org", "org_slugs": ["acme"]}


# ---------------------------------------------------------------------------
# decide_dataset
# ---------------------------------------------------------------------------

def test_decide_dataset_without_entry_is_operators():
    assert decide_dataset([], REGISTRY) == AccessDecision("operators", (), "no governance entry")


def test_decide_dataset_agreeing_entries():
    rule = _rule(access_level="internal", ownership=["rec"])
    matches = [(Path("a.yaml"), "k", rule), (Path("b.yaml"), "k", rule)]
    assert decide_dataset(matches, REGISTRY).org_slugs == ("greenland",)


def test_decide_dataset_conflicting_entries_is_operators():
    matches = [
        (Path("a.yaml"), "k", _rule(access_level="open")),
        (Path("b.yaml"), "k", _rule(access_level="internal", ownership=["rec"])),
    ]
    decision = decide_dataset(matches, REGISTRY)
    assert decision.access == "operators"
    assert decision.reason.startswith("conflicting governance entries")


# ---------------------------------------------------------------------------
# Replay of the real governance files, when the workspace has them
# ---------------------------------------------------------------------------

_PIPELINES = Path(__file__).resolve().parents[6] / "celine-pipelines"


@pytest.mark.skipif(not (_PIPELINES / "apps").is_dir(), reason="celine-pipelines checkout not beside this repository")
def test_replay_celine_pipelines_no_pii_dataset_reaches_an_org():
    files = [load_governance_file(p) for p in expand_globs([str(_PIPELINES / "apps/*/governance.yaml")])]
    sources = collect_sources([gf.config for gf in files], "ds_dev_gold.*")
    assert sources, "no gold sources found"

    pii = []
    for key in sources:
        _, schema, table = key.split(".")
        decision = decide_dataset(matching_rules(files, schema, table, "ds_dev_gold.*"), REGISTRY)
        rule = sources[key]
        if rule.classification == "pii" or rule.row_filters:
            pii.append(key)
            assert decision.access == "operators", key
        if decision.access == "org":
            assert decision.org_slugs, key

    assert pii, "expected pii gold datasets in celine-pipelines"
