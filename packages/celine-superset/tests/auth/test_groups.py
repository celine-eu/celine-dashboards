import pytest
from celine.superset.auth.groups import resolve_access


# ---------------------------------------------------------------------------
# Realm-level groups (claims.groups)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("group", ["admin", "realm_admin", "admins", "manager", "realm_manager", "managers", "/admin", "/realm_admin"])
def test_realm_admin_roles_map_to_admin(group):
    result = resolve_access({"groups": [group]})
    assert result.superset_roles == ["Admin"]
    assert result.org_slugs == []
    assert result.org_role_names == []


def test_realm_editor_maps_to_celine_managers():
    result = resolve_access({"groups": ["editor"]})
    assert result.superset_roles == ["celine:managers"]
    assert result.org_role_names == []


def test_realm_editors_plural_maps_to_celine_managers():
    result = resolve_access({"groups": ["editors"]})
    assert result.superset_roles == ["celine:managers"]


@pytest.mark.parametrize("group", ["viewer", "viewers", "participant", "member", "operator", "anything"])
def test_realm_reader_maps_to_celine_viewers(group):
    result = resolve_access({"groups": [group]})
    assert result.superset_roles == ["celine:viewers"]
    assert result.org_slugs == []
    assert result.org_role_names == []


def test_realm_admin_takes_priority_over_org():
    result = resolve_access({
        "groups": ["admin"],
        "organization": {"example_rec": {"type": ["rec"], "groups": ["/viewers"]}},
    })
    assert "Admin" in result.superset_roles
    assert result.org_slugs == ["example_rec"]
    assert "org:example_rec:viewers" in result.org_role_names


# ---------------------------------------------------------------------------
# Org-level groups — role name and base role mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("group,expected_level", [
    ("/admins", "admins"),
    ("admins", "admins"),
    ("/managers", "managers"),
    ("managers", "managers"),
    ("/editors", "editors"),
    ("editors", "editors"),
])
def test_org_elevated_groups_emit_only_org_role(group, expected_level):
    """Org users with elevated groups get only the org:<slug>:<level> role — no celine:* base."""
    result = resolve_access({
        "organization": {"example_dso": {"type": ["dso"], "groups": [group]}},
    })
    assert result.superset_roles == []
    assert result.org_slugs == ["example_dso"]
    assert f"org:example_dso:{expected_level}" in result.org_role_names


@pytest.mark.parametrize("group", ["/viewers", "/operator", "/participant", "/anything"])
def test_org_reader_groups_emit_viewer_org_role(group):
    result = resolve_access({
        "organization": {"example_rec": {"type": ["rec"], "groups": [group]}},
    })
    assert result.superset_roles == []
    assert result.org_slugs == ["example_rec"]
    assert result.org_role_names == ["org:example_rec:viewers"]


def test_org_member_no_groups_defaults_to_viewer_org_role():
    """Org present but no groups list → org:<slug>:viewers only."""
    result = resolve_access({
        "organization": {"example_rec": {"type": ["rec"]}},
    })
    assert result.superset_roles == []
    assert result.org_slugs == ["example_rec"]
    assert result.org_role_names == ["org:example_rec:viewers"]


def test_actual_dso_admin_claims():
    """DSO admin JWT: no realm groups, org admins group → org role only."""
    result = resolve_access({
        "groups": None,
        "organization": {"example_dso": {"type": ["dso"], "groups": ["/admins"]}},
    })
    assert result.superset_roles == []
    assert result.org_slugs == ["example_dso"]
    assert result.org_role_names == ["org:example_dso:admins"]


def test_actual_rec_participant_claims():
    """REC participant JWT: realm viewers group + org membership → celine:viewers from realm."""
    result = resolve_access({
        "groups": ["participant"],
        "organization": {"example_rec": {"type": ["rec"]}},
    })
    assert result.superset_roles == ["celine:viewers"]
    assert result.org_slugs == ["example_rec"]
    assert result.org_role_names == ["org:example_rec:viewers"]


# ---------------------------------------------------------------------------
# Multi-org
# ---------------------------------------------------------------------------

def test_multi_org_accumulates_slugs():
    result = resolve_access({
        "organization": {
            "example_rec": {"type": ["rec"], "groups": ["/viewers"]},
            "example_dso": {"type": ["dso"], "groups": ["/viewers"]},
        },
    })
    assert result.superset_roles == []
    assert set(result.org_slugs) == {"example_rec", "example_dso"}
    assert set(result.org_role_names) == {"org:example_rec:viewers", "org:example_dso:viewers"}


def test_multi_org_different_roles():
    """User is admins in one org and viewers in another → two org roles, no celine:* base."""
    result = resolve_access({
        "organization": {
            "example_rec": {"type": ["rec"], "groups": ["/admins"]},
            "example_dso": {"type": ["dso"], "groups": ["/viewers"]},
        },
    })
    assert result.superset_roles == []
    assert set(result.org_slugs) == {"example_rec", "example_dso"}
    assert set(result.org_role_names) == {"org:example_rec:admins", "org:example_dso:viewers"}


# ---------------------------------------------------------------------------
# Deny cases
# ---------------------------------------------------------------------------

def test_empty_claims_denied():
    result = resolve_access({})
    assert result.superset_roles == []
    assert result.org_slugs == []
    assert result.org_role_names == []


def test_null_groups_no_org_denied():
    result = resolve_access({"groups": None})
    assert result.superset_roles == []


def test_empty_groups_no_org_denied():
    result = resolve_access({"groups": []})
    assert result.superset_roles == []
