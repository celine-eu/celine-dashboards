import pytest
from celine.superset.auth.groups import resolve_access, DEFAULT_ROLE


# --- realm-level groups ---

@pytest.mark.parametrize("group", ["/realm_admin", "/realm_manager", "/admins", "/managers"])
def test_realm_admin_groups_map_to_admin(group):
    result = resolve_access([group])
    assert result.superset_roles == ["Admin"]
    assert result.org_slugs == []


# --- org-level editor roles ---

@pytest.mark.parametrize("role", ["admin", "manager"])
def test_org_editor_maps_to_alpha(role):
    result = resolve_access([f"/rec-rome/{role}"])
    assert result.superset_roles == ["Alpha"]
    assert result.org_slugs == ["rec-rome"]


# --- org-level reader roles ---

@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_org_reader_maps_to_gamma(role):
    result = resolve_access([f"/rec-milan/{role}"])
    assert result.superset_roles == ["Gamma"]
    assert result.org_slugs == ["rec-milan"]


# --- multiple groups ---

def test_multiple_orgs_accumulates_slugs():
    result = resolve_access(["/rec-rome/viewer", "/rec-milan/viewer"])
    assert result.superset_roles == ["Gamma"]
    assert set(result.org_slugs) == {"rec-rome", "rec-milan"}


def test_realm_admin_plus_org_role_gives_admin():
    result = resolve_access(["/realm_admin", "/rec-rome/viewer"])
    assert "Admin" in result.superset_roles
    assert result.org_slugs == ["rec-rome"]


def test_org_editor_and_reader_gives_both_roles():
    result = resolve_access(["/rec-a/admin", "/rec-b/viewer"])
    assert set(result.superset_roles) == {"Alpha", "Gamma"}


# --- fallback ---

def test_empty_groups_returns_public():
    result = resolve_access([])
    assert result.superset_roles == [DEFAULT_ROLE]
    assert result.org_slugs == []


def test_unknown_group_returns_public():
    result = resolve_access(["/unknown-group"])
    assert result.superset_roles == [DEFAULT_ROLE]


def test_string_input_normalised():
    result = resolve_access("/realm_admin")
    assert result.superset_roles == ["Admin"]


def test_empty_path_segments_ignored():
    result = resolve_access(["//", "/"])
    assert result.superset_roles == [DEFAULT_ROLE]
