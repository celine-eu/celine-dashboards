import pytest
from celine.superset.auth.groups import (
    PLATFORM_ADMIN_ROLE,
    is_platform_admin,
    realm_roles,
    resolve_access,
)

PLATFORM_ADMIN_CLAIMS = {
    "azp": "oauth2_proxy",
    "preferred_username": "admin",
    "realm_access": {"roles": ["platform-admin"]},
}
ORG_ADMIN_CLAIMS = {
    "azp": "oauth2_proxy",
    "preferred_username": "org-admin",
    "realm_access": {"roles": ["default-roles-celine", "offline_access", "uma_authorization"]},
    "organization": {"example_rec": {"type": ["rec"], "groups": ["/admins"]}},
}
# The old oauth2_proxy access token of a realm-/admins member: both group forms (scope
# mapper and client mapper), and the retired realm role `admin` the group mapped to.
LEGACY_ADMIN_CLAIMS = {
    "azp": "oauth2_proxy",
    "preferred_username": "legacy-admin",
    "groups": ["/admins", "admins"],
    "realm_access": {"roles": ["admin"]},
    "organization": {"example-rec": {"type": ["rec"], "groups": ["/admins"]}},
}


# ---------------------------------------------------------------------------
# Platform level: the realm role platform-admin, from realm_access.roles only
# ---------------------------------------------------------------------------

def test_platform_admin_role_value():
    assert PLATFORM_ADMIN_ROLE == "platform-admin"


def test_platform_admin_maps_to_admin():
    result = resolve_access(PLATFORM_ADMIN_CLAIMS)
    assert result.superset_roles == ["Admin"]
    assert result.org_slugs == []
    assert result.org_role_names == []


def test_organisation_admins_is_not_a_platform_admin():
    result = resolve_access(ORG_ADMIN_CLAIMS)
    assert result.superset_roles == []
    assert result.org_slugs == ["example_rec"]
    assert result.org_role_names == ["org:example_rec:admins"]


def test_legacy_realm_group_grants_nothing():
    """A realm group (and the retired realm role `admin`) still in a token grants nothing."""
    result = resolve_access(LEGACY_ADMIN_CLAIMS)
    assert result.superset_roles == []
    # Only the organisation membership counts, and only inside that organisation.
    assert result.org_role_names == ["org:example-rec:admins"]


@pytest.mark.parametrize("group", [
    "admin", "admins", "/admins", "realm_admin", "manager", "managers", "realm_manager",
    "editor", "editors", "/editors", "viewer", "/viewers", "platform-admin", "/platform-admin",
])
def test_realm_groups_claim_is_never_read(group):
    result = resolve_access({"groups": [group]})
    assert result.superset_roles == []
    assert result.org_slugs == []
    assert result.org_role_names == []


@pytest.mark.parametrize("role", ["admin", "manager", "editor", "viewer", "realm_admin", "default-roles-celine"])
def test_other_realm_roles_grant_nothing(role):
    """The retired realm roles admin/manager/editor/viewer are not a platform grant."""
    result = resolve_access({"realm_access": {"roles": [role]}})
    assert result.superset_roles == []


def test_no_celine_managers_cross_org_role():
    """The realm editor(s) → celine:managers cross-organisation path is gone."""
    for claims in ({"groups": ["editors"]}, {"realm_access": {"roles": ["editor"]}}):
        assert resolve_access(claims).superset_roles == []


@pytest.mark.parametrize("claims", [
    {"roles": ["platform-admin"]},
    {"groups": ["platform-admin"]},
    {"resource_access": {"oauth2_proxy": {"roles": ["platform-admin"]}}},
    {"organization": {"example_rec": {"groups": ["/platform-admin"]}}},
    {"realm_access": {"roles": "platform-admin"}},
    {"realm_access": ["platform-admin"]},
    {"realm_access": None},
])
def test_platform_admin_only_from_realm_access_roles(claims):
    assert not is_platform_admin(claims)
    assert "Admin" not in resolve_access(claims).superset_roles


def test_realm_roles_dedupes_and_skips_non_strings():
    claims = {"realm_access": {"roles": ["platform-admin", 3, None, "", "platform-admin", "x"]}}
    assert realm_roles(claims) == ["platform-admin", "x"]


def test_platform_admin_also_gets_its_org_roles():
    result = resolve_access({
        "realm_access": {"roles": ["platform-admin"]},
        "organization": {"example_rec": {"type": ["rec"], "groups": ["/viewers"]}},
    })
    assert result.superset_roles == ["Admin"]
    assert result.org_slugs == ["example_rec"]
    assert result.org_role_names == ["org:example_rec:viewers"]


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
    assert result.org_role_names == [f"org:example_dso:{expected_level}"]


@pytest.mark.parametrize("group", ["/viewers", "/operator", "/participant", "/anything"])
def test_org_reader_groups_emit_viewer_org_role(group):
    result = resolve_access({
        "organization": {"example_rec": {"type": ["rec"], "groups": [group]}},
    })
    assert result.superset_roles == []
    assert result.org_slugs == ["example_rec"]
    assert result.org_role_names == ["org:example_rec:viewers"]


@pytest.mark.parametrize("org_data", [
    {"type": ["rec"]},
    {"type": ["rec"], "groups": []},
    {"type": ["rec"], "groups": "/admins"},  # malformed: not a list, not a grant
    None,
])
def test_org_member_no_groups_defaults_to_viewer_org_role(org_data):
    """Org present but no (usable) groups list → org:<slug>:viewers only."""
    result = resolve_access({"organization": {"example_rec": org_data}})
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
    """REC participant JWT: a realm group + org membership → org role only."""
    result = resolve_access({
        "groups": ["participant"],
        "organization": {"example_rec": {"type": ["rec"]}},
    })
    assert result.superset_roles == []
    assert result.org_slugs == ["example_rec"]
    assert result.org_role_names == ["org:example_rec:viewers"]


# ---------------------------------------------------------------------------
# Multi-org: each group stays inside its own organisation
# ---------------------------------------------------------------------------

def test_multi_org_accumulates_slugs():
    result = resolve_access({
        "organization": {
            "example_rec": {"type": ["rec"], "groups": ["/viewers"]},
            "example_dso": {"type": ["dso"], "groups": ["/viewers"]},
        },
    })
    assert result.superset_roles == []
    assert result.org_slugs == ["example_dso", "example_rec"]
    assert set(result.org_role_names) == {"org:example_rec:viewers", "org:example_dso:viewers"}


def test_multi_org_admins_in_one_org_does_not_reach_the_other():
    """Admins in one org and viewers in another → two org roles, never admins in both."""
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


def test_malformed_organization_claim_denied():
    result = resolve_access({"organization": ["example_rec"]})
    assert result.superset_roles == []
    assert result.org_slugs == []
    assert result.org_role_names == []
