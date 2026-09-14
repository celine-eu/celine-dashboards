import json

import pytest

from celine.superset.plugin.access import (
    can_see_dataset,
    dataset_filter_sql,
    org_slugs_from_roles,
)

OPEN = {"celine_access": "open", "org_slugs": []}
GREENLAND = {"celine_access": "org", "org_slugs": ["greenland"]}
OPERATORS = {"celine_access": "operators", "org_slugs": []}

ADMIN = ["Admin"]
REALM_MANAGER = ["celine:managers"]
GREENLAND_VIEWER = ["org:greenland:viewers"]
SET_VIEWER = ["org:set:viewers"]


# ---------------------------------------------------------------------------
# can_see_dataset
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("roles", [ADMIN, REALM_MANAGER, GREENLAND_VIEWER, SET_VIEWER])
def test_open_dataset_visible_to_every_role(roles):
    assert can_see_dataset(OPEN, roles)


@pytest.mark.parametrize("roles,expected", [
    (ADMIN, True),
    (REALM_MANAGER, True),
    (GREENLAND_VIEWER, True),
    (SET_VIEWER, False),
])
def test_org_dataset(roles, expected):
    assert can_see_dataset(GREENLAND, roles) is expected


@pytest.mark.parametrize("roles,expected", [
    (ADMIN, True),
    (REALM_MANAGER, False),
    (GREENLAND_VIEWER, False),
    (["celine:viewers"], False),
])
def test_operators_dataset_admin_only(roles, expected):
    assert can_see_dataset(OPERATORS, roles) is expected


@pytest.mark.parametrize("extra", [
    None,
    "",
    "{}",
    "not json",
    "[]",
    {"org_slugs": []},              # legacy "open" tag — not honoured
    {"org_slugs": ["greenland"]},   # legacy org tag — not honoured
    {"celine_access": "public"},    # unknown value
    {"celine_access": "org"},       # org without slugs
    {"celine_access": "org", "org_slugs": "greenland"},
])
def test_untagged_or_malformed_is_admin_only(extra):
    assert can_see_dataset(extra, ADMIN)
    assert not can_see_dataset(extra, GREENLAND_VIEWER)
    assert not can_see_dataset(extra, REALM_MANAGER)


def test_extra_as_json_string():
    assert can_see_dataset(json.dumps(GREENLAND), GREENLAND_VIEWER)


def test_no_roles_sees_only_open():
    assert can_see_dataset(OPEN, [])
    assert not can_see_dataset(GREENLAND, [])


def test_org_slugs_from_roles_ignores_other_roles():
    assert org_slugs_from_roles(
        ["Admin", "celine:managers", "org:greenland:viewers", "org:set:admins", "org:bad"]
    ) == {"greenland", "set"}


# ---------------------------------------------------------------------------
# dataset_filter_sql
# ---------------------------------------------------------------------------

def test_filter_none_for_operator():
    assert dataset_filter_sql("tables", ADMIN) is None


def test_filter_cross_org_sees_open_and_org_never_operators():
    sql, params = dataset_filter_sql("tables", REALM_MANAGER)
    assert "= 'open'" in sql
    assert "= 'org'" in sql
    assert "operators" not in sql
    assert params == {}


def test_filter_org_user_binds_slugs():
    sql, params = dataset_filter_sql("tables", ["org:set:viewers", "org:greenland:admins"])
    assert sql.startswith("(")
    assert "tables.extra::jsonb" in sql
    assert params == {"slug_0": '["greenland"]', "slug_1": '["set"]'}
    assert ":slug_0" in sql and ":slug_1" in sql


def test_filter_no_org_no_realm_sees_only_open():
    sql, params = dataset_filter_sql("tables", [])
    assert sql == "((tables.extra::jsonb ->> 'celine_access') = 'open')"
    assert params == {}
