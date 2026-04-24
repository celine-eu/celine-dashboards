import json
from unittest.mock import Mock

from celine.superset.auth.user import resolve_superset_user


def _make_sm(*, user=None, role=Mock(), registration=True, sync=True):
    sm = Mock()
    sm.auth_user_registration = registration
    sm.auth_roles_sync_at_login = sync
    sm.find_user.return_value = user
    sm.find_role.return_value = role
    sm.add_user.return_value = Mock()
    return sm


# --- existing user ---

def test_existing_user_roles_synced():
    user = Mock()
    sm = _make_sm(user=user)
    claims = {"preferred_username": "alice", "groups": ["realm_admin"]}

    result = resolve_superset_user(sm, claims)

    assert result is user
    sm.update_user.assert_called_once()
    assert user.roles is not None


def test_existing_user_no_sync_skips_update():
    user = Mock()
    sm = _make_sm(user=user, sync=False)
    claims = {"preferred_username": "alice", "groups": ["realm_admin"]}

    resolve_superset_user(sm, claims)
    sm.update_user.assert_not_called()


def test_existing_user_org_stored_in_extra():
    user = Mock()
    sm = _make_sm(user=user)
    claims = {
        "preferred_username": "alice",
        "organization": {"rec-rome": {"type": ["rec"], "groups": ["/admins"]}},
    }

    resolve_superset_user(sm, claims)

    extra = json.loads(user.extra)
    assert extra["org_slugs"] == ["rec-rome"]


# --- new user creation ---

def test_new_user_created():
    sm = _make_sm(user=None)
    claims = {
        "preferred_username": "bob",
        "email": "bob@test",
        "given_name": "Bob",
        "family_name": "Test",
        "organization": {"rec-milan": {"type": ["rec"], "groups": ["/viewers"]}},
    }

    result = resolve_superset_user(sm, claims)

    sm.add_user.assert_called_once()
    assert result is not None


def test_no_registration_returns_none():
    sm = _make_sm(user=None, registration=False)
    claims = {
        "preferred_username": "carol",
        "organization": {"rec-rome": {"type": ["rec"], "groups": ["/viewers"]}},
    }

    assert resolve_superset_user(sm, claims) is None


def test_no_username_in_claims_returns_none():
    sm = _make_sm()
    assert resolve_superset_user(sm, {}) is None


# --- deny cases ---

def test_no_groups_denies_access():
    sm = _make_sm(user=None)
    claims = {"preferred_username": "dave", "groups": []}

    result = resolve_superset_user(sm, claims)

    assert result is None
    sm.add_user.assert_not_called()


def test_unknown_group_denies_access():
    sm = _make_sm(user=None)
    sm.find_role.return_value = None
    claims = {"preferred_username": "eve", "groups": ["unknown-role"]}

    result = resolve_superset_user(sm, claims)

    assert result is None
    sm.add_user.assert_not_called()


def test_existing_user_with_no_valid_groups_denied():
    user = Mock()
    sm = _make_sm(user=user)
    sm.find_role.return_value = None
    claims = {"preferred_username": "frank", "groups": []}

    result = resolve_superset_user(sm, claims)

    assert result is None
    sm.update_user.assert_not_called()


# --- multi-org org:<slug>:<level> role emission ---

def test_single_org_viewer_gets_only_org_role():
    """Org viewer gets only org:<slug>:viewers — no celine:* base role."""
    org_role = Mock(name="org:greenland:viewers")

    def _find_role(name):
        return {"org:greenland:viewers": org_role}.get(name)

    sm = _make_sm(user=None)
    sm.find_role.side_effect = _find_role
    claims = {
        "preferred_username": "alice",
        "organization": {"greenland": {"type": ["rec"], "groups": ["/viewers"]}},
    }

    resolve_superset_user(sm, claims)

    add_call_roles = sm.add_user.call_args[1]["role"]
    assert add_call_roles == [org_role]


def test_single_org_admins_gets_only_org_role():
    """Org admin gets only org:<slug>:admins — no celine:* base role."""
    org_role = Mock(name="org:greenland:admins")

    def _find_role(name):
        return {"org:greenland:admins": org_role}.get(name)

    sm = _make_sm(user=None)
    sm.find_role.side_effect = _find_role
    claims = {
        "preferred_username": "alice",
        "organization": {"greenland": {"type": ["rec"], "groups": ["/admins"]}},
    }

    resolve_superset_user(sm, claims)

    add_call_roles = sm.add_user.call_args[1]["role"]
    assert add_call_roles == [org_role]


def test_multi_org_gets_all_org_level_roles():
    """User viewers in two orgs gets both org:<slug>:viewers roles."""
    org_greenland = Mock(name="org:greenland:viewers")
    org_set = Mock(name="org:set:viewers")

    def _find_role(name):
        return {
            "org:greenland:viewers": org_greenland,
            "org:set:viewers": org_set,
        }.get(name)

    sm = _make_sm(user=None)
    sm.find_role.side_effect = _find_role
    claims = {
        "preferred_username": "bob",
        "organization": {
            "greenland": {"groups": ["/viewers"]},
            "set": {"groups": ["/viewers"]},
        },
    }

    resolve_superset_user(sm, claims)

    add_call_roles = sm.add_user.call_args[1]["role"]
    assert org_greenland in add_call_roles
    assert org_set in add_call_roles


def test_org_role_missing_denies_access():
    """If org:<slug>:<level> role doesn't exist in Superset yet, user is denied.

    Org users have no celine:* fallback — governance sync must run first to
    provision the org roles.
    """
    sm = _make_sm(user=None)
    sm.find_role.return_value = None
    claims = {
        "preferred_username": "carol",
        "organization": {"greenland": {"groups": ["/viewers"]}},
    }

    result = resolve_superset_user(sm, claims)

    assert result is None
    sm.add_user.assert_not_called()


def test_admin_user_gets_no_org_roles():
    """Realm admin has no org_slugs so no org:<slug>:* roles are added."""
    admin = Mock(name="Admin")

    sm = _make_sm(user=None)
    sm.find_role.return_value = admin
    claims = {"preferred_username": "dave", "groups": ["realm_admin"]}

    resolve_superset_user(sm, claims)

    org_calls = [c for c in sm.find_role.call_args_list if str(c[0][0]).startswith("org:")]
    assert org_calls == []
