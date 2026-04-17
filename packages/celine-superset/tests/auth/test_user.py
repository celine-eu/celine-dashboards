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
    claims = {"preferred_username": "alice", "groups": ["/realm_admin"]}

    result = resolve_superset_user(sm, claims)

    assert result is user
    sm.update_user.assert_called_once()
    assert user.roles is not None


def test_existing_user_no_sync_skips_update():
    user = Mock()
    sm = _make_sm(user=user, sync=False)
    claims = {"preferred_username": "alice", "groups": ["/realm_admin"]}

    resolve_superset_user(sm, claims)
    sm.update_user.assert_not_called()


def test_existing_user_org_stored_in_extra():
    user = Mock()
    sm = _make_sm(user=user)
    claims = {"preferred_username": "alice", "groups": ["/rec-rome/admin"]}

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
        "groups": ["/rec-milan/viewer"],
    }

    result = resolve_superset_user(sm, claims)

    sm.add_user.assert_called_once()
    assert result is not None


def test_no_registration_returns_none():
    sm = _make_sm(user=None, registration=False)
    claims = {"preferred_username": "carol", "groups": ["/rec-rome/viewer"]}

    assert resolve_superset_user(sm, claims) is None


def test_no_username_in_claims_returns_none():
    sm = _make_sm()
    assert resolve_superset_user(sm, {}) is None


# --- fallback role ---

def test_fallback_to_public_when_no_role_found():
    sm = _make_sm(user=None)
    sm.find_role.return_value = None  # no roles found at all
    claims = {"preferred_username": "dave", "groups": []}

    # Should not raise; add_user called with empty role list
    resolve_superset_user(sm, claims)
    sm.add_user.assert_called_once()
