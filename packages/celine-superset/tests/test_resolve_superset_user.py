from unittest.mock import Mock
import celine_superset.auth.security_manager as sm


def test_existing_user_roles_synced():
    smgr = Mock()
    smgr.auth_roles_sync_at_login = True

    role = Mock()
    smgr.find_role.return_value = role

    user = Mock()
    smgr.find_user.return_value = user

    claims = {
        "preferred_username": "alice",
        "groups": ["/admins"],
    }

    result = sm.resolve_superset_user(smgr, claims)

    assert result == user
    smgr.update_user.assert_called_once()


def test_user_created_when_missing():
    smgr = Mock()
    smgr.auth_user_registration = True
    smgr.auth_roles_sync_at_login = True

    role = Mock()
    smgr.find_role.return_value = role
    smgr.find_user.return_value = None

    new_user = Mock()
    smgr.add_user.return_value = new_user

    claims = {
        "preferred_username": "bob",
        "email": "bob@test",
        "groups": ["/admins"],
    }

    assert sm.resolve_superset_user(smgr, claims) == new_user
