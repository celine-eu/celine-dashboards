"""The plugin's operational log lines name the caller by token `sub`, never by a personal value.

The Superset username is the token's `preferred_username` (often an email address), and a new
user is created with the token's email and names: none of them reaches a log line, at any level.
The audit record on `celine.audit` is covered by `test_audit.py`.

`security_manager` imports Superset, which this suite's `tests/superset` package shadows: the few
Superset names it needs are stood in for here, only while a test runs.
"""

import importlib
import json
import logging
import sys
import types
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from flask import Flask

from celine.superset.auth import user as user_mod
from celine.superset.auth.user import resolve_superset_user
from celine.superset.plugin import audit

SUB = "5f0c7a52-0000-4000-8000-000000000001"
USERNAME = "member.one@rec.example.org"

CLAIMS = {
    "sub": SUB,
    "azp": "oauth2_proxy",
    "preferred_username": USERNAME,
    "email": USERNAME,
    "name": "Member One",
    "given_name": "Member",
    "family_name": "One",
    "organization": {"example-rec": {"groups": ["/viewers"]}},
}

PERSONAL = ("member.one", "rec.example.org", "Member One", "Member", "One")

app = Flask(__name__)


class _SecurityException(Exception):
    def __init__(self, error=None):
        super().__init__(getattr(error, "message", error))


class _BaseSecurityManager:
    def __init__(self, appbuilder=None):
        pass

    def raise_for_access(self, **kwargs):
        return None


def _orig_dataset_filter(base_model, *args):
    return "default filter"


def _superset_stand_in() -> dict[str, types.ModuleType]:
    def module(name, **attrs):
        mod = types.ModuleType(name)
        mod.__dict__.update(attrs)
        return mod

    return {
        "superset": module("superset"),
        "superset.exceptions": module(
            "superset.exceptions", SupersetSecurityException=_SecurityException
        ),
        "superset.security": module(
            "superset.security", SupersetSecurityManager=_BaseSecurityManager
        ),
        "superset.errors": module(
            "superset.errors",
            ErrorLevel=SimpleNamespace(ERROR="error"),
            SupersetError=lambda **kw: SimpleNamespace(**kw),
            SupersetErrorType=SimpleNamespace(DATASOURCE_SECURITY_ACCESS_ERROR="ds"),
        ),
        "superset.views": module("superset.views"),
        "superset.views.base": module(
            "superset.views.base", get_dataset_access_filters=_orig_dataset_filter
        ),
    }


@pytest.fixture
def sm_mod(monkeypatch):
    for name, mod in _superset_stand_in().items():
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.delitem(sys.modules, "celine.superset.plugin.security_manager", raising=False)
    mod = importlib.import_module("celine.superset.plugin.security_manager")
    yield mod
    sys.modules.pop("celine.superset.plugin.security_manager", None)


@pytest.fixture
def logs(caplog):
    """Every record of the plugin's loggers, at every level (the plugin logger does not propagate)."""
    loggers = [
        logging.getLogger("celine.superset.plugin.security_manager"),
        logging.getLogger(user_mod.__name__),
    ]
    saved = [(lg, lg.level) for lg in loggers]
    for lg in loggers:
        lg.setLevel(logging.DEBUG)
        lg.addHandler(caplog.handler)
    caplog.handler.setLevel(logging.DEBUG)
    yield caplog
    for lg, level in saved:
        lg.removeHandler(caplog.handler)
        lg.setLevel(level)


def _role(name):
    return SimpleNamespace(name=name)


def _user(*roles):
    return SimpleNamespace(
        username=USERNAME,
        email=USERNAME,
        first_name="Member",
        last_name="One",
        is_anonymous=False,
        roles=[_role(r) for r in roles],
    )


def _messages(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records]


def _assert_no_personal_value(caplog):
    messages = _messages(caplog)
    assert messages, "the path logged nothing"
    for message in messages:
        for value in PERSONAL:
            assert value not in message, message


def _dataset(access, slugs):
    return SimpleNamespace(
        id=7,
        table_name="example_table",
        extra=json.dumps({"celine_access": access, "org_slugs": slugs}),
    )


@pytest.mark.parametrize("roles", [("org:example-rec:viewers",), ("Admin",)])
def test_the_dataset_filter_logs_the_sub_only(sm_mod, logs, monkeypatch, roles):
    monkeypatch.setattr(sm_mod, "current_user", _user(*roles))
    monkeypatch.setattr(sm_mod, "_filter_patched", False)
    with app.test_request_context("/api/v1/dataset/"):
        audit.remember_claims(CLAIMS)
        sm_mod._patch_dataset_filter_once()
        sys.modules["superset.views.base"].get_dataset_access_filters(
            SimpleNamespace(__tablename__="tables")
        )

    _assert_no_personal_value(logs)
    assert any(SUB in m for m in _messages(logs) if "_org_filter" in m)


@pytest.mark.parametrize(
    "roles,dataset",
    [
        (("org:example-rec:viewers",), _dataset("org", ["example-rec"])),
        (("org:example-rec:viewers",), _dataset("operators", [])),
        (("Admin",), _dataset("operators", [])),
    ],
)
def test_the_access_check_logs_the_sub_only(sm_mod, logs, monkeypatch, roles, dataset):
    monkeypatch.setattr(sm_mod, "current_user", _user(*roles))
    manager = sm_mod.OAuth2ProxySecurityManager.__new__(sm_mod.OAuth2ProxySecurityManager)
    with app.test_request_context("/api/v1/chart/data"):
        audit.remember_claims(CLAIMS)
        try:
            manager.raise_for_access(datasource=dataset)
        except _SecurityException:
            pass
        manager.datasource_access(dataset)
        manager.can_access_all_datasources()

    _assert_no_personal_value(logs)
    assert any(SUB in m for m in _messages(logs) if "raise_for_access" in m)


def test_sign_in_logs_the_sub_only(sm_mod, logs, monkeypatch):
    signed_in = _user("org:example-rec:viewers")
    monkeypatch.setattr(sm_mod, "current_user", SimpleNamespace(is_anonymous=True))
    monkeypatch.setattr(sm_mod, "extract_jwt_claims", lambda headers: dict(CLAIMS))
    monkeypatch.setattr(sm_mod, "resolve_superset_user", lambda sm, claims: signed_in)
    monkeypatch.setattr(sm_mod, "login_user", lambda user, remember=False: True)
    monkeypatch.setattr(sm_mod, "_patch_dataset_filter_once", lambda: None)
    app.appbuilder = SimpleNamespace(sm=Mock())
    with app.test_request_context(
        "/api/v1/dashboard/", headers={"Authorization": "Bearer x"}
    ):
        assert sm_mod.OAuth2ProxySecurityManager.before_request() is None

    _assert_no_personal_value(logs)
    assert any(SUB in m for m in _messages(logs) if "Authenticated" in m)


def _sm(*, user=None, role=True, registration=True, created=True):
    sm = Mock()
    sm.auth_user_registration = registration
    sm.auth_roles_sync_at_login = True
    sm.find_user.return_value = user
    sm.find_role.side_effect = (lambda name: _role(name)) if role else (lambda name: None)
    sm.add_user.return_value = Mock() if created else None
    return sm


@pytest.mark.parametrize(
    "options",
    [
        pytest.param({}, id="new user"),
        pytest.param({"user": Mock()}, id="known user"),
        pytest.param({"role": False}, id="no role"),
        pytest.param({"registration": False}, id="registration disabled"),
        pytest.param({"created": False}, id="user not created"),
    ],
)
def test_user_resolution_logs_the_sub_only(logs, options):
    resolve_superset_user(_sm(**options), CLAIMS)

    _assert_no_personal_value(logs)
    assert any(SUB in m for m in _messages(logs))
