"""The access audit (`plugin/audit.py`): who read which dashboard, chart, dataset or query, and
who was refused, in the platform's record shape (`celine.sdk.audit`) on the logger `celine.audit`.

A Flask app stands in for Superset: its rules carry Superset's endpoint names, so a request is
classified exactly as in Superset. The wiring into `before_request` imports Superset, which this
suite's `tests/superset` package shadows; it was checked against a running Superset.
"""

import json
import logging

import pytest
from flask import Flask, Response, g

from celine.superset.auth import jwt as jwt_mod
from celine.superset.plugin import audit

SDK_FIELDS = (
    "event",
    "service",
    "sub",
    "client_id",
    "service_account",
    "action",
    "method",
    "route",
    "resource",
    "outcome",
    "reason",
    "request_id",
    "trace_id",
    "ts",
)

USER = {
    "sub": "5f0c7a52-0000-4000-8000-000000000001",
    "azp": "oauth2_proxy",
    "preferred_username": "member.one@rec.example.org",
    "email": "member.one@rec.example.org",
    "name": "Member One",
    "given_name": "Member",
    "family_name": "One",
    "organization": {"example-rec": {"groups": ["/viewers"]}},
}

SERVICE_ACCOUNT = {
    "sub": "5f0c7a52-0000-4000-8000-000000000002",
    "azp": "celine-cli",
    "preferred_username": "service-account-celine-cli",
}

PERSONAL = ("member.one", "rec.example.org", "Member One", "Member")


def _view(**_kwargs):
    return ""


app = Flask(__name__)
for rule, endpoint, methods in (
    ("/api/v1/dashboard/<id_or_slug>", "DashboardRestApi.get", ["GET"]),
    ("/superset/dashboard/<dashboard_id_or_slug>/", "Superset.dashboard", ["GET"]),
    ("/api/v1/chart/data", "ChartDataRestApi.data", ["POST"]),
    ("/api/v1/chart/<int:pk>/data/", "ChartDataRestApi.get_data", ["GET"]),
    ("/explore/", "ExploreView.root", ["GET"]),
    ("/api/v1/sqllab/execute/", "SqlLabRestApi.execute_sql_query", ["POST"]),
    ("/api/v1/dashboard/export/", "DashboardRestApi.export", ["GET"]),
    ("/api/v1/dashboard/", "DashboardRestApi.get_list", ["GET"]),
):
    app.add_url_rule(rule, endpoint=endpoint, view_func=_view, methods=methods)


@pytest.fixture
def records(caplog):
    caplog.set_level(logging.INFO, logger=audit.AUDIT_LOGGER)

    def read():
        return [
            (r.levelno, json.loads(r.getMessage()))
            for r in caplog.records
            if r.name == audit.AUDIT_LOGGER
        ]

    return read


def _respond(path, status=200, claims=USER, method="GET", **kwargs):
    """One request through the audit as `before_request` wires it: claims kept, then the response."""
    with app.test_request_context(path, method=method, **kwargs):
        audit.remember_claims(claims)
        audit.record_response(Response(status=status))


def _assert_no_personal_data(record):
    text = json.dumps(record)
    for value in PERSONAL:
        assert value not in text


# -- the record ------------------------------------------------------------------------------


def test_the_record_has_the_platform_fields_in_order(records):
    _respond("/api/v1/dashboard/12")
    [(level, record)] = records()
    assert tuple(record) == SDK_FIELDS == audit.FIELDS
    assert level == logging.INFO
    assert record["event"] == "access"
    assert record["service"] == "superset"
    assert record["outcome"] == "allowed"
    assert record["ts"].endswith("+00:00")


def test_the_caller_is_sub_and_client_never_email_or_name(records):
    _respond("/api/v1/dashboard/12")
    [(_, record)] = records()
    assert record["sub"] == USER["sub"]
    assert record["client_id"] == "oauth2_proxy"
    assert record["service_account"] is False
    _assert_no_personal_data(record)


def test_a_service_account_is_flagged(records):
    _respond("/api/v1/dashboard/12", claims=SERVICE_ACCOUNT)
    [(_, record)] = records()
    assert record["service_account"] is True
    assert record["client_id"] == "celine-cli"


_SUB = {"sub": "5f0c7a52-0000-4000-8000-000000000003"}


@pytest.mark.parametrize(
    "claims, service_account",
    [
        pytest.param(USER, False, id="person via oauth2-proxy"),
        pytest.param(
            {**_SUB, "azp": "svc-example", "preferred_username": "member.two"},
            False,
            id="person without email",
        ),
        pytest.param(
            {**_SUB, "azp": "oauth2_proxy", "organization": {"example-rec": {}}},
            False,
            id="organisation member without group, azp only",
        ),
        pytest.param(
            {
                **_SUB,
                "azp": "svc-example",
                "client_id": "svc-example",
                "organization": {"example-rec": {"groups": ["/viewers"]}},
            },
            False,
            id="organisation group",
        ),
        pytest.param(
            {
                **_SUB,
                "azp": "svc-example",
                "client_id": "svc-example",
                "groups": ["/admins"],
            },
            False,
            id="realm group",
        ),
        pytest.param(
            {
                **_SUB,
                "azp": "svc-example",
                "preferred_username": "service-account-svc-example",
                "email": "svc@rec.example.org",
            },
            True,
            id="svc client with keycloak username",
        ),
        pytest.param(
            {**_SUB, "azp": "svc-example", "gty": "client-credentials"},
            True,
            id="client-credentials grant type",
        ),
        pytest.param(
            {**_SUB, "azp": "svc-example", "client_id": "svc-example"},
            True,
            id="client id and no person",
        ),
        pytest.param(
            {**_SUB, "azp": "svc-example", "jti": "trrtcc:0000"},
            True,
            id="client credentials, azp only",
        ),
        pytest.param(
            {**_SUB, "azp": "oauth2_proxy", "jti": "onrtro:0000"},
            False,
            id="password grant, azp only",
        ),
        # Shapes Keycloak does not issue: this module's verdict, kept as it is.
        pytest.param(
            {
                **_SUB,
                "azp": "svc-example",
                "client_id": "svc-example",
                "groups": "admins",
            },
            False,
            id="groups claim not a list",
        ),
        pytest.param(
            {**_SUB, "azp": "svc-example", "client_id": "svc-example", "groups": [""]},
            False,
            id="groups claim without a name",
        ),
        pytest.param(
            {
                **_SUB,
                "azp": "svc-example",
                "client_id": "svc-example",
                "preferred_username": 7,
            },
            False,
            id="username not a string",
        ),
    ],
)
def test_the_service_account_verdict_per_token(records, claims, service_account):
    """`service_account` for every kind of token Superset accepts (see `audit.is_service_account`)."""
    _respond("/api/v1/dashboard/12", claims=claims)
    [(_, record)] = records()
    assert record["service_account"] is service_account
    assert record["sub"] == claims["sub"]
    assert record["client_id"] == claims["azp"]


def test_the_route_is_the_rule_not_the_path_or_query(records):
    _respond("/superset/dashboard/sales-overview/?standalone=1&native_filters=x")
    [(_, record)] = records()
    assert record["route"] == "/superset/dashboard/<dashboard_id_or_slug>/"
    assert record["method"] == "GET"
    assert record["action"] == "dashboard.view"
    assert record["resource"] == "dashboard:sales-overview"
    assert "standalone" not in json.dumps(record)


def test_request_and_trace_ids_are_carried_when_well_formed(records):
    trace = "4bf92f3577b34da6a3ce929d0e0e4736"
    _respond(
        "/api/v1/dashboard/12",
        headers={
            "X-Request-ID": "req-1",
            "traceparent": f"00-{trace}-00f067aa0ba902b7-01",
        },
    )
    _respond("/api/v1/dashboard/12", headers={"X-Request-ID": "bad id!"})
    [(_, first), (_, second)] = records()
    assert (first["request_id"], first["trace_id"]) == ("req-1", trace)
    assert (second["request_id"], second["trace_id"]) == (None, None)


def test_an_email_shaped_resource_is_pseudonymised(records):
    _respond("/api/v1/dashboard/member.one@rec.example.org")
    [(_, record)] = records()
    assert record["resource"].startswith("dashboard:h:")
    _assert_no_personal_data(record)


# -- what is recorded ------------------------------------------------------------------------


def test_chart_data_names_the_chart_or_the_dataset(records):
    _respond(
        "/api/v1/chart/data",
        method="POST",
        json={"datasource": {"id": 7, "type": "table"}, "form_data": {"slice_id": 5}},
    )
    _respond(
        "/api/v1/chart/data",
        method="POST",
        json={"datasource": {"id": 7, "type": "table"}},
    )
    _respond("/api/v1/chart/9/data/")
    assert [r["resource"] for _, r in records()] == ["chart:5", "dataset:7", "chart:9"]
    assert {r["action"] for _, r in records()} == {"chart.data"}


def test_explore_names_the_chart_or_the_dataset(records):
    _respond("/explore/?slice_id=5")
    _respond("/explore/?datasource_id=7&datasource_type=table")
    assert [(r["action"], r["resource"]) for _, r in records()] == [
        ("explore.view", "chart:5"),
        ("explore.view", "dataset:7"),
    ]


def test_sql_lab_records_the_database_and_a_hash_never_the_sql(records):
    sql = "SELECT name, email FROM members WHERE email = 'member.one@rec.example.org'"
    _respond(
        "/api/v1/sqllab/execute/", method="POST", json={"database_id": 3, "sql": sql}
    )
    [(_, record)] = records()
    assert record["action"] == "sqllab.execute"
    assert record["resource"] == f"database:3/{audit.sql_digest(sql)}"
    assert record["resource"].startswith("database:3/sql:")
    text = json.dumps(record)
    assert "SELECT" not in text and "members" not in text
    _assert_no_personal_data(record)


def test_an_export_names_the_ids_only(records):
    _respond("/api/v1/dashboard/export/?q=!(1,2)")
    [(_, record)] = records()
    assert (record["action"], record["resource"]) == (
        "dashboard.export",
        "dashboard:1,2",
    )


def test_a_request_that_is_not_a_listed_read_is_not_recorded(records):
    _respond("/api/v1/dashboard/")
    assert records() == []


def test_a_listed_read_that_fails_is_an_error(records):
    _respond("/api/v1/dashboard/12", status=500)
    [(_, record)] = records()
    assert (record["event"], record["outcome"], record["reason"]) == (
        "access",
        "error",
        "http 500",
    )


# -- refusals --------------------------------------------------------------------------------


def test_a_refused_read_is_denied_at_warning_with_the_caller(records):
    _respond("/api/v1/dashboard/12", status=403)
    [(level, record)] = records()
    assert level == logging.WARNING
    assert (record["event"], record["outcome"], record["reason"]) == (
        "denied",
        "denied",
        "http 403",
    )
    assert record["action"] == "dashboard.read"
    assert record["sub"] == USER["sub"]
    _assert_no_personal_data(record)


def test_any_refusal_is_recorded_even_off_the_list(records):
    _respond("/api/v1/dashboard/", status=403)
    [(_, record)] = records()
    assert (record["event"], record["action"], record["reason"]) == (
        "denied",
        audit.REQUEST,
        "http 403",
    )


def test_a_401_without_a_verified_caller_is_not_recorded(records):
    _respond("/api/v1/dashboard/12", status=401, claims=None)
    assert records() == []


def test_a_token_that_fails_verification_is_denied_with_the_resource(records):
    with app.test_request_context("/api/v1/dashboard/12"):
        audit.remember_claims(None)
        audit.deny_request("invalid_token")
        audit.record_response(Response(status=401))
    [(_, record)] = records()
    assert (record["action"], record["resource"], record["reason"], record["sub"]) == (
        "dashboard.read",
        "dashboard:12",
        "invalid_token",
        None,
    )


def test_a_noted_reason_is_used_only_when_the_request_is_refused(records):
    body = {"datasource": {"id": 7, "type": "table"}}
    with app.test_request_context("/api/v1/chart/data", method="POST", json=body):
        audit.remember_claims(USER)
        audit.note_refusal("not_in_organisation", "dataset:7")
        audit.record_response(Response(status=200))
    with app.test_request_context("/api/v1/chart/data", method="POST", json=body):
        audit.remember_claims(USER)
        audit.note_refusal("not_in_organisation", "dataset:7")
        audit.record_response(Response(status=403))
    [(_, shown), (_, refused)] = records()
    assert (shown["event"], shown["reason"]) == ("access", None)
    assert (refused["event"], refused["reason"], refused["resource"]) == (
        "denied",
        "not_in_organisation",
        "dataset:7",
    )


def test_a_refusal_recorded_in_before_request_is_not_recorded_twice(records):
    with app.test_request_context("/api/v1/dashboard/12"):
        audit.remember_claims(USER)
        audit.deny_request("no_role")
        audit.record_response(Response(status=403))
    [(_, record)] = records()
    assert (record["action"], record["reason"], record["sub"]) == (
        "dashboard.read",
        "no_role",
        USER["sub"],
    )


def test_an_unreadable_body_still_gets_a_record(records):
    _respond(
        "/api/v1/chart/data",
        method="POST",
        data="{not json",
        content_type="application/json",
    )
    [(_, record)] = records()
    assert (record["action"], record["resource"]) == ("chart.data", None)


def test_the_claims_stay_with_their_request():
    with app.test_request_context("/api/v1/dashboard/12"):
        audit.remember_claims(USER)
        assert audit.current_claims()["sub"] == USER["sub"]
    with app.test_request_context("/api/v1/dashboard/12"):
        assert audit.current_claims() is None
        assert g.get("celine_audit_recorded") is None


def test_the_audit_logger_stays_at_info():
    assert logging.getLogger(audit.AUDIT_LOGGER).level == logging.INFO


# -- the API description (R30) ---------------------------------------------------------------


@pytest.mark.parametrize(
    "env, public, served",
    [
        ("dev", None, True),
        (None, None, False),
        ("prod", None, False),
        ("prod", "true", True),
        ("prod", "false", False),
    ],
)
def test_the_api_description_is_served_in_dev_or_when_declared_public(
    monkeypatch, env, public, served
):
    for name in ("CELINE_ENV", "ENVIRONMENT", jwt_mod.PUBLIC_DOCS_ENV):
        monkeypatch.delenv(name, raising=False)
    if env:
        monkeypatch.setenv("CELINE_ENV", env)
    if public:
        monkeypatch.setenv(jwt_mod.PUBLIC_DOCS_ENV, public)
    assert jwt_mod.api_docs_enabled() is served
