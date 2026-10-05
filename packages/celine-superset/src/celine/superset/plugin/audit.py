"""Access audit for Superset: who read which dashboard, chart, dataset or query, and who was refused.

The record is the platform's (`celine.sdk.audit`): one JSON object per line on the logger
``celine.audit``, the same fields in the same order, ``null`` for an unknown value. The plugin
runs in Superset's own interpreter and does not depend on the SDK (ADR-0003), and the SDK reads
a Starlette request, so the emitter is mirrored here for Flask. A change to the record shape must
be made in both.

No superset imports, so the tests exercise it without installing Superset (as `access.py`).

How it is wired: `before_request` stores the verified token claims on ``g`` and registers
:func:`record_response` with ``after_this_request``, so every request that passed through the
security manager gets at most one record, after the response status is known:

- a read listed in :data:`READS` answers below 400: ``access`` / ``allowed``;
- any request answered 401 or 403: ``denied`` (the read's action, else ``superset.request``);
- a listed read answered with another error: ``access`` / ``error``.

A refusal `before_request` answers itself calls :func:`audit_denied` with a reason code
(``invalid_token``, ``no_role``), and :func:`record_response` then adds nothing. The dataset tag
check only notes its reason (:func:`note_refusal`): Superset also runs it to decide what to show,
so whether the request was refused is read from the response status.

Superset's own event logger (``EVENT_LOGGER``, the ``logs`` table) was not used as the hook: it
runs only around the decorated handlers, not for a refusal answered by ``before_request``, it
is skipped when a handler raises, and it does not know the response status. It keeps writing the
``logs`` table as before.

The caller is the token's ``sub`` and ``azp``: never the Superset username, which is the
token's ``preferred_username`` or email. SQL text never enters a record: SQL Lab is recorded
as the database id and a hash of the statement.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from flask import g, has_request_context, request

from celine.superset.auth.groups import _org_groups

AUDIT_LOGGER = "celine.audit"
#: Every record of this process carries it (``configure_audit`` in the SDK).
SERVICE = "superset"
#: Keys the HMAC behind ``pseudonymise``. Unset, a plain SHA-256 is used.
PSEUDONYM_KEY_VAR = "CELINE_AUDIT_PSEUDONYM_KEY"

ACCESS = "access"
DENIED = "denied"
ALLOWED = "allowed"
ERROR = "error"

#: The fields of a record, in order: `celine.sdk.audit.FIELDS`.
FIELDS: tuple[str, ...] = (
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

#: The action of a request that is not a listed read (a refused page or API call).
REQUEST = "superset.request"

_CLAIMS_KEY = "celine_audit_claims"
_DONE_KEY = "celine_audit_recorded"
_REASON_KEY = "celine_audit_reason"

_MAX_LEN = 256
_EMAIL = re.compile(r"[^\s@<>()\"',;:]+@[^\s@<>()\"',;:]+\.[^\s@<>()\"',;:]+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$")
_KEYCLOAK_GRANT = re.compile(r"^[a-z]{2}rt([a-z]{2}):")
_IDS = re.compile(r"\d+")

log = logging.getLogger(AUDIT_LOGGER)
log.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# The record (mirrors celine.sdk.audit)
# ---------------------------------------------------------------------------


def pseudonymise(value: str) -> str:
    """A stable, non-reversible stand-in for a personal identifier: ``h:`` + 16 hex."""
    data = value.encode("utf-8")
    key = os.environ.get(PSEUDONYM_KEY_VAR, "")
    if key:
        digest = hmac.new(key.encode("utf-8"), data, hashlib.sha256).hexdigest()
    else:
        digest = hashlib.sha256(data).hexdigest()
    return "h:" + digest[:16]


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = _CONTROL.sub("", str(value)).strip()
    if not text:
        return None
    text = _EMAIL.sub(lambda m: pseudonymise(m.group(0)), text)
    return text[:_MAX_LEN]


def is_service_account(claims: Mapping) -> bool:
    """A client-credentials token: `celine.sdk.auth.jwt.is_service_account`."""
    preferred_username = claims.get("preferred_username", "")
    if isinstance(preferred_username, str) and preferred_username.startswith(
        "service-account-"
    ):
        return True
    if claims.get("gty") == "client-credentials":
        return True
    if claims.get("email"):
        return False
    organization = claims.get("organization")
    if claims.get("groups") or (
        isinstance(organization, dict)
        and any(_org_groups(data) for data in organization.values())
    ):
        return False
    if preferred_username:
        return False
    if claims.get("client_id"):
        return True
    jti = claims.get("jti")
    match = _KEYCLOAK_GRANT.match(jti) if isinstance(jti, str) else None
    return bool(match) and match.group(1) == "cc"


def caller_fields(claims: Mapping | None) -> dict[str, Any]:
    """``sub``, ``client_id`` and ``service_account`` of verified claims. Nothing else is read."""
    if not claims:
        return {"sub": None, "client_id": None, "service_account": None}
    return {
        "sub": _clean(claims.get("sub")),
        "client_id": _clean(claims.get("azp") or claims.get("client_id")),
        "service_account": is_service_account(claims),
    }


def request_fields() -> dict[str, Any]:
    """``method``, ``route``, ``request_id`` and ``trace_id`` of the current Flask request.

    The route is the matched rule (``/api/v1/dashboard/<id_or_slug>``), never the raw path
    and never the query string; ``None`` when no rule matched.
    """
    if not has_request_context():
        return {"method": None, "route": None, "request_id": None, "trace_id": None}
    rule = request.url_rule
    headers = request.headers

    request_id = headers.get("X-Request-ID") or headers.get("X-Correlation-ID")
    if request_id and not _REQUEST_ID.match(request_id):
        request_id = None

    trace_id = None
    match = _TRACEPARENT.match((headers.get("traceparent") or "").strip().lower())
    if match:
        trace_id = match.group(1)

    return {
        "method": _clean(request.method),
        "route": _clean((request.script_root or "") + rule.rule) if rule else None,
        "request_id": request_id,
        "trace_id": trace_id,
    }


def _emit(
    event: str,
    action: str,
    *,
    claims: Mapping | None,
    resource: Any,
    outcome: str,
    reason: str | None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "event": event,
        "service": SERVICE,
        **caller_fields(claims),
        "action": _clean(action),
        **request_fields(),
        "resource": _clean(resource),
        "outcome": outcome,
        "reason": _clean(reason),
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
    }
    record = {name: record.get(name) for name in FIELDS}
    if has_request_context():
        setattr(g, _DONE_KEY, True)

    level = logging.WARNING if event == DENIED else logging.INFO
    log.log(level, json.dumps(record, separators=(",", ":")), extra={"audit": record})
    return record


def audit_access(
    action: str,
    *,
    claims: Mapping | None = None,
    resource: Any = None,
    outcome: str = ALLOWED,
    reason: str | None = None,
) -> dict[str, Any]:
    """Record that the caller performed ``action`` on ``resource``. Returns the record.

    ``claims`` defaults to the verified claims ``before_request`` stored for this request.
    """
    return _emit(
        ACCESS,
        action,
        claims=claims if claims is not None else current_claims(),
        resource=resource,
        outcome=outcome,
        reason=reason,
    )


def audit_denied(
    action: str,
    *,
    claims: Mapping | None = None,
    resource: Any = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Record that the caller was refused ``action``, at ``WARNING``. Returns the record.

    ``reason`` is a short code, not a message: it must not repeat what the caller sent.
    """
    return _emit(
        DENIED,
        action,
        claims=claims if claims is not None else current_claims(),
        resource=resource,
        outcome=DENIED,
        reason=reason,
    )


# ---------------------------------------------------------------------------
# The request
# ---------------------------------------------------------------------------


def remember_claims(claims: Mapping | None) -> None:
    """Keep the verified claims of this request, for the record written after the response."""
    setattr(g, _CLAIMS_KEY, dict(claims) if claims else None)


def note_refusal(reason: str, resource: Any = None) -> None:
    """Keep why an access check refused, for the record of a request answered 401 or 403.

    Not a record by itself: Superset also runs the checks to decide what to *show* (and turns
    the refusal into ``False``), so only the response status says the request was refused.
    """
    if has_request_context():
        setattr(g, _REASON_KEY, (reason, resource))


def current_claims() -> dict | None:
    if not has_request_context():
        return None
    return g.get(_CLAIMS_KEY)


def already_recorded() -> bool:
    return has_request_context() and bool(g.get(_DONE_KEY))


def sql_digest(sql: Any) -> str | None:
    """``sql:`` + 16 hex of the SHA-256 of a statement: names it without carrying it."""
    if not isinstance(sql, str) or not sql.strip():
        return None
    return "sql:" + hashlib.sha256(sql.encode("utf-8")).hexdigest()[:16]


def _body() -> dict:
    data = request.get_json(cache=True, silent=True)
    return data if isinstance(data, dict) else {}


def _form_data() -> dict:
    """The explore/chart ``form_data``, from the JSON body, the form or the query string."""
    raw: Any = _body().get("form_data")
    if raw is None:
        raw = request.form.get("form_data") or request.args.get("form_data")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _chart_or_dataset(
    slice_id: Any = None, datasource_id: Any = None, datasource: Any = None
) -> str | None:
    if _int(slice_id) is not None:
        return f"chart:{_int(slice_id)}"
    if isinstance(datasource, dict):
        datasource_id = datasource_id or datasource.get("id")
    elif isinstance(datasource, str) and "__" in datasource:  # "<id>__table"
        datasource_id = datasource_id or datasource.split("__", 1)[0]
    if _int(datasource_id) is not None:
        return f"dataset:{_int(datasource_id)}"
    return None


def _view_arg(prefix: str, name: str) -> Callable[[], str | None]:
    def resource() -> str | None:
        value = (request.view_args or {}).get(name)
        return f"{prefix}:{value}" if value is not None else None

    return resource


def _export(prefix: str) -> Callable[[], str | None]:
    """Exports name their objects in a rison list, ``?q=!(1,2)``: the ids only."""

    def resource() -> str | None:
        ids = _IDS.findall(request.args.get("q", ""))
        return f"{prefix}:{','.join(ids)}" if ids else None

    return resource


def _chart_data() -> str | None:
    body = _body()
    form_data = _form_data()
    return _chart_or_dataset(
        form_data.get("slice_id"),
        datasource=body.get("datasource") or form_data.get("datasource"),
    )


def _explore() -> str | None:
    view_args = request.view_args or {}
    form_data = _form_data()
    return _chart_or_dataset(
        request.args.get("slice_id") or form_data.get("slice_id"),
        view_args.get("datasource_id") or request.args.get("datasource_id"),
        form_data.get("datasource"),
    )


def _sqllab_execute() -> str | None:
    body = _body()
    database = _int(body.get("database_id"))
    parts = [
        f"database:{database}" if database is not None else None,
        sql_digest(body.get("sql")),
    ]
    return "/".join(p for p in parts if p) or None


def _datasource_query() -> str | None:
    view_args = request.view_args or {}
    return _chart_or_dataset(
        datasource_id=view_args.get("datasource_id")
        or request.args.get("datasource_id")
    )


def _none() -> None:
    return None


#: Reads that return data or the definition of a dashboard, chart, dataset or query, by Flask
#: endpoint: ``(action, resource)``. Lists, metadata lookups and the UI's own client-side
#: event log are not listed. A refusal is recorded on every endpoint, listed or not.
READS: dict[str, tuple[str, Callable[[], str | None]]] = {
    # Dashboards
    "Superset.dashboard": (
        "dashboard.view",
        _view_arg("dashboard", "dashboard_id_or_slug"),
    ),
    "Dashboard.embedded": (
        "dashboard.view",
        _view_arg("dashboard", "dashboard_id_or_slug"),
    ),
    "DashboardRestApi.get": ("dashboard.read", _view_arg("dashboard", "id_or_slug")),
    "DashboardRestApi.get_charts": (
        "dashboard.read",
        _view_arg("dashboard", "id_or_slug"),
    ),
    "DashboardRestApi.get_datasets": (
        "dashboard.read",
        _view_arg("dashboard", "id_or_slug"),
    ),
    "DashboardRestApi.get_tabs": (
        "dashboard.read",
        _view_arg("dashboard", "id_or_slug"),
    ),
    "EmbeddedDashboardRestApi.get": ("dashboard.read", _view_arg("embedded", "uuid")),
    "DashboardRestApi.export": ("dashboard.export", _export("dashboard")),
    # Charts and their data
    "Superset.slice": ("chart.view", _view_arg("chart", "slice_id")),
    "ChartRestApi.get": ("chart.read", _view_arg("chart", "id_or_uuid")),
    "ChartRestApi.export": ("chart.export", _export("chart")),
    "ChartDataRestApi.data": ("chart.data", _chart_data),
    "ChartDataRestApi.get_data": ("chart.data", _view_arg("chart", "pk")),
    "ChartDataRestApi.data_from_cache": ("chart.data", _none),
    "Superset.explore_json": ("chart.data", _explore),
    "Superset.explore_json_data": ("chart.data", _none),
    "Api.query": ("chart.data", _chart_data),
    # Explore
    "ExploreView.root": ("explore.view", _explore),
    "Superset.explore": ("explore.view", _explore),
    "ExploreRestApi.get": ("explore.read", _explore),
    # Datasets
    "DatasetRestApi.get": ("dataset.read", _view_arg("dataset", "pk")),
    "DatasetRestApi.export": ("dataset.export", _export("dataset")),
    "Datasource.get": ("dataset.read", _datasource_query),
    "Datasource.samples": ("dataset.samples", _datasource_query),
    "DatasourceRestApi.get_column_values": ("dataset.values", _datasource_query),
    # SQL Lab
    "SqlLabRestApi.execute_sql_query": ("sqllab.execute", _sqllab_execute),
    "SqlLabRestApi.get_results": ("sqllab.results", _none),
    "SqlLabRestApi.export_csv": ("sqllab.export", _view_arg("query", "client_id")),
    "QueryRestApi.get": ("query.read", _view_arg("query", "pk")),
    "SavedQueryRestApi.get": ("saved_query.read", _view_arg("saved_query", "pk")),
    "SavedQueryRestApi.export": ("saved_query.export", _export("saved_query")),
    # Whole-instance exports
    "ImportExportRestApi.export": ("assets.export", _none),
    "DatabaseRestApi.export": ("database.export", _export("database")),
}


def classify() -> tuple[str, Callable[[], str | None]] | None:
    """The ``(action, resource)`` of the current request, when it is a listed read."""
    return READS.get(request.endpoint or "")


def _current() -> tuple[str, str | None]:
    """The action and resource of the current request; an unreadable body costs the resource."""
    read = classify() if has_request_context() else None
    if read is None:
        return REQUEST, None
    action, resource_of = read
    try:
        return action, resource_of()
    except Exception:
        return action, None


def deny_request(reason: str, *, claims: Mapping | None = None) -> dict[str, Any]:
    """Record a refusal decided before the request reached Superset (``before_request``)."""
    action, resource = _current()
    return audit_denied(action, claims=claims, resource=resource, reason=reason)


def record_response(response: Any) -> Any:
    """``after_this_request`` callback: one record for the request, from the response status."""
    try:
        if already_recorded():
            return response
        status = int(getattr(response, "status_code", 0) or 0)
        if status == 401 and current_claims() is None:
            # No verified caller: no token at all (one that failed verification was
            # recorded by before_request). There is nobody to name.
            return response
        if classify() is None and status not in (401, 403):
            return response
        action, resource = _current()
        if status in (401, 403):
            noted_reason, noted_resource = g.get(_REASON_KEY) or (None, None)
            audit_denied(
                action,
                resource=resource or noted_resource,
                reason=noted_reason or f"http {status}",
            )
        elif status >= 400:
            audit_access(
                action, resource=resource, outcome=ERROR, reason=f"http {status}"
            )
        else:
            audit_access(action, resource=resource)
    except Exception:
        logging.getLogger(__name__).exception("audit: record failed")
    return response


__all__ = [
    "AUDIT_LOGGER",
    "FIELDS",
    "READS",
    "audit_access",
    "audit_denied",
    "deny_request",
    "note_refusal",
    "pseudonymise",
    "record_response",
    "remember_claims",
    "sql_digest",
]
