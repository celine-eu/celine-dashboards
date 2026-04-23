import json
import logging
import os
from typing import Any, Optional

from flask import abort, current_app, g, request
from flask_login import current_user, login_user, logout_user
from superset.exceptions import SupersetSecurityException
from superset.security import SupersetSecurityManager
from superset.errors import ErrorLevel, SupersetError, SupersetErrorType

from celine.superset.auth.jwt import extract_jwt_claims
from celine.superset.auth.user import resolve_superset_user
from celine.superset.plugin.views import OAuth2ProxyAuthRemoteUserView

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setLevel(logging.DEBUG)
    logger.addHandler(_h)
    logger.propagate = False

SSO_BASE_URL = os.getenv("CUSTOM_SECURITY_MANAGER_SSO_BASE_URL", "")
_REALM_BYPASS = frozenset(
    {"Admin", "celine:admins", "celine:managers", "celine:editors", "celine:viewers"}
)

# One-time flag: patch applied after first request (app context required)
_filter_patched = False


def _user_roles() -> list:
    return getattr(current_user, "roles", None) or []


def _is_realm_user() -> bool:
    return any(r.name in _REALM_BYPASS for r in _user_roles())


def _user_org_slugs() -> set[str]:
    return {
        parts[1]
        for role in _user_roles()
        if len(parts := role.name.split(":")) == 3 and parts[0] == "org"
    }


def _patch_dataset_filter_once() -> None:
    """Lazily replace Superset's dataset list filter with an org-aware version.

    Must be called after app init (requires superset.views.base to be importable).
    Idempotent — safe to call on every request.
    """
    global _filter_patched
    if _filter_patched:
        return
    _filter_patched = True

    import superset.views.base as _vb  # noqa: PLC0415
    _orig = _vb.get_dataset_access_filters

    def _org_aware_filter(base_model: Any, *args: Any) -> Any:
        from sqlalchemy import text

        user_slugs = _user_org_slugs()
        username = getattr(current_user, "username", "anonymous")

        logger.info("_org_filter: user=%s slugs=%s", username, user_slugs)

        if not user_slugs:
            logger.info("_org_filter: no org slugs — using default Superset filter")
            return _orig(base_model, *args)

        # Qualify with the actual table name to avoid ambiguity when DatasourceFilter
        # joins tables + dbs (both have an `extra` column).
        tname = base_model.__tablename__

        open_cond = (
            f"{tname}.extra IS NULL "
            f"OR {tname}.extra::jsonb -> 'org_slugs' IS NULL "
            f"OR {tname}.extra::jsonb -> 'org_slugs' = '[]'::jsonb"
        )

        bind_params: dict[str, str] = {}
        slug_conds: list[str] = []
        for i, slug in enumerate(sorted(user_slugs)):
            param = f"slug_{i}"
            bind_params[param] = json.dumps([slug])
            slug_conds.append(
                f"{tname}.extra::jsonb -> 'org_slugs' @> CAST(:{param} AS jsonb)"
            )

        full_sql = f"({open_cond})"
        if slug_conds:
            full_sql += " OR " + " OR ".join(slug_conds)

        logger.info("_org_filter: sql=%s params=%s", full_sql, bind_params)
        return text(full_sql).bindparams(**bind_params)

    _vb.get_dataset_access_filters = _org_aware_filter
    logger.info("Patched get_dataset_access_filters with org-aware version")


def _check_datasource_org(datasource: Any) -> None:
    """Raise SupersetSecurityException if the org user has no access to datasource.

    org_slugs absent or []  → open, passes.
    org_slugs=[...]         → user must hold org:<slug>:* for at least one slug.
    """
    table_name = getattr(datasource, "table_name", repr(datasource))
    ds_extra = json.loads(getattr(datasource, "extra", None) or "{}")
    org_slugs = ds_extra.get("org_slugs")
    user_slugs = _user_org_slugs()

    logger.info(
        "_check_datasource_org: table=%s org_slugs=%s user_slugs=%s",
        table_name,
        org_slugs,
        user_slugs,
    )

    if not org_slugs:
        logger.info("_check_datasource_org: table=%s is open — PASS", table_name)
        return

    if not user_slugs.intersection(org_slugs):
        logger.warning(
            "_check_datasource_org: table=%s DENIED — user has %s, need one of %s",
            table_name,
            user_slugs,
            org_slugs,
        )
        raise SupersetSecurityException(
            SupersetError(
                message=f"Access to {table_name!r} is restricted to its org members.",
                error_type=SupersetErrorType.DATASOURCE_SECURITY_ACCESS_ERROR,
                level=ErrorLevel.ERROR,
            )
        )

    logger.info(
        "_check_datasource_org: table=%s PASS — matched slug(s) %s",
        table_name,
        user_slugs.intersection(org_slugs),
    )


class OAuth2ProxySecurityManager(SupersetSecurityManager):

    authremoteuserview = OAuth2ProxyAuthRemoteUserView

    def can_access_all_datasources(self) -> bool:
        """Realm-level roles see everything; org users are restricted by org_slugs."""
        result = _is_realm_user()
        logger.info(
            "can_access_all_datasources: user=%s roles=%s result=%s",
            getattr(current_user, "username", "anonymous"),
            [r.name for r in _user_roles()],
            result,
        )
        return result

    def all_datasource_access(self) -> bool:
        """Legacy alias — delegates to can_access_all_datasources."""
        return self.can_access_all_datasources()

    def raise_for_access(  # type: ignore[override]
        self,
        dashboard: Optional[Any] = None,
        chart: Optional[Any] = None,
        database: Optional[Any] = None,
        datasource: Optional[Any] = None,
        query: Optional[Any] = None,
        query_context: Optional[Any] = None,
        table: Optional[Any] = None,
        viz: Optional[Any] = None,
        sql: Optional[str] = None,
        catalog: Optional[str] = None,
        schema: Optional[str] = None,
        template_params: Optional[dict[str, Any]] = None,
    ) -> None:
        """Enforce org-level restrictions on every datasource access path."""
        logger.info(
            "raise_for_access: user=%s datasource=%s viz=%s query_context=%s",
            getattr(current_user, "username", "anonymous"),
            getattr(datasource, "table_name", datasource),
            type(viz).__name__ if viz else None,
            type(query_context).__name__ if query_context else None,
        )
        if not self.can_access_all_datasources():
            ds = datasource
            if ds is None and viz is not None:
                ds = getattr(viz, "datasource", None)
            if ds is None and query_context is not None:
                ds = getattr(query_context, "datasource", None)
            if ds is not None:
                try:
                    _check_datasource_org(ds)
                except SupersetSecurityException:
                    raise
                except Exception:
                    logger.exception(
                        "raise_for_access: org check failed for %s",
                        getattr(ds, "table_name", ds),
                    )
                    raise SupersetSecurityException(
                        SupersetError(
                            message="Dataset access check failed.",
                            error_type=SupersetErrorType.DATASOURCE_SECURITY_ACCESS_ERROR,
                            level=ErrorLevel.ERROR,
                        )
                    )
            else:
                logger.info("raise_for_access: no datasource in args — skipping org check")

        if _user_org_slugs():
            # Org user: our org check is the authoritative datasource gate.
            # Call super() without datasource-related args so its native PVM checks
            # (which org users don't have) don't block access we already approved.
            logger.info("raise_for_access: org user — calling super() without datasource args")
            super().raise_for_access(
                dashboard=dashboard,
                chart=chart,
                database=database,
                query=query,
                table=table,
                sql=sql,
                catalog=catalog,
                schema=schema,
                template_params=template_params,
            )
        else:
            super().raise_for_access(
                dashboard=dashboard,
                chart=chart,
                database=database,
                datasource=datasource,
                query=query,
                query_context=query_context,
                table=table,
                viz=viz,
                sql=sql,
                catalog=catalog,
                schema=schema,
                template_params=template_params,
            )

    def datasource_access(self, datasource: Any) -> bool:
        """Legacy hook — kept for older Superset code paths."""
        table_name = getattr(datasource, "table_name", repr(datasource))
        logger.info(
            "datasource_access: user=%s table=%s",
            getattr(current_user, "username", "anonymous"),
            table_name,
        )
        if self.can_access_all_datasources():
            logger.info("datasource_access: table=%s — realm bypass PASS", table_name)
            return True
        try:
            _check_datasource_org(datasource)
            return True
        except SupersetSecurityException:
            logger.warning("datasource_access: table=%s — org check DENIED", table_name)
            return False
        except Exception:
            logger.exception("datasource_access: org check failed for %s", table_name)
            return False

    @staticmethod
    def before_request() -> None:
        if request.path.startswith(("/health", "/static", "/favicon.ico")):
            g.user = current_user
            return

        _patch_dataset_filter_once()

        sm: SupersetSecurityManager = current_app.appbuilder.sm  # type: ignore

        try:
            claims = extract_jwt_claims(request.headers)
            if not claims:
                logger.warning("JWT extraction failed — denying %s", request.path)
                abort(403)

            # Re-use the existing session only when the incoming JWT belongs to the
            # same user already logged in — prevents session fixation when a
            # different user's token arrives (e.g. after KC logout without hitting
            # Superset's /logout endpoint).
            if not current_user.is_anonymous:
                jwt_username = (
                    claims.get("preferred_username")
                    or claims.get("email")
                    or claims.get("azp")
                    or claims.get("sub")
                )
                if jwt_username and jwt_username == current_user.username:
                    g.user = current_user
                    return
                logout_user()

            user = resolve_superset_user(sm, claims)
            if not user:
                logger.warning(
                    "User resolution failed for sub=%s — denying access",
                    claims.get("sub"),
                )
                abort(403)

            login_user(user, remember=False)
            g.user = user
            request.environ["REMOTE_USER"] = user.username
            request.environ["JWT_CLAIMS"] = json.dumps(claims)
            # Strip the KC Bearer token so Flask-JWT-Extended doesn't try to
            # validate it as a Superset JWT (it only accepts HS256, not RS256).
            request.environ.pop("HTTP_AUTHORIZATION", None)

            logger.info("Authenticated user=%s via KC JWT", user.username)

        except Exception:
            logger.exception(
                "Authentication error in before_request for %s", request.path
            )
            abort(403)
