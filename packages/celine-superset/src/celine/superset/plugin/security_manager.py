import json
import logging
import os
import urllib.parse
from typing import Any, Optional

from flask import abort, current_app, g, redirect, request
from flask_login import current_user, login_user, logout_user
from superset.exceptions import SupersetSecurityException
from superset.security import SupersetSecurityManager
from superset.errors import ErrorLevel, SupersetError, SupersetErrorType

from celine.superset.auth.jwt import extract_jwt_claims
from celine.superset.auth.user import resolve_superset_user
from celine.superset.plugin.access import (
    ACCESS_KEY,
    ORG_SLUGS_KEY,
    can_see_dataset,
    dataset_filter_sql,
    is_cross_org,
    is_operator,
    org_slugs_from_roles,
    parse_extra,
)
from celine.superset.plugin.views import OAuth2ProxyAuthRemoteUserView

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setLevel(logging.DEBUG)
    logger.addHandler(_h)
    logger.propagate = False

SSO_BASE_URL = os.getenv("CUSTOM_SECURITY_MANAGER_SSO_BASE_URL", "")

# One-time flag: patch applied after first request (app context required)
_filter_patched = False


def _user_roles() -> list:
    return getattr(current_user, "roles", None) or []


def _user_role_names() -> list[str]:
    return [r.name for r in _user_roles()]


def _is_operator() -> bool:
    return is_operator(_user_role_names())


def _is_realm_user() -> bool:
    """Operators and cross-org realm roles. Neither bypasses the dataset tag check."""
    names = _user_role_names()
    return is_operator(names) or is_cross_org(names)


def _user_org_slugs() -> set[str]:
    return org_slugs_from_roles(_user_role_names())


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

        role_names = _user_role_names()
        username = getattr(current_user, "username", "anonymous")

        # Qualify with the actual table name to avoid ambiguity when DatasourceFilter
        # joins tables + dbs (both have an `extra` column).
        filter_sql = dataset_filter_sql(base_model.__tablename__, role_names)
        if filter_sql is None:
            logger.info("_org_filter: user=%s is an operator — default Superset filter", username)
            return _orig(base_model, *args)

        full_sql, bind_params = filter_sql
        logger.info(
            "_org_filter: user=%s roles=%s sql=%s params=%s",
            username,
            role_names,
            full_sql,
            bind_params,
        )
        return text(full_sql).bindparams(**bind_params)

    _vb.get_dataset_access_filters = _org_aware_filter
    logger.info("Patched get_dataset_access_filters with org-aware version")


def _check_datasource_org(datasource: Any) -> None:
    """Raise SupersetSecurityException unless the user may read datasource.

    Decided by the `celine_access` tag `governance sync` writes — see
    `celine.superset.plugin.access`. An untagged dataset is Admin only.
    """
    table_name = getattr(datasource, "table_name", repr(datasource))
    ds_extra = parse_extra(getattr(datasource, "extra", None))
    role_names = _user_role_names()

    logger.info(
        "_check_datasource_org: table=%s access=%s org_slugs=%s roles=%s",
        table_name,
        ds_extra.get(ACCESS_KEY),
        ds_extra.get(ORG_SLUGS_KEY),
        role_names,
    )

    if not can_see_dataset(ds_extra, role_names):
        logger.warning("_check_datasource_org: table=%s DENIED", table_name)
        raise SupersetSecurityException(
            SupersetError(
                message=f"Access to {table_name!r} is restricted.",
                error_type=SupersetErrorType.DATASOURCE_SECURITY_ACCESS_ERROR,
                level=ErrorLevel.ERROR,
            )
        )

    logger.info("_check_datasource_org: table=%s PASS", table_name)


class OAuth2ProxySecurityManager(SupersetSecurityManager):

    authremoteuserview = OAuth2ProxyAuthRemoteUserView

    def can_access_all_datasources(self) -> bool:
        """Operators and cross-org realm roles list every chart and dashboard.

        Not a data bypass: raise_for_access and the dataset list filter still apply
        the dataset tag to everyone except operators.
        """
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
        """Enforce the dataset tag on every datasource access path, for non-operators."""
        logger.info(
            "raise_for_access: user=%s datasource=%s viz=%s query_context=%s",
            getattr(current_user, "username", "anonymous"),
            getattr(datasource, "table_name", datasource),
            type(viz).__name__ if viz else None,
            type(query_context).__name__ if query_context else None,
        )
        if not _is_operator():
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
        if _is_operator():
            logger.info("datasource_access: table=%s — operator PASS", table_name)
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
    def _redirect_to_login() -> None:
        next_url = urllib.parse.quote(request.full_path.rstrip("?"), safe="")
        abort(redirect(f"/login/?next={next_url}"))

    @staticmethod
    def before_request() -> None:
        if request.path.startswith(("/health", "/static", "/favicon.ico")):
            g.user = current_user
            return

        # Let login/logout views handle their own redirects to the proxy
        # without requiring a valid JWT (the whole point is re-authentication).
        if request.path.startswith(("/login", "/logout")):
            return

        _patch_dataset_filter_once()

        sm: SupersetSecurityManager = current_app.appbuilder.sm  # type: ignore

        try:
            claims = extract_jwt_claims(request.headers)
            if not claims:
                logger.warning(
                    "JWT extraction failed for %s — redirecting to oauth2 proxy",
                    request.path,
                )
                OAuth2ProxySecurityManager._redirect_to_login()

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
                    "User resolution failed for sub=%s — redirecting to oauth2 proxy",
                    claims.get("sub"),
                )
                OAuth2ProxySecurityManager._redirect_to_login()

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
            OAuth2ProxySecurityManager._redirect_to_login()
