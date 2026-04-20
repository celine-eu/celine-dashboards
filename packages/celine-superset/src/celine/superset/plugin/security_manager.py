import json
import logging
import os

from flask import abort, current_app, g, request
from flask_login import current_user, login_user, logout_user
from superset.security import SupersetSecurityManager

from celine.superset.auth.jwt import extract_jwt_claims
from celine.superset.auth.user import resolve_superset_user
from celine.superset.plugin.views import OAuth2ProxyAuthRemoteUserView

logger = logging.getLogger(__name__)

logging.basicConfig(level=os.getenv("CUSTOM_SECURITY_MANAGER_LOG_LEVEL", "INFO"))

SSO_BASE_URL = os.getenv("CUSTOM_SECURITY_MANAGER_SSO_BASE_URL", "")


class OAuth2ProxySecurityManager(SupersetSecurityManager):

    authremoteuserview = OAuth2ProxyAuthRemoteUserView

    def datasource_access(self, datasource) -> bool:
        """
        Grant access to a datasource based on org_slugs tags set by `governance sync`.

        - Superset Admin role holders (realm admins/managers): full bypass.
        - Untagged datasets (org_slugs absent): open by default for backward compat.
        - org_slugs=[]: explicitly open — any authenticated user.
        - org_slugs=[...]: org-restricted — user must hold an org:<slug>:* role.

        Note: we do NOT delegate to super() for non-Admin users because celine:managers
        and celine:admins are seeded from Alpha which carries all_datasource_access,
        which would bypass the org check for every elevated user.
        """
        # Realm-level roles have cross-org access; only org:<slug>:* holders are restricted.
        _REALM_BYPASS = frozenset({"Admin", "celine:admins", "celine:managers", "celine:editors", "celine:viewers"})
        if any(
            role.name in _REALM_BYPASS
            for role in (getattr(current_user, "roles", None) or [])
        ):
            return True

        try:
            ds_extra = json.loads(getattr(datasource, "extra", None) or "{}")
            org_slugs = ds_extra.get("org_slugs")

            if org_slugs is None:
                return True  # not yet tagged by governance sync — open by default

            if not org_slugs:
                return True  # explicitly tagged as open

            # Derive user org membership from org:<slug>:<level> roles assigned at login.
            user_org_slugs = {
                parts[1]
                for role in (getattr(current_user, "roles", None) or [])
                if len(parts := role.name.split(":")) == 3 and parts[0] == "org"
            }
            return bool(user_org_slugs.intersection(org_slugs))
        except Exception:
            logger.exception(
                "datasource_access: org check failed for %s",
                getattr(datasource, "table_name", datasource),
            )
            return False

    @staticmethod
    def before_request() -> None:
        if request.path.startswith(("/health", "/static", "/favicon.ico")):
            g.user = current_user
            return

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
                # JWT belongs to a different user — invalidate the stale session.
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
