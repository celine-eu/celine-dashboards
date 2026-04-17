import json
import logging
import os

from flask import current_app, g, request
from flask_login import current_user, login_user
from superset.security import SupersetSecurityManager

from celine.superset.auth.jwt import extract_jwt_claims
from celine.superset.auth.user import resolve_superset_user
from celine.superset.plugin.views import OAuth2ProxyAuthRemoteUserView

logger = logging.getLogger(__name__)

logging.basicConfig(level=os.getenv("CUSTOM_SECURITY_MANAGER_LOG_LEVEL", "INFO"))

SSO_BASE_URL = os.getenv("CUSTOM_SECURITY_MANAGER_SSO_BASE_URL", "")


class OAuth2ProxySecurityManager(SupersetSecurityManager):

    authremoteuserview = OAuth2ProxyAuthRemoteUserView

    @staticmethod
    def before_request() -> None:
        if request.path.startswith(("/health", "/static", "/favicon.ico")):
            g.user = current_user
            return

        sm: SupersetSecurityManager = current_app.appbuilder.sm  # type: ignore

        if not current_user.is_anonymous:
            g.user = current_user
            return

        try:
            claims = extract_jwt_claims(request.headers)
            if not claims:
                logger.warning("JWT extraction failed for %s — request proceeds as anonymous", request.path)
                g.user = current_user
                return

            user = resolve_superset_user(sm, claims)
            if not user:
                logger.warning("User resolution failed for sub=%s — request proceeds as anonymous", claims.get("sub"))
                g.user = current_user
                return

            login_user(user, remember=False)
            g.user = user
            request.environ["REMOTE_USER"] = user.username
            request.environ["JWT_CLAIMS"] = json.dumps(claims)
            # Strip the KC Bearer token so Flask-JWT-Extended doesn't try to
            # validate it as a Superset JWT (it only accepts HS256, not RS256).
            request.environ.pop("HTTP_AUTHORIZATION", None)

            logger.info("Authenticated user=%s via KC JWT", user.username)

        except Exception:
            logger.exception("Authentication error in before_request for %s", request.path)
            g.user = current_user
