import requests
import json
import logging
import jwt
import os
import urllib.parse
from functools import lru_cache

from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import AuthRemoteUserView
from flask_login import login_user, logout_user
from flask_appbuilder.views import expose
from flask import g, request, redirect, session
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from celine_superset.auth.roles import GROUP_TO_SUPERSET_ROLE, DEFAULT_ROLE

# Set up detailed logging
logging.basicConfig(level=os.getenv("CUSTOM_SECURITY_MANAGER_LOG_LEVEL", "INFO"))
logger = logging.getLogger("superset.auth.jwt")

JWKS_URL = os.getenv("CUSTOM_SECURITY_MANAGER_KEYCLOAK_JWKS_URL", None)
AUDIENCE = os.getenv("CUSTOM_SECURITY_MANAGER_KEYCLOAK_AUDIENCE", "oauth2_proxy")

SSO_BASE_URL = os.getenv("CUSTOM_SECURITY_MANAGER_SSO_BASE_URL", "")
VERIFY_SSL = (
    os.getenv("CUSTOM_SECURITY_MANAGER_SKIP_SSL_VERIFY", "false").lower() != "true"
)


@lru_cache(maxsize=1)
def get_jwks_uri_from_jwt(token):
    if JWKS_URL:
        return JWKS_URL
    # Decode the JWT headers (not the payload, don't verify yet)
    unverified_claims = jwt.decode(token, options={"verify_signature": False})
    issuer = unverified_claims["iss"]
    well_known_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    resp = requests.get(well_known_url, verify=VERIFY_SSL)
    resp.raise_for_status()
    jwks_uri = resp.json()["jwks_uri"]
    return jwks_uri


@lru_cache(maxsize=1)
def get_public_key(jwks_url) -> RSAPublicKey:
    resp = requests.get(jwks_url, verify=VERIFY_SSL)
    resp.raise_for_status()
    jwks = resp.json()

    key_data = jwks["keys"][0]
    public_key = RSAAlgorithm.from_jwk(json.dumps(key_data))

    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("Expected RSAPublicKey from JWK")

    return public_key


def redirect_to_login(start_response, environ=None):
    # Default OAuth2 proxy login URL
    login_url = f"{SSO_BASE_URL}/oauth2/sign_in"

    # Get the originally requested URL (optional)
    next_url = "/"
    if environ:
        # Build the full URL the user was trying to access
        url = environ.get("RAW_URI")
        if not url:  # Fallback if RAW_URI is not set
            url = environ.get("PATH_INFO", "/")
            qs = environ.get("QUERY_STRING")
            if qs:
                url += "?" + qs
        next_url = url

    # Only add rd parameter if it's not already the login URL
    login_url_with_rd = login_url
    if next_url and next_url != login_url and "rd=" not in next_url:
        # Construct the full URL including scheme and host
        if environ and environ.get("HTTP_HOST"):
            scheme = environ.get("wsgi.url_scheme", "http")
            full_url = f"{scheme}://{environ['HTTP_HOST']}{next_url}"
        else:
            full_url = next_url

        # Add rd parameter
        sep = "&" if "?" in login_url else "?"
        login_url_with_rd = f"{login_url}{sep}rd={urllib.parse.quote(full_url)}"

    start_response(
        "302 Found",
        [
            ("Location", login_url_with_rd),
            ("Content-Type", "text/html"),
        ],
    )
    body = f'<html><body>Redirecting to <a href="{login_url_with_rd}">{login_url_with_rd}</a>...</body></html>'
    return [body.encode()]


def unauthorized(start_response, message="Unauthorized"):
    start_response(
        "401 Unauthorized",
        [
            ("Content-Type", "text/plain"),
            ("WWW-Authenticate", 'Bearer error="invalid_token"'),
        ],
    )
    return [message.encode()]


# Middleware: Extract JWT from OAuth2 Proxy header, decode for user info, set REMOTE_USER
class JWTRemoteUserMiddleware(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):

        jwt_token = (
            environ.get("HTTP_X_AUTH_REQUEST_ACCESS_TOKEN")
            or environ.get("HTTP_X_AUTH_REQUEST_ACCESS_TOKEN".replace("-", "_"))
            or environ.get("HTTP_X_AUTH_REQUEST_ACCESS_TOKEN".upper().replace("-", "_"))
        )

        path = environ.get("PATH_INFO", "").lower()

        # Skip health check and login/logout endpoints
        if path in ["/health"]:
            return self.app(environ, start_response)

        if not jwt_token:
            logger.error("JWT header missing, redirect to login")
            return redirect_to_login(start_response, environ)

        failed: bool = True
        try:

            jwks_url = get_jwks_uri_from_jwt(jwt_token)
            public_key = get_public_key(jwks_url)

            # Verify the token
            claims = jwt.decode(
                jwt_token,
                public_key,
                algorithms=["RS256"],
                audience=AUDIENCE,
            )

            username = claims.get("preferred_username") or claims.get("email")
            if not username:
                logger.warning(
                    "Username not found in JWT claims, redirecting to login."
                )
                return unauthorized(start_response, "Username missing in token")

            environ["REMOTE_USER"] = username
            environ["JWT_CLAIMS"] = json.dumps(claims)

            logger.debug(f"Loaded REMOTE_USER={username}")

            failed = False
        except jwt.ExpiredSignatureError as e:
            logger.error(
                "JWT token has expired. Clearing session and redirecting to login."
            )
        except jwt.InvalidTokenError as e:
            logger.error(f"JWT decode error: {e}")
        except requests.RequestException as e:
            logger.exception("HTTP error while resolving JWKS")
        except Exception as e:
            logger.exception("Unexpected error while authenticating via JWT")

        if failed:
            logger.warning(f"Login failed, redirect to login")
            # Clear any existing session data
            if "JWT_CLAIMS" in environ:
                del environ["JWT_CLAIMS"]
            if "REMOTE_USER" in environ:
                del environ["REMOTE_USER"]

            # Use the same redirect_to_login function
            return redirect_to_login(start_response, environ)

        return self.app(environ, start_response)


class CustomRemoteUserView(AuthRemoteUserView):
    login_template = ""

    @expose("/login/")
    def login(self):
        username = request.environ.get("REMOTE_USER")

        if not username:
            logger.error(f"Login failed. REMOTE_USER is missing.")
            self.logout()
            raise Exception("Login failed due to internal error.")

        logger.info(f"CustomRemoteUserView: /login/ with REMOTE_USER={username}")

        # Load claims from environ
        jwt_claims_json = request.environ.get("JWT_CLAIMS")
        claims = {}
        if jwt_claims_json:
            try:
                claims = json.loads(jwt_claims_json)
                logger.info(
                    f"User JWT claims in /login: {json.dumps(claims, indent=2)}"
                )
            except Exception as e:
                logger.error(f"Error parsing JWT_CLAIMS: {e}")

        logger.info("Check if user is logged-in")
        try:
            if g.user is not None and g.user.is_authenticated:
                logger.info("User already authenticated, redirecting to index.")
                return redirect(self.appbuilder.get_url_for_index)
        except AttributeError:
            pass
        except Exception:
            logger.exception("Failed to check user")
            raise

        try:
            security_manager = self.appbuilder.sm

            logger.info(f"Find user {username}")
            user = security_manager.find_user(username=username)
            if user is not None:
                logger.info(f"Found existing user {username}, logging in.")
                login_user(user)
                return redirect(self.appbuilder.get_url_for_index)

            # Extract fields from claims
            first_name = claims.get("given_name", "User")
            last_name = claims.get("family_name", "Name")
            email = claims.get("email", f"{username}@notfound.com")

            logger.info(f"Map roles for {username}")
            mapped_roles = set()
            try:
                groups = claims.get("groups", [])
                if isinstance(groups, str):
                    groups = [groups]
                logger.info(f"User groups {groups}")
                for group in groups:

                    parts = [p for p in group.split("/") if p]
                    group_name = parts[0] if len(parts) > 0 else None
                    if group_name is None:
                        logger.warning(f"Invalid group format {group}")
                        continue

                    superset_role = GROUP_TO_SUPERSET_ROLE.get(group_name)
                    if superset_role:
                        mapped_roles.add(security_manager.find_role(superset_role))
                        logger.info(f"Setting role {group} -> {superset_role}")
                if not mapped_roles:
                    mapped_roles.add(security_manager.find_role(DEFAULT_ROLE))
                    logger.info(f"Role not found, setting default {DEFAULT_ROLE}")
            except Exception:
                logger.exception("Group mapping failed")
                raise

            roles = list(mapped_roles)
            logger.info(f"Creating new user {username} with roles {roles}")

            user = security_manager.add_user(
                username=username,
                first_name=first_name,
                last_name=last_name,
                email=email,
                # Superset only takes first role here. For multiple roles, you need to set .roles after user creation.
                role=roles[0],
            )
            user.roles = roles

            if user:
                logger.info(f"User {username} created and logged in.")
                login_user(user)
            else:
                logger.error(f"Failed to create user {username}.")
        except Exception:
            logger.exception("User creation failed")
            raise

        return redirect(self.appbuilder.get_url_for_index)

    @expose("/logout/")
    def logout(self):
        # Clear Flask session
        session.clear()

        # Logout user
        try:
            logout_user()
        except Exception as e:
            logger.error(f"Error during logout: {e}")

        # Clear any JWT-related cookies if they exist
        if "JWT_CLAIMS" in session:
            del session["JWT_CLAIMS"]

        # Redirect to the OAuth2 proxy sign-out endpoint
        superset_home_url = request.host_url.rstrip("/") + "/"
        signout_url = f"{SSO_BASE_URL}/oauth2/sign_out?rd={urllib.parse.quote(superset_home_url, safe='')}"

        return redirect(signout_url)


class CustomSecurityManager(SupersetSecurityManager):
    authremoteuserview = CustomRemoteUserView
