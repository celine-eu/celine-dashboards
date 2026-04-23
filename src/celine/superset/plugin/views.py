import urllib.parse

from flask import redirect, request
from flask_appbuilder.security.views import AuthRemoteUserView
from flask_appbuilder.views import expose
from werkzeug.wrappers import Response as WerkzeugResponse


class OAuth2ProxyAuthRemoteUserView(AuthRemoteUserView):
    """Delegate login/logout to oauth2-proxy instead of FAB's built-in forms."""

    login_template = None

    def _redirect_to_oauth2(self, rd: str) -> WerkzeugResponse:
        return redirect(f"/oauth2/start?rd={urllib.parse.quote(rd, safe='')}", code=302)

    @expose("/login/")
    def login(self) -> WerkzeugResponse:
        next_url = request.args.get("next") or "/"
        return self._redirect_to_oauth2(next_url)

    @expose("/logout/")
    def logout(self) -> WerkzeugResponse:
        return redirect("/oauth2/sign_out", code=302)
