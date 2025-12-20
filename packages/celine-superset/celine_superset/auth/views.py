import urllib.parse
from flask import redirect, request
from flask_appbuilder.security.views import AuthRemoteUserView
from werkzeug.wrappers import Response as WerkzeugResponse
from flask_appbuilder.views import expose


class OAuth2ProxyAuthRemoteUserView(AuthRemoteUserView):
    """
    Override AUTH_REMOTE_USER login/logout to delegate to oauth2-proxy
    """

    login_template = None

    def _redirect_to_oauth2(self, rd: str) -> WerkzeugResponse:
        rd_enc = urllib.parse.quote(rd, safe="")
        return redirect(f"/oauth2/start?rd={rd_enc}", code=302)

    @expose("/login/")
    def login(self) -> WerkzeugResponse:
        """
        Ignore REMOTE_USER here.
        oauth2-proxy owns authentication.
        """
        next_url = request.args.get("next") or "/"
        return self._redirect_to_oauth2(next_url)

    @expose("/logout/")
    def logout(self) -> WerkzeugResponse:
        return redirect("/oauth2/sign_out", code=302)
