from flask import Flask
from celine_superset.auth.views import OAuth2ProxyAuthRemoteUserView


def _view_without_init():
    """
    Create OAuth2ProxyAuthRemoteUserView without triggering
    Flask-AppBuilder BaseView.__init__().
    """
    return OAuth2ProxyAuthRemoteUserView.__new__(OAuth2ProxyAuthRemoteUserView)


def test_login_redirects_to_oauth2():
    app = Flask(__name__)

    with app.test_request_context("/login/?next=/dashboard"):
        view = _view_without_init()
        response = view.login()

        assert response.status_code == 302
        assert response.location.startswith("/oauth2/start")
        assert "rd=%2Fdashboard" in response.location


def test_logout_redirects_to_oauth2():
    app = Flask(__name__)

    with app.test_request_context("/logout/"):
        view = _view_without_init()
        response = view.logout()

        assert response.status_code == 302
        assert response.location == "/oauth2/sign_out"
