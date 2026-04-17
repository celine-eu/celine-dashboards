from flask import Flask
from celine.superset.plugin.views import OAuth2ProxyAuthRemoteUserView


def _view():
    return OAuth2ProxyAuthRemoteUserView.__new__(OAuth2ProxyAuthRemoteUserView)


def test_login_redirects_to_oauth2():
    app = Flask(__name__)
    with app.test_request_context("/login/?next=/dashboard"):
        resp = _view().login()
        assert resp.status_code == 302
        assert resp.location.startswith("/oauth2/start")
        assert "rd=%2Fdashboard" in resp.location


def test_login_defaults_to_root():
    app = Flask(__name__)
    with app.test_request_context("/login/"):
        resp = _view().login()
        assert "rd=%2F" in resp.location


def test_logout_redirects_to_sign_out():
    app = Flask(__name__)
    with app.test_request_context("/logout/"):
        resp = _view().logout()
        assert resp.status_code == 302
        assert resp.location == "/oauth2/sign_out"
