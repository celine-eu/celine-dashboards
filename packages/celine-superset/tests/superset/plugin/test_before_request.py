"""What a request `before_request` refuses is answered with (`plugin/refusal.py`).

No verifiable identity: a page is sent to sign-in, an API call is told 401. A verified identity
Superset grants no role: 403 either way, because signing in again cannot change it. Refused API
calls used to answer 500. `before_request` itself imports Superset, which this suite's
`tests/superset` package shadows; its wiring was checked against a running Superset.
"""

from flask import Flask

from celine.superset.plugin import refusal

app = Flask(__name__)


def test_an_api_call_without_an_identity_is_401():
    with app.test_request_context("/api/v1/dataset/"):
        response = refusal.unauthenticated()
    assert response.status_code == 401
    assert response.get_json() == {"message": "Not authenticated"}


def test_a_page_without_an_identity_goes_to_sign_in():
    with app.test_request_context("/superset/welcome/?x=1"):
        response = refusal.unauthenticated()
    assert response.status_code == 302
    assert response.location == "/login/?next=%2Fsuperset%2Fwelcome%2F%3Fx%3D1"


def test_an_api_call_from_an_identity_with_no_role_is_403():
    with app.test_request_context("/api/v1/chart/"):
        response = refusal.forbidden()
    assert response.status_code == 403
    assert response.get_json() == {"message": "Access denied"}


def test_a_page_for_an_identity_with_no_role_is_403_not_a_sign_in_loop():
    with app.test_request_context("/superset/welcome/"):
        response = refusal.forbidden()
    assert response.status_code == 403
    assert response.location is None


def test_only_the_api_prefix_counts_as_an_api_call():
    with app.test_request_context("/apiary/"):
        assert refusal.is_api_request() is False
    with app.test_request_context("/api/v1/me/"):
        assert refusal.is_api_request() is True
