import pytest
from flask import Flask
from flask_login import LoginManager, AnonymousUserMixin


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"

    yield app
