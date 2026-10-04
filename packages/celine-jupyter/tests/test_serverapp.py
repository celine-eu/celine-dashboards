"""Startup: the CELINE authentication is what actually runs, and the server does not start without it.

Two ways the server is started, both covered:

- ``jupyter celine-server`` (the image's command): ``CelineServerApp``, authentication built in.
- a stock ``jupyter server`` / ``jupyter lab`` given the shipped ``jupyter_server_config.py`` (what
  the compose stack mounts at ``~/.jupyter/``).

The in-process tests initialise the application (no HTTP server). ``TestLiveServer`` starts real
servers in subprocesses and sends real requests with RS256 tokens of a local issuer.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests
from conftest import LEGACY_REALM_ADMIN, ORG_ADMIN, ORG_VIEWER, PLATFORM_ADMIN
from jupyter_server.serverapp import ServerApp

from celine.jupyter.identity import JWTIdentityProvider
from celine.jupyter.jwt_authorizer import JWTAuthorizer
from celine.jupyter.serverapp import EXTENSION, CelineServerApp

SHIPPED_CONFIG = Path(__file__).resolve().parents[3] / "config" / "jupyter" / "jupyter_server_config.py"


@pytest.fixture
def shipped_config(jupyter_env: Path) -> Path:
    """The repository's config/jupyter/jupyter_server_config.py, at ~/.jupyter/ as in the image."""
    assert SHIPPED_CONFIG.is_file(), SHIPPED_CONFIG
    target = jupyter_env / "jupyter_server_config.py"
    shutil.copy(SHIPPED_CONFIG, target)
    return target


def start(app_class: type[ServerApp], root: Path, *argv: str) -> ServerApp:
    app = app_class()
    app.initialize(argv=[f"--ServerApp.root_dir={root}", "--port=0", *argv], new_httpserver=False)
    return app


def assert_celine_authentication(app: ServerApp) -> None:
    assert type(app.identity_provider) is JWTIdentityProvider
    assert type(app.authorizer) is JWTAuthorizer
    assert app.authorizer.identity_provider is app.identity_provider
    assert app.identity_provider.token == ""
    assert app.allow_unauthenticated_access is False
    assert app.disable_check_xsrf is False
    assert app.web_app.settings["allow_unauthenticated_access"] is False
    assert app.web_app.settings["authorizer"] is app.authorizer
    assert app.web_app.settings["identity_provider"] is app.identity_provider


# Both launch paths: (application class, needs the shipped config file).
LAUNCHES = [
    pytest.param((CelineServerApp, False), id="celine-server"),
    pytest.param((CelineServerApp, True), id="celine-server+config"),
    pytest.param((ServerApp, True), id="stock-server+config"),
]


@pytest.fixture
def launch(request, jupyter_env, issuer, monkeypatch):
    app_class, with_config = request.param
    if with_config:
        shutil.copy(SHIPPED_CONFIG, jupyter_env / "jupyter_server_config.py")
    monkeypatch.setenv("CELINE_JUPYTER_JWT_ISSUER", issuer.issuer)
    root = jupyter_env.parent / "root"
    return lambda *argv: start(app_class, root, *argv)


@pytest.mark.parametrize("launch", LAUNCHES, indirect=True)
class TestStartup:
    def test_configured_authentication_is_active(self, launch, issuer):
        app = launch()
        assert_celine_authentication(app)
        assert app.identity_provider.issuer == issuer.issuer

    @pytest.mark.parametrize("override", [
        "--ServerApp.authorizer_class=jupyter_server.auth.authorizer.AllowAllAuthorizer",
        "--ServerApp.identity_provider_class=jupyter_server.auth.identity.PasswordIdentityProvider",
        "--ServerApp.identity_provider_class=jupyter_server.auth.identity.IdentityProvider",
        "--ServerApp.allow_unauthenticated_access=True",
        "--ServerApp.disable_check_xsrf=True",
    ])
    def test_refuses_to_start_when_overridden(self, launch, override):
        with pytest.raises(SystemExit, match="refuses to start"):
            launch(override)

    def test_refuses_to_start_without_an_issuer(self, launch, monkeypatch):
        monkeypatch.delenv("CELINE_JUPYTER_JWT_ISSUER")
        with pytest.raises(SystemExit, match="no trusted issuer"):
            launch()

    @pytest.mark.parametrize("token", ["--IdentityProvider.token=abc", "--ServerApp.token=abc"])
    def test_a_configured_server_token_is_dropped(self, launch, token):
        app = launch(token)
        assert_celine_authentication(app)

    def test_jupyter_token_environment_is_dropped(self, launch, monkeypatch):
        monkeypatch.setenv("JUPYTER_TOKEN", "leaked")
        assert_celine_authentication(launch())

    def test_unauthenticated_environment_switch_is_ignored(self, launch, monkeypatch):
        monkeypatch.setenv("JUPYTER_SERVER_ALLOW_UNAUTHENTICATED_ACCESS", "true")
        assert_celine_authentication(launch())


class TestShippedConfigOnStockServer:
    def test_enables_the_startup_check_extension(self, shipped_config, issuer, monkeypatch):
        monkeypatch.setenv("CELINE_JUPYTER_JWT_ISSUER", issuer.issuer)
        app = start(ServerApp, shipped_config.parent.parent / "root")
        assert app.jpserver_extensions.get(EXTENSION) is True
        assert EXTENSION in app.extension_manager.extensions
        assert_celine_authentication(app)

    def test_fails_closed_when_celine_jupyter_cannot_be_imported(self, shipped_config, issuer, monkeypatch):
        # Jupyter logs an exception in a config file and starts anyway with a random token;
        # the shipped file turns that into SystemExit.
        monkeypatch.setenv("CELINE_JUPYTER_JWT_ISSUER", issuer.issuer)
        monkeypatch.setitem(sys.modules, "celine.jupyter.serverapp", None)
        with pytest.raises(SystemExit, match="cannot load the CELINE authentication"):
            start(ServerApp, shipped_config.parent.parent / "root")

    def test_stock_server_without_the_config_is_not_ours(self, jupyter_env, issuer, monkeypatch):
        # Control: proves the tests above measure the config file, not a default.
        monkeypatch.setenv("CELINE_JUPYTER_JWT_ISSUER", issuer.issuer)
        app = start(ServerApp, jupyter_env.parent / "root")
        assert type(app.identity_provider) is not JWTIdentityProvider
        assert type(app.authorizer) is not JWTAuthorizer


# --- live server -------------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


SERVER_COMMANDS = {
    # `jupyter celine-server` is this module's console script; -m runs the same entry point.
    "celine-server": [sys.executable, "-m", "celine.jupyter.serverapp"],
    "stock-server+config": [sys.executable, "-m", "jupyter_server"],
}


@pytest.fixture(params=sorted(SERVER_COMMANDS), scope="class")
def live(request, issuer, tmp_path_factory):
    tmp = tmp_path_factory.mktemp(request.param)
    for name in ("config", "data", "runtime", "root"):
        (tmp / name).mkdir()
    if request.param.endswith("+config"):
        shutil.copy(SHIPPED_CONFIG, tmp / "config" / "jupyter_server_config.py")
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("JUPYTER", "CELINE_JUPYTER"))}
    env.update({
        "JUPYTER_CONFIG_DIR": str(tmp / "config"),
        "JUPYTER_DATA_DIR": str(tmp / "data"),
        "JUPYTER_RUNTIME_DIR": str(tmp / "runtime"),
        "CELINE_JUPYTER_JWT_ISSUER": issuer.issuer,
        # Must not open anything: the server has no token of its own.
        "JUPYTER_TOKEN": "leaked-server-token",
    })
    log = tmp / "server.log"
    with open(log, "w") as out:
        proc = subprocess.Popen(
            [*SERVER_COMMANDS[request.param], f"--port={port}", "--ip=127.0.0.1", "--no-browser",
             f"--ServerApp.root_dir={tmp / 'root'}"],
            env=env, stdout=out, stderr=subprocess.STDOUT, start_new_session=True,
        )
    base = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 60
    while True:
        if proc.poll() is not None:
            pytest.fail(f"{request.param} exited {proc.returncode}:\n{log.read_text()}")
        try:
            requests.get(f"{base}/api/status", timeout=2)
            break
        except requests.ConnectionError:
            if time.monotonic() > deadline:
                proc.kill()
                pytest.fail(f"{request.param} did not answer:\n{log.read_text()}")
            time.sleep(0.3)
    yield base, log
    os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)


class TestLiveServer:
    ENDPOINTS = ["/api/contents", "/api/kernels", "/api/terminals", "/api/sessions"]

    @pytest.mark.parametrize("path", ENDPOINTS)
    @pytest.mark.parametrize("header", ["X-Forwarded-Access-Token", "Authorization"])
    def test_platform_admin_gets_in(self, live, issuer, path, header):
        base, _ = live
        token = issuer.sign(PLATFORM_ADMIN)
        value = token if header == "X-Forwarded-Access-Token" else f"Bearer {token}"
        assert requests.get(base + path, headers={header: value}, timeout=10).status_code == 200

    @pytest.mark.parametrize("path", ENDPOINTS)
    @pytest.mark.parametrize("claims", [ORG_ADMIN, ORG_VIEWER, LEGACY_REALM_ADMIN], ids=["org-admin", "org-viewer", "legacy"])
    def test_everyone_else_is_refused(self, live, issuer, path, claims):
        base, _ = live
        token = issuer.sign(claims)
        for headers in ({"X-Forwarded-Access-Token": token}, {"Authorization": f"Bearer {token}"}):
            assert requests.get(base + path, headers=headers, timeout=10).status_code == 403

    @pytest.mark.parametrize("path", ENDPOINTS)
    def test_no_token_refused(self, live, path):
        base, _ = live
        assert requests.get(base + path, timeout=10).status_code == 403

    @pytest.mark.parametrize("path", ENDPOINTS)
    def test_the_servers_own_token_is_refused(self, live, path):
        base, _ = live
        assert requests.get(f"{base}{path}?token=leaked-server-token", timeout=10).status_code == 403
        assert requests.get(base + path, headers={"Authorization": "token leaked-server-token"},
                            timeout=10).status_code == 403

    def test_platform_admin_of_another_issuer_refused(self, live, issuer, other_key):
        base, _ = live
        token = issuer.sign(PLATFORM_ADMIN, iss="https://evil.example.org/realms/celine", key=other_key)
        assert requests.get(f"{base}/api/contents", headers={"Authorization": f"Bearer {token}"},
                            timeout=10).status_code == 403

    def test_forged_platform_admin_refused(self, live, issuer, other_key):
        base, _ = live
        token = issuer.sign(PLATFORM_ADMIN, key=other_key)
        assert requests.get(f"{base}/api/contents", headers={"Authorization": f"Bearer {token}"},
                            timeout=10).status_code == 403

    def test_no_login_page(self, live):
        base, _ = live
        assert requests.get(f"{base}/login", timeout=10).status_code == 403
        assert requests.post(f"{base}/login", data={"password": "x", "token": "leaked-server-token"},
                             timeout=10).status_code == 403

    def test_write_with_bearer_skips_xsrf_forwarded_keeps_it(self, live, issuer):
        base, _ = live
        token = issuer.sign(PLATFORM_ADMIN)
        created = requests.post(f"{base}/api/contents", json={"type": "notebook"},
                                headers={"Authorization": f"Bearer {token}"}, timeout=10)
        assert created.status_code == 201
        requests.delete(f"{base}/api/contents/{created.json()['path']}",
                        headers={"Authorization": f"Bearer {token}"}, timeout=10)
        # A forwarded token stands for a browser session: no XSRF token, no write.
        assert requests.post(f"{base}/api/contents", json={"type": "notebook"},
                             headers={"X-Forwarded-Access-Token": token}, timeout=10).status_code == 403
        # ... and an org admin cannot write either way.
        assert requests.post(f"{base}/api/contents", json={"type": "notebook"},
                             headers={"Authorization": f"Bearer {issuer.sign(ORG_ADMIN)}"},
                             timeout=10).status_code == 403

    def test_startup_log_shows_no_token_url(self, live):
        _, log = live
        text = log.read_text()
        assert "leaked-server-token" not in text
        startup = text.split("Use Control-C", 1)[0]
        assert "is running at" in startup
        assert "token=" not in startup
        assert "Only platform administrators' access tokens" in startup
