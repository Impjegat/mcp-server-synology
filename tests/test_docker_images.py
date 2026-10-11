"""The adapter and broker images, built and run.

These need Docker and images built from the Dockerfile's `adapter` and `broker`
targets, so they are off unless SYNOLOGY_TEST_DOCKER=1 (CI sets it, after building
the images and naming them in SYNOLOGY_TEST_ADAPTER_IMAGE and
SYNOLOGY_TEST_BROKER_IMAGE). Locally:

    docker build --target adapter -t synology-mcp-adapter:ci .
    docker build --target broker  -t synology-mcp-broker:ci .
    SYNOLOGY_TEST_DOCKER=1 python -m pytest tests/test_docker_images.py

What they show that the static checks in test_packaging.py cannot: that the image
really contains what the Dockerfile says, that nothing in it can write to the code
or run as root, that the adapter image refuses a NAS credential, and that a real
broker container, run the way deploy/broker/docker-compose.yml runs it (read-only
filesystem, no capabilities, a chosen user, config and TLS mounted read-only),
becomes healthy and answers a real adapter over verified TLS. No NAS is involved:
the broker is pointed at a made-up address and signed in to nothing.
"""

import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time

import httpx2
import pytest

from tests.test_broker_main import ROOT, TOKEN, _free_port, _policy_document
from tests.tls_support import adapter_session, make_pki

ENABLED = os.environ.get("SYNOLOGY_TEST_DOCKER") == "1" and shutil.which("docker") is not None
ADAPTER_IMAGE = os.environ.get("SYNOLOGY_TEST_ADAPTER_IMAGE", "synology-mcp-adapter:ci")
BROKER_IMAGE = os.environ.get("SYNOLOGY_TEST_BROKER_IMAGE", "synology-mcp-broker:ci")
DUMMY_PASSWORD = "Dummy-Docker-Password-7c1e"

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        not ENABLED, reason="set SYNOLOGY_TEST_DOCKER=1, with Docker and the built images"
    ),
]


def docker(*args, input_text=None, timeout=180, check=False):
    done = subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        input=input_text,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )
    if check and done.returncode != 0:
        raise AssertionError(f"docker {' '.join(args)} failed:\n{done.stdout}\n{done.stderr}")
    return done


def run(image, *args, entrypoint=None, env=(), mounts=(), input_text="", user=None, timeout=120):
    command = ["run", "--rm", "-i"]
    if entrypoint:
        command += ["--entrypoint", entrypoint]
    if user:
        command += ["--user", user]
    for name, value in env:
        command += ["-e", f"{name}={value}"]
    for mount in mounts:
        command += ["-v", mount]
    return docker(*command, image, *args, input_text=input_text, timeout=timeout)


# ------------------------------------------------------------------ adapter


class TestTheAdapterImage:
    def test_it_runs_as_an_account_that_is_not_root(self):
        done = run(ADAPTER_IMAGE, "-u", entrypoint="id")
        assert done.returncode == 0 and done.stdout.strip() == "10001", done.stderr

    def test_that_account_cannot_change_the_code(self):
        done = run(ADAPTER_IMAGE, "-c", "touch /app/x /app/src/adapter/x", entrypoint="sh")
        assert done.returncode != 0
        assert "denied" in (done.stdout + done.stderr).lower()

    def test_it_holds_only_the_adapter_and_none_of_the_nas_libraries(self):
        code = (
            "import importlib.util as u, os, json;"
            "print(json.dumps({'src': sorted(os.listdir('/app/src')),"
            " 'utils': sorted(os.listdir('/app/src/utils')),"
            " 'present': [m for m in ('requests','Crypto','dotenv','webauthn') if u.find_spec(m)]}))"
        )
        done = run(ADAPTER_IMAGE, "-c", code, entrypoint="python")
        assert done.returncode == 0, done.stderr
        found = json.loads(done.stdout.strip().splitlines()[-1])
        assert found["src"] == ["adapter", "utils"]
        assert [name for name in found["utils"] if not name.startswith("__")] == ["redact.py"]
        assert found["present"] == []

    def test_it_will_not_start_with_a_nas_password_in_its_environment(self):
        done = run(
            ADAPTER_IMAGE,
            "--config",
            "/nonexistent.json",
            env=[("SYNOLOGY_PASSWORD", DUMMY_PASSWORD)],
        )
        assert done.returncode != 0
        assert "SYNOLOGY_PASSWORD" in done.stderr
        assert DUMMY_PASSWORD not in done.stdout + done.stderr

    def test_it_starts_and_ends_cleanly_with_its_standard_output_kept_for_the_protocol(
        self, tmp_path
    ):
        config = tmp_path / "adapter.json"
        config.write_text(
            json.dumps(
                {
                    "broker_url": "http://127.0.0.1:9/mcp",
                    "allow_insecure_loopback": True,
                    "token_env": "ADAPTER_TOKEN",
                }
            )
        )
        done = run(
            ADAPTER_IMAGE,
            "--config",
            "/config/adapter.json",
            env=[("ADAPTER_TOKEN", "x" * 24)],
            mounts=[f"{config}:/config/adapter.json:ro"],
        )
        assert done.returncode == 0, done.stderr
        assert done.stdout == ""


# ------------------------------------------------------------------- broker


class TestTheBrokerImage:
    def test_run_with_nothing_it_prints_how_to_use_it_and_serves_nothing(self):
        done = run(BROKER_IMAGE)
        assert done.returncode == 0 and "usage" in done.stdout.lower()

    def test_it_refuses_to_serve_without_tls(self):
        done = run(BROKER_IMAGE, "serve", "--policy", "/nonexistent", "--host", "0.0.0.0")
        assert done.returncode == 2
        assert "Refusing to start without TLS" in done.stderr

    def test_it_runs_as_an_account_that_is_not_root_and_holds_no_test_tools(self):
        assert run(BROKER_IMAGE, "-u", entrypoint="id").stdout.strip() == "10001"
        code = "import importlib.util as u; print(u.find_spec('pytest') is None)"
        done = run(BROKER_IMAGE, "-c", code, entrypoint="python")
        assert done.stdout.strip() == "True"


class RunningBroker:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.name = f"synology-broker-test-{os.getpid()}-{int(time.time())}"
        self.port = _free_port()
        self.private_port = _free_port()
        self.pki = make_pki(tmp_path / "tls")
        self.user = f"{os.getuid()}:{os.getgid()}"

    def prepare(self):
        config = self.tmp_path / "config"
        state = self.tmp_path / "state"
        for directory in (config, state):
            directory.mkdir()
            os.chmod(directory, 0o700)
        (config / "settings.json").write_text(
            json.dumps(
                {
                    "synology": {
                        "default": {"host": "nas.example.test", "port": 5001, "username": "reader"}
                    }
                }
            )
        )
        os.chmod(config / "settings.json", 0o600)
        (config / "broker-policy.json").write_text(json.dumps(_policy_document()))
        os.chmod(config / "broker-policy.json", 0o600)
        # the container's user is the test's user, so the mounts are readable and owned right
        self.config, self.state = config, state

    def start(self):
        self.prepare()
        docker(
            "run",
            "-d",
            "--name",
            self.name,
            "--user",
            self.user,
            "--read-only",
            "--tmpfs",
            "/tmp",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "-p",
            f"127.0.0.1:{self.port}:8443",
            "-p",
            f"127.0.0.1:{self.private_port}:8444",
            "--health-interval",
            "3s",
            "--health-start-period",
            "1s",
            "--health-retries",
            "3",
            "-e",
            "XDG_CONFIG_HOME=/config",
            "-v",
            f"{self.config}:/config/synology-mcp:ro",
            "-v",
            f"{self.pki.cert.parent}:/tls:ro",
            "-v",
            f"{self.state}:/state",
            BROKER_IMAGE,
            "serve",
            "--policy=/config/synology-mcp/broker-policy.json",
            "--host=0.0.0.0",
            "--port=8443",
            f"--allowed-host=localhost:{self.port}",
            "--tls-cert=/tls/cert.pem",
            "--tls-key=/tls/key.pem",
            f"--private-origin=https://localhost:{self.private_port}",
            "--private-host=0.0.0.0",
            "--private-port=8444",
            f"--private-allowed-host=localhost:{self.private_port}",
            "--rp-id=localhost",
            "--owner-store=/state/owner.json",
            check=True,
        )
        self.wait_until_healthy()

    def status(self):
        done = docker(
            "inspect", "--format", "{{.State.Status}} {{.State.Health.Status}}", self.name
        )
        return done.stdout.strip()

    def logs(self):
        done = docker("logs", self.name)
        return done.stdout + done.stderr

    def wait_until_healthy(self, seconds=120):
        deadline = time.monotonic() + seconds
        last = ""
        while time.monotonic() < deadline:
            last = self.status()
            if last == "running healthy":
                return
            if last.startswith("exited"):
                break
            time.sleep(2)
        raise AssertionError(
            f"the broker container did not become healthy ({last}):\n{self.logs()}"
        )

    def stop(self):
        docker("rm", "-f", self.name)


@pytest.fixture
def broker(tmp_path):
    running = RunningBroker(tmp_path)
    running.start()
    yield running
    running.stop()


def _verify(path):
    return ssl.create_default_context(cafile=str(path))


@pytest.mark.skipif(sys.platform == "win32", reason="the containers run on Linux")
class TestARunningBrokerContainer:
    def test_the_image_health_check_reports_it_healthy_with_nobody_signed_in(self, broker):
        assert broker.status() == "running healthy"

    def test_it_answers_over_verified_tls_and_serves_the_private_login(self, broker):
        verify = _verify(broker.pki.ca)
        ready = httpx2.get(f"https://localhost:{broker.port}/readyz", verify=verify, timeout=5)
        assert ready.status_code == 200
        page = httpx2.get(f"https://localhost:{broker.private_port}/", verify=verify, timeout=5)
        assert page.status_code == 200 and "No owner enrolled" in page.text

    @pytest.mark.asyncio
    async def test_a_real_adapter_reaches_it_and_is_told_to_have_the_user_sign_in(
        self, broker, tmp_path
    ):
        async with adapter_session(
            tmp_path / "adapter",
            f"https://localhost:{broker.port}/mcp",
            token=TOKEN,
            ca_file=broker.pki.ca,
        ) as session:
            listing = (await session.list_tools()).tools
            shares = await session.call_tool("list_shares", {"nas_name": "default"})
        titles = {t.name: t.title for t in listing}
        assert titles["list_shares"] == "Browse shared folders" and "synology_login" not in titles
        assert shares.is_error is True and shares.content[0].text.startswith(
            "AUTHENTICATION_REQUIRED"
        )

    def test_it_is_run_the_way_the_template_runs_it(self, broker):
        info = json.loads(docker("inspect", broker.name, check=True).stdout)[0]
        host = info["HostConfig"]
        assert host["ReadonlyRootfs"] is True
        assert host["CapDrop"] == ["ALL"] and host["Privileged"] is False
        assert "no-new-privileges:true" in host["SecurityOpt"]
        assert info["Config"]["User"] == broker.user
        assert all(not b.startswith("/var/run/docker.sock") for b in host["Binds"])

    def test_the_code_cannot_be_written_and_the_config_is_read_only(self, broker):
        assert docker("exec", broker.name, "sh", "-c", "touch /app/x").returncode != 0
        assert (
            docker("exec", broker.name, "sh", "-c", "touch /config/synology-mcp/x").returncode != 0
        )
        assert docker("exec", broker.name, "sh", "-c", "touch /tls/x").returncode != 0
        # the one place it may write is the owner's state
        assert docker("exec", broker.name, "sh", "-c", "touch /state/probe").returncode == 0

    def test_nothing_secret_is_in_its_log_or_its_environment(self, broker):
        env = docker("inspect", "--format", "{{json .Config.Env}}", broker.name, check=True).stdout
        assert not re.search(r"(PASSWORD|OTP|TOKEN|SECRET|DEVICE)", env, re.I)
        logs = broker.logs()
        assert TOKEN not in logs and "Authorization" not in logs


# --------------------------------------------------------- the compose template


class TestTheComposeTemplateAsComposeReadsIt:
    def _config(self, **overrides):
        env = {
            "BROKER_UID": "10001",
            "BROKER_GID": "10001",
            "BROKER_HOST": "broker.example.lan",
            "BROKER_BIND_ADDRESS": "192.0.2.10",
            "BROKER_PRIVATE_BIND_ADDRESS": "192.0.2.11",
            "BROKER_CONFIG_DIR": "/opt/synology-broker/synology-mcp",
            "BROKER_TLS_DIR": "/opt/synology-broker/tls",
            "BROKER_STATE_DIR": "/opt/synology-broker/state",
            **overrides,
        }
        done = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(ROOT / "deploy" / "broker" / "docker-compose.yml"),
                "config",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, **env},
        )
        return done

    def test_it_resolves_to_a_locked_down_service_published_where_it_was_told(self):
        done = self._config()
        assert done.returncode == 0, done.stderr
        service = json.loads(done.stdout)["services"]["broker"]
        assert service["read_only"] is True and service["cap_drop"] == ["ALL"]
        assert service["user"] == "10001:10001"
        assert "env_file" not in service and not service.get("privileged")
        published = sorted((p["host_ip"], p["target"]) for p in service["ports"])
        assert published == [("192.0.2.10", 8443), ("192.0.2.11", 8444)]
        writable = [v for v in service["volumes"] if not v.get("read_only")]
        assert [v["target"] for v in writable] == ["/state"]
        assert "--allowed-host=broker.example.lan:8443" in service["command"]

    def test_it_will_not_resolve_without_choosing_where_to_publish(self):
        done = self._config(BROKER_BIND_ADDRESS="")
        assert done.returncode != 0
        assert "BROKER_BIND_ADDRESS" in done.stderr
