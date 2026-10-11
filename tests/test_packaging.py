"""Packaging, deployment and documentation of the manual-authentication setup.

None of this needs Docker or a network. It reads the Dockerfile, the compose
template, the ignore files, the configuration examples and the documents, and
holds them to what the code actually accepts and does:

- an image's files are exactly what its Dockerfile copies, so the adapter's file
  set is rebuilt from those COPY lines and the adapter is run in it;
- the examples are parsed by the real parsers and contain no secret;
- every flag, setting and error code a document mentions exists in the code;
- private files are ignored by git and by Docker, and the examples are not.

The images themselves are built and run by tests/test_docker_images.py, which CI
enables.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


# ---------------------------------------------------------------- Dockerfile


def _logical_lines(text: str):
    """The Dockerfile's instructions, one string each, continuations joined and
    comments dropped."""
    lines, buffer = [], ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue
        if not stripped and not buffer:
            continue
        if stripped.endswith("\\"):
            buffer += stripped[:-1].strip() + " "
            continue
        lines.append((buffer + stripped).strip())
        buffer = ""
    return lines


def dockerfile_stages():
    """Ordered mapping: stage name -> {"base": ..., "instructions": [(NAME, args)]}."""
    stages = {}
    current = None
    for line in _logical_lines(_read("Dockerfile")):
        name, _, rest = line.partition(" ")
        name = name.upper()
        if name == "FROM":
            match = re.match(r"(\S+)(?:\s+AS\s+(\S+))?", rest, re.IGNORECASE)
            current = match.group(2) or match.group(1)
            stages[current] = {"base": match.group(1), "instructions": []}
        else:
            stages[current]["instructions"].append((name, rest.strip()))
    return stages


def _copies(stage):
    """[(sources, destination, flags)] for the COPY instructions of a stage."""
    found = []
    for name, args in dockerfile_stages()[stage]["instructions"]:
        if name != "COPY":
            continue
        parts = args.split()
        flags = [p for p in parts if p.startswith("--")]
        paths = [p for p in parts if not p.startswith("--")]
        found.append((paths[:-1], paths[-1], flags))
    return found


def _instructions(stage, wanted):
    return [a for n, a in dockerfile_stages()[stage]["instructions"] if n == wanted]


RUNTIME_IMAGES = ("adapter", "broker", "legacy")
BUILDERS = ("build-adapter", "build-server")


class TestDockerfile:
    def test_it_makes_the_three_images_and_the_old_one_is_last(self):
        stages = list(dockerfile_stages())
        assert {"adapter", "broker", "legacy"} <= set(stages)
        # `docker build .` and docker-compose.yml build the last stage
        assert stages[-1] == "legacy"

    @pytest.mark.parametrize("stage", RUNTIME_IMAGES)
    def test_every_image_runs_as_an_account_that_is_not_root(self, stage):
        users = _instructions(stage, "USER")
        assert users, f"{stage} never sets USER"
        assert users[-1].split(":")[0] not in ("root", "0")
        # and nothing that follows it needs privileges
        instructions = dockerfile_stages()[stage]["instructions"]
        last_user = max(i for i, (n, _) in enumerate(instructions) if n == "USER")
        assert not [n for n, _ in instructions[last_user + 1 :] if n in ("RUN", "COPY", "ADD")]

    @pytest.mark.parametrize("stage", ("adapter", "broker"))
    def test_the_code_is_not_owned_or_writable_by_the_account_that_runs_it(self, stage):
        for sources, destination, flags in _copies(stage):
            assert not [f for f in flags if f.startswith("--chown") or f.startswith("--chmod")]
        for command in _instructions(stage, "RUN"):
            assert "chown" not in command and "chmod" not in command, command

    def test_the_legacy_image_makes_only_its_log_directory_writable(self):
        for command in _instructions("legacy", "RUN"):
            if "chown" in command:
                assert re.search(r"chown\s+mcpuser:mcpuser\s+/app/logs\s*$", command), command
                assert "-R" not in command
        for _sources, _destination, flags in _copies("legacy"):
            assert not [f for f in flags if f.startswith("--chown")]

    @pytest.mark.parametrize("stage", ("runtime", *RUNTIME_IMAGES))
    def test_the_runtime_images_carry_no_compiler_and_install_nothing(self, stage):
        for command in _instructions(stage, "RUN"):
            for forbidden in ("apt-get", "apt ", "gcc", "pip install", "curl", "wget"):
                assert forbidden not in command, (stage, command)

    def test_dependencies_are_built_in_stages_that_do_not_become_images(self):
        for builder, requirements in (
            ("build-adapter", "requirements-adapter.txt"),
            ("build-server", "requirements.txt"),
        ):
            commands = " ".join(_instructions(builder, "RUN"))
            assert f"-r {requirements}" in commands
            assert [s for s, _d, _f in _copies(builder)] == [[requirements]]
        sources = {tuple(s) for stage in RUNTIME_IMAGES for s, _d, _f in _copies(stage)}
        assert ("requirements-dev.txt",) not in sources

    def test_each_image_takes_its_dependencies_from_the_right_builder(self):
        def venv_from(stage):
            return [f for _s, _d, flags in _copies(stage) for f in flags if "--from=" in f]

        assert venv_from("adapter") == ["--from=build-adapter"]
        assert venv_from("broker") == ["--from=build-server"]
        assert venv_from("legacy") == ["--from=build-server"]

    def test_the_adapter_image_holds_the_adapter_and_nothing_else(self):
        own = {
            (tuple(sources), destination)
            for sources, destination, flags in _copies("adapter")
            if not flags
        }
        assert own == {
            (("adapter_main.py",), "./"),
            (("src/adapter/",), "./src/adapter/"),
            (("src/utils/redact.py",), "./src/utils/redact.py"),
        }

    def test_the_broker_image_copies_named_things_and_no_configuration(self):
        own = {tuple(sources) for sources, _d, flags in _copies("broker") if not flags}
        assert own == {("main.py", "broker_main.py"), ("src/",), ("docker/broker_healthcheck.py",)}

    @pytest.mark.parametrize("stage", RUNTIME_IMAGES)
    def test_no_image_copies_the_whole_context_or_a_secret(self, stage):
        secret_names = re.compile(
            r"(\.env|settings|token|\.pem|\.key|owner|policy|adapter\.json|secret|password)", re.I
        )
        for sources, _destination, flags in _copies(stage):
            if flags:
                continue
            for source in sources:
                assert source not in (".", "./", "*", "/", "src/..")
                assert not secret_names.search(source.replace("broker_main.py", "")), source

    def test_nothing_secret_is_set_in_the_environment_or_as_a_build_argument(self):
        for stage in dockerfile_stages():
            for name in ("ENV", "ARG"):
                for args in _instructions(stage, name):
                    assert not re.search(
                        r"(password|passwd|otp|token|secret|device|credential)", args, re.I
                    ), (stage, args)

    def test_the_broker_image_has_a_real_health_check_and_a_safe_default_command(self):
        health = _instructions("broker", "HEALTHCHECK")
        assert len(health) == 1 and "broker_healthcheck.py" in health[0]
        assert _instructions("broker", "ENTRYPOINT") == ['["python", "broker_main.py"]']
        # no default `serve`: it would start without a policy or TLS, or refuse confusingly
        assert _instructions("broker", "CMD") == ['["--help"]']
        assert "8443" in _instructions("broker", "EXPOSE")[0]

    def test_the_adapter_image_starts_the_adapter_and_exposes_nothing(self):
        assert _instructions("adapter", "ENTRYPOINT") == ['["python", "adapter_main.py"]']
        assert not _instructions("adapter", "EXPOSE")
        assert not _instructions("adapter", "HEALTHCHECK")

    def test_the_base_does_not_write_bytecode_into_code_that_is_read_only(self):
        env = " ".join(_instructions("runtime", "ENV"))
        assert "PYTHONDONTWRITEBYTECODE=1" in env


# --------------------------------------------- the adapter image's real files


def _populate(tree: Path, stage: str, skip=()):
    """Copy what the Dockerfile's `stage` copies from the build context (and only
    that) into `tree`, as COPY would."""
    for sources, destination, flags in _copies(stage):
        if flags:
            continue
        for source in sources:
            if source in skip:
                continue
            origin = ROOT / source
            target_dir = tree / destination.lstrip("/")
            if origin.is_dir():
                shutil.copytree(
                    origin,
                    target_dir,
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
                )
            elif destination.endswith("/"):
                target_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy(origin, target_dir / origin.name)
            else:
                target_dir.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(origin, target_dir)


def _minimal_environment():
    keep = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "LANG")
    return {name: os.environ[name] for name in keep if name in os.environ}


def _run_adapter(tree: Path, config: Path, **env):
    return subprocess.run(
        [sys.executable, "adapter_main.py", "--config", str(config)],
        input="",  # closing standard input ends it at once
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(tree),
        env={**_minimal_environment(), "PACKAGING_TEST_TOKEN": "x" * 24, **env},
    )


@pytest.fixture
def adapter_config(tmp_path):
    path = tmp_path / "adapter.json"
    path.write_text(
        json.dumps(
            {
                "broker_url": "http://127.0.0.1:9/mcp",
                "allow_insecure_loopback": True,
                "token_env": "PACKAGING_TEST_TOKEN",
            }
        )
    )
    return path


class TestTheAdapterImageContents:
    """The Dockerfile's adapter stage copies a handful of files. Rebuild exactly
    that tree and run the adapter in it: anything the adapter needs that the stage
    does not copy fails here, not in a container."""

    @pytest.fixture
    def tree(self, tmp_path):
        tree = tmp_path / "app"
        tree.mkdir()
        _populate(tree, "adapter")
        return tree

    def test_the_file_set_is_small_and_has_no_nas_code(self, tree):
        present = sorted(
            str(p.relative_to(tree)).replace("\\", "/") for p in tree.rglob("*") if p.is_file()
        )
        assert "adapter_main.py" in present
        assert all(
            p == "adapter_main.py" or p.startswith("src/adapter/") or p == "src/utils/redact.py"
            for p in present
        ), present
        for module in ("auth", "config", "mcp_server", "filestation", "broker", "private_auth"):
            assert (
                not (tree / "src" / module).exists()
                and not (tree / "src" / f"{module}.py").exists()
            )

    def test_the_adapter_starts_and_exits_cleanly_in_that_tree(self, tree, adapter_config):
        done = _run_adapter(tree, adapter_config)
        assert done.returncode == 0, done.stderr
        assert done.stdout == ""  # standard output is protocol only

    def test_it_answers_the_protocol_with_the_broker_down(self, tree, adapter_config):
        import anyio
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
        from mcp.shared.exceptions import MCPError

        async def scenario():
            params = StdioServerParameters(
                command=sys.executable,
                args=["adapter_main.py", "--config", str(adapter_config)],
                env={**_minimal_environment(), "PACKAGING_TEST_TOKEN": "x" * 24},
                cwd=str(tree),
            )
            with open(tree.parent / "adapter.err", "w", encoding="utf-8") as errlog:
                async with stdio_client(params, errlog=errlog) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        with pytest.raises(MCPError) as error:
                            await session.list_tools()
                        return str(error.value)

        assert "BROKER_UNAVAILABLE" in anyio.run(scenario)

    def test_a_missing_file_is_noticed(self, tmp_path, adapter_config):
        """The check above can fail: leave out the redaction module the adapter's
        logging needs and it does not start."""
        broken = tmp_path / "broken"
        broken.mkdir()
        _populate(broken, "adapter", skip=("src/utils/redact.py",))
        done = _run_adapter(broken, adapter_config)
        assert done.returncode != 0
        assert "utils" in done.stderr  # No module named 'utils'

    def test_it_still_refuses_a_nas_credential_in_that_tree(self, tree, adapter_config):
        done = _run_adapter(tree, adapter_config, SYNOLOGY_PASSWORD="Dummy-Packaging-Password-1")
        assert done.returncode != 0
        assert "SYNOLOGY_PASSWORD" in done.stderr
        assert "Dummy-Packaging-Password-1" not in done.stderr + done.stdout


# ------------------------------------------------------------- requirements


def _requirement_lines(name):
    lines = []
    for raw in _read(name).splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return lines


def _third_party_imports(paths):
    import ast

    names = set()
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return {n for n in names if n not in sys.stdlib_module_names}


class TestRequirements:
    def test_tests_and_runtime_are_separate_files(self):
        runtime = " ".join(_requirement_lines("requirements.txt"))
        assert "pytest" not in runtime and "pyyaml" not in runtime.lower()
        dev = _requirement_lines("requirements-dev.txt")
        assert "-r requirements.txt" in dev
        joined = " ".join(dev)
        assert (
            "pytest>=" in joined and "pytest-asyncio>=" in joined and "pyyaml>=" in joined.lower()
        )

    def test_the_adapter_asks_for_nothing_the_runtime_file_does_not(self):
        adapter = _requirement_lines("requirements-adapter.txt")
        runtime = _requirement_lines("requirements.txt")
        assert adapter and set(adapter) <= set(runtime)
        assert {r.split(">")[0].split(";")[0].strip() for r in adapter} == {"mcp", "exceptiongroup"}

    def test_the_adapters_imports_are_all_provided_by_its_requirements(self):
        files = [ROOT / "adapter_main.py", ROOT / "src" / "utils" / "redact.py"]
        files += sorted((ROOT / "src" / "adapter").glob("*.py"))
        imported = _third_party_imports(files) - {"adapter", "utils"}
        # mcp's own dependencies come with it
        provided = {"mcp", "anyio", "httpx2", "exceptiongroup"}
        assert imported <= provided, imported - provided

    def test_the_broker_and_legacy_images_get_the_passkey_library(self):
        assert any(line.startswith("webauthn") for line in _requirement_lines("requirements.txt"))
        assert not any(
            line.startswith("webauthn") for line in _requirement_lines("requirements-adapter.txt")
        )


# ------------------------------------------------------------ ignore files


def _docker_pattern_matches(pattern: str, path: str) -> bool:
    """A small version of .dockerignore matching: `**/` is any depth, `*` does
    not cross a slash, and a pattern without `**` matches from the root only."""
    regex = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            regex += "(?:.*/)?"
            i += 3
        elif pattern[i] == "*":
            regex += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            regex += "[^/]"
            i += 1
        else:
            regex += re.escape(pattern[i])
            i += 1
    return re.fullmatch(regex, path) is not None


def _docker_ignores(patterns, path: str) -> bool:
    """Whether any pattern excludes `path` or one of the directories above it."""
    parts = path.split("/")
    for i in range(1, len(parts) + 1):
        prefix = "/".join(parts[:i])
        if any(_docker_pattern_matches(p.rstrip("/"), prefix) for p in patterns):
            return True
    return False


PRIVATE = (
    ".env",
    "src/.env",
    "settings.json",
    "config/settings.json",
    "broker-policy.json",
    "src/broker/broker-policy.json",
    "owner.json",
    "adapter.json",
    "broker.token",
    "src/adapter/broker.token",
    "deploy/broker/broker.env",
    "cert.pem",
    "src/key.pem",
    "tls/server.key",
)
EXAMPLES = (
    "config/adapter.example.json",
    "config/broker.example.json",
    "config/settings.broker.example.json",
    "deploy/broker/broker.env.example",
    "deploy/broker/docker-compose.yml",
    "env.example",
)


class TestIgnoreFiles:
    def _patterns(self):
        lines = [line.strip() for line in _read(".dockerignore").splitlines()]
        return [line for line in lines if line and line[0] not in "#!"]

    @pytest.mark.parametrize("path", PRIVATE)
    def test_docker_keeps_private_files_out_of_the_build_context(self, path):
        assert _docker_ignores(self._patterns(), path), path

    @pytest.mark.parametrize(
        "path",
        (
            "src/mcp_server.py",
            "src/adapter/client.py",
            "main.py",
            "docker/broker_healthcheck.py",
            "requirements.txt",
        ),
    )
    def test_docker_still_sends_what_the_images_copy(self, path):
        assert not _docker_ignores(self._patterns(), path), path

    @pytest.mark.skipif(
        shutil.which("git") is None or not (ROOT / ".git").exists(), reason="needs a git checkout"
    )
    @pytest.mark.parametrize("path", PRIVATE)
    def test_git_ignores_private_files(self, path):
        done = subprocess.run(["git", "check-ignore", "-q", path], cwd=ROOT, capture_output=True)
        assert done.returncode == 0, path

    @pytest.mark.skipif(
        shutil.which("git") is None or not (ROOT / ".git").exists(), reason="needs a git checkout"
    )
    @pytest.mark.parametrize("path", EXAMPLES)
    def test_git_does_not_ignore_the_examples(self, path):
        done = subprocess.run(["git", "check-ignore", "-q", path], cwd=ROOT, capture_output=True)
        assert done.returncode == 1, path


# -------------------------------------------------------- compose templates

COMPOSE = "deploy/broker/docker-compose.yml"


def _yaml():
    return pytest.importorskip("yaml")  # installed by requirements-dev.txt


def _compose(relative=COMPOSE):
    return _yaml().safe_load(_read(relative))


def _serve_flags():
    done = subprocess.run(
        [sys.executable, str(ROOT / "broker_main.py"), "serve", "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        env=_minimal_environment(),
    )
    assert done.returncode == 0, done.stderr
    return set(re.findall(r"--[a-z][a-z-]*", done.stdout))


class TestTheBrokerComposeTemplate:
    def _service(self):
        return _compose()["services"]["broker"]

    def test_nothing_in_it_can_take_a_password_from_a_file_or_widen_the_container(self):
        service = self._service()
        for key in (
            "env_file",
            "privileged",
            "network_mode",
            "pid",
            "ipc",
            "devices",
            "cap_add",
            "cgroup_parent",
            "userns_mode",
        ):
            assert key not in service, key

    def test_the_container_is_locked_down(self):
        service = self._service()
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert str(service["user"]).startswith("${BROKER_UID:?")
        assert service["pids_limit"] > 0

    def test_it_is_built_from_the_broker_target(self):
        build = self._service()["build"]
        assert build["target"] == "broker" and build["context"] == "../.."

    def test_the_only_writable_mount_is_the_owners_public_key_store(self):
        volumes = self._service()["volumes"]
        writable = [v for v in volumes if not v.endswith(":ro")]
        assert len(writable) == 1 and writable[0].endswith(":/state")
        for volume in volumes:
            source = volume.split(":")[0]
            assert source.startswith("${BROKER_"), volume  # always a chosen directory
            assert "docker.sock" not in volume and "/var/run" not in volume

    def test_every_published_port_names_the_address_it_is_published_on(self):
        ports = self._service()["ports"]
        assert len(ports) == 2
        for port in ports:
            assert port.startswith("${BROKER_") and "BIND_ADDRESS:?" in port, port

    def test_the_environment_carries_no_secret(self):
        environment = self._service()["environment"]
        for name, value in environment.items():
            assert not re.search(r"(password|otp|token|secret|device|credential)", name, re.I), name
        assert environment["XDG_CONFIG_HOME"] == "/config"

    def test_the_nas_certificate_is_verified_by_default_and_false_is_said_to_be_refused(self):
        """Manual authentication refuses `false` (review R04); the template and the
        documents beside it must not suggest otherwise."""
        from config import _broker_tls_problem

        environment = self._service()["environment"]
        default = re.search(r"\$\{NAS_VERIFY_SSL:-([^}]*)\}", environment["VERIFY_SSL"]).group(1)
        assert default == "true"
        assert _broker_tls_problem(True) is None
        assert _broker_tls_problem(False) is not None

        compose = _read(COMPOSE)
        assert "`false` is refused" in compose
        assert "refused" in _read("deploy/broker/broker.env.example")
        assert "refuses to start with `false`" in _read("docs/MANUAL_AUTHENTICATION.md")
        # No line offers the three values as equals any more.
        assert "`true`, `false`, or" not in compose

    def test_it_asks_for_tls_a_policy_and_the_private_login_with_flags_that_exist(self):
        command = self._service()["command"]
        assert command[0] == "serve"
        flags = {item.split("=", 1)[0] for item in command[1:]}
        assert {
            "--policy",
            "--tls-cert",
            "--tls-key",
            "--allowed-host",
            "--private-origin",
        } <= flags
        assert "--allow-plain-http-loopback" not in flags
        assert flags <= _serve_flags(), flags - _serve_flags()

    def test_the_variables_it_requires_are_all_in_the_example_and_nothing_else_is(self):
        text = _read(COMPOSE)
        required = set(re.findall(r"\$\{([A-Z_]+):\?", text))
        used = set(re.findall(r"\$\{([A-Z_]+)[:}]", text))
        example = _read("deploy/broker/broker.env.example")
        active = {m.group(1) for m in re.finditer(r"^([A-Z_]+)=", example, re.M)}
        documented = active | {m.group(1) for m in re.finditer(r"^# ([A-Z_]+)=", example, re.M)}
        assert required <= active, required - active
        assert used <= documented, used - documented
        assert documented <= used, documented - used

    def test_the_example_environment_holds_no_secret(self):
        for line in _read("deploy/broker/broker.env.example").splitlines():
            if line.startswith("#") or "=" not in line:
                continue
            name = line.split("=", 1)[0]
            assert not re.search(r"(password|otp|token|secret|device|credential|key)", name, re.I)

    def test_the_legacy_service_still_builds_the_legacy_image(self):
        service = _compose("docker-compose.yml")["services"]["synology-mcp"]
        assert service["build"]["target"] == "legacy"
        assert service["command"] == ["python", "main.py"]  # CI's stdio test depends on this


# ------------------------------------------------- the configuration examples


def _json(relative):
    return json.loads(_read(relative))


class TestConfigurationExamples:
    def test_the_adapter_example_is_accepted_by_the_adapter(self, tmp_path):
        from adapter.config import parse_settings

        data = _json("config/adapter.example.json")
        ca = tmp_path / "ca.pem"
        ca.write_text("placeholder")
        data["ca_file"] = str(ca)  # the only setting that must name a file that exists
        settings = parse_settings(data)
        assert settings.broker_url.startswith("https://")
        assert settings.token_file and not settings.token_env

    def test_the_adapter_example_holds_no_credential_and_only_known_settings(self):
        from adapter.config import _KEYS

        data = _json("config/adapter.example.json")
        assert set(data) <= set(_KEYS)
        for name in data:
            assert not re.search(r"(password|otp|device|secret)", name, re.I)

    def test_the_policy_example_is_accepted_by_the_broker_with_placeholder_digests(self):
        import mcp_server
        from broker.policy import parse_policy

        policy = parse_policy(
            _json("config/broker.example.json"),
            known_nas={"nas1"},
            known_tools=set(mcp_server.SynologyMCPServer()._tool_registry),
        )
        assert len(policy.clients) == 2
        for client in policy.clients.values():
            # a digest no token can have: 63 leading zero hex digits
            assert client.token_sha256.startswith("0" * 63)
        narrow = policy.clients["claude-desktop"]
        assert "list_shares" not in narrow.tools and "synology_health_summary" in narrow.tools

    def test_the_settings_example_has_endpoints_and_no_credential(self, tmp_path, monkeypatch):
        import importlib

        original = sys.modules.get("config")
        path = tmp_path / "settings.json"
        path.write_text(_read("config/settings.broker.example.json"))
        os.chmod(str(path), 0o600)
        for name in [k for k in sys.modules if k == "config" or k.startswith("config.")]:
            del sys.modules[name]
        monkeypatch.setenv("SYNOLOGY_AUTH_MODE", "broker")
        try:
            module = importlib.import_module("config")
            monkeypatch.setattr(module, "SETTINGS_FILE", path)
            built = module.SynologyConfig()
        finally:
            sys.modules.pop("config", None)
            if original is not None:
                sys.modules["config"] = original  # the instance every other module holds
        assert built.nas_configs["nas1"]["base_url"] == "https://nas.example.lan:5001"
        assert "password" not in built.nas_configs["nas1"]
        assert built._broker_violations == []

    def test_the_example_environment_file_sets_no_credential_unless_you_uncomment_it(self):
        active = [
            line.split("=", 1)[0].strip()
            for line in _read("env.example").splitlines()
            if line.strip() and not line.lstrip().startswith("#") and "=" in line
        ]
        assert not [
            n
            for n in active
            if n in ("SYNOLOGY_PASSWORD", "SYNOLOGY_OTP_CODE", "SYNOLOGY_USERNAME", "SYNOLOGY_URL")
        ]
        text = _read("env.example")
        assert "RECOMMENDED: manual authentication" in text and "LEGACY" in text
        assert text.index("RECOMMENDED") < text.index("LEGACY")

    def test_no_example_looks_like_it_holds_a_real_secret(self):
        for relative in (
            "config/adapter.example.json",
            "config/broker.example.json",
            "config/settings.broker.example.json",
            "deploy/broker/broker.env.example",
            "env.example",
        ):
            text = _read(relative)
            assert not re.search(
                r"(?=[A-Za-z0-9+/_-]*[0-9])(?=[A-Za-z0-9+/_-]*[A-Za-z])[A-Za-z0-9+/_-]{40,}",
                text.replace("0" * 63, ""),
            ), relative
            assert "BEGIN " not in text


# ----------------------------------------------------------------- documents

MARKDOWN = (
    "README.md",
    "docs/MANUAL_AUTHENTICATION.md",
    "deploy/broker/README.md",
    "tests/README.md",
    "skills/synology-nas/SKILL.md",
    *[
        f"skills/synology-nas/references/{p.name}"
        for p in sorted((ROOT / "skills" / "synology-nas" / "references").glob("*.md"))
    ],
)


def _slugs(text):
    seen, slugs = {}, set()
    for line in _without_code(text).splitlines():
        match = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if not match:
            continue
        heading = re.sub(r"[`*_]", "", match.group(1)).lower()
        slug = re.sub(r"[^\w\- ]", "", heading).replace(" ", "-")
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        slugs.add(slug if count == 0 else f"{slug}-{count}")
    return slugs


def _code_blocks(text):
    """[(language, body)] for each fenced block."""
    blocks, language, body, inside = [], None, [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            if inside:
                blocks.append((language, "\n".join(body)))
                language, body, inside = None, [], False
            else:
                language, body, inside = line.strip()[3:].strip(), [], True
        elif inside:
            body.append(line)
    return blocks


def _without_code(text):
    kept, inside = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            inside = not inside
        elif not inside:
            kept.append(line)
    return "\n".join(kept)


class TestDocuments:
    @pytest.mark.parametrize("relative", MARKDOWN)
    def test_every_relative_link_and_anchor_resolves(self, relative):
        text = _without_code(_read(relative))
        base = (ROOT / relative).parent
        for target in re.findall(r"\]\(([^)\s]+)\)", text):
            if re.match(r"^(https?:|mailto:)", target):
                continue
            path, _, anchor = target.partition("#")
            destination = (base / path).resolve() if path else (ROOT / relative)
            assert destination.exists(), f"{relative}: {target}"
            if anchor and destination.suffix == ".md":
                assert anchor in _slugs(
                    destination.read_text(encoding="utf-8")
                ), f"{relative}: {target}"

    def test_the_commands_in_the_guide_use_flags_and_subcommands_that_exist(self):
        guide = _read("docs/MANUAL_AUTHENTICATION.md")
        blocks = [body for _language, body in _code_blocks(guide)]
        serve = " ".join(b for b in blocks if "broker_main.py serve" in b)
        flags = set(re.findall(r"--[a-z][a-z-]*", serve.replace("\\\n", " ")))
        assert flags and flags <= _serve_flags(), flags - _serve_flags()
        assert "broker_main.py new-token" in guide
        assert "enroll --owner-store" in guide and "new-code" in guide and "--add-device" in guide
        for sub in ("list", "revoke"):
            assert f"`enroll {sub}" in guide
        done = subprocess.run(
            [sys.executable, str(ROOT / "broker_main.py"), "enroll", "--help"],
            capture_output=True,
            text=True,
            timeout=60,
            env=_minimal_environment(),
        )
        assert "new-code" in done.stdout and "revoke" in done.stdout

    def test_the_guides_error_table_lists_exactly_the_codes_the_adapter_can_say(self):
        from adapter.client import _MESSAGES

        guide = _read("docs/MANUAL_AUTHENTICATION.md")
        section = guide.split("What the AI reports, and what it means:")[1].split(
            "Other things people hit"
        )[0]
        mentioned = set(re.findall(r"`([A-Z][A-Z_]+)`", section))
        assert mentioned == set(_MESSAGES) | {"AUTHENTICATION_REQUIRED", "AUTHORIZATION_DENIED"}

    def test_the_guides_numbers_are_the_code_defaults(self):
        from broker.policy import SessionPolicy

        guide = _read("docs/MANUAL_AUTHENTICATION.md")
        defaults = SessionPolicy()
        assert f"`idle_seconds` (default {defaults.idle_seconds})" in guide
        assert f"`absolute_seconds` (default {defaults.absolute_seconds}" in guide
        assert f"`pending_seconds` (default {defaults.pending_seconds})" in guide
        assert "15 minutes without use or 8 hours" in guide  # 900 s and 28800 s
        assert defaults.idle_seconds == 900 and defaults.absolute_seconds == 28800

    def test_the_guides_adapter_settings_are_the_adapters_real_ones(self):
        from adapter.config import _KEYS

        guide = _read("docs/MANUAL_AUTHENTICATION.md")
        for language, block in _code_blocks(guide):
            if language != "json":
                continue
            data = json.loads(block)
            if "broker_url" in data:
                assert set(data) <= set(_KEYS), set(data) - set(_KEYS)

    def test_the_guide_says_who_does_what_and_where_the_limits_are(self):
        guide = _read("docs/MANUAL_AUTHENTICATION.md")
        for heading in (
            "## Who does what",
            "## Where the broker runs",
            "## Turning on one-time codes (OTP)",
            "## Moving from the old setup",
            "## What this protects, and what it does not",
            "## Legacy mode",
        ):
            assert heading in guide, heading
        assert "A container is packaging, not proof" in guide
        assert "Rollback" in guide and "Do **not** put the old password-based server back" in guide

    def test_the_readme_leads_with_manual_authentication_and_labels_the_legacy_path(self):
        readme = _read("README.md")
        assert readme.index("## \U0001f510 Recommended: manual authentication") < readme.index(
            "Quick Start with Docker (legacy single-process mode)"
        )
        assert "docs/MANUAL_AUTHENTICATION.md" in readme and "docs/TOOL_CATALOG.md" in readme

    def test_the_documents_never_tell_anyone_to_put_a_password_in_the_chat_or_a_file_for_the_ai(
        self,
    ):
        for relative in (
            "docs/MANUAL_AUTHENTICATION.md",
            "skills/synology-nas/references/auth.md",
            "skills/synology-nas/SKILL.md",
        ):
            text = _read(relative).lower()
            for phrase in (
                "paste your password",
                "type your password into the chat",
                "give the assistant your password",
                "tell claude your password",
            ):
                assert phrase not in text, (relative, phrase)


class TestTheSkillKnowsTheNewMode:
    def test_it_tells_the_assistant_what_to_do_when_there_is_no_session(self):
        auth = _read("skills/synology-nas/references/auth.md")
        assert "AUTHENTICATION_REQUIRED" in auth and "AUTHORIZATION_DENIED" in auth
        assert "never ask for a NAS password or one-time code" in auth
        assert "no `synology_login` means manual authentication" in auth

    def test_the_main_skill_file_says_signing_in_is_the_users_job(self):
        skill = _read("skills/synology-nas/SKILL.md")
        assert "Sign-in is the user's job" in skill
        assert "never ask for, accept or repeat a NAS password" in skill.replace("**", "")
        assert "Asking the user for their NAS password" in skill

    def test_there_is_an_eval_for_the_user_who_offers_their_password(self):
        evals = _json("skills/synology-nas/evals/evals.json")["evals"]
        ids = [e["id"] for e in evals]
        assert len(ids) == len(set(ids))
        match = [e for e in evals if e["name"] == "sign-in-required-never-ask-for-password"]
        assert len(match) == 1
        assertions = " ".join(a["text"] for a in match[0]["assertions"])
        assert "NOT to share" in assertions and "NOT repeat the password" in assertions

    def test_the_logout_example_uses_an_argument_the_tool_takes(self):
        import mcp_server

        server = mcp_server.SynologyMCPServer()
        logout = next(
            t for t in server._all_session_tool_definitions() if t.name == "synology_logout"
        )
        assert logout.input_schema["required"] == ["base_url"]
        assert 'synology_logout(base_url="' in _read("skills/synology-nas/references/auth.md")
        assert "synology_logout(nas_name=" not in _read("skills/synology-nas/references/auth.md")


# --------------------------------------------------------------- the workflow


class TestTheWorkflow:
    def _workflow(self):
        return _yaml().safe_load(_read(".github/workflows/tests.yml"))

    def _steps(self, job):
        return "\n".join(
            str(step.get("run", "")) + str(step.get("env", ""))
            for step in self._workflow()["jobs"][job]["steps"]
        )

    def test_it_installs_the_test_dependencies_and_checks_the_catalog(self):
        steps = self._steps("test")
        assert "requirements-dev.txt" in steps
        assert "generate_tool_catalog.py --check" in steps

    def test_lint_covers_every_entry_point_and_script(self):
        steps = self._steps("lint")
        for path in ("adapter_main.py", "broker_main.py", "scripts/", "src/", "tests/", "docker/"):
            assert steps.count(path) >= 2, path  # in ruff and in black

    def test_the_docker_job_builds_all_three_images_and_runs_the_image_tests(self):
        steps = self._steps("docker")
        for target in ("adapter", "broker"):
            assert f"--target {target}" in steps
        assert "docker compose build" in steps  # the legacy image, as before
        assert "deploy/broker/docker-compose.yml" in steps and "config" in steps
        assert "SYNOLOGY_TEST_DOCKER" in steps and "tests/test_docker_images.py" in steps

    def test_it_uses_no_secret(self):
        assert "secrets." not in _read(".github/workflows/tests.yml")
