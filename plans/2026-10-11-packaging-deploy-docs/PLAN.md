# Packaging, deployment and documentation

**Written:** 11 October 2026
**Roadmap:** [`../2026-10-10-manual-auth-roadmap/PLAN.md`](../2026-10-10-manual-auth-roadmap/PLAN.md), PR 6
**Source plan:** §7.3, and §3.1, §8 and §11 for what the documents must say, of [`../2026-10-06-manual-authentication/PLAN.md`](../2026-10-06-manual-authentication/PLAN.md)
**Builds on:** everything before it: the core (#18, #19), the broker (#20), the private login (#21), the adapter (#22, #23) and the tool catalog (#24).

## What this adds

The pieces of the roadmap all exist and work. This PR makes them installable, runnable on a host you can defend, and understandable: images, a deployment template, examples with no secret in them, the guide, and CI that runs it all.

| Piece | Files | What it does |
|---|---|---|
| Three images | `Dockerfile`, `requirements-adapter.txt`, `docker/broker_healthcheck.py` | `--target adapter` (the credential-free adapter and nothing else), `--target broker`, and `legacy` (the original server, still the last stage). Non-root, code owned by root and not writable by the account that runs it, no compiler in any runtime image, no secret baked in |
| Broker template | `deploy/broker/` | A compose file with a read-only filesystem, no capabilities, a chosen user, no environment file, no privileged mode, no Docker socket, no host network, and no default publication address |
| Examples | `config/*.example.json`, `env.example`, `deploy/broker/broker.env.example` | Secret-free; `env.example` now leads with manual authentication and labels legacy mode |
| Ignore files | `.gitignore`, `.dockerignore` | Private files (policy, owner store, tokens, keys, local config) are never committed and never enter a build context, at any depth |
| Requirements | `requirements.txt`, `-adapter.txt`, `-dev.txt` | Runtime, adapter-only and test dependencies are separate files |
| The guide | `docs/MANUAL_AUTHENTICATION.md` | Setup, who does what, where the broker may run, daily use, one-time codes, cutover and rollback, troubleshooting, and what it does not protect against |
| Other documents | `README.md`, `skills/synology-nas/`, `tests/README.md`, `CHANGELOG.md` | Manual authentication first, legacy labelled; the skill never solicits a password |
| CI | `.github/workflows/tests.yml` | Lint covers every entry point, the catalog is checked, and the Docker job builds all three images, validates the template, and runs the image tests |

## Design choices worth knowing

- **The adapter image is built from a list, and the list is tested by running it.** The adapter stage copies three things (`adapter_main.py`, `src/adapter/`, one standalone file from `src/utils/`). A test rebuilds exactly that tree from the Dockerfile's own COPY lines and starts the adapter in it. This caught a real mistake while writing the Dockerfile: the adapter's logging imports `utils.redact`, which the first draft did not copy, so the image would have crashed on start. The test also proves it can fail: with that file left out the adapter does not start.
- **The adapter image has no NAS libraries because it does not install them.** `requirements-adapter.txt` is `mcp` and the Python 3.10 backport. A test checks that every third-party import in the adapter's code is covered by it, and that its `mcp` bound is the one in `requirements.txt`.
- **Code is not writable by the account that runs it.** Dependencies are built in a stage with a compiler and copied in as a finished virtual environment, so the runtime image has no `gcc` and no package manager use. Files are owned by root; only `legacy` has a writable path (`/app/logs`, which its compose file mounts anyway). The legacy image's account used to own `/app`; it no longer does.
- **The template publishes nothing by default.** `BROKER_BIND_ADDRESS` and `BROKER_PRIVATE_BIND_ADDRESS` are required and have no default, so nothing is exposed to a network by omission. The private login has its own address and port, so it can be limited to your own devices while the MCP port is reachable by the adapters. `docker compose config` fails with the variable's name if either is missing.
- **The broker runs as the account that owns its files.** The broker already refuses a `settings.json` that another account owns or that others can read, so the template runs the container as `BROKER_UID:BROKER_GID` rather than papering over that. The one writable mount is the owner's public-key store.
- **A container is not presented as isolation.** The guide's "Where the broker runs" section says what must be true of the host, that a separate machine is the straightforward answer, and that if it cannot be shown the password must not be described as out of the AI's reach. The template is hardening for a host you already trust.
- **The guide is checked against the code.** Tests parse the guide's commands against the real argument parser, its JSON examples against the adapter's real settings, its error table against the adapter's real set of codes, its numbers against the session defaults, and every relative link and anchor in the documents. A flag renamed or a code added without the guide following fails a test.
- **The container health check is `/readyz`, not a test of sign-in.** A broker nobody has signed in to is ready. A first draft sent a `Host` header and the template listed a loopback `--allowed-host` for it; running the real broker showed the health endpoints do not check the host, so both were removed rather than documented as needed.
- **Examples are parsed by the real parsers.** The policy example is accepted by `parse_policy`, the adapter example by `parse_settings`, the settings example by the real configuration in broker mode (no credential, no violation). Their digests are 63 leading zeros, a value no token can have.

## Acceptance criteria

- `docker build --target adapter|broker|legacy` each produces an image that runs as a non-root account with code that account cannot change; the adapter image contains no NAS code or libraries and refuses a NAS credential in its environment.
- The broker template starts a broker that becomes healthy, answers a real adapter over verified TLS, and serves the private login, with no secret in its environment, files or logs.
- No example, image layer or document contains a password, one-time code, token or key; private files are ignored by git and by Docker.
- The guide lets a person set the whole thing up and says plainly which steps are theirs, what the design protects and what it does not.
- CI runs the adapter and broker with fake authentication on Linux and Windows (the real-process tests), builds and tests the images, validates the template, and lints every entry point.

## Verification

`pytest -m "not real_nas"`, ruff and black over `src/`, the entry points, `scripts/`, `docker/` and `tests/`, and `python scripts/generate_tool_catalog.py --check`.

New: `tests/test_packaging.py` (the Dockerfile, the adapter image's real file set, requirements, ignore files, the compose template, the examples, the documents and the workflow), `tests/test_tls_end_to_end.py` (the real broker with a real certificate and the real adapter, with the chain and the host name checked, and the container health script), and `tests/test_docker_images.py` (the built images, run; off unless `SYNOLOGY_TEST_DOCKER=1`, which CI sets).

Result: 1373 passed, 29 skipped. The skips are the 13 that need a POSIX filesystem, as before, and the 16 image tests that need Docker. 1251 passed before this PR; `tests/test_packaging.py` adds 113 tests and `tests/test_tls_end_to_end.py` 9.

Fifty faults were put into the Dockerfile, the compose template, the ignore files, the examples, the guide, the README, the skill, the requirements, the workflow and the health script, one at a time, to confirm the tests can fail: an image running as root, code made writable, a compiler or a test tool installed, the redaction module left out of the adapter image, no health check, the broker starting by default, a privileged or writable container, the Docker socket or an environment file handed in, a port published on every interface, nested key files reaching the build context, the policy file no longer ignored, a believable digest or a password in an example, a flag, a code, a default or a link in the guide that does not exist, the skill no longer saying never to ask for a password, and CI no longer building the broker or checking the catalog. All fifty were caught.

Writing the tests also turned up three things that were wrong and are fixed here: the adapter image first left out `src/utils/redact.py`, which its logging imports; the health check and the template first assumed the health endpoints check the `Host` header (they do not); and the old skill example called `synology_logout` with an argument that tool does not take.

## Not yet verified

- **The images have not been built or run on the machine that wrote them.** There is no Docker on it. Everything about the Dockerfile that can be checked without Docker is (its structure, the adapter's file set run for real, the template's properties, the health script against a real TLS broker). The image build, the container tests and `docker compose config` run for the first time in CI on this PR, and a failure there is expected to be about Docker details rather than the design.
- **A real certificate from a real CA, and a real browser doing the passkey ceremony.** The tests use a throwaway CA and a software authenticator.
- **A broker host that meets the isolation prerequisites.** That is a property of a machine, not of this repository. It has to be shown on the host that will run the broker, with dummy values, before a real password is entered (the guide says how).
- **The guide followed end to end by someone who did not write it.**
- **Python 3.10**, as before: CI and the images run 3.13 only.

## After this PR

The software of the roadmap is complete. What remains is the cutover, which only the user can do: choose and prove the host, deploy the broker, enrol the passkey, replace the three client registrations, delete `.env`, change the password and enrol one-time codes (the guide's "Moving from the old setup"), then update the outer `INSTALLATION.md` and `REVIEW_FOLLOWUP_2026-09-29.md` in place with dated evidence. These plan folders move to `plans/shipped/` when that has been verified, as the source plan asks.
