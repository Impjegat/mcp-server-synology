# Broker deployment template

`docker-compose.yml` runs the broker (see [`docs/MANUAL_AUTHENTICATION.md`](../../docs/MANUAL_AUTHENTICATION.md)) in a container with a read-only filesystem, no capabilities, no privileged mode, no Docker socket, no host network, and no environment file.

Before you use it, read the section "Where the broker runs" in that guide. A container does not make a host safe: the broker is only as protected as the account and the machine it runs on.

```bash
cp broker.env.example broker.env      # edit: host name, uid/gid, bind addresses, directories
docker compose --env-file broker.env config      # check what will run
docker compose --env-file broker.env up -d --build
```

`broker.env` holds names and paths only and is ignored by git. The policy, the settings file, the TLS key and the owner's passkey store live in the directories you name there; they are never part of the image.
