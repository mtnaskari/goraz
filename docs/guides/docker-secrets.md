---
title: Use secrets in Docker containers
description: Run a container with encrypted secrets and a read-only filesystem using goraz and Docker secrets, and avoid putting tokens in environment files or images.
---

# Use secrets in Docker containers

First [create a service file and key](api-tokens-in-go-service.md). Then deliver the key as a Docker secret.

## Mount the service file's directory, not the file

Keep the service file in a directory of its own, such as `deploy/vault/`, and mount that directory. `goraz service sync` replaces the file atomically, by renaming a new file over it. **A single-file bind mount keeps pointing at the old file**, so a running container never sees an update: no error, just old data until the stale limit or `--valid-for` window ends it. Don't put the key in the same directory.

## Docker Compose

```yaml
services:
  api:
    image: my-api
    read_only: true
    cap_drop: [ALL]
    # File-backed secrets keep their owner and mode from the host, so run the
    # service as the user that owns the key file. Put UID and GID in .env.
    user: "${UID}:${GID}"
    volumes:
      - ./deploy/vault:/etc/goraz:ro
    secrets:
      - goraz-key

secrets:
  goraz-key:
    file: ./deploy/secrets/goraz-key
```

```bash
chmod 0400 deploy/secrets/goraz-key
printf 'UID=%s\nGID=%s\n' "$(id -u)" "$(id -g)" > .env
```

goraz refuses a key file that others can read. With file-backed secrets, Compose keeps the file's mode and owner from the host, and doesn't apply `mode` or `uid`. So the key file is 0400 on the host, and the service runs as its owner. Swarm secrets are different: there, set `uid` and `mode: 0400` on the secret, because the default mode is world-readable.

## A plain container

```bash
docker run --read-only --user "$(id -u):$(id -g)" \
  -v "$PWD/deploy/vault:/etc/goraz:ro" \
  -v "$PWD/deploy/secrets/goraz-key:/run/secrets/goraz-key:ro" \
  my-api
```

Your program then uses [`service.Open`](api-tokens-in-go-service.md#4-read-tokens-in-your-code), or runs under `goraz run --audit stderr`.

## Read-only containers need an audit stream

goraz normally writes its audit log and state to disk. In a read-only container, give it a stream instead: `audit.NewJSONSink(os.Stdout)` in Go, or `--audit stderr` on the command line. Without one, reads fail.

## Rotating the key

Docker mounts a secret file the same way, so a new key file isn't seen until the container is recreated: `docker compose up -d --force-recreate api`. Write the new key as a second line first (`goraz service rotate` does this), recreate the container, deploy the new service file, then remove the old line.

## What has been tested

The Compose form was run on Docker Desktop for macOS with Linux arm64 containers: a read-only root, all capabilities dropped, Postgres alongside, and secret rotations reaching the running container without a restart. A plain `docker run` was run with a read-only root, no network and all capabilities dropped. Swarm secrets have not been tested.

## Common errors

**"the machine key file must be a regular file..."**: the key file is readable by others. See [troubleshooting](troubleshooting.md).
