---
title: Use secrets in Docker containers
description: Run a container with encrypted secrets and a read-only filesystem using goraz and Docker secrets, and avoid putting tokens in environment files or images.
---

# Use secrets in Docker containers

First [create a service file and key](api-tokens-in-go-service.md). Then deliver the key as a Docker secret.

## Docker Compose

```yaml
services:
  api:
    image: my-api
    read_only: true
    user: "1000"
    volumes:
      - ./api.goraz:/etc/goraz/api.goraz:ro
    secrets:
      - source: goraz_key
        target: goraz-key
        uid: "1000"
        mode: 0400

secrets:
  goraz_key:
    file: ./api.key
```

goraz refuses a key file that others can read, and the default secret mode is world-readable, so `mode` is required. `uid` must match the container's user, or a non-root process can't read the file.

File-backed Compose secrets may ignore `mode` and `uid`, depending on your Docker version. In that case, the file's mode on the host applies, so run `chmod 0400 api.key` and make sure the container's user owns it.

## A plain container

```bash
docker run --read-only --user "$(id -u):$(id -g)" \
  -v "$PWD/api.goraz:/etc/goraz/api.goraz:ro" \
  -v "$PWD/api.key:/run/secrets/goraz-key:ro" \
  my-api
```

Your program then uses [`service.Open`](api-tokens-in-go-service.md#4-read-tokens-in-your-code), or runs under `goraz run --audit stderr`.

## Read-only containers need an audit stream

goraz normally writes its audit log and state to disk. In a read-only container, give it a stream instead: `audit.NewJSONSink(os.Stdout)` in Go, or `--audit stderr` on the command line. Without one, reads fail.

## What has been tested

The plain `docker run` form was tested on Linux arm64 with a read-only root, no network and all capabilities dropped. The Compose example has not been run, so check its `mode` and `uid` behaviour on your Docker version.

## Common errors

**"the machine key file must be a regular file..."**: the key file is readable by others. See [troubleshooting](troubleshooting.md).
