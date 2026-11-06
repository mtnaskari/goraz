---
title: Use secrets with systemd
description: Give a systemd service its encrypted secrets using LoadCredential and goraz, without Environment= lines or plaintext files in unit configuration.
---

# Use secrets with systemd

First [create a service file and key](api-tokens-in-go-service.md). Then install them:

```bash
sudo install -m 0644 api.goraz /etc/goraz/api.goraz
sudo install -m 0400 api.key /etc/goraz/api.key
```

```ini
[Service]
ExecStart=/usr/local/bin/my-api
DynamicUser=yes
LoadCredential=goraz-key:/etc/goraz/api.key
ProtectSystem=strict
NoNewPrivileges=yes
```

systemd exposes the key at `$CREDENTIALS_DIRECTORY/goraz-key`, readable only by the service.

```go
c, err := service.Open(ctx, service.Options{
	Path:  "/etc/goraz/api.goraz",
	Key:   service.KeyFile(filepath.Join(os.Getenv("CREDENTIALS_DIRECTORY"), "goraz-key")),
	Audit: audit.NewJSONSink(os.Stdout),
})
```

The audit stream goes to the journal.

## Without changing your program

```ini
[Service]
ExecStart=/usr/local/bin/goraz run --vault /etc/goraz/api.goraz \
  --machine-key-file ${CREDENTIALS_DIRECTORY}/goraz-key --audit stderr --no-warn \
  --env STRIPE_KEY=goraz://prod/api/stripe -- /usr/local/bin/my-api
LoadCredential=goraz-key:/etc/goraz/api.key
```

## Rotating the key

`LoadCredential` copies the key when the service starts, so a new key needs a restart. Replace the key file with its two-line form and restart, then deploy the new service file.

## What has been tested

**This unit has not been run under systemd.** Please check it on your system, and [report what you find](https://github.com/mtnaskari/goraz/issues).
