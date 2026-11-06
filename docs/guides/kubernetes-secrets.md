---
title: Use secrets in Kubernetes
description: Keep application tokens encrypted in a Kubernetes pod using goraz, with the key in a Kubernetes Secret and no secret values in environment variables.
---

# Use secrets in Kubernetes

First [create a service file and key](api-tokens-in-go-service.md). Keep the encrypted file and its key in separate objects.

```bash
kubectl create secret generic api-goraz-key --from-file=key=api.key
kubectl create configmap api-goraz --from-file=api.goraz
```

```yaml
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
  containers:
    - name: api
      image: my-api
      securityContext:
        readOnlyRootFilesystem: true
      volumeMounts:
        - { name: goraz-key, mountPath: /run/secrets/goraz, readOnly: true }
        - { name: goraz-file, mountPath: /etc/goraz, readOnly: true }
  volumes:
    - name: goraz-key
      secret:
        secretName: api-goraz-key
        defaultMode: 0440
    - name: goraz-file
      configMap:
        name: api-goraz
```

In your program:

```go
c, err := service.Open(ctx, service.Options{
	Path:  "/etc/goraz/api.goraz",
	Key:   service.KeyFile("/run/secrets/goraz/key"),
	Audit: audit.NewJSONSink(os.Stdout),
})
```

## Why these settings

- **`defaultMode: 0440` and `fsGroup`:** goraz refuses a key that others can read, and the default mode is 0644.
- **Symlinks:** Kubernetes mounts secrets through symlinks. goraz follows them for the service file and key.
- **Reloads:** don't use `subPath`. A `subPath` mount never receives updates, so your pod would keep old data with no error. Use `--valid-for` if this matters to you.

## Rotating the key

Add the new key beside the old one, so pods that restart in the middle of the rollout still start:

1. Update the Secret so its key file has two lines: the old key and the new one.
2. Update the ConfigMap with the new file.
3. Remove the old line from the Secret.

See [what to do when a key leaks](secret-or-key-leaked.md).

## ConfigMap size

A ConfigMap is limited to about 1 MiB. Use a volume or bake the file into your image if your service file is larger.

## What has been tested

**This setup has not been run on a Kubernetes cluster.** The mode, symlink and read-only rules it relies on are covered by tests and by a read-only container run. Please check it in your cluster, and [report what you find](https://github.com/mtnaskari/goraz/issues).
