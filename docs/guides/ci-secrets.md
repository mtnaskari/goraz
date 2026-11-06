---
title: Use secrets in CI pipelines
description: Give a CI job only the secrets it needs, using an encrypted goraz file in the repository and one key stored in GitHub Actions or another CI system.
---

# Use secrets in CI pipelines

A CI job gets its own encrypted file, holding only what that job needs. The CI system stores one key, and the encrypted file can live in your repository.

## Create the file

```bash
goraz put ci/deploy/registry-token
goraz service create ci-deploy --prefix ci/deploy --out ci-deploy.goraz --key-out ci-deploy.key
```

Commit `ci-deploy.goraz`. Add the contents of `ci-deploy.key` to your CI system as a secret, then delete the local copy. **Never commit the key.**

## Use it in GitHub Actions

```yaml
- name: Deploy
  env:
    GORAZ_KEY: ${{ secrets.GORAZ_CI_DEPLOY_KEY }}
  run: |
    goraz run --vault ci-deploy.goraz --machine-key-fd 3 --audit stderr --no-warn \
      --env REGISTRY_TOKEN=goraz://ci/deploy/registry-token \
      -- ./deploy.sh 3<<<"$GORAZ_KEY"
```

goraz takes the key from a file descriptor rather than an environment variable. In this example, the shell passes it from a variable the CI system provides, so limit that variable to this one step.

## Things to know

- **Updating:** run `goraz service sync ci-deploy --out ci-deploy.goraz` and commit the result.
- **Git history:** old versions of the file stay readable with the key that was valid for them. After a leak, follow [the leak guide](secret-or-key-leaked.md).
- **Merge conflicts:** the file is binary, so resolve a conflict by running `service sync` again.
- **Forked pull requests:** don't expose this secret to workflows that run untrusted code.
- **Log masking:** goraz doesn't mask secrets in your job's output. Your CI system's masking applies only to values it knows about.
