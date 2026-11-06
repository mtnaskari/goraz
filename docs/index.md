---
title: goraz documentation
description: Keep API tokens, secrets and passwords encrypted in Go services and on the command line, with no server. Start from what you need to do.
---

# goraz documentation

goraz is an open-source Go library and command-line tool that keeps API tokens, secrets and passwords in an encrypted file. It needs no server.

> **Version 0.1 is an early release, and goraz has not had an independent security audit.** Read [what it does not defend against](threat-model.md#4-what-goraz-does-not-defend-against) before relying on it.

## What do you need to do?

**Run a service in production**

- [Store API tokens securely in a Go service](guides/api-tokens-in-go-service.md)
- [Use secrets in Docker containers](guides/docker-secrets.md)
- [Use secrets in Kubernetes](guides/kubernetes-secrets.md)
- [Use secrets with systemd](guides/systemd-credentials.md)
- [Use secrets in CI pipelines](guides/ci-secrets.md)

**Build an API**

- [Issue and verify API tokens in Go](guides/issue-api-tokens-in-go.md)

**Work on your own machine**

- [Get started in five minutes](guides/getting-started.md)
- [Replace a .env file](guides/replace-dotenv-file.md)
- [Manage passwords and one-time codes from the terminal](guides/password-manager-cli.md)

**Respond to a problem**

- [A secret or key has leaked](guides/secret-or-key-leaked.md)
- [Fix common errors](guides/troubleshooting.md)

**Decide whether it fits**

- [goraz compared with Vault, OpenBao, SOPS and gopass](guides/alternatives.md)
- [Limits and performance](limits.md)
- [What goraz does not defend against](threat-model.md#4-what-goraz-does-not-defend-against)

## Reference

- [Command reference](cli-reference.md)
- [Go API on pkg.go.dev](https://pkg.go.dev/github.com/mtnaskari/goraz)
- [Threat model](threat-model.md)
- [Security design and file format](security-design.md)
- [Feature matrix: included, deferred and rejected](feature-matrix.md)
- [Research on earlier projects](research/comparison.md)
