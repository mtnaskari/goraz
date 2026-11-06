# Contributing

Thank you for considering a contribution. Security reviews are especially welcome. To report a vulnerability, follow [SECURITY.md](SECURITY.md) and don't open a public issue.

## Before you change anything

- A change that affects security must update [the threat model](docs/threat-model.md) first, and answer its section 8 questions.
- A change to the file format is a new format version. There is no negotiation and no legacy path. The golden tests must not be regenerated for format v1.
- New cryptography isn't accepted. Compositions of vetted primitives need a published source.
- A new dependency needs a written reason. The aim is to depend only on the Go project's own modules.

## Checks

```bash
make check
```

That runs `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck` and `go test -race`. `make fuzz` runs each fuzz target briefly.

## Commits

- **Atomic commits.** One clear purpose per commit. Avoid both very large commits and a flood of one-file commits that only make sense together.
- **Conventional messages:** `feat(vault):`, `fix(token):`, `test(audit):`, `docs(security):`, `chore(deps):`, `ci(release):`. Use a short imperative subject and a body that explains why.

## Licensing

Contributions are accepted under the Apache-2.0 license. Sign off each commit with `git commit -s` to certify the [Developer Certificate of Origin](https://developercertificate.org/). There is no contributor license agreement, so the project's license can't be changed unilaterally.
