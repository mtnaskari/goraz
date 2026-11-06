# Security policy

## Status

**goraz has not had an independent security audit.** Its design has been reviewed only by its authors, and its cryptographic composition (docs/security-design.md, section 4) has not been analysed by an outside party. It is pre-release software, with one maintainer.

Automated checks are not a substitute for review. Passing tests, fuzzing and static analysis show only the absence of the problems those tools can find.

If you are qualified to review the design and are willing to, that would be very welcome.

## Reporting a vulnerability

Please report privately through [GitHub security advisories](https://github.com/mtnaskari/goraz/security/advisories/new). Please don't open a public issue.

Include what you found, how to reproduce it, and the versions affected. Please don't include real secrets.

This is a personal project, so response times are a good-faith effort, not a guarantee:

- An initial response within 14 days.
- For a confirmed issue of medium severity or above, a fix within 60 days of the issue becoming public, or an honest statement of why that isn't possible.
- Credit in the advisory, if you want it.

## Supported versions

Before version 1.0, only the latest release gets security fixes. The file format is frozen by golden tests, so a fix doesn't require migrating a vault unless the format itself is at fault. In that case, a one-way migration tool will be provided and old format support will be removed.

## What is in scope

Issues that break a claim in [the threat model](docs/threat-model.md), for example:

- Reading or forging vault data without a credential.
- Altered, swapped or older data being accepted without an error.
- A secret reaching a log, an error message, the audit log or a command line.
- A field in a vault or import file choosing a network address, path, program or template.
- A token verifying when it should not.
- A service reading what another service holds.

## What is not in scope

These are stated limits, listed in [section 4 of the threat model](docs/threat-model.md#4-what-goraz-does-not-defend-against):

- Malware running as your user, and root or kernel compromise.
- Recovering secrets from the memory of a running process. Go can't guarantee that memory is erased.
- Weak passphrases.
- Old file copies opening with credentials that were valid when the copy was made.
- A restarted service with no pinned minimum generation trusting the first file it sees.

If you can show that one of these limits is worse than documented, please report that.

## Verifying what you run

Install only from `github.com/mtnaskari/goraz`. The `github.com/goraz` organization is unrelated. goraz has no installer scripts.

Build it yourself with:

```bash
CGO_ENABLED=0 go build -trimpath ./cmd/goraz
```

`goraz doctor` reports the protections that are actually active on your machine.
