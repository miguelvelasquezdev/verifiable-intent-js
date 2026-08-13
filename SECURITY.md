# Security Policy

`verifiable-intent-js` is a cryptographic verification library: its correctness is
its value. This document describes its posture and how to report a vulnerability.

## Status: independent, pre-audit

This is a community project (pre-1.0) and an independent implementation of the
Verifiable Intent spec. It has **not** had an independent third-party security
audit. It is validated verdict-for-verdict against the upstream reference's
conformance vectors and includes fail-closed hardening tests, but do not rely on
it as the sole control for authorizing real payments until it has been
independently reviewed.

## Design principles

- **Fail closed.** Verification returns `{ valid: false, errors }` on any problem
  and never throws on malformed credentials. Algorithms are pinned to ES256 and
  keys come from the previous layer's `cnf`, never from a token header.
- **Zero runtime dependencies.** Web-standard APIs only (WebCrypto, TextEncoder);
  no filesystem, network, or logging I/O.

## Supported versions

The current `0.x` line is the only supported version; fixes land on the latest
`0.x`.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** via GitHub private
vulnerability reporting on this repository, rather than a public issue. We aim to
acknowledge within a few business days and will coordinate a disclosure timeline
(target 90 days, or sooner once a fix ships).
