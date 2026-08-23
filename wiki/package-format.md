---
type: Reference
title: TokenSaver plugin package format
description: Deterministic single-platform archive and integrity contract for TSPP plugins.
tags: [tokensaver, plugin, package, integrity]
---

# TokenSaver plugin package format

`tsp package` produces a stored ZIP32 archive with the `.tsplug` extension. A package contains
one platform executable and a package-local `plugin.json`. The manifest keeps the plugin id,
release version, creator, capabilities, limits, and unknown additive v1 fields, but rewrites
`runtime.entry` to the archive-local executable and adds:

```json
{
  "integrity": {
    "algorithm": "sha256",
    "digests": {
      "windows-x64": "sha256:<64 lowercase hexadecimal characters>"
    }
  }
}
```

The archive also includes `plugin.superec`, the `wiki/` OKF tree, README, and license files when
they are owned by the plugin directory. Paths are sorted and normalized, timestamps are fixed,
file modes are normalized, and symlinks and special files are rejected. Identical inputs produce
byte-identical archives and SHA-256 archive digests.

## Manifest resource limits

TSPP v1 uses the same acceptance rule in the public schema, shared conformance corpus,
workbench, package verifier, product registry, and runtime:

- `capabilities.maxInputBytes` may be omitted or zero to use the 16 MiB host ceiling.
  An explicit value must be from 1 through 16,777,216 bytes.
- `limits.timeBudgetMs` may be omitted or zero to use 250 ms. An explicit value must
  be from 50 through 1000 ms.

Values outside those ranges are rejected. They are never silently clamped. The verified
time budget is retained in the transactional registry and is used by both activation
handshake and request execution.

## Release catalog

Native release jobs save the `tsp package --json` report beside each canonical archive as
`<plugin-id>-<version>-<platform>.tsplug.package-report.json`. The command:

```text
tsp catalog dist --output <plugin-id>-<version>-catalog.json
```

requires exactly one report per package, verifies the reported archive size and SHA-256 digest,
requires one plugin id and release version, rejects duplicate platforms and non-release files,
and writes platforms in deterministic order. The v1 output follows
`schemas/package-catalog.v1.json`; the automation report follows
`schemas/catalog-report.v1.json`.

The checked-in release matrix publishes only targets validated by a native runner: Windows
x64/arm64, Linux x64/arm64, and macOS x64/arm64. Windows and Linux x86 remain manifest
compatibility targets until native x86 validation is available. A cross-compiled package must
not be labeled Level 1 merely for release convenience.

Integrity proves artifact identity, not trust. A package cannot declare itself built-in, grant
permissions, install itself, enable itself, or activate itself. TokenSaver assigns built-in or
community provenance through its trusted install path and independently verifies every executable
digest and TSPP result. Community release remains blocked until TokenSaver provides OS-enforced
process confinement on every supported platform.

The product registry never becomes a second manifest authority. On doctor and runtime inventory
reads, TokenSaver reopens the exact stored package and re-derives its id, version, platform,
entry, release identity, arguments, capabilities, and limits. Those values must match the
registry exactly, and the extracted executable is rehashed separately before execution.

The package-report schema fixes its certification level to Level 1. Catalog assembly accepts only
that local Level 1 report today and rejects self-promotion. Level 2 and Level 3 require a separate
issuer-owned report bound to the
exact package digest under `schemas/certification-report.v1.json`, plus issuer authentication and
a live revocation check in the trusted distribution path.

The host-side `tools/tsp-certification-host` connector retrieves report and envelope documents by
immutable release id and package digest, then retrieves the configured issuer's current revocation
document from the same HTTPS origin. It does not fetch the trust store. Downloaded bytes remain
untrusted until the existing verifier binds them to the exact package and durably records the
accepted revocation sequence.

Protocol-fuzz certification uses `schemas/certification-fuzz-corpus.v1.json` rather than opaque
corpus bytes. The policy binds the exact corpus digest, while the corpus fixes deterministic cases,
repetitions, execution limits, and required sanitizers. Neither the corpus nor its worker output is
stored inside or trusted from the plugin package.

The public trust contracts are `schemas/certification-envelope.v1.json`,
`schemas/certification-trust-store.v1.json`, `schemas/certification-revocations.v1.json`, and
`schemas/certification-revocation-state.v1.json`. Their Rust verifier authenticates exact report bytes,
checks purpose-separated Ed25519 keys and validity windows, rejects stale or rolled-back
revocation state, and validates the immutable package subject. A transport-neutral authenticated
source boundary and append-only cross-process state store connect retrieval, verification, and
durable rollback protection without adding an HTTP client. The signing wire format and shared
cross-language vectors are documented in `wiki/certification.md` and
`conformance/certification-trust-v1.cases.json`. This verifier grants no package provenance,
installation, enablement, or activation authority.

Issuer-side pipeline inputs use `schemas/certification-stage-evidence.v1.json`,
`schemas/certification-benchmark-policy.v1.json`,
`schemas/certification-fuzz-policy.v1.json`,
`schemas/certification-fuzz-report.v1.json`,
`schemas/certification-reproducible-build-policy.v1.json`, and
`schemas/certification-reproducible-build-report.v1.json`, plus
`schemas/certification-artifact-signature.v1.json`,
`schemas/certification-artifact-signature-policy.v1.json`, and the independently provisioned
`schemas/certification-artifact-trust-store.v1.json`. These documents are separate from `.tsplug`
contents. They bind external compliance work to the immutable package and are evidence for a
separately signed certification report, never package-controlled trust claims. An artifact trust
store must never be loaded from `.tsplug`, package report, or catalog data.

Package reports carry a deterministic `releaseId` derived from the plugin id, version, platform,
and executable digest. Catalog assembly recomputes that value and copies it into each platform
entry. Activation-attempt ids are intentionally absent because random execution correlation would
make otherwise identical package reports differ.

Release identity is an additive v1 field. Catalog assembly derives it when reading an older v1
package report that predates the field, while a present but conflicting value is rejected as
tampering.
