# Changelog

All notable changes to the TokenSaver Plugin SDK are documented here.

## [0.1.3] - 2026-09-05

- Ship additive Rust TSPP v2 context-service support and the latest native runtime hosts.
- Align all release versions before tagging; verify tag/source identity in release CI.
- Skip unpublished v0.1.2: its tag points to source declaring v0.1.1; preserve that tag history.

- Add the Rust Caveman community compatibility optimizer with conservative pass-through gates,
  bounded streaming diagnostics reduction, deterministic fixtures, real-process verification,
  and native release packaging for all six supported platform targets.

## [0.1.1] - 2026-08-23

- Move first-party example plugin IDs under the domain-owned `com.vic-e.tokensaver` namespace.
- Align Ponytails publisher metadata with `https://vic-e.com`.
- Republish identity-bound packages, catalogs, SUPEREC records, and runtime assets without
  replacing the immutable v0.1.0 release.

## [0.1.0] - 2026-08-23

- Publish the versioned and additive TSPP v1 contract.
- Ship Rust, Go, Python, and TypeScript SDKs with AI-friendly scaffolds.
- Ship Ponytails and DeepSeek Harness as reproducible community examples.
- Add VIC-E SUPEREC records and an OKF wiki for generated plugins.
- Add deterministic validation, benchmark, package, catalog, and certification contracts.
- Add native Windows, Linux, and macOS confinement drivers and the hash-pinned runtime host.
- Enforce one manifest limit contract across schema, conformance corpus, workbench, and host consumers.
- Build and attest six-platform plugin packages, catalogs, and runtime-host assets in release CI.

[0.1.0]: https://github.com/VIC-E-com/tokensaver-plugin-sdk/releases/tag/v0.1.0
[0.1.1]: https://github.com/VIC-E-com/tokensaver-plugin-sdk/releases/tag/v0.1.1
