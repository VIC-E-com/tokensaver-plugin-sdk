# Caveman plugin instructions

- This directory is a public, community TSPP v1 plugin. It is not a built-in TokenSaver optimizer.
- Keep `apiVersion`, plugin id, version, binary name, wiki identity, SUPEREC identity, fixtures, and release workflow synchronized.
- Keep stdout exclusively for SDK-managed TSPP frames. The optimizer itself must not log.
- Preserve already compacted Caveman output, recovery references, JSON/NDJSON, status output, diagnostics, remediation, and accounting evidence exactly.
- Eligibility must remain narrow. Never optimize unrelated wrapper output merely because a wrapper such as npm or Node.js launched it.
- Return `Action::Pass` for uncertainty, allocation failure, malformed assumptions, or less than 20% reduction.
- Keep the optimizer stateless and linear-time. Do not add threads, global mutable state, caches, filesystem access, network access, environment reads, credentials, subprocesses, or unbounded per-line indexes.
- Retain only a bounded rolling line window. Do not collect a maximum-size request into `Vec<&str>` or clone the input.
- Add exact golden fixtures and unit tests for every behavior change, including success, failure, recovery, accounting, newline shape, narrow eligibility, and the reduction threshold.
- Run unit, real-process, fixture, benchmark, validation, deterministic-package, workspace, strict Clippy, formatting, and every repository-wide SDK gate required by the root `AGENTS.md`.
- Packaging and tests must never install, activate, or assign provenance to the plugin.
- Keep the non-affiliation notice in the manifest, README, and wiki.

