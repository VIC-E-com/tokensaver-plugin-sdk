# TokenSaver Plugin SDK instructions

- Product plugins belong on one dedicated Plugins screen. Never duplicate plugin management or plugin cards in the dashboard or Settings. Keep the screen hidden and inactive until confinement, lifecycle, and full localization gates pass.

- Read `AI-QUICKSTART.md`, `README.md`, and `schemas/plugin-manifest.v1.json` before editing a
  plugin or workbench command.
- Treat TSPP `apiVersion` as a major compatibility boundary. Preserve v1 field meanings and
  accept unknown additive fields. Use reverse-DNS keys inside `extensions` for experiments.
- Keep plugin stdout exclusively for framed JSON-RPC. Diagnostics belong on stderr.
- Keep the SDK free of TokenSaver proprietary optimization logic and ambient credentials.
- Keep `tsp-workbench` free of HTTP clients and network authority. Production certification
  retrieval belongs only in the separate host connector, and registry evidence must never supply
  the independently provisioned trust store.
- Keep trusted fuzz orchestration separate from its OS confinement backend. Never add an
  unsandboxed fallback; every execution must be deadline-bound, output-bound, killed if needed, and
  reaped before the backend returns.
- Native certification drivers must pass the exact `tsp-certification-confinement` v1 profile on
  every operation. Never weaken, infer, reorder, or silently omit a platform control, and never let
  the protocol oracle acquire process-launch authority.
- The non-published `tsp-runtime-host` is a product trust boundary. Preserve its schema-v1 bounds,
  exact package and executable rehash, native-only execution, idempotent deprovisioning, minimal
  environment, and bounded error codes. Never add a direct or unsandboxed plugin fallback.
- Built-in and community plugins use identical protocol and safety verification. Do not add a
  manifest trust flag or activation side effect.
- Built-in plugin implementations belong in the TokenSaver product repository. Do not copy,
  publish, or scaffold proprietary built-in optimization logic in this public SDK repository.
- Add deterministic golden fixtures for optimizer behavior. Every fixture process must be
  bounded, shut down, killed if necessary, and reaped.
- Treat `tsp bench` reports, `.tsplug` package bytes, and package catalogs as versioned
  reproducibility contracts. Never let packaging or catalog assembly install, activate, or
  self-assign provenance.
- Before handoff run `cargo test --workspace`, strict Clippy, Rust formatting,
  `go test -race ./...`, `go vet ./...`, and Go formatting in
  `sdk/go/tokensaverplugin`; `python -m unittest discover -s tests -v` in
  `sdk/python`; and `npm test` plus `npm run check` in
  `sdk/typescript/tokensaver-plugin`. Also run Go host contract tests and the
  renderer checks required by the parent repository.
- TSPP v1 runtime entries are standalone executables. Do not scaffold Python or
  TypeScript plugins around ambient interpreters. A new language scaffold must
  have an audited self-contained build on every platform it claims.
