# Caveman Output Compatibility Optimizer

A Rust community plugin for TokenSaver Plugin Protocol (TSPP) v1. It reduces only long, clearly identified Caveman diagnostic streams while preserving the evidence an agent or developer needs to recover, audit accounting, and diagnose failures.

This integration is maintained by VIC-E. It is not affiliated with or endorsed by Caveman or Julius Brussee.

Compatibility was reviewed against Caveman commit
`df2ccd85c94ec3c8289cb62ac020d241ccfb0c60` and its public CLI/output documentation. The
optimizer is independently implemented; it does not import, link, or copy Caveman code. TSPP v1
already provides every required input field, so this integration does not expand the SDK protocol.

## Safety model

The plugin is deliberately conservative:

- Already compacted Caveman output and every `caveman retrieve` recovery reference pass through byte-for-byte.
- JSON, NDJSON, status output, short output, unrelated commands, and changes below 20% reduction pass through byte-for-byte.
- Warnings, errors, failures, timeouts, recovery and remediation instructions, and accounting evidence remain visible.
- Failed commands retain three surrounding lines; successful commands retain one.
- The first 10 and final 16 lines always remain visible.
- Every removed run is replaced by a deterministic omitted-line count.

The optimizer is stateless. It creates no threads, caches, files, sockets, timers, or global mutable state. Processing is linear in input size, retains only a fixed 17-line window, and handles output allocation failure by returning `Action::Pass`. If the plugin is not installed and activated, TokenSaver does not start its executable, so it has zero runtime activity.

## Architecture

```text
TokenSaver host
    │ validated TSPP/1 request (max 16 MiB)
    ▼
Exact-pass gates ── status / JSON / NDJSON / short / already compacted ──► Pass
    │
    ▼
Narrow Caveman eligibility gate ── unrelated program ───────────────────► Pass
    │
    ▼
Bounded streaming selector
    ├── 10-line head
    ├── warnings, failures, remediation, and accounting evidence
    ├── 1 or 3 lines of context
    └── 16-line tail
    │
    ▼
Reduction gate (<20% saved) ─────────────────────────────────────────────► Pass
    │
    ▼
Action::Optimize
```

The SDK owns protocol framing and panic isolation. TokenSaver independently validates the proposal before using it.

## Build and verify

From the SDK repository root:

```text
cargo test -p tokensaver-caveman-plugin
cargo clippy -p tokensaver-caveman-plugin --all-targets -- -D warnings
cargo run -p tsp-workbench -- test examples/caveman
cargo run -p tsp-workbench -- bench examples/caveman --iterations 10
cargo run -p tsp-workbench -- validate examples/caveman
cargo run -p tsp-workbench -- package examples/caveman --output caveman.tsplug
```

The checked-in manifest declares native executables for Windows x64/arm64, Linux x64/arm64, and macOS x64/arm64. The release workflow builds each artifact on its native runner and assembles a deterministic catalog.

## License

Apache-2.0. The implementation is independent and does not copy Caveman implementation code.
