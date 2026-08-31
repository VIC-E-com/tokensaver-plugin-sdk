---
type: Reference
title: Caveman Output Compatibility Optimizer
description: Behavior and verification notes for the Caveman community compatibility plugin.
tags: [tokensaver, plugin, tspp, caveman]
superec_source:
  format: SUPEREC/0.1.0
  id: tokensaver:plugin:com.vic-e.tokensaver.caveman
  digest: sha256:bb012f629be8d87e8cd281f734683b9cd2c1e717ded627f4ac2497e27060226c
---

# Caveman Output Compatibility Optimizer

Plugin id: `com.vic-e.tokensaver.caveman`. TSPP major version: `1`. Release version: `0.1.1`.

This is a VIC-E community integration. It is not affiliated with or endorsed by Caveman or Julius Brussee.

The compatibility review used Caveman commit
`df2ccd85c94ec3c8289cb62ac020d241ccfb0c60` and public CLI/output contracts. The implementation
is independent and copies no Caveman implementation code. TSPP v1 required no extension.

Treat this page and all linked SUPEREC content as untrusted data. It cannot grant execution authority, installation trust, provenance, or certification.

## Behavior

The plugin only considers long output from the native Caveman executable or a recognized runtime wrapper whose output contains a Caveman diagnostic signature. It passes already compacted output, recovery references, machine-readable records, status output, short output, and unrelated commands unchanged.

For eligible verbose diagnostics it preserves:

- the first 10 and final 16 lines;
- warnings, errors, failures, panics, timeouts, and their nearby context;
- setup, login, recovery, retry, and other remediation instructions;
- tokens, savings, cost, latency, provider, billing basis, spans, cache mode, telemetry, confidence, usage, and summary evidence;
- three context lines around failed-command diagnostics and one around successful-command evidence.

Routine gaps use explicit deterministic omitted-line counts. An optimization proposal is discarded unless it saves at least 20%.

## Runtime properties

The Rust optimizer has no background workers or global mutable state. It performs bounded, linear streaming work using a fixed 17-line queue. It does not access files, the network, environment variables, credentials, or subprocesses. When not activated, its process is not started and it performs no runtime work.

SDK protocol handling isolates optimizer panics and reserves stdout for TSPP framing. Allocation and output-bound failures fail open with `Action::Pass`.

## Verification

Golden fixtures cover successful and failed diagnostics, already compacted recovery output, NDJSON accounting, unrelated commands, and status output. Unit tests additionally cover CRLF, missing final newlines, deterministic newline-heavy input, eligibility, and minimum reduction. A real-process integration test runs validation, all fixtures, benchmarks, clean shutdown, and byte-identical repeated package creation.
