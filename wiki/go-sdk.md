---
type: Reference
title: TokenSaver Plugin SDK for Go
description: Public Go API and safety boundaries for TSPP v1 optimizer plugins.
tags: [tokensaver, plugins, sdk, go, tspp]
---

# TokenSaver Plugin SDK for Go

The Go SDK is a standard-library-only module at
`sdk/go/tokensaverplugin`. It owns bounded `Content-Length` framing, JSON-RPC
2.0 lifecycle handling, base64 conversion, UTF-8 and NUL validation, panic
isolation, and structured protocol errors.

Plugin code supplies an immutable `Identity` and one `Optimizer` method. Use
`OptimizerFunc` for small plugins. Return `Pass()` unless `Optimized(content)`
succeeds and the result is meaningfully smaller. TokenSaver independently
enforces the minimum 20 percent reduction.

The `Request` exposes only the host-classified kind, executable basename, exit
code, UTF-8 text, and advisory budget. TSPP v1 does not disclose command
arguments or ambient credentials. stdout is reserved for SDK-managed frames;
diagnostics belong on stderr.

Run `go test -race ./...`, `go vet ./...`, `tsp test .`, `tsp bench .`, and
`tsp validate .` before packaging. Built-in and community plugins use the same
protocol and safety verification. A manifest, package, SUPEREC record, or OKF
page cannot install, activate, grant permissions, or self-assign provenance.
