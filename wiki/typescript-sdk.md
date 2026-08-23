---
type: Reference
title: TokenSaver Plugin SDK for TypeScript
description: Public TypeScript API and safety boundaries for TSPP v1 optimizer plugins.
tags: [tokensaver, plugins, sdk, typescript, node, tspp]
---

# TokenSaver Plugin SDK for TypeScript

The TypeScript-consumable SDK at `sdk/typescript/tokensaver-plugin` ships a
JavaScript runtime plus declarations and has no runtime package dependencies. It
owns bounded queued framing, JSON-RPC 2.0 lifecycle handling, strict standard
base64 conversion, fatal UTF-8 decoding, NUL and unpaired-surrogate rejection,
sync and async exception isolation, write completion, and structured diagnostics.

TypeScript-only development pins TypeScript 7.0.2 for strict declaration and consumer-contract
checks. It remains a development dependency. The JavaScript protocol runtime has no runtime
dependencies, and TypeScript is not introduced into the Rust, Go, Python, or TokenSaver host core.

Requests and actions are frozen at runtime and readonly in TypeScript. An
optimizer can be a sync or async function or an object with `optimize(request)`.
Use `passOutput()` by default and `optimized(content)` only for a safe,
meaningfully smaller result. TokenSaver independently verifies every proposal.

Run `npm ci`, `npm test`, and `npm run check` for the SDK. A project created with
`tsp new --lang typescript` vendors the runtime and declarations, pins Bun 1.4.0, and generates
unit, standalone-executable, and native three-OS CI tests without runtime package dependencies. The
release manifest names the compiled artifact under `dist/`, not an ambient Bun or Node
interpreter. Built-in and community plugins use the same protocol and output checks; only the
trusted host assigns provenance.
