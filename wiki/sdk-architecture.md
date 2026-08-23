---
type: Reference
title: TokenSaver Plugin SDK architecture
description: Boundaries and trust rules for built-in and community command-output optimizers.
tags: [tokensaver, plugins, sdk, security]
---

# TokenSaver Plugin SDK architecture

A TokenSaver plugin is a standalone executable speaking TSPP over framed stdin and stdout.
The process boundary keeps crashes isolated and makes the interface language-neutral.

The Rust, standard-library-only Go and Python, and zero-runtime-dependency
TypeScript SDKs contain public protocol plumbing, validation, and developer
tooling. They do not contain TokenSaver's proprietary optimization heuristics.
A plugin may implement its own logic and may be open or closed source.

Every v1 manifest points to a standalone executable. The Python scaffold vendors the public
runtime and uses pinned PyInstaller 6.22.2 for native one-file builds. The TypeScript scaffold
vendors the public runtime and declarations and uses pinned Bun 1.4.0 to compile a native
executable without package dependencies. Their generated CI builds and exercises artifacts
natively on Windows, Linux, and macOS. Distributed plugins cannot rely on an ambient interpreter.

Built-in and community plugins use the same manifest rules, handshake, safety checks, and
output verification. TokenSaver assigns provenance through its trusted installation path.
A manifest or SUPEREC graph cannot grant itself built-in trust.

Community distribution stays blocked until TokenSaver enforces operating-system process
confinement. Workbench validation does not install, activate, or enable a plugin.
