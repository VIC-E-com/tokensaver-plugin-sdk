---
type: Reference
title: TokenSaver Plugin SDK for Python
description: Public Python API and safety boundaries for TSPP v1 optimizer plugins.
tags: [tokensaver, plugins, sdk, python, tspp]
---

# TokenSaver Plugin SDK for Python

The Python 3.10+ SDK at `sdk/python/tokensaver_plugin` uses only the standard
library at runtime. It owns bounded `Content-Length` framing, JSON-RPC 2.0
lifecycle handling, strict standard base64 conversion, UTF-8 and NUL validation,
exception isolation, complete writes, and structured protocol diagnostics.

Plugin code supplies a frozen `Identity` and either a callable or an object with
`optimize(request)`. The `Request` and returned actions are frozen and contain
only the host-classified kind, executable basename, exit code, UTF-8 text, and
advisory budget. Use `pass_output()` by default and `optimized(content)` only for
a safe, meaningfully smaller result. TokenSaver independently verifies it.

Run `python -m unittest discover -s tests -v` for the SDK. A project created with
`tsp new --lang python` vendors that runtime, pins PyInstaller 6.22.2, and generates unit,
standalone-executable, and native three-OS CI tests. The release manifest names the one-file
artifact under `dist/`, not an ambient Python interpreter. Built-in and community plugins
receive identical protocol checks; only the trusted host assigns provenance.
