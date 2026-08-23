---
type: Reference
title: TSPP v1 compatibility
description: Major-version and additive-extension rules for TokenSaver Plugin Protocol v1.
tags: [tokensaver, tspp, compatibility, protocol]
---

# TSPP v1 compatibility

`apiVersion` is the TSPP major version. A v1 host and plugin reject a different major during
`initialize`. Plugin release `version` is independent and must match `plugin.json`.

Within v1, producers may add optional JSON fields and consumers must ignore fields they do
not understand. Private experiments belong under `extensions` and use reverse-DNS owner keys.
Existing fields, required fields, methods, and safety meanings cannot change within v1.

The v1 native launch contract accepts at most 32 `runtime.args` values. Each value is at most
4096 UTF-8 bytes and cannot contain NUL. Empty arguments are valid. Plugin ids are at most
128 ASCII bytes, contain at least three lowercase DNS labels, and limit every label to 63
bytes. The Go host, transactional installer, Rust workbench, public schema, shared conformance
corpus, and native runtime host test these same boundaries so validation cannot succeed and
then fail later during activation.

The v1 lifecycle is spawn, `initialize`, one `optimize` request, `shutdown`, and process exit.
The host independently enforces deadlines, UTF-8 text safety, absence of NUL bytes, and at
least 20 percent byte reduction before displaying plugin output.
