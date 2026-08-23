---
type: Reference
title: VIC-E SUPEREC in the TokenSaver Plugin SDK
description: Authoritative graph, integrity, extension, and OKF contracts for SDK artifacts.
tags: [vic-e, superec, graph, integrity, okf]
---

# VIC-E SUPEREC in the TokenSaver Plugin SDK

SUPEREC is the VIC-E Software Unified Portable Ecosystem Record standard. The SDK's
`system.superec` and every scaffolded plugin's optional `plugin.superec` are sealed
SUPEREC 0.1.0 workspace graphs, not TokenSaver-specific flat records.

The graph represents a plugin as a `plugin` resource, TSPP v1 as an `api` resource,
and the implementation claim as a directed `implements` relationship citing
`plugin.json`. Golden suites and other verification material are resources and
evidence. The official SUPEREC schema, integrity rules, capabilities, graph
semantics, and trust boundary remain authoritative.

TokenSaver adds only the inert `com.vic-e.tokensaver/plugin` resource extension.
Its additive v1 payload is documented by
`schemas/tokensaver-superec-plugin-profile.v1.json` and links the manifest, TSPP
major, and OKF knowledge root. Ignoring that extension never changes the meaning
of the core SUPEREC graph.

The record cannot activate a plugin, grant permissions, claim built-in provenance,
or authorize execution. TokenSaver assigns provenance through its trusted install
path and applies identical safety verification to built-in and community plugins.

Run `superec validate plugin.superec` for full VIC-E conformance. `tsp validate`
also verifies the RFC 8785 SHA-256 seal and the TokenSaver plugin profile. Regenerate
the OKF v0.2 projection whenever the sealed source graph changes.
