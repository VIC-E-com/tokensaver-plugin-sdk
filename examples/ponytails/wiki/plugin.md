---
type: Reference
title: Ponytails optimizer behavior
description: Reference head-and-tail optimizer with error-anchored failure context.
tags: [tokensaver, plugin, tests, reference]
---

# Ponytails optimizer behavior

Ponytails is an open-source community reference plugin. It handles test, build, lint,
status, and log output through TSPP v1.

Outputs shorter than 40 lines pass unchanged. Longer successful outputs keep the first
10 and last 20 lines. For a failing command, Ponytails also keeps a 10-line window around
the final line containing `error`, `failed`, or `panic` when that window is outside the
normal head and tail.

The SDK rejects empty, oversized, or NUL-containing proposed output. TokenSaver
independently requires valid UTF-8 and at least 20 percent byte reduction. Ponytails
returns pass when it cannot propose safe compact output.

The assembled-process test runs the Cargo-built executable through `tsp run`, exact
golden `tsp test`, and Level 1 `tsp validate` paths. Its sealed VIC-E SUPEREC graph links
the plugin to TSPP v1 and cites manifest and golden-fixture evidence without assigning
installation trust.
