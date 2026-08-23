# DeepSeek Harness Output Optimizer instructions

- Keep `plugin.json`, the compiled plugin id, the SUPEREC identity, and the
  executable version synchronized.
- Keep stdout exclusively SDK-managed TSPP frames. Diagnostics belong on
  stderr and must never contain input content or environment values.
- Keep eligibility narrow. Output from unrelated package-manager workspaces
  must return `Action::Pass`.
- Preserve command boundaries, summaries, warnings, failures, and diagnostic
  context. Add an exact regression test before changing classification rules.
- Return `Action::Pass` unless the proposed output saves at least 20 percent.
- Do not add filesystem, network, ambient-environment, or persistent-state
  access. TSPP v1 grants no permissions.
- Run the unit tests, real-process workbench test, Clippy, formatting, and
  deterministic package checks before release.
