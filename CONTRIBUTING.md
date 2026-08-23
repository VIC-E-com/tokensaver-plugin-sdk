# Contributing

TokenSaver Plugin SDK contributions are welcome. Keep changes focused, preserve TSPP v1
compatibility, and never add TokenSaver proprietary optimization logic or ambient credentials.

Before submitting a change, run `scripts/verify.ps1` on Windows or `bash scripts/verify.sh`
on Linux or macOS. Manifest changes must update the schema, shared valid and invalid
conformance cases, every host-equivalent validator, tests, and documentation together.
Native confinement changes must retain the exact platform controls and may not add an
ordinary-process fallback.

Contributors certify their work under the Developer Certificate of Origin by using
`git commit --signoff`. AI-assisted contributions require human review for correctness,
security, provenance, and license compatibility.
