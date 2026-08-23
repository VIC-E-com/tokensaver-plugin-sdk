# AI and human quickstart

TokenSaver plugins are ordinary executables that speak the versioned TokenSaver Plugin
Protocol (TSPP) over stdin and stdout. The Rust, Go, Python, and TypeScript SDKs own framing,
validation, optimizer failure isolation, and shutdown so plugin authors can focus on their own
optimization behavior.

## Fast path

From the SDK repository:

```text
cargo run -p tsp-workbench -- new examples/my-plugin --lang rust --id com.example.my-plugin
cd examples/my-plugin
cargo build
tsp run fixtures/smoke.input.txt --plugin . --kind test --program cargo
tsp test .
tsp bench . --iterations 10
tsp validate .
tsp package .
tsp catalog dist --output catalog.json
```

For Go, replace the scaffold command with:

```text
cargo run -p tsp-workbench -- new examples/my-plugin --lang go --id com.example.my-plugin
cd examples/my-plugin
go build .
go test -race ./...
go vet ./...
tsp test .
tsp bench . --iterations 10
tsp validate .
```

For Python:

```text
cargo run -p tsp-workbench -- new examples/my-plugin --lang python --id com.example.my-plugin
cd examples/my-plugin
python -m pip install --requirement requirements-build.txt
python -m unittest tests.test_plugin -v
python build.py
python -m unittest tests.test_executable -v
tsp test .
tsp bench . --iterations 10
tsp validate .
```

For TypeScript:

```text
cargo run -p tsp-workbench -- new examples/my-plugin --lang typescript --id com.example.my-plugin
cd examples/my-plugin
bun install
bun run check
bun test tests/plugin.test.ts
bun run build
bun test tests/executable.test.ts
tsp test .
tsp bench . --iterations 10
tsp validate .
```

The scaffold starts with a safe pass action, cannot overwrite a non-empty directory, includes a
manifest, an exact golden fixture, CI, and an `AGENTS.md` that gives an AI coding assistant the
same safety and verification rules a human author needs.

For Python, generate with `--lang python`, install the exact versions in
`requirements-build.txt`, run the unit test, and run `python build.py`. The scaffold vendors the
public protocol runtime and uses pinned PyInstaller 6.22.2 to create a native one-file executable
under `dist/`. Run the executable test before the workbench lifecycle. Python is a build-time
dependency only and is not required on the destination computer.

For TypeScript, generate with `--lang typescript`, run `bun install`, and commit the generated
`bun.lock`. TypeScript 7.0.2 is development-only type-checking tooling. Run `bun run check`, the
unit test,
`bun run build`, and the executable test. The scaffold vendors the public JavaScript protocol
runtime and its TypeScript declarations, has no runtime package dependencies, and compiles a native
executable under `dist/`. TypeScript, Bun, and Node are not required on the destination computer.
TypeScript does not enter the Rust, Go, Python, host, wire-protocol, or runtime core.

Python and TypeScript builds run natively on Windows, Linux, and macOS in the generated CI.
Do not cross-compile a release or point `plugin.json` at an ambient Python, Bun, or Node
interpreter. Add the resulting native platform entries before publishing a multi-platform release.

## Compatibility rules

- `apiVersion` is the TSPP major version. A v1 host and plugin reject another major version.
- Additive JSON fields are allowed within v1 and ignored by readers that do not understand
  them. Put private experimental data under an `extensions` object keyed by a reverse-DNS
  owner such as `com.example.trace`.
- Existing field meanings, required fields, method names, and safety rules cannot change
  within v1. A breaking change requires a new protocol major and a new manifest schema URL.
- Plugin release `version` is independent from `apiVersion`. Keep the compiled id and release
  version identical to `plugin.json`; `tsp validate` checks both during initialize.
- Fixture descriptors use their own `schemaVersion` and published
  `schemas/fixture-case.v1.json`. Unknown additive fields are accepted for forward evolution.
- `releaseId` is deterministic for one plugin id, version, platform, and executable digest. Every
  real process start receives a fresh `activationAttemptId`. Use the release id for immutable
  artifact identity and the activation-attempt id only to correlate one bounded execution.
- Built-in and community plugins follow the same handshake, conformance suite, and output
  verification. Provenance is assigned by TokenSaver's trusted install path, never by a
  self-asserted manifest field.

## Stable automation surface

Use `--json` with `tsp new`, `run`, `test`, `bench`, `validate`, `package`, or `catalog`. Reports contain a stable `ok` value,
command-specific results, and actionable error `code`, `message`, and `remediation` fields.
Exit code 0 means success, 1 means validation or test failure, and 2 means invalid command use.

`tsp bench` verifies every repeated result against the same exact golden fixture before reporting
weighted savings and nearest-rank latency percentiles. `tsp package` reruns Level 1 conformance
and creates a deterministic single-platform `.tsplug` archive with SHA-256 digests. It never
installs, enables, or activates a plugin.

Release CI runs `tsp package --json` on each native target and stores the report next to the
archive as `<package>.tsplug.package-report.json`. `tsp catalog` accepts only those paired files,
recomputes every archive size and SHA-256 digest, rejects mixed releases or duplicate platforms,
and writes a deterministic v1 catalog. A catalog records immutable artifacts and conformance
levels; it does not assign built-in or community provenance or authorize activation.

Never raise `certificationLevel` in a manifest, package report, or catalog by editing JSON. Local
`tsp validate` and `tsp package` issue Level 1 evidence only, and catalog assembly rejects a local
report claiming more. Levels 2 and 3 use the cumulative, digest-bound
`schemas/certification-report.v1.json` contract and require authentication by the trusted issuer
plus a revocation lookup. Structural report validation alone is not authorization.

Trusted CI uses the non-published `tools/tsp-certification-worker` crate for protocol fuzzing.
Supply exact executable bytes, `certification-fuzz-corpus.v1.json`, the matching policy, producer
identity, and a platform-specific `CertificationFuzzExecutor`. The corpus fixes sorted valid and
malformed wire inputs, repetitions, deadlines, memory and stream limits, and required sanitizers.
The worker recomputes every counter and passes its report through `evaluate_protocol_fuzzing`.
Executor infrastructure failures produce no evidence; observed plugin or safety failures produce a
truthful failed stage. Never use an ordinary unsandboxed process executor as a fallback.

Implement native drivers behind `tools/tsp-certification-confinement`. Its adapter requires a
canonical v1 profile with an immutable sandbox-policy digest, exact platform controls, and a sorted
sanitizer engine. It checks the profile before every execution, binds a deterministic attempt id,
rejects cross-platform subjects and forged observations before counting, and keeps protocol
classification separate from process-launch authority. A missing OS facility is an infrastructure
error. Never retry without AppContainer and Job Objects on Windows, namespaces, seccomp, Landlock,
and cgroup v2 on Linux, or the deny-by-default sandbox profile and hard process/resource controls on
macOS.

Trusted certification automation can call `evaluate_reproducible_build` with exact in-memory
bytes for the subject package, immutable source archive, policy, runner report, and two rebuilt
packages. The evaluator does not execute builds or access the network. A well-formed mismatch
becomes truthful failed stage evidence; malformed, ambiguous, oversized, or identity-drifted
evidence is rejected. No local command uses this primitive to claim Level 2.

Trusted automation can call `evaluate_signed_artifact` with exact in-memory executable, signature,
policy, and artifact trust-store bytes. Provision the trust store independently from the plugin and
catalog. Never accept a signer key embedded by the plugin. The evaluator performs no network or
filesystem access and returns auditable failed stage evidence for an untrusted, expired, or
cryptographically invalid signature. Use
`conformance/certification-artifact-signature-v1.cases.json` when implementing the signing message
in another language.

Level 3 automation can call `evaluate_sbom` with the exact package, CycloneDX 1.6 SBOM, policy,
and generator report bytes, then call `evaluate_license_provenance` with that same exact SBOM,
the license policy, and review report. Both evaluators recompute component counts and evidence
digests. SBOM acceptance requires stable component identity and, under the v1 policy, a SHA-256,
SPDX license id, and package URL for every component. License review applies sorted, disjoint SPDX
allow and deny lists and requires complete license and provenance coverage. Malformed or drifted
evidence is rejected; well-formed incomplete or disallowed evidence becomes a truthful failed
stage. These functions evaluate supplied evidence only. They do not generate an SBOM, decide a
license, access a network, or grant certification.

The final Level 3 stage uses `evaluate_admin_policy_metadata` to prove that one bounded metadata
document is an exact projection of the validated `plugin.json`. The projection exposes runtime
platform names, counts rather than argument values, capability kinds, declared and effective
limits, permission count, and integrity coverage. It excludes runtime paths, argument contents,
plugin output, and credentials. Complete SHA-256 coverage is required for the stage to pass. This
evidence does not apply enterprise policy itself; a separately authenticated host policy remains
the decision authority.

Issuer automation can call `issue_certification_envelope` and
`issue_certification_revocations` with a `CertificationSigningProvider`. Implement that interface
as an adapter to an independently protected HSM or signing service. The SDK creates the exact
domain-separated message and receives only a 64-byte Ed25519 signature; private keys must never
enter the SDK. Route `CertificationSigningPurpose::Certification` and
`CertificationSigningPurpose::Revocation` to separately provisioned key ids. Issuance validates
the complete report, issuer identity, validity window, and canonical revocation structure before
requesting a signature, and it converts provider failures to bounded generic errors. Issued bytes
must still pass `verify_certification_evidence` and authenticated distribution before use. Issuance
does not assign provenance, install, enable, or activate a plugin.

Production hosts use the separate non-published `tools/tsp-certification-host` crate to implement
`AuthenticatedCertificationSource`. Configure one administrator-controlled credential-free HTTPS
base URL and expected issuer id. The connector derives immutable release and package paths, disables
ambient proxies and redirects, requests identity-encoded JSON, enforces the verifier's streaming
size limits, and shares one bounded deadline across all three documents. Pass it directly to
`fetch_verify_and_record_certification` with an independently provisioned trust store and private
revocation-state directory. Never treat successful retrieval as trust acceptance.

Run, test, benchmark, and validation JSON reports expose immutable `tsr1_` release ids and fresh
`tsa1_` activation-attempt ids. Package reports remain reproducible and therefore contain the
release id but no random activation id. Catalog assembly recomputes the release identity from the
plugin id, version, platform, and executable digest before accepting a package report.

An AI creating or editing a plugin should keep stdout protocol-only, send diagnostics to
stderr, add deterministic golden cases for behavior changes, and run the language unit tests,
`tsp test`, `tsp bench`, and `tsp validate` before handing work back to a human.
