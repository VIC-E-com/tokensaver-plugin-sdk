# TokenSaver Plugin SDK

This repository is the public `VIC-E-com/tokensaver-plugin-sdk` source. It contains only the public TokenSaver
Plugin Protocol (TSPP) plumbing and reference tooling. TokenSaver optimization
heuristics and product secrets do not belong here.

## Rust SDK

The Rust SDK handles JSON-RPC framing, the TSPP handshake, base64 conversion,
request validation, panic isolation, and graceful shutdown. A plugin only
implements `Optimizer`:

```rust
use tokensaver_plugin::{run, Action, Optimizer, Request};

struct MyOptimizer;

impl Optimizer for MyOptimizer {
    const PLUGIN_ID: &'static str = "com.example.my-optimizer";
    const VERSION: &'static str = "1.0.0";

    fn optimize(&self, request: Request) -> Action {
        let compact = request.text().lines().take(20).collect::<Vec<_>>().join("\n");
        Action::optimized(compact).unwrap_or(Action::Pass)
    }
}

fn main() {
    run(MyOptimizer);
}
```

`Action::optimized` rejects empty output, NUL bytes, and payloads over 16 MiB.
The TokenSaver host independently rechecks UTF-8 safety and the minimum 20%
reduction before using any plugin output.

## Go SDK

The standard-library-only Go SDK provides the same TSPP v1 lifecycle and safety
contract. A plugin implements one method or uses `OptimizerFunc`:

```go
package main

import tsp "github.com/VIC-E-com/tokensaver-plugin-sdk/sdk/go/tokensaverplugin"

func main() {
    identity := tsp.Identity{PluginID: "com.example.my-optimizer", Version: "1.0.0"}
    tsp.Run(identity, tsp.OptimizerFunc(func(request tsp.Request) tsp.Action {
        return tsp.Pass()
    }))
}
```

`Optimized` rejects empty output, invalid UTF-8, NUL bytes, and payloads over
16 MiB. The runtime bounds framing and decoded input, isolates optimizer panics,
accepts additive v1 fields, and reserves stdout for protocol frames.

## Python SDK

The Python 3.10+ SDK is standard-library-only at runtime and accepts either a
callable or an object with `optimize(request)`. Requests and actions are frozen:

```python
from tokensaver_plugin import Identity, pass_output, run


def optimize(request):
    return pass_output()


run(Identity("com.example.my-optimizer", "1.0.0"), optimize)
```

`optimized(content)` validates the proposal before protocol emission. The SDK
bounds framing and decoded input, strictly validates base64 and UTF-8, isolates
plugin exceptions, and keeps stdout protocol-only.

## TypeScript SDK

The TypeScript-consumable SDK ships a zero-runtime-dependency JavaScript
implementation plus declarations. Optimizers may be synchronous or asynchronous:

```typescript
import { passOutput, run, type Identity, type Request } from "@tokensaver/plugin-sdk";

const identity: Identity = {
  pluginId: "com.example.my-optimizer",
  version: "1.0.0",
};

await run(identity, async (request: Request) => passOutput());
```

Its queued stream reader keeps framing memory bounded without repeatedly copying
large bodies. It strictly validates standard base64, UTF-8, NUL bytes, Unicode
scalar values, response size, and Node stream write completion.

For a task-oriented path suitable for both people and AI coding assistants, read
[`AI-QUICKSTART.md`](AI-QUICKSTART.md). The SDK also ships an OKF v0.2 knowledge bundle at
[`wiki/index.md`](wiki/index.md), and every generated plugin includes focused `AGENTS.md`
instructions.

## Develop and test

Run the same complete verification as CI:

```powershell
./scripts/verify.ps1
```

```sh
bash scripts/verify.sh
```

The individual commands are:

```text
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cd sdk/go/tokensaverplugin
go test -race ./...
go vet ./...
cd ../../python
python -m unittest discover -s tests -v
cd ../typescript/tokensaver-plugin
npm ci
npm test
npm run check
```

Build the release workspace after verification with `scripts/build.ps1` on Windows or
`bash scripts/build.sh` on Linux and macOS. `VERSION`, every package manifest, the
changelog, and the release workflow are checked as one version contract. A signed `v*`
tag starts the native six-platform package, catalog, runtime-host, provenance, checksum,
and GitHub Release workflow.

## Workbench

Create a safe Rust, Go, Python, or TypeScript scaffold:

```text
cargo run -p tsp-workbench -- new examples/my-plugin --lang rust --id com.example.my-plugin
cargo run -p tsp-workbench -- new examples/my-go-plugin --lang go --id com.example.my-go-plugin
cargo run -p tsp-workbench -- new examples/my-python-plugin --lang python --id com.example.my-python-plugin
cargo run -p tsp-workbench -- new examples/my-typescript-plugin --lang typescript --id com.example.my-typescript-plugin
```

`tsp new` never overwrites a non-empty directory. It generates source, a v1 manifest, tests,
CI, golden fixtures, AI instructions, a sealed VIC-E SUPEREC 0.1.0 graph, and an OKF v0.2 wiki.
Python uses pinned PyInstaller 6.22.2 to produce a one-file executable. TypeScript uses
development-only TypeScript 7.0.2 for strict checks and pinned Bun 1.4.0 to compile a native
executable. Neither tool enters the runtime or TSPP core. Both scaffolds vendor an
exact public SDK runtime snapshot and point `plugin.json` only to the generated executable under
`dist/`, never to an ambient interpreter. Build releases natively on every target operating system.

Run a recorded command output and inspect the savings and terminal-safe before/after diff:

```text
cargo run -p tsp-workbench -- run examples/ponytails/fixtures/smoke.input.txt --plugin examples/ponytails --kind test --program cargo
```

Run deterministic golden fixtures. Each `fixtures/*.case.json` descriptor uses
`schemas/fixture-case.v1.json`, points to an input file, declares `pass` or `optimize`, and
for optimized output points to an exact golden file. Every case starts a fresh process.

```text
cargo run -p tsp-workbench -- test examples/ponytails
```

Benchmark that same versioned corpus with fresh bounded processes. Repeated results must remain
byte-identical to their golden files. The v1 JSON report includes weighted savings plus min,
mean, p50, p95, p99, and max latency in microseconds.

```text
cargo run -p tsp-workbench -- bench examples/ponytails --iterations 10
```

Validate a packaged plugin directory or an explicit `plugin.json` path:

```text
cargo run -p tsp-workbench -- validate examples/ponytails
cargo run -p tsp-workbench -- validate examples/ponytails --json
```

The current platform executable named by `runtime.entry` must already exist. Validation checks:

- host-equivalent v1 manifest semantics from `conformance/manifest-v1.cases.json`;
- exact resource declarations: `maxInputBytes` may be zero for the 16 MiB host ceiling or
  1 through 16 MiB, while `timeBudgetMs` may be zero for the 250 ms default or 50 through
  1000 ms; other values are rejected rather than silently changed;
- VIC-E SUPEREC 0.1.0 duplicate-member rejection, integrity, plugin identity, TSPP relationship evidence, and OKF index when `plugin.superec` is present;
- platform resolution and executable startup with a scrubbed environment;
- initialize identity matching `plugin.json`;
- optimize response UTF-8 safety, NUL rejection, and minimum 20% reduction;
- rejection of optimize before initialize and malformed base64 input;
- bounded framing, response count, deadline, shutdown, kill, and process reap.

Text and JSON reports identify the failed rule and remediation. Exit code 0 means Level 1
conformance passed, 1 means validation failed, and 2 means command usage was invalid.
Validation does not install or activate a plugin.

Create a deterministic single-platform release artifact after validation:

```text
cargo run -p tsp-workbench -- package examples/ponytails --output ponytails-windows-x64.tsplug
```

The stored ZIP32 `.tsplug` contains a package-local manifest, the current platform executable,
SHA-256 integrity metadata, and package-owned SUPEREC, OKF, README, and license files when
present. Entries are sorted, timestamps and modes are normalized, symlinks are rejected, and
existing output is never overwritten. Packaging reruns Level 1 conformance and never installs,
enables, or activates the plugin. The archive and package report are byte-reproducible for
identical inputs.

Assemble native packages and their JSON reports into a release catalog:

```text
cargo run -p tsp-workbench -- catalog dist --output com.tokensaver.ponytails-0.1.0-catalog.json
```

Each canonical package must be named `<plugin-id>-<version>-<platform>.tsplug`; its unmodified
`tsp package --json` output must be stored beside it as `<package>.package-report.json`.
`tsp catalog` requires one plugin id and version, rejects missing reports, unexpected files,
duplicate platforms, size or digest mismatches, and existing output, and sorts platform keys.
Identical inputs produce byte-identical catalog JSON. The catalog records immutable package
identity and native Level 1 evidence but never installs, enables, activates, or assigns
built-in/community provenance.

Certification levels are a typed cumulative contract. Level 1 is manifest, TSPP lifecycle, and
safety conformance. Level 2 adds public-corpus thresholds, protocol fuzzing, reproducible-build
verification, and a verified artifact signature. Level 3 adds SBOM, license/provenance review,
and admin policy metadata. `schemas/certification-report.v1.json` binds every named check to the
exact package digest, API major, issuer policy, release id, and revocation id. Local validation and
packaging emit Level 1 only. Catalog assembly rejects a self-promoted local report. A trusted path
must authenticate the issuer and check revocation before accepting any certification report.

The versioned certification pipeline accepts one exact
`certification-stage-evidence.v1.json` document per cumulative requirement. It enforces canonical
stage order, stable rules, producer/environment identity, bounded timing, exact artifact and package
bindings, byte-identical reproducible-build outputs, and Level 3 SBOM/manifest handoffs before
computing each evidence digest. The public-corpus evaluator independently recomputes benchmark
accounting and applies an exact `certification-benchmark-policy.v1.json` using integer basis-point
savings and microsecond p95 latency. The protocol-fuzz evaluator binds exact executable, corpus,
policy, and report bytes; verifies TSPP/1 identity, timing, and counter accounting; applies the exact
`certification-fuzz-policy.v1.json`; and requires complete valid/malformed handling with zero process
or protocol safety failures. The reproducible-build evaluator consumes the exact subject package,
immutable source archive, two independently rebuilt packages,
`certification-reproducible-build-policy.v1.json`, and
`certification-reproducible-build-report.v1.json`. It verifies every digest and runner identity,
requires two distinct clean-room environments, successful network-isolated builds with no
undeclared inputs, bounded timing, and byte-identical package outputs. Failed stages produce
truthful failed reports. The signed-artifact evaluator verifies a detached Ed25519 signature over
the exact plugin id, version, platform, API major, executable digest, and release id. Its policy and
artifact trust store are separate caller inputs whose exact bytes are evidence-bound; they can never
be learned from a plugin package or catalog. Current validity, signer key lifetime, remaining
validity, canonical key/signature encodings, weak keys, and the cryptographic signature are checked
before the stage passes. The Level 3 SBOM evaluator binds the exact subject package to a CycloneDX
1.6 document and independently recomputes bounded component, SHA-256, SPDX license, and package URL
coverage from stable component identities. The license and provenance evaluator consumes that same
exact SBOM, applies sorted disjoint SPDX allow and deny lists, and recomputes complete license and
provenance counters. Both evaluators reject malformed, ambiguous, oversized, duplicate, or drifted
evidence and preserve well-formed policy failures as truthful failed stage evidence.

The admin-policy metadata evaluator verifies a bounded, versioned projection of the exact validated
manifest. It recomputes runtime platform and capability inventories, argument and permission counts,
declared and effective limits, and exact SHA-256 integrity coverage without exposing executable
paths or argument contents. Level 3 requires complete integrity coverage. The metadata is input to a
separately authenticated enterprise policy decision and cannot grant permission or activation.

The actual fuzzing, clean-room builds, artifact signing, SBOM generation, license review, and admin
metadata generation remain trusted CI work. The evaluators perform no execution, network, filesystem,
installation, provenance, enablement, or activation action. The assembler is unsigned and grants no
issuer authority. Cross-language implementations use
`conformance/certification-artifact-signature-v1.cases.json` to pin the binary signing message.

The SDK provides that deterministic verification primitive through
`verify_certification_evidence` and the versioned envelope, trust-store, revocation, and durable
revocation-state schemas.
It verifies exact report bytes with purpose-separated Ed25519 keys, bounded validity and freshness,
monotonic revocation sequences, exact issuer and package identity, and current revocation state.
`conformance/certification-trust-v1.cases.json` pins the binary signing preimage for implementations
in other languages. `AuthenticatedCertificationSource` lets a host supply authenticated evidence
without giving this SDK network authority; the independently provisioned trust store is never
fetched from registry evidence. `CertificationRevocationStateStore` uses bounded cross-process
locking and immutable synchronized markers to reject durable rollback. A concrete production HTTPS
connector now lives in the separate non-published `tools/tsp-certification-host` host crate, so the
public SDK retains no network authority. It uses Web PKI HTTPS with no ambient proxy, cookie,
credential, redirect, or decompression authority; derives fixed immutable release/package paths;
requires exact same-URL HTTP 200 JSON; applies verifier-sized streaming bounds; and shares one total
deadline across report, envelope, and revocation retrieval. It composes directly with
`fetch_verify_and_record_certification`. Verification never assigns built-in or community
provenance and never installs or activates a plugin.

Offline issuer integration uses `issue_certification_envelope`,
`issue_certification_revocations`, and the purpose-aware `CertificationSigningProvider` boundary.
The SDK validates the exact report, issuer, validity window, and canonical revocation publication,
then sends only the domain-separated message to an external HSM or signing service. It never
receives or stores private key material. Certification and revocation purposes must resolve to
separately provisioned key ids, and provider diagnostics are reduced to bounded generic errors.
The resulting documents are compatible with the same real verifier above. Issuance does not
authenticate distribution, assign built-in or community provenance, install, enable, or activate
a plugin.

All seven commands support `--json` as a stable automation surface. `run`, `test`, `bench`,
`validate`, and `package` use the same manifest resolution, scrubbed process environment, bounded TSPP
framing, deadline, shutdown, kill, reap, and output safety rules.

## Trusted protocol-fuzz worker

The non-published `tools/tsp-certification-worker` crate owns deterministic protocol-fuzz
orchestration and report construction. The exact `certification-fuzz-corpus.v1.json` document fixes
sorted valid and malformed wire cases, repetitions, per-execution deadlines, memory and stream
limits, and required sanitizers. The evaluator parses those exact corpus bytes independently,
bounds reported valid and malformed executions by the plan, and verifies every required sanitizer
was active.

`CertificationFuzzExecutor` requires trusted CI to provide a fresh OS-confined,
sanitizer-instrumented, resource-bounded, killed-and-reaped process for every case. There is no
permissive local-process fallback. Executor infrastructure failures produce no evidence; measured
plugin failures produce truthful failed evidence. The platform confinement backend remains trusted
CI work, and neither worker nor evaluator can issue certification, install, enable, or activate a
plugin.

The non-published `tools/tsp-certification-confinement` adapter requires an immutable platform
policy and the exact Windows AppContainer/Job Object, Linux namespace/seccomp/Landlock/cgroup v2,
or macOS sandbox control set. It rechecks the profile before every execution, rejects
subject-platform and attestation drift, and independently maps bounded native observations into
safety counters. The separate Windows driver now implements capability-free AppContainer launch,
pre-resume Job Object assignment, exact handle inheritance, hard memory/stream/deadline bounds, and
verified reap without an ordinary-process fallback. Separate Linux and macOS crates now implement
the namespace/seccomp/Landlock/cgroup v2 and deny-by-default sandbox/resource-limit drivers. The
non-published `tools/tsp-runtime-host` composes those kernels into the product runtime boundary. It
accepts one bounded schema-v1 request, rehashes the exact package and executable, forwards manifest
arguments exactly, returns host-measured proof, and supports idempotent native deprovisioning. It is
not part of the public plugin API and has no ordinary-process fallback. The release workflow runs
the real Linux proof in a delegated cgroup and the ignored native macOS proof
on x64 and arm64 runners before packaging. Provisioned Windows CI must still supply the immutable
AppContainer-readable instrumented executable and private sanitizer/coverage directory for a real
instrumented campaign.

Every product runtime kernel supplies `TOKENSAVER_PLUGIN=1` inside its minimal environment, and the
real native fixture verifies that marker with exact argument forwarding. An opt-in Go integration
also exercises the full transactional manager, confined activator, runtime, Rust sidecar, plugin
protocol, deprovision, and removal path. Native Windows, Linux, macOS x64, and macOS arm64 CI jobs run
that product-level integration only after their direct kernel proof passes.

Every product runtime-host artifact directory also carries a versioned
`runtime-host-assets.v1.json` manifest. The Go product boundary rejects foreign platforms,
ambiguous JSON, path escape, missing native resources, and SHA-256 drift before constructing the
native executor. The manifest cannot provide writable paths, Linux cgroup authority, provenance,
installation, enablement, or activation.

Product build staging consumes only the exact aggregate six-platform bundle. The independent
the monorepo `../scripts/stage-plugin-runtime-assets.py` verifier rejects shortened checksum inventories,
foreign members, symlinks, duplicate manifest members, platform drift, and digest mismatch,
then atomically stages one platform. Windows native and Electron builds, Linux AppImage/DEB/RPM
builds, and macOS Electron builds share that contract. Release builds can set
`TOKENSAVER_REQUIRE_PLUGIN_RUNTIME_ASSETS=1` so a missing bundle fails the package rather than
silently omitting confinement assets. Assets remain inert while the runtime and UI gates are
closed.

Workbench reports keep three identities separate. The plugin id is stable across releases. A
`tsr1_` release id is SHA-256 over length-prefixed plugin id, version, platform, and executable
digest, so Rust and Go derive the same immutable value without ambiguous string concatenation.
Every actual subprocess start receives a fresh 128-bit `tsa1_` activation-attempt id from the
operating-system random source. Activation ids correlate diagnostics only and never grant trust.
Deterministic package reports omit random activation ids; catalogs verify and preserve release ids.
The shared vectors in `conformance/identity-v1.cases.json` prevent host and SDK drift.
For additive v1 compatibility, catalog assembly derives the release id for an older package report
that does not contain one, but rejects any supplied value that conflicts with the immutable inputs.

The checked-in release workflow packages Ponytails and the DeepSeek Harness Output Optimizer
on native Windows x64/arm64, Linux x64/arm64, and macOS x64/arm64 runners before separate
catalog assembly. Ponytails manifest's Windows and Linux x86 entries remain compatibility
targets, but CI does not publish them as Level 1 catalog artifacts until native x86 validation
runners are available.

Build Ponytails with `cargo build -p ponytails --release`. Its manifest is at
`examples/ponytails/plugin.json`. Copy the built binary into the manifest's current-platform
`bin/<platform>/` entry before running the checked-in example directly, or point a temporary
development manifest at the built executable as the real-process integration test does.

Ponytails is the community/reference example. TokenSaver also supports built-in
plugins shipped with the product. Built-in plugin implementations remain in the private
TokenSaver product repository and are not exported through this public SDK repository.
Source is assigned by TokenSaver's trusted install path and is not declared by a plugin manifest. Both sources use the same TSPP
safety and output verification; community distribution additionally requires
OS-enforced process confinement before release.

`examples/deepseek-harness` is a second community example based on the public DeepSeek
Harness development workflow. It narrowly recognizes Harness output, preserves summaries
and diagnostic context, and passes unrelated package-manager output unchanged. It includes
real-process validation, deterministic benchmarking and packaging, SUPEREC, OKF, and the
same six-platform release and provenance controls as Ponytails. It is a VIC-E community
integration and is not affiliated with or endorsed by DeepSeek.

## Versioning and extension contract

TSPP `apiVersion` is a major compatibility boundary. V1 readers accept unknown additive JSON
fields, while the initialize handshake rejects another major version. Private experiments use
an `extensions` object with reverse-DNS owner keys. Existing fields, method meanings, and
safety rules never change within v1. The plugin release version remains a separate semver and
must match the compiled initialize identity.

Manifest, fixture, run-report, test-report, validation-report, benchmark-report, package-report,
package-catalog, catalog-report, and certification-report
documents have independent versioned schemas. `system.superec` and each
optional `plugin.superec` use the authoritative VIC-E SUPEREC 0.1.0 workspace schema. The
TokenSaver-specific `com.vic-e.tokensaver/plugin` extension has its own additive v1 profile
schema. SUPEREC is portable, sealed evidence, never an activation or provenance authority.
Use the VIC-E `superec validate` command for full standard conformance; `tsp validate` also
checks the sealed digest and the TokenSaver plugin profile.

The canonical v1 manifest schema is
`schemas/plugin-manifest.v1.json`. Runtime acceptance remains authoritative in
TokenSaver's exported Go `ValidatePluginManifest` function; schema and host
contract tests must evolve together.
