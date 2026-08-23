---
type: How-to
title: TokenSaver plugin workbench workflow
description: Repeatable workflow for people and AI agents creating and verifying plugins.
tags: [tokensaver, tsp, testing, conformance]
---

# TokenSaver plugin workbench workflow

Create a Rust, Go, Python, or TypeScript plugin with
`tsp new <directory> --lang rust|go|python|typescript --id <reverse-dns-id>`. The command
never overwrites a non-empty directory and generates a safe pass-through optimizer, manifest,
CI, golden fixture, sealed VIC-E SUPEREC 0.1.0 graph, OKF wiki, and AI instructions.

Rust and Go build directly with their native toolchains. Python scaffolds pin PyInstaller 6.22.2
and create a one-file executable. TypeScript scaffolds pin Bun 1.4.0 and compile a native
executable without package dependencies. Python, Bun, and Node are build-time tools only; a v1
manifest always points to the generated executable. Build each release on its target operating
system, then run the generated executable lifecycle test before `tsp test`.

After implementing optimizer behavior:

1. Run the generated language unit tests and native executable build.
2. Run `tsp run <fixture> --plugin .` to inspect the before and after output and savings.
3. Run `tsp test .` for deterministic, exact-output golden fixtures.
4. Run `tsp bench .` for golden-verified weighted savings and latency percentiles.
5. Run `tsp validate .` for manifest, process, protocol, deadline, and safety conformance.
6. Run `tsp package .` to create a deterministic, digest-sealed single-platform `.tsplug`.
7. In trusted release CI, place native package reports beside their archives and run
   `tsp catalog dist --output catalog.json` to seal the multi-platform release inventory.

Every command supports `--json` for stable automation. A successful command exits 0, a test
or validation failure exits 1, and invalid command use exits 2.

Packaging reruns Level 1 conformance, refuses symlinks and existing output, normalizes archive
metadata, and includes package-owned SUPEREC and OKF evidence. It never installs or activates a
plugin. Built-in or community provenance remains host-assigned outside the package manifest.
Catalog assembly verifies immutable archive identity and native package reports. It has the
same no-install and no-activation boundary.

Level 1 is the only certification level a local validation or package report can claim. The
versioned `schemas/certification-report.v1.json` contract models cumulative Levels 1 through 3,
immutable package identity, evidence digests, issuer policy, and revocation identity. Higher
levels require a trusted certification pipeline. Catalog assembly rejects an edited package
report that promotes itself above Level 1.

Trusted CI can use versioned stage-evidence, benchmark-policy, and protocol-fuzz contracts to
assemble a Level 2 or Level 3 report. The assembler hashes exact evidence bytes and enforces
immutable artifact, package, reproducible-build, SBOM, and manifest handoffs. The public-corpus
evaluator recomputes benchmark accounting and thresholds instead of trusting an asserted pass. The
protocol-fuzz evaluator independently binds exact executable, corpus, policy, and report bytes,
checks all execution counters and thresholds, and requires zero process or protocol safety failures.
The reproducible-build evaluator binds the package, immutable source, exact policy, runner report,
and two output byte streams, then requires independent network-isolated builds and byte-identical
packages. The signed-artifact evaluator verifies a detached signature over the immutable executable
identity using a separate caller-provisioned policy and trust store. Trusted CI must still perform
the actual fuzz executions, clean-room builds, and artifact signing. Level 3 SBOM and license
evaluators bind an exact CycloneDX 1.6 document to the package, recompute component completeness,
and apply a versioned SPDX allow and deny policy without trusting report counters. Trusted CI still
generates and attests the SBOM and performs the legal review. The admin metadata evaluator verifies
an exact privacy-safe projection of the validated manifest, including limits, capability and runtime
inventories, counts, and complete integrity coverage. It does not apply enterprise policy; the host
must evaluate that metadata under a separately authenticated policy.
Assembly produces an unsigned report only; trusted envelope signing, authenticated retrieval,
revocation, and durable rollback checks remain separate mandatory decisions.
Trusted issuer automation can pass that report to the purpose-aware
`CertificationSigningProvider` boundary. The SDK validates issuer inputs and creates exact
domain-separated certification or revocation messages, while an external HSM or signing service
retains private keys and returns only the signature. Certification and revocation use separate
key ids. Issued documents still require the real verifier, authenticated distribution, and durable
rollback checks. Issuance grants no provenance, installation, enablement, or activation authority.
Production retrieval is implemented in the separate non-published
`tools/tsp-certification-host` crate. This preserves the SDK's no-network boundary while providing
fixed immutable HTTPS paths, no ambient proxy or credential use, no redirects or decompression,
strict JSON responses, verifier-sized streaming limits, and one total deadline. The connector is
only a source for the existing verify-and-record transaction; a successful download is never an
acceptance decision.

The non-published `tools/tsp-certification-worker` crate turns an exact versioned protocol-fuzz
corpus into independently evaluated stage evidence. Its corpus fixes sorted wire cases,
repetitions, resource limits, and required sanitizers. The worker recomputes counters and never
accepts executor-provided aggregates. A trusted platform backend still owns OS confinement,
instrumentation, deadline kill, bounded output collection, and process reap. There is no
unsandboxed fallback, and the worker cannot certify or activate a plugin.

`tools/tsp-certification-confinement` is the separate native-driver adapter. It pins one immutable
sandbox-policy digest and canonical platform control profile, verifies it before every execution,
binds each observation to a deterministic attempt id, rejects backend or subject drift, and maps
native findings without trusting aggregate counters. A protocol oracle classifies TSPP output but
cannot launch a process. The operating-system drivers are still required and must fail closed when
any named control is unavailable.

## Report identity

Every report names the stable plugin id and immutable release id. The release id uses a
length-prefixed SHA-256 contract over plugin id, version, platform, and executable digest. Shared
Go and Rust golden vectors prevent cross-language drift. Run and golden-test cases record one
fresh activation-attempt id per spawned process; benchmark cases record the bounded list of ids
for their samples; validation checks record ids only for checks that actually launch a process.

Package reports must remain reproducible, so they contain the deterministic release id and no
random activation id. Catalog assembly recomputes the release id before copying it. Neither type
of id grants permissions, provenance, certification, installation, enablement, or activation.
