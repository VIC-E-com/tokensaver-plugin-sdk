---
type: Reference
title: TokenSaver plugin certification
description: Versioned certification levels, evidence, revocation, and trust boundaries.
tags: [tokensaver, plugin, certification, compliance]
---

# TokenSaver plugin certification

Certification is a registry and enterprise compliance decision about one exact package. It is
not a claim a plugin can make about itself. The subject identity includes the plugin id, release
version, platform, TSPP major, and package SHA-256 digest. Changing any one of those values
requires a new assessment.

## Levels

| Level | Name | Required evidence |
|---|---|---|
| 1 | Conformant | Host-equivalent manifest validation, TSPP lifecycle, and safety contract |
| 2 | Certified | Every Level 1 check, public-corpus thresholds, protocol fuzzing, reproducible build verification, and a verified artifact signature |
| 3 | Enterprise Certified | Every Level 2 check, SBOM, license and provenance review, and admin policy metadata |

Requirements are cumulative. A Level 3 report contains all ten named checks, not only the three
checks added at Level 3. Every check records a stable rule id, pass state, SHA-256 evidence digest,
plain-language detail, and actionable remediation. The canonical machine contract is
`schemas/certification-report.v1.json`.

The same report shape represents failed assessments. A failed report preserves every required
check and identifies the exact failed rule and remediation, but validation refuses to accept it
as certification evidence.

## Pipeline evidence

`schemas/certification-stage-evidence.v1.json` defines one bounded, exact-byte evidence document
for every cumulative requirement. Each document binds the immutable subject, stable rule,
producer version and environment digest, bounded execution time, pass state, canonical named
inputs and outputs, plain-language detail, and remediation. Unknown security fields, duplicate
JSON members, oversized documents, missing stages, duplicate stages, and noncanonical ordering are
rejected. The report records SHA-256 over each exact stage document, including its original JSON
bytes.

`assemble_certification_report` verifies all subject and cross-stage bindings before producing an
unsigned report. Level 2 requires the lifecycle, safety, and fuzz stages to name the exact subject
executable; benchmark and SBOM stages name the exact package; both independent reproducible-build
outputs must equal the subject package digest; and artifact-signature evidence names the exact
executable. Level 3 additionally requires license review to consume the generated SBOM and admin
metadata to consume the manifest that passed validation. A failed stage creates a truthful failed
report that cannot pass certification validation.

The public-corpus stage is not a self-asserted pass. `evaluate_public_corpus_benchmark` parses the
exact benchmark report and `schemas/certification-benchmark-policy.v1.json`, recomputes all case and
total byte accounting, validates activation ids and latency ordering, enforces host pass/optimize
safety rules, calculates weighted savings in integer basis points, applies minimum corpus, sample,
input, and savings thresholds plus maximum p95 latency, and binds both exact documents by digest.
The trusted issuer chooses and versions the policy.

The protocol-fuzz stage is independently evaluated too. `evaluate_protocol_fuzzing` consumes the
exact executable, protocol corpus, `schemas/certification-fuzz-policy.v1.json`, and
`schemas/certification-fuzz-report.v1.json` bytes. It recomputes their SHA-256 bindings, requires
exact TSPP/1 and immutable subject identity, validates execution and input-class accounting, and
applies the versioned execution, valid-input, malformed-input, coverage, and duration thresholds.
Passing requires every valid input to be accepted, every malformed input to be rejected, and zero
crashes, hangs, sanitizer failures, memory-limit violations, stdout protocol violations,
stderr-limit violations, deadline violations, or unreaped processes. Unknown security fields,
duplicate JSON members, oversized documents, inconsistent timing, and impossible counters are
rejected. A trusted CI fuzz runner must still generate the raw report under real process and
sanitizer confinement.

The reproducible-build stage is independently evaluated by `evaluate_reproducible_build`. It
consumes the exact subject package, immutable source archive, two rebuilt packages,
`schemas/certification-reproducible-build-policy.v1.json`, and
`schemas/certification-reproducible-build-report.v1.json`. The evaluator recomputes every digest,
binds both ordered build attempts to their actual outputs, requires distinct attempt and environment
identities, and applies successful-exit, zero-network, declared-input, per-build, and total-duration
rules. Passing requires both rebuilt package byte streams to equal the subject package exactly. A
well-formed mismatch is retained as failed evidence so an assessment remains auditable, while
malformed evidence fails closed. The evaluator never executes a build, accesses the network, signs
evidence, certifies a package, installs a plugin, or activates one. Trusted CI must perform the two
clean-room builds.

### Trusted protocol-fuzz worker

`schemas/certification-fuzz-corpus.v1.json` makes the previously opaque corpus bytes independently
checkable. It binds canonical sorted valid and malformed wire cases, deterministic repetitions,
per-execution deadline, memory, stdout and stderr limits, and sorted required sanitizers. The
evaluator rejects ambiguous, oversized, unsorted, duplicate, noncanonical-base64, single-class, or
impossible policy/corpus plans. Reports cannot claim more valid, malformed, or total executions than
the exact corpus permits, and every required sanitizer must appear in the engine's canonical active
set.

The non-published `tools/tsp-certification-worker` crate validates the subject and exact executable
before execution, drives the corpus in deterministic repetition and case order, recomputes every
counter, and immediately evaluates the generated report through `evaluate_protocol_fuzzing`.
Campaign time remaining narrows each execution deadline. Executor or coverage infrastructure errors
are bounded and produce no evidence. Crashes, hangs, sanitizer findings, memory or stream violations,
protocol failures, incomplete dispositions, deadline exhaustion, and unreaped processes become
truthful failed evidence. An unreaped process stops the campaign immediately.

The worker deliberately does not include an ordinary process fallback. Trusted CI must implement
`CertificationFuzzExecutor` with a fresh OS-confined, sanitizer-instrumented process for every case,
apply every supplied limit, kill on deadline, drain bounded output, and reap before returning. The
The non-published `tools/tsp-certification-confinement` crate now supplies the fail-closed adapter
for those drivers. It requires an immutable policy digest and the exact v1 control set for Windows,
Linux, or macOS, revalidates the profile before each operation, rejects cross-platform execution and
observation drift, and derives crash, deadline, memory, stream, sanitizer, protocol, and reap
findings from bounded native observations. The separate Windows driver implements capability-free
AppContainer launch, loopback-exemption refusal, suspended creation, pre-resume Job Object
assignment, exact inherited handles, bounded streams, full-job deadline termination, and verified
reap. Separate native crates now implement Linux namespace/seccomp/Landlock/cgroup v2 confinement
and macOS deny-by-default sandbox, process-group, resource-limit, bounded-stream, deadline, and reap
confinement. The release workflow provisions and runs the real Linux proof and both macOS
architectures. A provisioned instrumented Windows execution and complete hosted campaign evidence
remain trusted production work.

The signed-artifact stage is cryptographically evaluated by `evaluate_signed_artifact`. It consumes
the exact executable, `schemas/certification-artifact-signature.v1.json`,
`schemas/certification-artifact-signature-policy.v1.json`, and an independently provisioned
`schemas/certification-artifact-trust-store.v1.json`. The detached Ed25519 signature binds the
plugin id, release version, platform, TSPP major, executable digest, and deterministic release id.
The evaluator rejects malformed or ambiguous documents, duplicate or weak keys, noncanonical
base64, subject drift, and oversized evidence. An untrusted signer, invalid cryptographic
signature, expired or premature signature, insufficient remaining validity, or signer-key lifetime
mismatch produces truthful failed stage evidence that cannot certify the package.

The artifact trust store is an explicit caller input delivered through an authenticated policy
channel. It is never discovered in plugin, package, catalog, or registry-controlled evidence. The
evaluator has no network, filesystem, signing, installation, provenance, enablement, or activation
authority. Trusted release infrastructure must protect the private signing key and produce the
detached signature.

## SBOM and license provenance

`evaluate_sbom` consumes the exact subject package, a CycloneDX 1.6 SBOM,
`schemas/certification-sbom-policy.v1.json`, and
`schemas/certification-sbom-report.v1.json`. It verifies that the SBOM application root binds the
release id, plugin id, version, and package SHA-256. It walks the complete nested component graph
with a fixed upper bound, requires unique stable `bom-ref` identities, and independently recomputes
the number of components carrying SHA-256 hashes, SPDX license ids, and valid package URLs. The
report must reproduce those counters and bind the exact policy and SBOM bytes.

`evaluate_license_provenance` consumes that same exact SBOM plus
`schemas/certification-license-policy.v1.json` and
`schemas/certification-license-provenance-report.v1.json`. It applies sorted, unique, disjoint SPDX
allow and deny lists. Every component must have an allowed SPDX id and provenance represented by
both a SHA-256 and package URL. License expressions, denied ids, ids outside the allowlist, missing
licenses, and missing provenance are counted independently. The supplied report must exactly match
the recomputed counters and observed SPDX ids.

Both evaluators reject ambiguous JSON, duplicate members, unknown report or policy fields,
oversized documents, subject drift, digest drift, duplicate component identities, invalid timing,
and impossible counters. A structurally valid SBOM with incomplete coverage or a license review
with disallowed findings returns a truthful failed stage instead of pretending the evidence was
malformed. The evaluators do not generate SBOMs, interpret legal obligations, access a network,
issue certification, install a plugin, or activate one. Trusted CI must still generate and attest
the SBOM, perform the license review, collect admin policy metadata, and issue the final signed
certification evidence.

## Admin policy metadata

`evaluate_admin_policy_metadata` consumes the exact validated `plugin.json` and
`schemas/certification-admin-policy-metadata.v1.json`. It checks manifest identity against the
immutable certification subject and recomputes a deterministic control-plane projection. The
projection contains runtime platform names, capability kinds, declared input and time limits, the
host-resolved effective time budget, permission and argument counts, and integrity-covered platform
names. It deliberately excludes runtime paths, argument values, plugin content, and credentials.

The report must match every recomputed value and bind the exact manifest digest. Complete SHA-256
integrity requires an exact digest for every non-empty runtime platform entry and requires the
subject platform digest to equal the immutable executable digest. A legacy or partially covered
manifest produces truthful failed evidence. Duplicate JSON, unknown metadata fields, oversized
documents, invalid platform identities, subject drift, artifact drift, report drift, and invalid
timing are rejected.

This stage supplies verified facts to enterprise controls. It does not interpret or apply an
organization's policy, assign built-in or community provenance, grant permissions, install, enable,
or activate a plugin. The trusted host must obtain its enterprise policy through a separately
authenticated channel and make the final allow or deny decision.

## Artifact signature message v1

Artifact signatures cover a binary message, not JSON serialization. Each byte string is encoded as
an unsigned 64-bit big-endian byte length followed by its exact UTF-8 bytes. Integers are encoded as
unsigned 64-bit big-endian values. The fields, in exact order, are:

1. byte string `TokenSaver plugin artifact signature v1` as the domain;
2. `schemaVersion` as an unsigned 64-bit integer;
3. byte strings `pluginId`, `version`, and `platform`;
4. `apiVersion` as an unsigned 64-bit integer;
5. byte strings `artifactDigest`, `releaseId`, `signerId`, and `keyId`;
6. integers `issuedAtUnix` and `expiresAtUnix`; and
7. byte string `algorithm`.

The signature field is excluded. No separator, terminator, Unicode normalization, JSON
canonicalization, or platform-native integer encoding is used.
`conformance/certification-artifact-signature-v1.cases.json` publishes a stable message length and
SHA-256 digest for cross-language implementations.

## Issuance and revocation

The report subject records the immutable release id, executable artifact digest, and package
digest. Its authority records an issuer id, certification policy id and version, and revocation
id. Structural validation proves that the report is complete and bound to the expected release
and package. It does not authenticate the issuer. A trusted install or policy path must also
verify the issuer-controlled envelope and check the revocation registry at decision time.

The SDK provides offline issuer functions for certification envelopes and revocation
publications. They accept a purpose-aware `CertificationSigningProvider` implemented by trusted
automation around an HSM or independently protected signing service. The SDK constructs the exact
domain-separated signing message and accepts only the resulting 64-byte Ed25519 signature. Private
keys never enter the SDK. Certification and revocation requests carry distinct purposes and must
be routed to separately provisioned key ids.

Before calling the provider, envelope issuance parses unambiguous bounded JSON, validates the
complete certification report, checks exact issuer identity, and validates the document lifetime.
Revocation issuance validates issuer identity, freshness window, sequence, bounds, canonical sort
order, uniqueness, and each entry. Provider failures become bounded generic errors so private HSM
diagnostics cannot enter public evidence. The emitted documents are then verified by the same
`verify_certification_evidence` path used for externally obtained evidence.

The v1 trust verifier consumes four exact byte documents: the certification report, its signed
envelope, an enterprise-provisioned issuer key store, and the issuer's signed revocation list. It
also requires the expected immutable package subject, current Unix time, and the last accepted
revocation sequence. Acceptance requires all of the following:

- the envelope binds the SHA-256 digest of the exact report bytes;
- Ed25519 signatures validate under explicitly trusted keys with separate certification and
  revocation purposes;
- each key covers the complete lifetime of the document it signs;
- the envelope is current and no longer than 366 days;
- the revocation list is current, no longer than seven days, and has not rolled back below the
  caller's last accepted sequence;
- envelope, report, and revocation issuers match exactly; and
- the report's revocation id is absent from the canonically sorted revocation entries.

The cryptographic verifier is deterministic and has no network or storage authority. The SDK adds
an `AuthenticatedCertificationSource` boundary so a host can supply authenticated report,
envelope, and revocation bytes without granting the SDK network access. The trust store is a
separate argument and can never be learned from registry evidence. A production source must use
authenticated same-origin retrieval, bounded response bodies, no ambient credentials, and no
cross-origin redirects. The non-published `tools/tsp-certification-host` crate implements this host
boundary without adding network authority to `tsp-workbench`. It uses Web PKI HTTPS, disables
ambient proxies and redirects, derives exact release/package paths, requests uncompressed JSON,
checks the effective URL, media type, status, and encoding, enforces the verifier's streaming size
limits, and applies one total deadline across all three documents. Its bounded errors never include
server bodies, URLs, or private transport diagnostics.

`CertificationRevocationStateStore` durably retains accepted sequences as immutable append-only
markers described by `schemas/certification-revocation-state.v1.json`. It hashes issuer ids into
directory names, rejects symbolic links, malformed JSON, unknown fields, unexpected entries,
oversized markers, and excessive marker counts, and serializes writers with a bounded cross-process
lock. A marker is fully written and synchronized before an atomic no-clobber link makes it visible.
Verification occurs before locking. Under the lock, an older verified sequence is rejected, an
equal sequence is idempotent, and a newer sequence is appended. A failed fetch, stale list,
malformed document, unknown security field, key mismatch, invalid signature, lock timeout,
persistence failure, or rollback is a rejection, never permission to reuse unverified
certification.

## Signing message v1

Signatures are over a binary signing message, not serialized JSON. Every byte-string field is
encoded as its byte length in unsigned 64-bit big-endian form followed by its exact UTF-8 bytes.
Every numeric field is encoded directly as unsigned 64-bit big-endian. The signature field itself
is never included. No separator, terminator, Unicode normalization, JSON canonicalization, or
platform-native integer encoding is used.

The certification-envelope message fields, in exact order, are:

1. byte string `TokenSaver certification envelope v1` as the domain;
2. `schemaVersion` as an unsigned 64-bit integer;
3. byte strings `reportDigest`, `issuerId`, and `keyId`;
4. integers `issuedAtUnix` and `expiresAtUnix`; and
5. byte string `algorithm`.

The revocation-list message fields, in exact order, are:

1. byte string `TokenSaver certification revocations v1` as the domain;
2. `schemaVersion` as an unsigned 64-bit integer;
3. byte strings `issuerId` and `keyId`;
4. integers `sequence`, `issuedAtUnix`, and `nextUpdateUnix`;
5. byte string `algorithm`;
6. the number of `revoked` entries as an unsigned 64-bit integer; and
7. for each already sorted entry, byte string `revocationId`, integer `revokedAtUnix`, then byte
   string `reason`.

`conformance/certification-trust-v1.cases.json` publishes the expected message lengths and
SHA-256 digests for both messages. Issuers and verifiers in every language must pass these vectors
before exchanging signed evidence. Public keys and signatures use canonical padded standard
base64. The report digest uses lowercase `sha256:` hexadecimal and covers the report bytes exactly,
including whitespace.

Local `tsp validate` and `tsp package` produce Level 1 evidence only. `tsp catalog` rejects an
edited package report that claims Level 2 or Level 3. Higher levels can be issued only by the
trusted certification pipeline after it verifies every external prerequisite. Until the trusted
pipeline, production HSM adapter, and authenticated distribution path are connected, no local
command claims a higher level.

Certification never assigns built-in or community provenance and never installs, enables, or
activates a plugin. Provenance and activation remain separate host-owned decisions.
