# TokenSaver trusted certification worker

This non-published crate orchestrates exact TSPP/1 protocol-fuzz campaigns for trusted
certification infrastructure. It parses the versioned corpus and policy, validates immutable
executable identity, drives a separately hardened executor in deterministic order, recomputes every
counter, and sends the generated report through the independent `tsp-workbench` evaluator.

The corpus contract is `schemas/certification-fuzz-corpus.v1.json`. It fixes:

- canonical sorted valid and malformed cases with exact base64 wire bytes;
- deterministic repetitions;
- per-execution deadline, memory, stdout, and stderr limits;
- the sanitizers that must remain active for the complete campaign.

Implement `CertificationFuzzExecutor` with a platform-specific sandbox. Every call must start a
fresh process, apply the supplied resource limits, collect instrumentation, kill on deadline, drain
only bounded output, and reap the process before returning. The worker stops the campaign
immediately if an executor reports an unreaped process.

The worker distinguishes infrastructure failures from plugin findings. Executor or coverage errors
produce one bounded generic error and no evidence. Plugin crashes, hangs, sanitizer findings,
resource violations, protocol violations, incomplete dispositions, and campaign deadline exhaustion
produce truthful failed evidence that the independent evaluator refuses to certify.

This crate does not provide a permissive local-process fallback. A production Windows, Linux, or
macOS confinement backend must be explicitly supplied by trusted CI. The worker cannot issue a
certificate, sign evidence, assign provenance, install, enable, or activate a plugin.
