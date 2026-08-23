# TokenSaver Windows certification confinement driver

This non-published trusted-infrastructure crate launches each fuzz case in a capability-free
AppContainer and assigns its suspended process to a new Job Object before the first plugin
instruction can run. The Job Object allows one active process, enforces the per-process memory
limit, blocks breakaway, applies the complete cross-version `0xff` UI restriction set, kills on
close, and terminates the complete job on deadline. A private completion port records the
authoritative process-memory-limit notification instead of inferring it from an exit code.

The driver never inherits the TokenSaver process environment. Callers provide a canonical minimal
allowlist containing `SYSTEMROOT`, `SYSTEMDRIVE`, a synthetic sandbox-local `LOCALAPPDATA`, and
optional sandbox temp and sanitizer/coverage variables. The real user profile is never inherited.
`LOCALAPPDATA` is required by Windows when creating this AppContainer process and points only to
the ephemeral writable evidence directory. The exact executable is rehashed before every
execution. The AppContainer SID is checked against the machine loopback-exemption list before
every launch. Any missing API, denied job assignment,
profile drift, loopback exemption, digest mismatch, pipe failure, termination failure, or reap
failure fails closed. There is no ordinary-process retry.

Trusted CI must provision an AppContainer-readable immutable executable and working directory. Do
not grant the AppContainer access to a user profile, repository, credentials, network capability,
or writable host directory. A private ephemeral directory may be granted only for sanitizer and
coverage output and must be destroyed by the CI host after evidence collection.

The safe adapter uses injected kernel and coverage-reader contracts so policy, failure, drift,
stream, artifact, concurrency, and coverage behavior can be tested without weakening the native
boundary. Native calls are isolated in `windows_driver/win32.rs` and use bounded generic errors.

Process creation uses an explicit inherited-handle list containing only stdin, stdout, and stderr.
The executable is rehashed before every execution, and the AppContainer SID is rechecked against
the machine loopback-exemption list immediately before launch.

The production driver does not create or delete AppContainer profiles, modify ACLs, change loopback
exemptions, issue certification, sign, install, enable, activate, assign provenance, or expose
plugin UI. Profile and ACL provisioning belongs to trusted infrastructure; the integration test
uses only an ephemeral self-cleaning profile to prove that contract.

## Native integration proof

The ignored Windows test creates a unique capability-free AppContainer profile, grants its exact
SID access only to ephemeral executable and working directories, and removes the profile and those
directories afterward. It proves exact I/O, filesystem and loopback denial, child-process denial,
runtime threads, scrubbed environment, writable evidence, both stream limits, deadline kill,
crash classification, completion-port-backed memory-limit attribution, eight concurrent runs, and
verified Job Object reap. The release workflow runs this proof on `windows-2025`; packaging cannot
start unless it passes.
