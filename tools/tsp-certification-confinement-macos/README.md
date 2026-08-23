# TokenSaver macOS certification confinement driver

This non-published trusted-infrastructure crate owns the macOS native protocol-fuzz boundary. It
does not certify, sign, install, activate, assign provenance, or expose plugins.

The safe adapter binds the exact plugin, trusted launcher, deny-by-default sandbox profile,
minimal environment, sanitizer engine, writable evidence directory, and all hard limits into an
immutable policy digest. Both executables are rehashed before every operation.

The native backend requires Apple's root-owned `sandbox-exec`, a private 0700 evidence directory,
immutable executables, a dedicated process group, hard address-space/data/process/file limits,
bounded nonblocking streams, deadline and overflow group termination, `wait4` memory accounting,
direct-child reap, and proof that the process group is empty. Network and fork operations are
denied by the sandbox profile. There is no unconstrained-process fallback.

The trusted launcher exists because resource limits must be installed after the sandbox is active
and before the plugin executable starts. CI must build and pin this launcher separately for macOS
x64 and arm64, then run the ignored native integration suite on each architecture before release.

Certification subjects use the package platform keys `darwin-x64` and `darwin-arm64`. Adapter tests
reject the obsolete `macos-*` spelling, malformed attempts and limits, artifact or policy drift,
forged stream bounds, unreaped observations, private kernel failures, and sanitizer findings. The
native integration covers exact I/O, filesystem/network/fork denial, runtime threads, writable
evidence, both stream limits, deadline kill, crash and memory behavior, eight concurrent runs, and
verified reap.
