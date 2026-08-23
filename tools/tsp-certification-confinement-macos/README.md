# TokenSaver macOS certification confinement driver

This non-published trusted-infrastructure crate owns the macOS native protocol-fuzz boundary. It
does not certify, sign, install, activate, assign provenance, or expose plugins.

The safe adapter binds the exact plugin, trusted launcher, deny-by-default sandbox profile,
minimal environment, sanitizer engine, writable evidence directory, and all hard limits into an
immutable policy digest. Both executables are rehashed before every operation.

The native backend requires Apple's root-owned `sandbox-exec`, Apple's system runtime sandbox base
followed by an explicit TokenSaver file-read reset, executable-directory denials, and pinned
executable and Apple runtime allowlists, a private 0700 evidence directory, immutable executables,
a dedicated process group, a native physical-footprint watchdog, hard process/file
limits, bounded nonblocking streams, deadline and overflow group termination, `wait4` memory
accounting, direct-child reap, and proof that the process group is empty. Network and fork
operations remain explicitly denied by the TokenSaver profile. Importing Apple's baseline cannot
grant reads beside the pinned plugin or launcher because TokenSaver resets that operation class,
denies both containing directories, and then reopens only the exact executables and required Apple
runtime trees. The trusted parent samples
`proc_pid_rusage` with a bounded safety margin and kills the complete process group before the
configured memory ceiling. The launcher applies process-count, descriptor, and core limits before
executing the plugin. There is no unconstrained-process fallback.

The trusted launcher exists because resource limits must be installed after the sandbox is active
and before the plugin executable starts. CI must build and pin this launcher separately for macOS
x64 and arm64, then run the ignored native integration suite on each architecture before release.

Certification subjects use the package platform keys `darwin-x64` and `darwin-arm64`. Adapter tests
reject the obsolete `macos-*` spelling, malformed attempts and limits, artifact or policy drift,
forged stream bounds, unreaped observations, private kernel failures, and sanitizer findings. The
native integration covers exact I/O, denial of a real private sibling file, network/fork denial,
runtime threads, writable evidence, both stream limits, deadline kill, crash and memory behavior,
eight concurrent runs, and verified reap.
