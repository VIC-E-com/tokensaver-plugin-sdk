# TokenSaver trusted native confinement adapter

This non-published crate is the fail-closed boundary between the protocol-fuzz worker and a native
Windows, Linux, or macOS confinement driver. It does not launch an ordinary process and contains no
permissive fallback.

Every driver profile binds an immutable sandbox-policy digest, a canonical sanitizer engine, and
the complete v1 control set for its platform. The adapter checks that profile during construction
and again before every execution and coverage read. A missing, reordered, duplicated, cross-platform,
or drifted control profile is an infrastructure error and produces no certification evidence.

The required platform controls are:

- Windows: AppContainer isolation and Job Object process-tree/resource enforcement.
- Linux: mount, network, and PID namespaces plus seccomp, Landlock, and cgroup v2 enforcement.
- macOS: a deny-by-default sandbox profile plus process-group and hard resource-limit enforcement.

All platforms must also guarantee a fresh process, filesystem and network isolation, process-tree
control, hard memory and stream limits, deadline termination, and reap. The adapter independently
maps native termination and bounded observations into worker safety counters. It refuses oversized
returned streams, attempt or policy drift, inconsistent limit flags, and sanitizer-set drift.

`NativeConfinementDriver` remains trusted infrastructure. Its native implementations must apply the
named operating-system controls before plugin bytes can execute. If a required facility is missing
or denied, the driver must return an error. It must never retry with an ordinary process. The
separate protocol oracle classifies accepted and rejected TSPP/1 responses but has no process-launch
authority.

This adapter cannot certify, sign, install, enable, activate, assign provenance, or expose a plugin.
Separate native crates implement the Windows AppContainer and Job Object, Linux
namespace/seccomp/Landlock/cgroup v2, and macOS deny-by-default sandbox drivers. The release
workflow provisions a real Linux delegated-cgroup proof and runs the native macOS proof on x64 and
arm64. Provisioned instrumented Windows execution and complete hosted fuzz campaigns remain trusted
infrastructure work.
