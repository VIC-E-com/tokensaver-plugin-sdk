# TokenSaver Linux certification confinement driver

This non-published trusted-infrastructure crate owns the Linux native protocol-fuzz boundary.
It is not part of the public plugin SDK and it has no certification, signing, installation,
activation, provenance, or product-UI authority.

The production driver requires all of these controls at once:

- fresh user, mount, network, and PID namespaces created with `clone3`
- direct placement into a dedicated cgroup v2 leaf before the child can run
- hard memory, zero-swap, OOM-group, and process-count limits
- a private tmpfs root with immutable executable and runtime-library mounts
- one private writable evidence mount with execution disabled
- a deny-by-default Landlock filesystem policy
- an architecture-checked seccomp filter that denies networking and process creation while
  allowing runtime threads
- bounded nonblocking stdin, stdout, and stderr handling
- pidfd deadline and exit observation
- complete cgroup termination, direct-child reap, memory accounting, and leaf cleanup

Every operation rechecks the native prerequisites and rehashes the exact executable. Any missing
kernel feature, artifact drift, setup failure, output overflow, deadline, cleanup failure, or
unreaped process fails closed. There is no ordinary-process retry.

## Native integration test

The ignored integration test requires a modern kernel and a delegated cgroup hierarchy. Linux
applies its cgroup migration permission check at the common ancestor of the caller's current
cgroup and the `CLONE_INTO_CGROUP` destination. Therefore the test runner must execute in a
sibling cgroup, and the delegated sandbox parent must expose enabled `memory` and `pids`
controllers. Delegating only the destination directory is insufficient.

The test covers exact I/O, filesystem and network denial, writable evidence, fork denial, thread
allowance, stdout and stderr overflow, deadline termination, crash classification, memory
exhaustion, cgroup accounting, verified reap, eight concurrent executions, and resource cleanup.
Its WSL2 command and verified environment are recorded in
`.doc/plugin-platform-implementation-status.md`.

The checked-in release workflow creates sibling `runner` and `sandboxes` cgroups, enables `memory`
and `pids` on the root, common ancestor, and sandbox parent, moves the test runner into `runner`, and
executes the ignored native suite as the unprivileged build user. Packaging cannot start unless this
proof succeeds.
