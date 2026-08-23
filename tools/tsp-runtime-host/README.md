# TokenSaver trusted plugin runtime host

This non-published binary is the product-owned bridge between the Go plugin platform and the
platform-native confinement kernels. It is not a plugin, an SDK runtime, or an optimizer. It has no
ordinary-process fallback.

The machine-readable contracts are
[`runtime-host-request.v1.json`](../../schemas/runtime-host-request.v1.json) and
[`runtime-host-response.v1.json`](../../schemas/runtime-host-response.v1.json). The Rust parser and
Go caller remain the enforcement authorities; schemas exist for review, tooling, and AI-assisted
maintenance.

Release artifact directories use the separately versioned
[`runtime-host-assets.v1.json`](../../schemas/runtime-host-assets.v1.json) manifest. It binds the
exact native platform, host filename, and SHA-256 digest, plus the required macOS limit launcher.
Host-owned writable and Linux cgroup provisioning paths are deliberately excluded.
`scripts/verify_runtime_host_assets.py` rejects shortened checksum inventories, extra files,
ambiguous manifests, platform drift, and file-digest drift before artifacts are uploaded.

For each invocation the host:

1. reads exactly one bounded versioned JSON request;
2. rejects unknown and duplicate request fields;
3. canonicalizes the release, executable, and private work paths;
4. recomputes the exact package and executable SHA-256 identities;
5. applies the native Windows AppContainer and Job Object, Linux namespace, Landlock, seccomp and
   cgroup v2, or macOS sandbox and resource-limit kernel;
6. forwards the exact TSPP arguments and preframed input with `TOKENSAVER_PLUGIN=1` in the minimal
   plugin environment;
7. returns one bounded observation with host-measured duration, memory, termination, stream-limit,
   and reap evidence.

Windows derives a distinct capability-free AppContainer identity from the protocol domain,
plugin ID, and immutable release ID using length-prefixed UTF-8 fields. Retained releases of one
plugin therefore never share an AppContainer SID or accumulated filesystem ACLs. Deprovisioning
uses that same release-scoped identity.

The Go caller independently pins and rehashes this host before every execution. On macOS it also
pins and rehashes the separate resource-limit launcher. The host response is revalidated against
the original execution by the TokenSaver product lifecycle boundary.

`cargo test --locked -p tokensaver-plugin-runtime-host` runs portable protocol and identity tests.
The ignored `native_runtime` test requires the real platform kernel. It executes two retained
releases of the same plugin and proves one release cannot read a secret from its sibling, in
addition to checking exact arguments, I/O, reaping, and idempotent deprovisioning. The release
workflow provisions that environment and runs the ignored proof on Windows, Linux, and both macOS
architectures.

Each native job then runs the opt-in Go product integration, which verifies package installation,
activation, optimization, disable deprovisioning, removal, and registry cleanup through this host.

Production activation remains separately gated. Building this binary never enables plugins.
