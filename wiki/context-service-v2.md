# TSPP v2 context-service profile

The Rust SDK exposes `tokensaver_plugin::context::{ContextService, serve}`.
This is a separate major protocol with `apiVersion: 2` and
`profile: "context-service.v1"`. It does not change v1 optimizer meanings.
Initialize must negotiate both values. Subsequent context.* requests use
Content-Length JSON-RPC framing (1 MiB frames, 8 KiB headers). Shutdown ends
the worker. The caller must bound wall time, memory, stdout and stderr, and
kill and reap the worker using the existing native confinement host.

Context services receive explicit JSON data only. The manifest retains empty
permissions and has no optimizer kinds. It grants no ambient filesystem,
process, credential, or network access. Host applications supply any scoped
project operations through their own validated capability boundary.

The v1 workbench optimizer run/bench/certification commands remain v1-only.
They must not reinterpret context-service results as compressed output.
The additive v2 manifest schema is separate. Product-specific package and
lifecycle integration belongs in the host repository. No built-in optimization
implementation, heuristic, or product source is included here.
