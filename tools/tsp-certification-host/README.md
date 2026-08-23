# TokenSaver certification host connector

This non-published host crate retrieves signed certification evidence from one
administrator-provisioned HTTPS origin. It is intentionally separate from `tsp-workbench`, so the
public SDK retains no network authority.

```rust
use tokensaver_certification_host::{CertificationHttpsConfig, HttpsCertificationSource};
use tsp_workbench::fetch_verify_and_record_certification;

let source = HttpsCertificationSource::new(CertificationHttpsConfig::new(
    "https://plugins.tokensaver.app/certification/",
    "com.tokensaver.registry",
))?;

let verified = fetch_verify_and_record_certification(
    &source,
    &enterprise_trust_store_bytes,
    &expected_subject,
    current_unix_time,
    &durable_revocation_state,
)?;
# Ok::<(), tsp_workbench::ValidationError>(())
```

The configured base path is preserved. The connector appends these percent-encoded paths:

| Evidence | Relative path |
|---|---|
| Report | `v1/releases/<releaseId>/sha256-<packageDigest>/certification-report.json` |
| Envelope | `v1/releases/<releaseId>/sha256-<packageDigest>/certification-envelope.json` |
| Revocations | `v1/issuers/<issuerId>/certification-revocations.json` |

The release id binds plugin id, version, platform, API major, and executable digest. The package
digest adds exact archive identity. The verifier independently rechecks both after retrieval.

Security properties:

- HTTPS with bundled Web PKI roots only;
- no ambient proxy, cookie, authorization, or client-certificate credentials;
- redirects disabled and exact effective URL checked;
- `Accept-Encoding: identity`, automatic decompression disabled, and encoded bodies rejected;
- only HTTP 200 and exactly one `application/json` content type accepted;
- verifier-sized streaming bounds apply even without `Content-Length`;
- one total deadline covers report, envelope, and revocation retrieval;
- server bodies, URLs, and transport diagnostics never enter returned errors.

Retrieval is not trust acceptance. Only the composed verifier authenticates signatures, exact
subject identity, freshness, revocation, and durable rollback. Neither layer assigns built-in or
community provenance, installs, enables, or activates a plugin.
