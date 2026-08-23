//! Host-owned HTTPS retrieval for TokenSaver certification evidence.
//!
//! This crate is deliberately separate from the public workbench SDK. It retrieves evidence only;
//! the workbench verifier remains the authority for signatures, subject binding, revocation, and
//! durable rollback. Retrieval never installs, enables, or activates a plugin.

#![forbid(unsafe_code)]

use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, PRAGMA,
};
use reqwest::redirect::Policy;
use std::io::Read;
use std::time::{Duration, Instant};
use tsp_workbench::{
    AuthenticatedCertificationSource, CertificationEvidenceDocuments, CertificationSubject,
    MAX_CERTIFICATION_ENVELOPE_BYTES, MAX_CERTIFICATION_REPORT_BYTES,
    MAX_CERTIFICATION_REVOCATION_BYTES, ValidationError, validate_certification_subject,
};

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_TOTAL_TIMEOUT: Duration = Duration::from_secs(60);

const USER_AGENT: &str = "TokenSaver-Certification-Host/1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationHttpsConfig {
    pub base_url: String,
    pub issuer_id: String,
    pub connect_timeout: Duration,
    pub total_timeout: Duration,
}

impl CertificationHttpsConfig {
    pub fn new(base_url: impl Into<String>, issuer_id: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            issuer_id: issuer_id.into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            total_timeout: DEFAULT_TOTAL_TIMEOUT,
        }
    }
}

#[derive(Clone)]
pub struct HttpsCertificationSource {
    core: SourceCore<ReqwestTransport>,
}

impl HttpsCertificationSource {
    /// Builds a production source with Web PKI roots and no proxy, cookie, redirect, credential,
    /// or content-decompression authority.
    pub fn new(config: CertificationHttpsConfig) -> Result<Self, ValidationError> {
        let base_url = validate_config(&config)?;
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(config.connect_timeout)
            .timeout(config.total_timeout)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|_| {
                https_error(
                    "certification.httpsClient",
                    "the authenticated certification HTTPS client could not be initialized",
                    "Restore the platform TLS runtime and retry without accepting certification evidence.",
                )
            })?;
        Ok(Self {
            core: SourceCore {
                base_url,
                issuer_id: config.issuer_id,
                total_timeout: config.total_timeout,
                transport: ReqwestTransport { client },
            },
        })
    }
}

impl AuthenticatedCertificationSource for HttpsCertificationSource {
    fn fetch(
        &self,
        expected_subject: &CertificationSubject,
    ) -> Result<CertificationEvidenceDocuments, ValidationError> {
        self.core.fetch(expected_subject)
    }
}

#[derive(Clone)]
struct SourceCore<T> {
    base_url: Url,
    issuer_id: String,
    total_timeout: Duration,
    transport: T,
}

impl<T: HttpsTransport> AuthenticatedCertificationSource for SourceCore<T> {
    fn fetch(
        &self,
        expected_subject: &CertificationSubject,
    ) -> Result<CertificationEvidenceDocuments, ValidationError> {
        validate_certification_subject(expected_subject)?;
        let started = Instant::now();
        let package = expected_subject
            .package_digest
            .strip_prefix("sha256:")
            .expect("validated certification digest");
        let release_root = self.url(&[
            "v1",
            "releases",
            &expected_subject.release_id,
            &format!("sha256-{package}"),
        ])?;
        let report = self.fetch_document(
            append_segment(&release_root, "certification-report.json")?,
            MAX_CERTIFICATION_REPORT_BYTES,
            started,
        )?;
        let envelope = self.fetch_document(
            append_segment(&release_root, "certification-envelope.json")?,
            MAX_CERTIFICATION_ENVELOPE_BYTES,
            started,
        )?;
        let revocations = self.fetch_document(
            self.url(&[
                "v1",
                "issuers",
                &self.issuer_id,
                "certification-revocations.json",
            ])?,
            MAX_CERTIFICATION_REVOCATION_BYTES,
            started,
        )?;
        Ok(CertificationEvidenceDocuments {
            report,
            envelope,
            revocations,
        })
    }
}

impl<T: HttpsTransport> SourceCore<T> {
    fn url(&self, segments: &[&str]) -> Result<Url, ValidationError> {
        let mut url = self.base_url.clone();
        let mut path = url.path_segments_mut().map_err(|_| {
            configuration_error("certification HTTPS base URL cannot contain path segments")
        })?;
        path.pop_if_empty();
        for segment in segments {
            path.push(segment);
        }
        drop(path);
        Ok(url)
    }

    fn fetch_document(
        &self,
        url: Url,
        maximum_bytes: usize,
        started: Instant,
    ) -> Result<Vec<u8>, ValidationError> {
        let timeout = self
            .total_timeout
            .checked_sub(started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(deadline_error)?;
        let response = self
            .transport
            .get(TransportRequest {
                url: url.clone(),
                timeout,
            })
            .map_err(|_| {
                https_error(
                    "certification.httpsTransport",
                    "authenticated certification evidence could not be retrieved",
                    "Retry the trusted HTTPS endpoint and reject evidence if retrieval remains unavailable.",
                )
            })?;
        if response.effective_url != url {
            return Err(https_error(
                "certification.httpsRedirect",
                "certification evidence retrieval changed its exact HTTPS URL",
                "Disable redirects and retrieve evidence from the configured same-origin endpoint.",
            ));
        }
        if response.status != 200 {
            return Err(https_error(
                "certification.httpsStatus",
                "certification evidence endpoint did not return HTTP 200",
                "Restore the immutable certification endpoint and reject unavailable evidence.",
            ));
        }
        if !response
            .content_type
            .as_deref()
            .is_some_and(is_json_content_type)
        {
            return Err(https_error(
                "certification.httpsContentType",
                "certification evidence response is not application/json",
                "Serve exact JSON evidence with the application/json media type.",
            ));
        }
        if response
            .content_encoding
            .as_deref()
            .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
        {
            return Err(https_error(
                "certification.httpsContentEncoding",
                "certification evidence response uses an unsupported content encoding",
                "Serve uncompressed bounded certification JSON with identity encoding.",
            ));
        }
        if response
            .content_length
            .is_some_and(|length| length > maximum_bytes as u64)
        {
            return Err(document_size_error());
        }
        let mut bytes = Vec::with_capacity(
            response
                .content_length
                .unwrap_or(0)
                .min(maximum_bytes as u64) as usize,
        );
        response
            .body
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                https_error(
                    "certification.httpsBody",
                    "certification evidence response body could not be read completely",
                    "Retry the trusted endpoint and reject partial certification evidence.",
                )
            })?;
        if bytes.is_empty() || bytes.len() > maximum_bytes {
            return Err(document_size_error());
        }
        Ok(bytes)
    }
}

#[derive(Clone)]
struct ReqwestTransport {
    client: Client,
}

impl HttpsTransport for ReqwestTransport {
    fn get(&self, request: TransportRequest) -> Result<TransportResponse, ()> {
        let response = self
            .client
            .get(request.url)
            .header(ACCEPT, "application/json")
            .header(ACCEPT_ENCODING, "identity")
            .header(CACHE_CONTROL, "no-cache, no-store")
            .header(PRAGMA, "no-cache")
            .timeout(request.timeout)
            .send()
            .map_err(|_| ())?;
        let effective_url = response.url().clone();
        let status = response.status().as_u16();
        let content_type = header_value(&response, CONTENT_TYPE);
        let content_encoding = header_value(&response, CONTENT_ENCODING);
        let content_length = response.content_length();
        Ok(TransportResponse {
            effective_url,
            status,
            content_type,
            content_encoding,
            content_length,
            body: Box::new(response),
        })
    }
}

fn header_value(
    response: &reqwest::blocking::Response,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    let values = response.headers().get_all(name).iter().collect::<Vec<_>>();
    match values.as_slice() {
        [] => None,
        [value] => Some(value.to_str().unwrap_or("<invalid>").to_owned()),
        _ => Some("<multiple>".to_owned()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransportRequest {
    url: Url,
    timeout: Duration,
}

struct TransportResponse {
    effective_url: Url,
    status: u16,
    content_type: Option<String>,
    content_encoding: Option<String>,
    content_length: Option<u64>,
    body: Box<dyn Read + Send>,
}

trait HttpsTransport: Send + Sync {
    fn get(&self, request: TransportRequest) -> Result<TransportResponse, ()>;
}

fn validate_config(config: &CertificationHttpsConfig) -> Result<Url, ValidationError> {
    let base_url = Url::parse(&config.base_url)
        .map_err(|_| configuration_error("certification HTTPS base URL is invalid"))?;
    if base_url.scheme() != "https"
        || base_url.cannot_be_a_base()
        || base_url.host_str().is_none()
        || !base_url.username().is_empty()
        || base_url.password().is_some()
        || base_url.query().is_some()
        || base_url.fragment().is_some()
    {
        return Err(configuration_error(
            "certification base URL must be credential-free HTTPS without query or fragment",
        ));
    }
    if !valid_issuer_id(&config.issuer_id) {
        return Err(configuration_error(
            "certification issuer id is empty, oversized, or invalid",
        ));
    }
    if config.connect_timeout.is_zero()
        || config.connect_timeout > MAX_CONNECT_TIMEOUT
        || config.total_timeout.is_zero()
        || config.total_timeout > MAX_TOTAL_TIMEOUT
        || config.connect_timeout > config.total_timeout
    {
        return Err(configuration_error(
            "certification HTTPS timeouts are invalid or unbounded",
        ));
    }
    Ok(base_url)
}

fn valid_issuer_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
}

fn append_segment(base: &Url, segment: &str) -> Result<Url, ValidationError> {
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|_| configuration_error("certification HTTPS URL cannot contain path segments"))?
        .push(segment);
    Ok(url)
}

fn is_json_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn document_size_error() -> ValidationError {
    https_error(
        "certification.httpsDocumentSize",
        "certification evidence response is empty or exceeds its verifier limit",
        "Serve one non-empty bounded document and reject oversized certification evidence.",
    )
}

fn deadline_error() -> ValidationError {
    https_error(
        "certification.httpsDeadline",
        "certification evidence retrieval exceeded its total deadline",
        "Restore the trusted endpoint and retry without accepting incomplete evidence.",
    )
}

fn configuration_error(message: &'static str) -> ValidationError {
    https_error(
        "certification.httpsConfiguration",
        message,
        "Use one administrator-provisioned credential-free HTTPS origin and bounded timeouts.",
    )
}

fn https_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> ValidationError {
    ValidationError::new(code, message, remediation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{self, Cursor};
    use std::sync::Mutex;
    use tsp_workbench::{CertificationSubject, release_id};

    struct FakeTransport {
        responses: Mutex<VecDeque<ResponseSpec>>,
        requests: Mutex<Vec<TransportRequest>>,
    }

    struct ResponseSpec {
        effective_url: Option<Url>,
        status: u16,
        content_type: Option<&'static str>,
        content_encoding: Option<&'static str>,
        content_length: Option<u64>,
        body: BodySpec,
    }

    enum BodySpec {
        Bytes(Vec<u8>),
        ReadFailure,
        TransportFailure,
    }

    impl FakeTransport {
        fn new(responses: Vec<ResponseSpec>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpsTransport for FakeTransport {
        fn get(&self, request: TransportRequest) -> Result<TransportResponse, ()> {
            self.requests
                .lock()
                .expect("requests")
                .push(request.clone());
            let response = self
                .responses
                .lock()
                .expect("responses")
                .pop_front()
                .expect("fake response");
            let body: Box<dyn Read + Send> = match response.body {
                BodySpec::Bytes(bytes) => Box::new(Cursor::new(bytes)),
                BodySpec::ReadFailure => Box::new(FailingReader),
                BodySpec::TransportFailure => return Err(()),
            };
            Ok(TransportResponse {
                effective_url: response.effective_url.unwrap_or(request.url),
                status: response.status,
                content_type: response.content_type.map(str::to_owned),
                content_encoding: response.content_encoding.map(str::to_owned),
                content_length: response.content_length,
                body,
            })
        }
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("private read failure"))
        }
    }

    fn subject() -> CertificationSubject {
        let artifact_digest = format!("sha256:{}", "a".repeat(64));
        CertificationSubject {
            plugin_id: "com.example.plugin".into(),
            version: "1.2.3".into(),
            platform: "linux-x64".into(),
            api_version: 1,
            release_id: release_id("com.example.plugin", "1.2.3", "linux-x64", &artifact_digest),
            artifact_digest,
            package_digest: format!("sha256:{}", "b".repeat(64)),
        }
    }

    fn response(body: &[u8]) -> ResponseSpec {
        ResponseSpec {
            effective_url: None,
            status: 200,
            content_type: Some("application/json; charset=utf-8"),
            content_encoding: None,
            content_length: Some(body.len() as u64),
            body: BodySpec::Bytes(body.to_vec()),
        }
    }

    fn core(responses: Vec<ResponseSpec>) -> SourceCore<FakeTransport> {
        SourceCore {
            base_url: Url::parse("https://plugins.tokensaver.app/certification/")
                .expect("base URL"),
            issuer_id: "com.tokensaver.registry".into(),
            total_timeout: Duration::from_secs(1),
            transport: FakeTransport::new(responses),
        }
    }

    #[test]
    fn immutable_same_origin_paths_fetch_exact_bounded_documents() {
        let source = core(vec![
            response(b"report"),
            response(b"envelope"),
            response(b"revocations"),
        ]);
        let documents = source.fetch(&subject()).expect("HTTPS evidence");
        assert_eq!(documents.report, b"report");
        assert_eq!(documents.envelope, b"envelope");
        assert_eq!(documents.revocations, b"revocations");

        let requests = source.transport.requests.into_inner().expect("requests");
        assert_eq!(requests.len(), 3);
        let release = &subject().release_id;
        let package = "b".repeat(64);
        assert_eq!(
            requests[0].url.as_str(),
            format!(
                "https://plugins.tokensaver.app/certification/v1/releases/{release}/sha256-{package}/certification-report.json"
            )
        );
        assert_eq!(
            requests[1].url.as_str(),
            format!(
                "https://plugins.tokensaver.app/certification/v1/releases/{release}/sha256-{package}/certification-envelope.json"
            )
        );
        assert_eq!(
            requests[2].url.as_str(),
            "https://plugins.tokensaver.app/certification/v1/issuers/com.tokensaver.registry/certification-revocations.json"
        );
        assert!(
            requests
                .iter()
                .all(|request| request.timeout <= Duration::from_secs(1))
        );
    }

    #[test]
    fn configuration_rejects_non_https_credentials_fragments_and_unbounded_timeouts() {
        for base_url in [
            "http://plugins.tokensaver.app/",
            "https://user@plugins.tokensaver.app/",
            "https://plugins.tokensaver.app/?channel=prod",
            "https://plugins.tokensaver.app/#fragment",
            "not a URL",
        ] {
            let error = validate_config(&CertificationHttpsConfig::new(
                base_url,
                "com.tokensaver.registry",
            ))
            .expect_err("invalid base URL");
            assert_eq!(error.code, "certification.httpsConfiguration");
        }

        let mut invalid = CertificationHttpsConfig::new(
            "https://plugins.tokensaver.app/",
            "com.tokensaver.registry",
        );
        invalid.connect_timeout = Duration::ZERO;
        assert!(validate_config(&invalid).is_err());
        invalid.connect_timeout = DEFAULT_CONNECT_TIMEOUT;
        invalid.total_timeout = Duration::from_secs(61);
        assert!(validate_config(&invalid).is_err());
        invalid.total_timeout = Duration::from_secs(1);
        assert!(validate_config(&invalid).is_err());
        invalid.total_timeout = DEFAULT_TOTAL_TIMEOUT;
        invalid.issuer_id.clear();
        assert!(validate_config(&invalid).is_err());
    }

    #[test]
    fn redirect_status_media_encoding_length_stream_and_read_failures_are_rejected() {
        let cases = [
            ResponseSpec {
                effective_url: Some(
                    Url::parse("https://other.example/report.json").expect("redirect URL"),
                ),
                ..response(b"report")
            },
            ResponseSpec {
                status: 302,
                ..response(b"report")
            },
            ResponseSpec {
                content_type: Some("text/html"),
                ..response(b"report")
            },
            ResponseSpec {
                content_encoding: Some("gzip"),
                ..response(b"report")
            },
            ResponseSpec {
                content_length: Some(MAX_CERTIFICATION_REPORT_BYTES as u64 + 1),
                ..response(b"report")
            },
            ResponseSpec {
                content_length: None,
                body: BodySpec::Bytes(vec![b'x'; MAX_CERTIFICATION_REPORT_BYTES + 1]),
                ..response(b"report")
            },
            ResponseSpec {
                content_length: None,
                body: BodySpec::ReadFailure,
                ..response(b"report")
            },
            ResponseSpec {
                content_length: None,
                body: BodySpec::TransportFailure,
                ..response(b"report")
            },
        ];
        let expected_codes = [
            "certification.httpsRedirect",
            "certification.httpsStatus",
            "certification.httpsContentType",
            "certification.httpsContentEncoding",
            "certification.httpsDocumentSize",
            "certification.httpsDocumentSize",
            "certification.httpsBody",
            "certification.httpsTransport",
        ];
        for (case, expected_code) in cases.into_iter().zip(expected_codes) {
            let error = core(vec![case])
                .fetch(&subject())
                .expect_err("unsafe HTTPS response");
            assert_eq!(error.code, expected_code);
            assert!(!error.message.contains("private read failure"));
        }
    }

    #[test]
    fn invalid_subject_fails_before_network_access() {
        let source = core(Vec::new());
        let mut invalid = subject();
        invalid.release_id = format!("tsr1_{}", "f".repeat(64));
        assert_eq!(
            source.fetch(&invalid).expect_err("subject drift").code,
            "certification.subjectContract"
        );
        assert!(
            source
                .transport
                .requests
                .into_inner()
                .expect("requests")
                .is_empty()
        );
    }

    #[test]
    fn source_is_thread_safe() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HttpsCertificationSource>();
        HttpsCertificationSource::new(CertificationHttpsConfig::new(
            "https://plugins.tokensaver.app/certification/",
            "com.tokensaver.registry",
        ))
        .expect("production rustls client");
    }
}
