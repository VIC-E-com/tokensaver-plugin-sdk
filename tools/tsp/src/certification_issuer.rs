use crate::certification::{CertificationReport, validate_certification_report};
use crate::certification_pipeline::sha256_digest;
use crate::certification_trust::{
    CERTIFICATION_SIGNATURE_ALGORITHM, CertificationDecisionContext, CertificationEnvelope,
    CertificationRevocation, CertificationRevocationList, MAX_CERTIFICATION_REPORT_BYTES,
    certification_envelope_signing_message, revocation_list_signing_message, validate_envelope,
    validate_revocation_list_contract,
};
use crate::manifest::ValidationError;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::from_slice;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationIssuerIdentity {
    pub issuer_id: String,
    pub certification_key_id: String,
    pub revocation_key_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificationEnvelopeValidity {
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationRevocationPublication {
    pub sequence: u64,
    pub issued_at_unix: u64,
    pub next_update_unix: u64,
    pub revoked: Vec<CertificationRevocation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificationSigningPurpose {
    Certification,
    Revocation,
}

#[derive(Clone, Copy, Debug)]
pub struct CertificationSigningRequest<'a> {
    pub purpose: CertificationSigningPurpose,
    pub issuer_id: &'a str,
    pub key_id: &'a str,
    pub message: &'a [u8],
}

/// Boundary for an HSM, key service, or other independently protected Ed25519 signer.
///
/// The SDK supplies the exact domain-separated message and never receives private key material.
/// Implementations must route certification and revocation purposes to independently provisioned
/// keys. Provider error details are deliberately not copied into certification evidence.
pub trait CertificationSigningProvider: Send + Sync {
    type Error;

    fn sign(&self, request: CertificationSigningRequest<'_>) -> Result<[u8; 64], Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedCertificationEnvelope {
    pub document: CertificationEnvelope,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedCertificationRevocations {
    pub document: CertificationRevocationList,
    pub bytes: Vec<u8>,
}

/// Validate and sign an exact successful certification report without handling private keys.
pub fn issue_certification_envelope<S: CertificationSigningProvider + ?Sized>(
    report_bytes: &[u8],
    identity: &CertificationIssuerIdentity,
    validity: CertificationEnvelopeValidity,
    signer: &S,
) -> Result<IssuedCertificationEnvelope, ValidationError> {
    validate_purpose_separation(identity)?;
    let report = parse_report(report_bytes)?;
    validate_certification_report(&report, &report.subject)?;
    if report.authority.issuer_id != identity.issuer_id {
        return Err(issuer_error(
            "certification.issuerIdentity",
            "certification report authority does not match the signing issuer",
            "Issue the report and envelope under the same independently configured issuer id.",
        ));
    }

    let mut envelope = CertificationEnvelope {
        schema_version: 1,
        report_digest: sha256_digest(report_bytes),
        issuer_id: identity.issuer_id.clone(),
        key_id: identity.certification_key_id.clone(),
        issued_at_unix: validity.issued_at_unix,
        expires_at_unix: validity.expires_at_unix,
        algorithm: CERTIFICATION_SIGNATURE_ALGORITHM.into(),
        signature: String::new(),
    };
    validate_envelope(&envelope, validity.issued_at_unix)?;
    let message = certification_envelope_signing_message(&envelope);
    envelope.signature = sign_message(
        signer,
        CertificationSigningRequest {
            purpose: CertificationSigningPurpose::Certification,
            issuer_id: &identity.issuer_id,
            key_id: &identity.certification_key_id,
            message: &message,
        },
    )?;
    let bytes = serde_json::to_vec(&envelope).map_err(|_| {
        issuer_error(
            "certification.issuerSerialization",
            "certification envelope could not be serialized",
            "Retry issuance with the bounded v1 envelope contract.",
        )
    })?;
    Ok(IssuedCertificationEnvelope {
        document: envelope,
        bytes,
    })
}

/// Validate, canonically order-check, and sign a current revocation publication.
pub fn issue_certification_revocations<S: CertificationSigningProvider + ?Sized>(
    identity: &CertificationIssuerIdentity,
    publication: CertificationRevocationPublication,
    signer: &S,
) -> Result<IssuedCertificationRevocations, ValidationError> {
    validate_purpose_separation(identity)?;
    let mut document = CertificationRevocationList {
        schema_version: 1,
        issuer_id: identity.issuer_id.clone(),
        key_id: identity.revocation_key_id.clone(),
        sequence: publication.sequence,
        issued_at_unix: publication.issued_at_unix,
        next_update_unix: publication.next_update_unix,
        algorithm: CERTIFICATION_SIGNATURE_ALGORITHM.into(),
        revoked: publication.revoked,
        signature: String::new(),
    };
    validate_revocation_list_contract(
        &document,
        &identity.issuer_id,
        CertificationDecisionContext {
            now_unix: document.issued_at_unix,
            minimum_revocation_sequence: document.sequence,
        },
    )?;
    let message = revocation_list_signing_message(&document);
    document.signature = sign_message(
        signer,
        CertificationSigningRequest {
            purpose: CertificationSigningPurpose::Revocation,
            issuer_id: &identity.issuer_id,
            key_id: &identity.revocation_key_id,
            message: &message,
        },
    )?;
    let bytes = serde_json::to_vec(&document).map_err(|_| {
        issuer_error(
            "certification.issuerSerialization",
            "certification revocation list could not be serialized",
            "Retry issuance with the bounded v1 revocation contract.",
        )
    })?;
    Ok(IssuedCertificationRevocations { document, bytes })
}

fn parse_report(bytes: &[u8]) -> Result<CertificationReport, ValidationError> {
    if bytes.is_empty() || bytes.len() > MAX_CERTIFICATION_REPORT_BYTES {
        return Err(issuer_error(
            "certification.issuerReportSize",
            "certification report is empty or exceeds 1 MiB",
            "Issue one bounded certification-report.v1.json document.",
        ));
    }
    crate::superec::validate_unambiguous_json(bytes).map_err(|error| {
        issuer_error(
            "certification.issuerReportJson",
            format!("certification report is ambiguous or invalid JSON: {error}"),
            "Remove duplicate members and trailing JSON before issuer signing.",
        )
    })?;
    from_slice(bytes).map_err(|error| {
        issuer_error(
            "certification.issuerReportJson",
            format!("certification report does not match the v1 contract: {error}"),
            "Use schemas/certification-report.v1.json.",
        )
    })
}

fn sign_message<S: CertificationSigningProvider + ?Sized>(
    signer: &S,
    request: CertificationSigningRequest<'_>,
) -> Result<String, ValidationError> {
    signer
        .sign(request)
        .map(|signature| BASE64.encode(signature))
        .map_err(|_| {
            issuer_error(
                "certification.issuerSigning",
                "the protected signing provider could not sign certification evidence",
                "Keep the evidence unsigned, restore the purpose-bound signer, and retry issuance.",
            )
        })
}

fn validate_purpose_separation(
    identity: &CertificationIssuerIdentity,
) -> Result<(), ValidationError> {
    if identity.certification_key_id == identity.revocation_key_id {
        return Err(issuer_error(
            "certification.issuerKeyPurpose",
            "certification and revocation signing require distinct key ids",
            "Provision independent certification and revocation keys with different key ids.",
        ));
    }
    Ok(())
}

fn issuer_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> ValidationError {
    ValidationError::new(code, message, remediation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification::{
        CERTIFICATION_POLICY_ID, CERTIFICATION_POLICY_VERSION, CertificationAuthority,
        CertificationCheck, CertificationLevel, CertificationSubject,
    };
    use crate::certification_pipeline::certification_rule;
    use crate::certification_trust::{
        CertificationTrustStore, TrustedIssuerKey, TrustedKeyPurpose, verify_certification_evidence,
    };
    use base64::engine::general_purpose::STANDARD as BASE64;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::Mutex;

    const ISSUED: u64 = 2_000_000_000;
    const EXPIRES: u64 = ISSUED + 3_600;
    const NEXT_UPDATE: u64 = ISSUED + 1_800;

    struct TestSigner {
        certification: SigningKey,
        revocation: SigningKey,
        requests: Mutex<Vec<(CertificationSigningPurpose, String)>>,
    }

    impl CertificationSigningProvider for TestSigner {
        type Error = ();

        fn sign(&self, request: CertificationSigningRequest<'_>) -> Result<[u8; 64], Self::Error> {
            self.requests
                .lock()
                .expect("request lock")
                .push((request.purpose, request.key_id.into()));
            let key = match request.purpose {
                CertificationSigningPurpose::Certification
                    if request.key_id == "certification-2026" =>
                {
                    &self.certification
                }
                CertificationSigningPurpose::Revocation if request.key_id == "revocation-2026" => {
                    &self.revocation
                }
                _ => return Err(()),
            };
            Ok(key.sign(request.message).to_bytes())
        }
    }

    struct FailedSigner;

    impl CertificationSigningProvider for FailedSigner {
        type Error = &'static str;

        fn sign(&self, _request: CertificationSigningRequest<'_>) -> Result<[u8; 64], Self::Error> {
            Err("private HSM diagnostic must not escape")
        }
    }

    fn identity() -> CertificationIssuerIdentity {
        CertificationIssuerIdentity {
            issuer_id: "com.tokensaver.registry".into(),
            certification_key_id: "certification-2026".into(),
            revocation_key_id: "revocation-2026".into(),
        }
    }

    fn subject() -> CertificationSubject {
        let artifact_digest = sha256_digest(b"exact executable");
        let mut subject = CertificationSubject {
            plugin_id: "com.example.plugin".into(),
            version: "1.2.3".into(),
            platform: "linux-x64".into(),
            api_version: 1,
            artifact_digest,
            package_digest: sha256_digest(b"exact package"),
            release_id: String::new(),
        };
        subject.release_id = crate::identity::release_id(
            &subject.plugin_id,
            &subject.version,
            &subject.platform,
            &subject.artifact_digest,
        );
        subject
    }

    fn report() -> CertificationReport {
        let subject = subject();
        let checks = CertificationLevel::Conformant
            .requirements()
            .iter()
            .copied()
            .map(|requirement| CertificationCheck {
                requirement,
                ok: true,
                rule: certification_rule(requirement).into(),
                evidence_digest: sha256_digest(certification_rule(requirement).as_bytes()),
                detail: "exact Level 1 evidence passed".into(),
                remediation: "rerun the exact evidence for every release".into(),
            })
            .collect();
        CertificationReport {
            schema_version: 1,
            ok: true,
            certification_level: CertificationLevel::Conformant,
            subject,
            authority: CertificationAuthority {
                issuer_id: identity().issuer_id,
                policy_id: CERTIFICATION_POLICY_ID.into(),
                policy_version: CERTIFICATION_POLICY_VERSION,
                revocation_id: "cert:release:0123456789abcdef".into(),
            },
            checks,
        }
    }

    fn signer() -> TestSigner {
        TestSigner {
            certification: SigningKey::from_bytes(&[7; 32]),
            revocation: SigningKey::from_bytes(&[9; 32]),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn trust_store(signer: &TestSigner) -> CertificationTrustStore {
        CertificationTrustStore {
            schema_version: 1,
            keys: vec![
                TrustedIssuerKey {
                    issuer_id: identity().issuer_id,
                    key_id: identity().certification_key_id,
                    purpose: TrustedKeyPurpose::Certification,
                    public_key: BASE64.encode(signer.certification.verifying_key().as_bytes()),
                    not_before_unix: ISSUED - 1,
                    not_after_unix: EXPIRES + 1,
                },
                TrustedIssuerKey {
                    issuer_id: identity().issuer_id,
                    key_id: identity().revocation_key_id,
                    purpose: TrustedKeyPurpose::Revocation,
                    public_key: BASE64.encode(signer.revocation.verifying_key().as_bytes()),
                    not_before_unix: ISSUED - 1,
                    not_after_unix: NEXT_UPDATE + 1,
                },
            ],
        }
    }

    #[test]
    fn purpose_separated_issuance_round_trips_through_the_real_verifier() {
        let report = report();
        let report_bytes = serde_json::to_vec(&report).expect("report bytes");
        let signer = signer();
        let envelope = issue_certification_envelope(
            &report_bytes,
            &identity(),
            CertificationEnvelopeValidity {
                issued_at_unix: ISSUED,
                expires_at_unix: EXPIRES,
            },
            &signer,
        )
        .expect("issued envelope");
        let revocations = issue_certification_revocations(
            &identity(),
            CertificationRevocationPublication {
                sequence: 5,
                issued_at_unix: ISSUED,
                next_update_unix: NEXT_UPDATE,
                revoked: Vec::new(),
            },
            &signer,
        )
        .expect("issued revocations");
        let trust_store_bytes =
            serde_json::to_vec(&trust_store(&signer)).expect("trust store bytes");

        let verified = verify_certification_evidence(
            &report_bytes,
            &envelope.bytes,
            &trust_store_bytes,
            &revocations.bytes,
            &report.subject,
            CertificationDecisionContext {
                now_unix: ISSUED + 60,
                minimum_revocation_sequence: 5,
            },
        )
        .expect("verified issued evidence");
        assert_eq!(verified.report, report);
        assert_eq!(
            signer.requests.into_inner().expect("requests"),
            [
                (
                    CertificationSigningPurpose::Certification,
                    "certification-2026".into()
                ),
                (
                    CertificationSigningPurpose::Revocation,
                    "revocation-2026".into()
                )
            ]
        );
    }

    #[test]
    fn invalid_reports_windows_and_revocations_are_rejected_before_signing() {
        let signer = signer();
        let mut shared_key_identity = identity();
        shared_key_identity.revocation_key_id = shared_key_identity.certification_key_id.clone();
        let error = issue_certification_envelope(
            &serde_json::to_vec(&report()).expect("report bytes"),
            &shared_key_identity,
            CertificationEnvelopeValidity {
                issued_at_unix: ISSUED,
                expires_at_unix: EXPIRES,
            },
            &signer,
        )
        .expect_err("shared signing key id");
        assert_eq!(error.code, "certification.issuerKeyPurpose");

        let mut wrong_issuer = report();
        wrong_issuer.authority.issuer_id = "com.example.wrong".into();
        let error = issue_certification_envelope(
            &serde_json::to_vec(&wrong_issuer).expect("report bytes"),
            &identity(),
            CertificationEnvelopeValidity {
                issued_at_unix: ISSUED,
                expires_at_unix: EXPIRES,
            },
            &signer,
        )
        .expect_err("issuer drift");
        assert_eq!(error.code, "certification.issuerIdentity");

        let error = issue_certification_envelope(
            &serde_json::to_vec(&report()).expect("report bytes"),
            &identity(),
            CertificationEnvelopeValidity {
                issued_at_unix: ISSUED,
                expires_at_unix: ISSUED,
            },
            &signer,
        )
        .expect_err("invalid validity window");
        assert_eq!(error.code, "certification.envelopeTime");

        let error = issue_certification_revocations(
            &identity(),
            CertificationRevocationPublication {
                sequence: 5,
                issued_at_unix: ISSUED,
                next_update_unix: NEXT_UPDATE,
                revoked: vec![
                    CertificationRevocation {
                        revocation_id: "cert:z".into(),
                        revoked_at_unix: ISSUED,
                        reason: "superseded".into(),
                    },
                    CertificationRevocation {
                        revocation_id: "cert:a".into(),
                        revoked_at_unix: ISSUED,
                        reason: "withdrawn".into(),
                    },
                ],
            },
            &signer,
        )
        .expect_err("unsorted revocations");
        assert_eq!(error.code, "certification.revocationEntries");
        assert!(signer.requests.into_inner().expect("requests").is_empty());
    }

    #[test]
    fn ambiguous_reports_and_signer_failures_are_bounded() {
        let duplicate = br#"{"schemaVersion":1,"schemaVersion":1}"#;
        assert_eq!(
            issue_certification_envelope(
                duplicate,
                &identity(),
                CertificationEnvelopeValidity {
                    issued_at_unix: ISSUED,
                    expires_at_unix: EXPIRES,
                },
                &FailedSigner,
            )
            .expect_err("duplicate report")
            .code,
            "certification.issuerReportJson"
        );

        let report_bytes = serde_json::to_vec(&report()).expect("report bytes");
        let error = issue_certification_envelope(
            &report_bytes,
            &identity(),
            CertificationEnvelopeValidity {
                issued_at_unix: ISSUED,
                expires_at_unix: EXPIRES,
            },
            &FailedSigner,
        )
        .expect_err("signer failure");
        assert_eq!(error.code, "certification.issuerSigning");
        assert!(!error.message.contains("private HSM diagnostic"));
    }
}
