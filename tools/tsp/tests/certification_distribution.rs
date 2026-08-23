use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tsp_workbench::{
    AuthenticatedCertificationSource, CERTIFICATION_POLICY_ID, CERTIFICATION_POLICY_VERSION,
    CERTIFICATION_SIGNATURE_ALGORITHM, CertificationAuthority, CertificationCheck,
    CertificationEnvelope, CertificationEvidenceDocuments, CertificationLevel, CertificationReport,
    CertificationRevocationList, CertificationRevocationStateStore, CertificationSubject,
    CertificationTrustStore, TrustedIssuerKey, TrustedKeyPurpose, ValidationError,
    certification_envelope_signing_message, fetch_verify_and_record_certification,
    revocation_list_signing_message,
};

const NOW: u64 = 2_000_000_000;

#[derive(Clone)]
struct StaticAuthenticatedSource {
    documents: CertificationEvidenceDocuments,
}

impl AuthenticatedCertificationSource for StaticAuthenticatedSource {
    fn fetch(
        &self,
        _expected_subject: &CertificationSubject,
    ) -> Result<CertificationEvidenceDocuments, ValidationError> {
        Ok(self.documents.clone())
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "tokensaver-certification-distribution-{}-{unique}",
            std::process::id()
        )))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn evidence(
    sequence: u64,
) -> (
    CertificationSubject,
    CertificationEvidenceDocuments,
    Vec<u8>,
) {
    let certification_key = SigningKey::from_bytes(&[7; 32]);
    let revocation_key = SigningKey::from_bytes(&[9; 32]);
    let mut subject = CertificationSubject {
        plugin_id: "com.example.plugin".into(),
        version: "1.2.3".into(),
        platform: "linux-x64".into(),
        api_version: 1,
        artifact_digest: digest('b'),
        package_digest: digest('a'),
        release_id: String::new(),
    };
    subject.release_id = tsp_workbench::release_id(
        &subject.plugin_id,
        &subject.version,
        &subject.platform,
        &subject.artifact_digest,
    );
    let level = CertificationLevel::Certified;
    let report = CertificationReport {
        schema_version: 1,
        ok: true,
        certification_level: level,
        subject: subject.clone(),
        authority: CertificationAuthority {
            issuer_id: "com.tokensaver.registry".into(),
            policy_id: CERTIFICATION_POLICY_ID.into(),
            policy_version: CERTIFICATION_POLICY_VERSION,
            revocation_id: "cert:release:0123456789abcdef".into(),
        },
        checks: level
            .requirements()
            .iter()
            .enumerate()
            .map(|(index, requirement)| CertificationCheck {
                requirement: *requirement,
                ok: true,
                rule: format!("certification.rule{index}"),
                evidence_digest: digest(char::from(b'0' + index as u8)),
                detail: "verified by the trusted certification pipeline".into(),
                remediation: "rerun the named certification pipeline stage".into(),
            })
            .collect(),
    };
    let report_bytes = serde_json::to_vec_pretty(&report).expect("report");
    let mut envelope = CertificationEnvelope {
        schema_version: 1,
        report_digest: sha256_digest(&report_bytes),
        issuer_id: report.authority.issuer_id.clone(),
        key_id: "certification-2026-01".into(),
        issued_at_unix: NOW - 60,
        expires_at_unix: NOW + 86_400,
        algorithm: CERTIFICATION_SIGNATURE_ALGORITHM.into(),
        signature: String::new(),
    };
    envelope.signature = BASE64.encode(
        certification_key
            .sign(&certification_envelope_signing_message(&envelope))
            .to_bytes(),
    );
    let trust_store = CertificationTrustStore {
        schema_version: 1,
        keys: vec![
            trusted_key(
                &certification_key,
                "certification-2026-01",
                TrustedKeyPurpose::Certification,
            ),
            trusted_key(
                &revocation_key,
                "revocation-2026-01",
                TrustedKeyPurpose::Revocation,
            ),
        ],
    };
    let mut revocations = CertificationRevocationList {
        schema_version: 1,
        issuer_id: report.authority.issuer_id,
        key_id: "revocation-2026-01".into(),
        sequence,
        issued_at_unix: NOW - 60,
        next_update_unix: NOW + 3_600,
        algorithm: CERTIFICATION_SIGNATURE_ALGORITHM.into(),
        revoked: Vec::new(),
        signature: String::new(),
    };
    revocations.signature = BASE64.encode(
        revocation_key
            .sign(&revocation_list_signing_message(&revocations))
            .to_bytes(),
    );
    (
        subject,
        CertificationEvidenceDocuments {
            report: report_bytes,
            envelope: serde_json::to_vec(&envelope).expect("envelope"),
            revocations: serde_json::to_vec(&revocations).expect("revocations"),
        },
        serde_json::to_vec(&trust_store).expect("trust store"),
    )
}

fn trusted_key(key: &SigningKey, key_id: &str, purpose: TrustedKeyPurpose) -> TrustedIssuerKey {
    TrustedIssuerKey {
        issuer_id: "com.tokensaver.registry".into(),
        key_id: key_id.into(),
        purpose,
        public_key: BASE64.encode(key.verifying_key().to_bytes()),
        not_before_unix: NOW - 86_400,
        not_after_unix: NOW + tsp_workbench::MAX_CERTIFICATION_LIFETIME_SECONDS,
    }
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[test]
fn authenticated_source_verification_and_durable_rollback_form_one_decision() {
    let directory = TestDirectory::new();
    let store = CertificationRevocationStateStore::new(&directory.0);
    let (subject, documents, trust_store) = evidence(42);
    let accepted = fetch_verify_and_record_certification(
        &StaticAuthenticatedSource { documents },
        &trust_store,
        &subject,
        NOW,
        &store,
    )
    .expect("authenticated certification");
    assert_eq!(accepted.revocation_sequence, 42);
    assert_eq!(
        store
            .highest_sequence("com.tokensaver.registry")
            .expect("durable sequence"),
        Some(42)
    );

    let (rollback_subject, rollback_documents, rollback_trust_store) = evidence(41);
    let error = fetch_verify_and_record_certification(
        &StaticAuthenticatedSource {
            documents: rollback_documents,
        },
        &rollback_trust_store,
        &rollback_subject,
        NOW,
        &store,
    )
    .expect_err("durable rollback");
    assert_eq!(error.code, "certification.revocationRollback");
}
