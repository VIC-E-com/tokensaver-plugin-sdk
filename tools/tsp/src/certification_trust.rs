use crate::certification::{
    CertificationReport, CertificationSubject, validate_certification_report,
};
use crate::manifest::ValidationError;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const CERTIFICATION_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const MAX_CERTIFICATION_LIFETIME_SECONDS: u64 = 366 * 24 * 60 * 60;
pub const MAX_REVOCATION_WINDOW_SECONDS: u64 = 7 * 24 * 60 * 60;

pub const MAX_CERTIFICATION_REPORT_BYTES: usize = 1 << 20;
pub const MAX_CERTIFICATION_ENVELOPE_BYTES: usize = 16 << 10;
pub const MAX_CERTIFICATION_REVOCATION_BYTES: usize = 1 << 20;
const MAX_TRUST_STORE_BYTES: usize = 256 << 10;
const MAX_TRUSTED_KEYS: usize = 128;
pub(crate) const MAX_REVOCATIONS: usize = 100_000;
const ENVELOPE_DOMAIN: &[u8] = b"TokenSaver certification envelope v1";
const REVOCATION_DOMAIN: &[u8] = b"TokenSaver certification revocations v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustedKeyPurpose {
    Certification,
    Revocation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationEnvelope {
    pub schema_version: u32,
    pub report_digest: String,
    pub issuer_id: String,
    pub key_id: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedIssuerKey {
    pub issuer_id: String,
    pub key_id: String,
    pub purpose: TrustedKeyPurpose,
    pub public_key: String,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationTrustStore {
    pub schema_version: u32,
    pub keys: Vec<TrustedIssuerKey>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationRevocation {
    pub revocation_id: String,
    pub revoked_at_unix: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationRevocationList {
    pub schema_version: u32,
    pub issuer_id: String,
    pub key_id: String,
    pub sequence: u64,
    pub issued_at_unix: u64,
    pub next_update_unix: u64,
    pub algorithm: String,
    pub revoked: Vec<CertificationRevocation>,
    pub signature: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificationDecisionContext {
    pub now_unix: u64,
    pub minimum_revocation_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedCertification {
    pub report: CertificationReport,
    pub issuer_id: String,
    pub certification_key_id: String,
    pub revocation_key_id: String,
    pub revocation_sequence: u64,
}

pub fn verify_certification_evidence(
    report_bytes: &[u8],
    envelope_bytes: &[u8],
    trust_store_bytes: &[u8],
    revocation_bytes: &[u8],
    expected_subject: &CertificationSubject,
    context: CertificationDecisionContext,
) -> Result<VerifiedCertification, ValidationError> {
    let envelope: CertificationEnvelope = parse_document(
        envelope_bytes,
        MAX_CERTIFICATION_ENVELOPE_BYTES,
        "certification.envelope",
        "certification envelope",
    )?;
    let trust_store: CertificationTrustStore = parse_document(
        trust_store_bytes,
        MAX_TRUST_STORE_BYTES,
        "certification.trustStore",
        "certification trust store",
    )?;
    let revocations: CertificationRevocationList = parse_document(
        revocation_bytes,
        MAX_CERTIFICATION_REVOCATION_BYTES,
        "certification.revocations",
        "certification revocation list",
    )?;
    if report_bytes.is_empty() || report_bytes.len() > MAX_CERTIFICATION_REPORT_BYTES {
        return Err(trust_error(
            "certification.reportSize",
            "certification report is empty or exceeds the 1 MiB trust limit",
            "Use one bounded certification-report.v1.json document.",
        ));
    }
    crate::superec::validate_unambiguous_json(report_bytes).map_err(|error| {
        ValidationError::new(
            "certification.reportJson",
            format!("certification report is not unambiguous JSON: {error}"),
            "Remove duplicate members and trailing JSON before certification.",
        )
    })?;

    validate_trust_store(&trust_store)?;
    validate_envelope(&envelope, context.now_unix)?;
    let report_digest = sha256_digest(report_bytes);
    if envelope.report_digest != report_digest {
        return Err(trust_error(
            "certification.reportDigest",
            "certification envelope does not bind the exact report bytes",
            "Use the exact report bytes signed by the trusted certification issuer.",
        ));
    }
    let certification_key = trusted_key(
        &trust_store,
        &envelope.issuer_id,
        &envelope.key_id,
        TrustedKeyPurpose::Certification,
    )?;
    validate_key_window(
        certification_key,
        envelope.issued_at_unix,
        envelope.expires_at_unix,
    )?;
    verify_signature(
        certification_key,
        &certification_envelope_signing_message(&envelope),
        &envelope.signature,
        "certification.envelopeSignature",
    )?;

    let report: CertificationReport = serde_json::from_slice(report_bytes).map_err(|error| {
        ValidationError::new(
            "certification.reportJson",
            format!("certification report is invalid JSON: {error}"),
            "Use schemas/certification-report.v1.json.",
        )
    })?;
    validate_certification_report(&report, expected_subject)?;
    if report.authority.issuer_id != envelope.issuer_id {
        return Err(trust_error(
            "certification.issuer",
            "signed envelope issuer does not match the certification report authority",
            "Issue the envelope and report from the same trusted certification authority.",
        ));
    }

    validate_revocations(&revocations, &trust_store, &envelope.issuer_id, context)?;
    if revocations
        .revoked
        .iter()
        .any(|entry| entry.revocation_id == report.authority.revocation_id)
    {
        return Err(trust_error(
            "certification.revoked",
            "certification evidence has been revoked by the trusted issuer",
            "Reject this release and obtain current certification evidence for a corrected package.",
        ));
    }

    Ok(VerifiedCertification {
        report,
        issuer_id: envelope.issuer_id,
        certification_key_id: envelope.key_id,
        revocation_key_id: revocations.key_id,
        revocation_sequence: revocations.sequence,
    })
}

pub fn certification_envelope_signing_message(envelope: &CertificationEnvelope) -> Vec<u8> {
    let mut output = Vec::with_capacity(256);
    append_field(&mut output, ENVELOPE_DOMAIN);
    append_u64(&mut output, u64::from(envelope.schema_version));
    append_field(&mut output, envelope.report_digest.as_bytes());
    append_field(&mut output, envelope.issuer_id.as_bytes());
    append_field(&mut output, envelope.key_id.as_bytes());
    append_u64(&mut output, envelope.issued_at_unix);
    append_u64(&mut output, envelope.expires_at_unix);
    append_field(&mut output, envelope.algorithm.as_bytes());
    output
}

pub fn revocation_list_signing_message(list: &CertificationRevocationList) -> Vec<u8> {
    let mut output = Vec::with_capacity(256 + list.revoked.len() * 128);
    append_field(&mut output, REVOCATION_DOMAIN);
    append_u64(&mut output, u64::from(list.schema_version));
    append_field(&mut output, list.issuer_id.as_bytes());
    append_field(&mut output, list.key_id.as_bytes());
    append_u64(&mut output, list.sequence);
    append_u64(&mut output, list.issued_at_unix);
    append_u64(&mut output, list.next_update_unix);
    append_field(&mut output, list.algorithm.as_bytes());
    append_u64(&mut output, list.revoked.len() as u64);
    for entry in &list.revoked {
        append_field(&mut output, entry.revocation_id.as_bytes());
        append_u64(&mut output, entry.revoked_at_unix);
        append_field(&mut output, entry.reason.as_bytes());
    }
    output
}

pub(crate) fn validate_envelope(
    envelope: &CertificationEnvelope,
    now_unix: u64,
) -> Result<(), ValidationError> {
    if envelope.schema_version != 1
        || envelope.algorithm != CERTIFICATION_SIGNATURE_ALGORITHM
        || !valid_digest(&envelope.report_digest)
        || !valid_token(&envelope.issuer_id, 1, 128)
        || !valid_token(&envelope.key_id, 1, 128)
    {
        return Err(trust_error(
            "certification.envelopeContract",
            "certification envelope identity, algorithm, or report digest is invalid",
            "Use certification-envelope.v1.json with Ed25519 and a lowercase SHA-256 report digest.",
        ));
    }
    if envelope.issued_at_unix > now_unix
        || now_unix > envelope.expires_at_unix
        || envelope.expires_at_unix <= envelope.issued_at_unix
        || envelope
            .expires_at_unix
            .saturating_sub(envelope.issued_at_unix)
            > MAX_CERTIFICATION_LIFETIME_SECONDS
    {
        return Err(trust_error(
            "certification.envelopeTime",
            "certification envelope is not currently valid or exceeds the maximum lifetime",
            "Use current issuer time and renew certification within 366 days.",
        ));
    }
    Ok(())
}

fn validate_trust_store(store: &CertificationTrustStore) -> Result<(), ValidationError> {
    if store.schema_version != 1 || store.keys.is_empty() || store.keys.len() > MAX_TRUSTED_KEYS {
        return Err(trust_error(
            "certification.trustStoreContract",
            "certification trust store version or key count is invalid",
            "Use certification-trust-store.v1.json with 1 to 128 explicitly trusted keys.",
        ));
    }
    let mut identities = BTreeSet::new();
    for key in &store.keys {
        if !valid_token(&key.issuer_id, 1, 128)
            || !valid_token(&key.key_id, 1, 128)
            || key.not_after_unix <= key.not_before_unix
            || decode_exact::<32>(&key.public_key).is_none()
            || !identities.insert((key.issuer_id.clone(), key.key_id.clone(), key.purpose))
        {
            return Err(trust_error(
                "certification.trustKey",
                "certification trust store contains an invalid or duplicate key",
                "Use unique issuer, key, and purpose tuples with canonical base64 Ed25519 public keys and bounded validity.",
            ));
        }
    }
    Ok(())
}

fn validate_key_window(
    key: &TrustedIssuerKey,
    starts_at_unix: u64,
    ends_at_unix: u64,
) -> Result<(), ValidationError> {
    if starts_at_unix < key.not_before_unix || ends_at_unix > key.not_after_unix {
        return Err(trust_error(
            "certification.keyValidity",
            "trusted issuer key does not cover the complete signed document lifetime",
            "Rotate or renew evidence with a currently trusted key whose validity covers the document.",
        ));
    }
    Ok(())
}

fn trusted_key<'a>(
    store: &'a CertificationTrustStore,
    issuer_id: &str,
    key_id: &str,
    purpose: TrustedKeyPurpose,
) -> Result<&'a TrustedIssuerKey, ValidationError> {
    store
        .keys
        .iter()
        .find(|key| {
            key.issuer_id == issuer_id && key.key_id == key_id && key.purpose == purpose
        })
        .ok_or_else(|| {
            trust_error(
                "certification.untrustedKey",
                "certification document was not signed by an explicitly trusted key for this purpose",
                "Refresh the enterprise trust store through its authenticated policy channel.",
            )
        })
}

fn validate_revocations(
    list: &CertificationRevocationList,
    store: &CertificationTrustStore,
    expected_issuer: &str,
    context: CertificationDecisionContext,
) -> Result<(), ValidationError> {
    validate_revocation_list_contract(list, expected_issuer, context)?;
    let key = trusted_key(
        store,
        &list.issuer_id,
        &list.key_id,
        TrustedKeyPurpose::Revocation,
    )?;
    validate_key_window(key, list.issued_at_unix, list.next_update_unix)?;
    verify_signature(
        key,
        &revocation_list_signing_message(list),
        &list.signature,
        "certification.revocationSignature",
    )
}

pub(crate) fn validate_revocation_list_contract(
    list: &CertificationRevocationList,
    expected_issuer: &str,
    context: CertificationDecisionContext,
) -> Result<(), ValidationError> {
    if list.schema_version != 1
        || list.algorithm != CERTIFICATION_SIGNATURE_ALGORITHM
        || list.issuer_id != expected_issuer
        || !valid_token(&list.issuer_id, 1, 128)
        || !valid_token(&list.key_id, 1, 128)
        || list.revoked.len() > MAX_REVOCATIONS
    {
        return Err(trust_error(
            "certification.revocationContract",
            "certification revocation list identity, algorithm, or size is invalid",
            "Use certification-revocations.v1.json from the same issuer with at most 100000 entries.",
        ));
    }
    if list.issued_at_unix > context.now_unix
        || context.now_unix > list.next_update_unix
        || list.next_update_unix <= list.issued_at_unix
        || list.next_update_unix.saturating_sub(list.issued_at_unix) > MAX_REVOCATION_WINDOW_SECONDS
    {
        return Err(trust_error(
            "certification.revocationFreshness",
            "certification revocation list is stale, premature, or valid for too long",
            "Fetch the current signed revocation list; it must be renewed at least every seven days.",
        ));
    }
    if list.sequence < context.minimum_revocation_sequence {
        return Err(trust_error(
            "certification.revocationRollback",
            "certification revocation list sequence is older than the last accepted sequence",
            "Reject rollback and fetch a signed list with an equal or newer sequence.",
        ));
    }
    let mut previous = None;
    for entry in &list.revoked {
        if !valid_token(&entry.revocation_id, 1, 128)
            || !valid_text(&entry.reason, 1, 512)
            || entry.revoked_at_unix > list.issued_at_unix
            || previous.is_some_and(|value: &str| value >= entry.revocation_id.as_str())
        {
            return Err(trust_error(
                "certification.revocationEntries",
                "certification revocation entries are invalid, duplicated, or not canonically sorted",
                "Sort unique revocation ids, bound reasons, and use revocation times no later than list issuance.",
            ));
        }
        previous = Some(entry.revocation_id.as_str());
    }
    Ok(())
}

fn verify_signature(
    key: &TrustedIssuerKey,
    message: &[u8],
    encoded_signature: &str,
    code: &'static str,
) -> Result<(), ValidationError> {
    let public_key = decode_exact::<32>(&key.public_key).ok_or_else(|| {
        trust_error(
            "certification.trustKey",
            "trusted issuer public key is not canonical base64 Ed25519 key material",
            "Replace the invalid trust-store key through the authenticated policy channel.",
        )
    })?;
    let signature = decode_exact::<64>(encoded_signature).ok_or_else(|| {
        trust_error(
            code,
            "certification signature is not canonical base64 Ed25519 signature material",
            "Use the exact signature emitted by the trusted issuer.",
        )
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_| {
        trust_error(
            "certification.trustKey",
            "trusted issuer public key is not a valid Ed25519 point",
            "Replace the invalid trust-store key through the authenticated policy channel.",
        )
    })?;
    verifying_key
        .verify_strict(message, &Signature::from_bytes(&signature))
        .map_err(|_| {
            trust_error(
                code,
                "certification signature verification failed",
                "Reject the evidence and fetch an untampered document from the trusted issuer.",
            )
        })
}

fn parse_document<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
    code: &'static str,
    label: &'static str,
) -> Result<T, ValidationError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ValidationError::new(
            code,
            format!("{label} is empty or exceeds its size limit"),
            "Use one bounded JSON document from the trusted distribution path.",
        ));
    }
    crate::superec::validate_unambiguous_json(bytes).map_err(|error| {
        ValidationError::new(
            code,
            format!("{label} is not unambiguous JSON: {error}"),
            "Remove duplicate members and trailing JSON data.",
        )
    })?;
    serde_json::from_slice(bytes).map_err(|error| {
        ValidationError::new(
            code,
            format!("{label} does not match its v1 contract: {error}"),
            "Use the published v1 schema without unknown security fields.",
        )
    })
}

fn decode_exact<const N: usize>(value: &str) -> Option<[u8; N]> {
    let decoded = BASE64.decode(value).ok()?;
    if decoded.len() != N || BASE64.encode(&decoded) != value {
        return None;
    }
    decoded.try_into().ok()
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("write SHA-256 hex");
    }
    output
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    append_u64(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn append_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_token(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
}

fn valid_text(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && !value.contains('\0')
        && !value.chars().any(char::is_control)
}

fn trust_error(
    code: &'static str,
    message: &'static str,
    remediation: &'static str,
) -> ValidationError {
    ValidationError::new(code, message, remediation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certification::{
        CERTIFICATION_POLICY_ID, CERTIFICATION_POLICY_VERSION, CertificationAuthority,
        CertificationCheck, CertificationLevel,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde::Deserialize;

    const NOW: u64 = 2_000_000_000;

    struct Evidence {
        subject: CertificationSubject,
        report_bytes: Vec<u8>,
        envelope: CertificationEnvelope,
        trust_store: CertificationTrustStore,
        revocations: CertificationRevocationList,
        certification_key: SigningKey,
        revocation_key: SigningKey,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct SigningMessageCorpus {
        schema_version: u32,
        algorithm: String,
        envelope: EnvelopeSigningVector,
        revocations: RevocationSigningVector,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct EnvelopeSigningVector {
        document: CertificationEnvelope,
        message_length: usize,
        message_sha256: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct RevocationSigningVector {
        document: CertificationRevocationList,
        message_length: usize,
        message_sha256: String,
    }

    impl Evidence {
        fn new() -> Self {
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
            subject.release_id = crate::identity::release_id(
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
            let report_bytes = serde_json::to_vec_pretty(&report).expect("serialize report");
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
                    trusted_key_record(
                        &certification_key,
                        "certification-2026-01",
                        TrustedKeyPurpose::Certification,
                    ),
                    trusted_key_record(
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
                sequence: 42,
                issued_at_unix: NOW - 60,
                next_update_unix: NOW + 3_600,
                algorithm: CERTIFICATION_SIGNATURE_ALGORITHM.into(),
                revoked: Vec::new(),
                signature: String::new(),
            };
            sign_revocations(&mut revocations, &revocation_key);
            Self {
                subject,
                report_bytes,
                envelope,
                trust_store,
                revocations,
                certification_key,
                revocation_key,
            }
        }

        fn verify(
            &self,
            minimum_revocation_sequence: u64,
        ) -> Result<VerifiedCertification, ValidationError> {
            verify_certification_evidence(
                &self.report_bytes,
                &serde_json::to_vec(&self.envelope).expect("serialize envelope"),
                &serde_json::to_vec(&self.trust_store).expect("serialize trust store"),
                &serde_json::to_vec(&self.revocations).expect("serialize revocations"),
                &self.subject,
                CertificationDecisionContext {
                    now_unix: NOW,
                    minimum_revocation_sequence,
                },
            )
        }

        fn resign_envelope(&mut self) {
            self.envelope.signature = BASE64.encode(
                self.certification_key
                    .sign(&certification_envelope_signing_message(&self.envelope))
                    .to_bytes(),
            );
        }

        fn resign_revocations(&mut self) {
            sign_revocations(&mut self.revocations, &self.revocation_key);
        }
    }

    fn trusted_key_record(
        signing_key: &SigningKey,
        key_id: &str,
        purpose: TrustedKeyPurpose,
    ) -> TrustedIssuerKey {
        TrustedIssuerKey {
            issuer_id: "com.tokensaver.registry".into(),
            key_id: key_id.into(),
            purpose,
            public_key: BASE64.encode(signing_key.verifying_key().to_bytes()),
            not_before_unix: NOW - 86_400,
            not_after_unix: NOW + MAX_CERTIFICATION_LIFETIME_SECONDS,
        }
    }

    fn sign_revocations(list: &mut CertificationRevocationList, key: &SigningKey) {
        list.signature = BASE64.encode(key.sign(&revocation_list_signing_message(list)).to_bytes());
    }

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    #[test]
    fn shared_signing_message_vectors_are_stable() {
        let corpus: SigningMessageCorpus = serde_json::from_str(include_str!(
            "../../../conformance/certification-trust-v1.cases.json"
        ))
        .expect("certification trust signing corpus");
        assert_eq!(corpus.schema_version, 1);
        assert_eq!(
            corpus.algorithm,
            "tokensaver-certification-signing-message-v1"
        );

        let envelope_message = certification_envelope_signing_message(&corpus.envelope.document);
        assert_eq!(envelope_message.len(), corpus.envelope.message_length);
        assert_eq!(
            sha256_digest(&envelope_message),
            corpus.envelope.message_sha256
        );

        let revocation_message = revocation_list_signing_message(&corpus.revocations.document);
        assert_eq!(revocation_message.len(), corpus.revocations.message_length);
        assert_eq!(
            sha256_digest(&revocation_message),
            corpus.revocations.message_sha256
        );
    }

    #[test]
    fn trusted_evidence_authenticates_exact_report_and_current_revocations() {
        let evidence = Evidence::new();
        let verified = evidence.verify(42).expect("trusted certification");
        assert_eq!(
            verified.report.certification_level,
            CertificationLevel::Certified
        );
        assert_eq!(verified.issuer_id, "com.tokensaver.registry");
        assert_eq!(verified.revocation_sequence, 42);
    }

    #[test]
    fn report_and_envelope_tampering_are_rejected() {
        let mut report_tampering = Evidence::new();
        report_tampering.report_bytes.push(b' ');
        assert_eq!(
            report_tampering
                .verify(42)
                .expect_err("report tampering")
                .code,
            "certification.reportDigest"
        );

        let mut envelope_tampering = Evidence::new();
        envelope_tampering.envelope.expires_at_unix -= 1;
        assert_eq!(
            envelope_tampering
                .verify(42)
                .expect_err("envelope tampering")
                .code,
            "certification.envelopeSignature"
        );
    }

    #[test]
    fn issuer_purpose_and_key_rotation_are_fail_closed() {
        let mut wrong_purpose = Evidence::new();
        wrong_purpose.trust_store.keys[0].purpose = TrustedKeyPurpose::Revocation;
        assert_eq!(
            wrong_purpose
                .verify(42)
                .expect_err("wrong key purpose")
                .code,
            "certification.untrustedKey"
        );

        let mut rotated = Evidence::new();
        let replacement = SigningKey::from_bytes(&[11; 32]);
        rotated.envelope.key_id = "certification-2026-02".into();
        rotated.certification_key = replacement;
        rotated.trust_store.keys.push(trusted_key_record(
            &rotated.certification_key,
            "certification-2026-02",
            TrustedKeyPurpose::Certification,
        ));
        rotated.resign_envelope();
        assert!(rotated.verify(42).is_ok());
    }

    #[test]
    fn validity_freshness_and_rollback_are_enforced() {
        let mut expired = Evidence::new();
        expired.envelope.expires_at_unix = NOW - 1;
        expired.resign_envelope();
        assert_eq!(
            expired.verify(42).expect_err("expired envelope").code,
            "certification.envelopeTime"
        );

        let stale = Evidence::new();
        assert_eq!(
            stale.verify(43).expect_err("revocation rollback").code,
            "certification.revocationRollback"
        );

        let mut stale = Evidence::new();
        stale.revocations.next_update_unix = NOW - 1;
        stale.resign_revocations();
        assert_eq!(
            stale.verify(42).expect_err("stale revocations").code,
            "certification.revocationFreshness"
        );

        let mut incomplete_key_window = Evidence::new();
        incomplete_key_window.trust_store.keys[0].not_after_unix =
            incomplete_key_window.envelope.expires_at_unix - 1;
        assert_eq!(
            incomplete_key_window
                .verify(42)
                .expect_err("key does not cover the signed lifetime")
                .code,
            "certification.keyValidity"
        );
    }

    #[test]
    fn revoked_and_noncanonical_entries_are_rejected() {
        let mut revoked = Evidence::new();
        revoked.revocations.revoked.push(CertificationRevocation {
            revocation_id: "cert:release:0123456789abcdef".into(),
            revoked_at_unix: NOW - 90,
            reason: "artifact signature was withdrawn".into(),
        });
        revoked.resign_revocations();
        assert_eq!(
            revoked.verify(42).expect_err("revoked evidence").code,
            "certification.revoked"
        );

        let mut unordered = Evidence::new();
        unordered.revocations.revoked = vec![
            CertificationRevocation {
                revocation_id: "revocation:z".into(),
                revoked_at_unix: NOW - 90,
                reason: "withdrawn".into(),
            },
            CertificationRevocation {
                revocation_id: "revocation:a".into(),
                revoked_at_unix: NOW - 90,
                reason: "withdrawn".into(),
            },
        ];
        unordered.resign_revocations();
        assert_eq!(
            unordered.verify(42).expect_err("unordered entries").code,
            "certification.revocationEntries"
        );
    }

    #[test]
    fn ambiguous_and_unknown_security_documents_are_rejected() {
        let evidence = Evidence::new();
        let duplicate = br#"{"schemaVersion":1,"schemaVersion":1}"#;
        let error = verify_certification_evidence(
            &evidence.report_bytes,
            duplicate,
            &serde_json::to_vec(&evidence.trust_store).expect("trust store"),
            &serde_json::to_vec(&evidence.revocations).expect("revocations"),
            &evidence.subject,
            CertificationDecisionContext {
                now_unix: NOW,
                minimum_revocation_sequence: 42,
            },
        )
        .expect_err("duplicate envelope member");
        assert_eq!(error.code, "certification.envelope");

        let mut envelope = serde_json::to_value(&evidence.envelope).expect("envelope value");
        envelope["extensions"] = serde_json::json!({});
        let error = verify_certification_evidence(
            &evidence.report_bytes,
            &serde_json::to_vec(&envelope).expect("unknown envelope field"),
            &serde_json::to_vec(&evidence.trust_store).expect("trust store"),
            &serde_json::to_vec(&evidence.revocations).expect("revocations"),
            &evidence.subject,
            CertificationDecisionContext {
                now_unix: NOW,
                minimum_revocation_sequence: 42,
            },
        )
        .expect_err("unknown security field");
        assert_eq!(error.code, "certification.envelope");
    }

    #[test]
    fn malformed_keys_invalid_signatures_and_issuer_drift_are_rejected() {
        let mut malformed_key = Evidence::new();
        malformed_key.trust_store.keys[0].public_key = "not-canonical-base64".into();
        assert_eq!(
            malformed_key
                .verify(42)
                .expect_err("malformed trusted key")
                .code,
            "certification.trustKey"
        );

        let mut invalid_revocation_signature = Evidence::new();
        invalid_revocation_signature.revocations.sequence += 1;
        assert_eq!(
            invalid_revocation_signature
                .verify(42)
                .expect_err("invalid revocation signature")
                .code,
            "certification.revocationSignature"
        );

        let mut wrong_revocation_issuer = Evidence::new();
        wrong_revocation_issuer.revocations.issuer_id = "com.example.other-issuer".into();
        wrong_revocation_issuer.trust_store.keys[1].issuer_id =
            wrong_revocation_issuer.revocations.issuer_id.clone();
        wrong_revocation_issuer.resign_revocations();
        assert_eq!(
            wrong_revocation_issuer
                .verify(42)
                .expect_err("revocation issuer drift")
                .code,
            "certification.revocationContract"
        );

        let mut wrong_report_issuer = Evidence::new();
        let mut report: CertificationReport =
            serde_json::from_slice(&wrong_report_issuer.report_bytes).expect("report");
        report.authority.issuer_id = "com.example.other-issuer".into();
        wrong_report_issuer.report_bytes = serde_json::to_vec_pretty(&report).expect("report");
        wrong_report_issuer.envelope.report_digest =
            sha256_digest(&wrong_report_issuer.report_bytes);
        wrong_report_issuer.resign_envelope();
        assert_eq!(
            wrong_report_issuer
                .verify(42)
                .expect_err("report issuer drift")
                .code,
            "certification.issuer"
        );
    }
}
