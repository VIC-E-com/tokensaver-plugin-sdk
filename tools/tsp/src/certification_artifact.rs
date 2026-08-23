use crate::certification::{CertificationRequirement, CertificationSubject};
use crate::certification_pipeline::{
    CertificationEvidenceReference, CertificationStageEvidence, CertificationStageProducer,
    certification_rule, sha256_digest, validate_stage,
};
use crate::manifest::ValidationError;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const ARTIFACT_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const MAX_ARTIFACT_SIGNATURE_LIFETIME_SECONDS: u64 = 366 * 24 * 60 * 60;

const MAX_ARTIFACT_SIGNATURE_BYTES: usize = 32 << 10;
const MAX_ARTIFACT_SIGNATURE_POLICY_BYTES: usize = 64 << 10;
const MAX_ARTIFACT_TRUST_STORE_BYTES: usize = 256 << 10;
const MAX_ARTIFACT_TRUST_KEYS: usize = 128;
const ARTIFACT_SIGNATURE_DOMAIN: &[u8] = b"TokenSaver plugin artifact signature v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationArtifactIdentity {
    pub plugin_id: String,
    pub version: String,
    pub platform: String,
    pub api_version: u32,
    pub artifact_digest: String,
    pub release_id: String,
}

impl From<&CertificationSubject> for CertificationArtifactIdentity {
    fn from(subject: &CertificationSubject) -> Self {
        Self {
            plugin_id: subject.plugin_id.clone(),
            version: subject.version.clone(),
            platform: subject.platform.clone(),
            api_version: subject.api_version,
            artifact_digest: subject.artifact_digest.clone(),
            release_id: subject.release_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationArtifactSignature {
    pub schema_version: u32,
    pub artifact: CertificationArtifactIdentity,
    pub signer_id: String,
    pub key_id: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationArtifactSignaturePolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub algorithm: String,
    pub maximum_signature_lifetime_seconds: u64,
    pub minimum_remaining_validity_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedArtifactSigningKey {
    pub signer_id: String,
    pub key_id: String,
    pub public_key: String,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationArtifactTrustStore {
    pub schema_version: u32,
    pub keys: Vec<TrustedArtifactSigningKey>,
}

#[derive(Clone, Copy, Debug)]
pub struct CertificationArtifactSignatureEvidence<'a> {
    pub plugin_executable_bytes: &'a [u8],
    pub artifact_signature_bytes: &'a [u8],
    pub signature_policy_bytes: &'a [u8],
    pub artifact_trust_store_bytes: &'a [u8],
}

/// Verifies an exact plugin executable under an independently provisioned artifact trust store.
///
/// The trust store and policy are caller inputs and must never be learned from a plugin package or
/// catalog. This function performs no network, filesystem, signing, installation, or activation.
pub fn evaluate_signed_artifact(
    evidence: CertificationArtifactSignatureEvidence<'_>,
    subject: &CertificationSubject,
    producer: CertificationStageProducer,
    started_at_unix: u64,
    completed_at_unix: u64,
) -> Result<CertificationStageEvidence, ValidationError> {
    let CertificationArtifactSignatureEvidence {
        plugin_executable_bytes,
        artifact_signature_bytes,
        signature_policy_bytes,
        artifact_trust_store_bytes,
    } = evidence;
    if plugin_executable_bytes.is_empty()
        || sha256_digest(plugin_executable_bytes) != subject.artifact_digest
    {
        return Err(artifact_error(
            "certification.artifactExecutable",
            "signed-artifact evidence is not bound to the subject executable bytes",
            "Use the exact executable named by the immutable certification subject.",
        ));
    }

    let policy: CertificationArtifactSignaturePolicy = parse_document(
        signature_policy_bytes,
        MAX_ARTIFACT_SIGNATURE_POLICY_BYTES,
        "certification.artifactPolicySize",
        "certification.artifactPolicyJson",
        "artifact-signature policy",
        "64 KiB",
        "schemas/certification-artifact-signature-policy.v1.json",
    )?;
    validate_policy(&policy)?;
    let trust_store: CertificationArtifactTrustStore = parse_document(
        artifact_trust_store_bytes,
        MAX_ARTIFACT_TRUST_STORE_BYTES,
        "certification.artifactTrustStoreSize",
        "certification.artifactTrustStoreJson",
        "artifact trust store",
        "256 KiB",
        "schemas/certification-artifact-trust-store.v1.json",
    )?;
    validate_trust_store(&trust_store)?;
    let artifact_signature: CertificationArtifactSignature = parse_document(
        artifact_signature_bytes,
        MAX_ARTIFACT_SIGNATURE_BYTES,
        "certification.artifactSignatureSize",
        "certification.artifactSignatureJson",
        "artifact signature",
        "32 KiB",
        "schemas/certification-artifact-signature.v1.json",
    )?;
    validate_signature_contract(&artifact_signature, subject, &policy)?;

    let failure = assess_signature(
        &artifact_signature,
        &policy,
        &trust_store,
        completed_at_unix,
    );
    let ok = failure.is_none();
    let detail = match failure {
        Some(reason) => format!(
            "artifact signature: signer {} key {} was not accepted: {reason}",
            artifact_signature.signer_id, artifact_signature.key_id
        ),
        None => format!(
            "artifact signature: verified signer {} key {} for the exact executable",
            artifact_signature.signer_id, artifact_signature.key_id
        ),
    };
    let remediation = if ok {
        "sign every changed executable with a current explicitly trusted artifact key"
    } else {
        "obtain a current valid signature from an explicitly trusted artifact signer for these exact executable bytes"
    };
    let stage = CertificationStageEvidence {
        schema_version: 1,
        requirement: CertificationRequirement::SignedArtifact,
        subject: subject.into(),
        rule: certification_rule(CertificationRequirement::SignedArtifact).into(),
        producer,
        started_at_unix,
        completed_at_unix,
        ok,
        inputs: vec![
            CertificationEvidenceReference {
                name: "plugin-executable".into(),
                digest: subject.artifact_digest.clone(),
            },
            CertificationEvidenceReference {
                name: "signature-policy".into(),
                digest: sha256_digest(signature_policy_bytes),
            },
            CertificationEvidenceReference {
                name: "artifact-trust-store".into(),
                digest: sha256_digest(artifact_trust_store_bytes),
            },
        ],
        outputs: vec![CertificationEvidenceReference {
            name: "artifact-signature".into(),
            digest: sha256_digest(artifact_signature_bytes),
        }],
        detail,
        remediation: remediation.into(),
    };
    validate_stage(&stage, subject)?;
    Ok(stage)
}

/// Returns the stable binary message signed by an artifact signing key.
pub fn artifact_signature_signing_message(signature: &CertificationArtifactSignature) -> Vec<u8> {
    let mut output = Vec::with_capacity(384);
    append_field(&mut output, ARTIFACT_SIGNATURE_DOMAIN);
    append_u64(&mut output, u64::from(signature.schema_version));
    append_field(&mut output, signature.artifact.plugin_id.as_bytes());
    append_field(&mut output, signature.artifact.version.as_bytes());
    append_field(&mut output, signature.artifact.platform.as_bytes());
    append_u64(&mut output, u64::from(signature.artifact.api_version));
    append_field(&mut output, signature.artifact.artifact_digest.as_bytes());
    append_field(&mut output, signature.artifact.release_id.as_bytes());
    append_field(&mut output, signature.signer_id.as_bytes());
    append_field(&mut output, signature.key_id.as_bytes());
    append_u64(&mut output, signature.issued_at_unix);
    append_u64(&mut output, signature.expires_at_unix);
    append_field(&mut output, signature.algorithm.as_bytes());
    output
}

fn parse_document<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
    size_code: &'static str,
    json_code: &'static str,
    document_name: &'static str,
    size_name: &'static str,
    schema_name: &'static str,
) -> Result<T, ValidationError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(artifact_error(
            size_code,
            format!("{document_name} is empty or exceeds the {size_name} limit"),
            "Use one bounded v1 JSON document.",
        ));
    }
    crate::superec::validate_unambiguous_json(bytes).map_err(|error| {
        ValidationError::new(
            json_code,
            format!("{document_name} is not unambiguous JSON: {error}"),
            "Remove duplicate members and trailing JSON from certification evidence.",
        )
    })?;
    serde_json::from_slice(bytes).map_err(|error| {
        ValidationError::new(
            json_code,
            format!("{document_name} does not match {schema_name}: {error}"),
            "Use the exact v1 schema without unknown security fields.",
        )
    })
}

fn validate_policy(policy: &CertificationArtifactSignaturePolicy) -> Result<(), ValidationError> {
    if policy.schema_version != 1
        || !valid_token(&policy.policy_id)
        || policy.algorithm != ARTIFACT_SIGNATURE_ALGORITHM
        || !(1..=MAX_ARTIFACT_SIGNATURE_LIFETIME_SECONDS)
            .contains(&policy.maximum_signature_lifetime_seconds)
        || policy.minimum_remaining_validity_seconds > policy.maximum_signature_lifetime_seconds
    {
        return Err(artifact_error(
            "certification.artifactPolicy",
            "artifact-signature policy identity, algorithm, or validity thresholds are invalid",
            "Use a bounded Ed25519 policy with a remaining-validity threshold no larger than its maximum lifetime.",
        ));
    }
    Ok(())
}

fn validate_trust_store(store: &CertificationArtifactTrustStore) -> Result<(), ValidationError> {
    if store.schema_version != 1
        || store.keys.is_empty()
        || store.keys.len() > MAX_ARTIFACT_TRUST_KEYS
    {
        return Err(artifact_error(
            "certification.artifactTrustStore",
            "artifact trust store version or key count is invalid",
            "Provision 1 to 128 explicit artifact signing keys through the trusted caller.",
        ));
    }
    let mut identities = BTreeSet::new();
    for key in &store.keys {
        if !valid_token(&key.signer_id)
            || !valid_token(&key.key_id)
            || key.not_after_unix <= key.not_before_unix
            || !valid_public_key(&key.public_key)
            || !identities.insert((key.signer_id.as_str(), key.key_id.as_str()))
        {
            return Err(artifact_error(
                "certification.artifactTrustKey",
                "artifact trust store contains an invalid or duplicate signing key",
                "Use unique signer and key ids with canonical base64 Ed25519 public keys and bounded validity.",
            ));
        }
    }
    Ok(())
}

fn validate_signature_contract(
    signature: &CertificationArtifactSignature,
    subject: &CertificationSubject,
    policy: &CertificationArtifactSignaturePolicy,
) -> Result<(), ValidationError> {
    if signature.schema_version != 1
        || signature.artifact != CertificationArtifactIdentity::from(subject)
        || !valid_token(&signature.signer_id)
        || !valid_token(&signature.key_id)
        || signature.issued_at_unix == 0
        || signature.algorithm != policy.algorithm
        || decode_exact::<64>(&signature.signature).is_none()
    {
        return Err(artifact_error(
            "certification.artifactSignature",
            "artifact signature version, identity, signer, algorithm, time, or encoding is invalid",
            "Use a canonical v1 Ed25519 signature for the exact immutable executable identity.",
        ));
    }
    Ok(())
}

fn assess_signature(
    signature: &CertificationArtifactSignature,
    policy: &CertificationArtifactSignaturePolicy,
    store: &CertificationArtifactTrustStore,
    evaluated_at_unix: u64,
) -> Option<&'static str> {
    if signature.expires_at_unix <= signature.issued_at_unix
        || signature
            .expires_at_unix
            .saturating_sub(signature.issued_at_unix)
            > policy.maximum_signature_lifetime_seconds
    {
        return Some("the signature lifetime is invalid or exceeds policy");
    }
    if evaluated_at_unix < signature.issued_at_unix
        || evaluated_at_unix > signature.expires_at_unix
        || signature.expires_at_unix.saturating_sub(evaluated_at_unix)
            < policy.minimum_remaining_validity_seconds
    {
        return Some("the signature is not currently valid for the policy window");
    }
    let Some(key) = store
        .keys
        .iter()
        .find(|key| key.signer_id == signature.signer_id && key.key_id == signature.key_id)
    else {
        return Some("the signer key is not explicitly trusted by the caller");
    };
    if signature.issued_at_unix < key.not_before_unix
        || signature.expires_at_unix > key.not_after_unix
    {
        return Some("the trusted key does not cover the complete signature lifetime");
    }
    let public_key = decode_exact::<32>(&key.public_key).expect("validated artifact public key");
    let signature_bytes =
        decode_exact::<64>(&signature.signature).expect("validated artifact signature");
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).expect("validated artifact public key point");
    let signature_value = Signature::from_bytes(&signature_bytes);
    if verifying_key
        .verify_strict(
            &artifact_signature_signing_message(signature),
            &signature_value,
        )
        .is_err()
    {
        return Some("the cryptographic signature does not verify");
    }
    None
}

fn decode_exact<const N: usize>(value: &str) -> Option<[u8; N]> {
    let decoded = BASE64.decode(value).ok()?;
    if decoded.len() != N || BASE64.encode(&decoded) != value {
        return None;
    }
    decoded.try_into().ok()
}

fn valid_public_key(value: &str) -> bool {
    decode_exact::<32>(value)
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        .is_some_and(|key| !key.is_weak())
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    append_u64(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn append_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn valid_token(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
}

fn artifact_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> ValidationError {
    ValidationError::new(code, message, remediation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ArtifactSignatureVectors {
        schema_version: u32,
        algorithm: String,
        cases: Vec<ArtifactSignatureVector>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ArtifactSignatureVector {
        name: String,
        artifact_signature: CertificationArtifactSignature,
        expected_message_length: usize,
        expected_message_sha256: String,
    }

    const EXECUTABLE: &[u8] = b"exact signed plugin executable bytes";
    const STARTED: u64 = 2_000_000_000;
    const COMPLETED: u64 = 2_000_000_060;
    const ISSUED: u64 = 1_999_999_900;
    const EXPIRES: u64 = 2_000_003_600;

    fn subject() -> CertificationSubject {
        let artifact_digest = sha256_digest(EXECUTABLE);
        let mut subject = CertificationSubject {
            plugin_id: "com.example.plugin".into(),
            version: "1.2.3".into(),
            platform: "linux-x64".into(),
            api_version: 1,
            artifact_digest,
            package_digest: sha256_digest(b"exact plugin package"),
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

    fn producer() -> CertificationStageProducer {
        CertificationStageProducer {
            id: "com.tokensaver.artifact-verifier".into(),
            version: "1.0.0".into(),
            environment_digest: sha256_digest(b"trusted artifact verifier environment"),
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn policy() -> CertificationArtifactSignaturePolicy {
        CertificationArtifactSignaturePolicy {
            schema_version: 1,
            policy_id: "com.tokensaver.certification.artifact-signature.v1".into(),
            algorithm: ARTIFACT_SIGNATURE_ALGORITHM.into(),
            maximum_signature_lifetime_seconds: 7_200,
            minimum_remaining_validity_seconds: 300,
        }
    }

    fn trust_store() -> CertificationArtifactTrustStore {
        CertificationArtifactTrustStore {
            schema_version: 1,
            keys: vec![TrustedArtifactSigningKey {
                signer_id: "com.example.publisher".into(),
                key_id: "release-2026".into(),
                public_key: BASE64.encode(signing_key().verifying_key().as_bytes()),
                not_before_unix: ISSUED - 1,
                not_after_unix: EXPIRES + 1,
            }],
        }
    }

    fn unsigned_signature() -> CertificationArtifactSignature {
        CertificationArtifactSignature {
            schema_version: 1,
            artifact: (&subject()).into(),
            signer_id: "com.example.publisher".into(),
            key_id: "release-2026".into(),
            issued_at_unix: ISSUED,
            expires_at_unix: EXPIRES,
            algorithm: ARTIFACT_SIGNATURE_ALGORITHM.into(),
            signature: BASE64.encode([0; 64]),
        }
    }

    fn sign(mut signature: CertificationArtifactSignature) -> CertificationArtifactSignature {
        let value = signing_key().sign(&artifact_signature_signing_message(&signature));
        signature.signature = BASE64.encode(value.to_bytes());
        signature
    }

    fn evaluate(
        signature: &CertificationArtifactSignature,
        policy: &CertificationArtifactSignaturePolicy,
        trust_store: &CertificationArtifactTrustStore,
    ) -> Result<CertificationStageEvidence, ValidationError> {
        let signature_bytes = serde_json::to_vec(signature).expect("artifact signature bytes");
        let policy_bytes = serde_json::to_vec(policy).expect("artifact policy bytes");
        let trust_store_bytes =
            serde_json::to_vec(trust_store).expect("artifact trust store bytes");
        evaluate_signed_artifact(
            CertificationArtifactSignatureEvidence {
                plugin_executable_bytes: EXECUTABLE,
                artifact_signature_bytes: &signature_bytes,
                signature_policy_bytes: &policy_bytes,
                artifact_trust_store_bytes: &trust_store_bytes,
            },
            &subject(),
            producer(),
            STARTED,
            COMPLETED,
        )
    }

    #[test]
    fn valid_signature_binds_every_exact_input_and_output() {
        let signature = sign(unsigned_signature());
        let policy = policy();
        let trust_store = trust_store();
        let signature_bytes = serde_json::to_vec(&signature).expect("artifact signature bytes");
        let policy_bytes = serde_json::to_vec(&policy).expect("artifact policy bytes");
        let trust_store_bytes = serde_json::to_vec(&trust_store).expect("trust store bytes");
        let stage = evaluate(&signature, &policy, &trust_store).expect("signature evaluation");

        assert!(stage.ok);
        assert_eq!(stage.inputs[0].digest, sha256_digest(EXECUTABLE));
        assert_eq!(stage.inputs[1].digest, sha256_digest(&policy_bytes));
        assert_eq!(stage.inputs[2].digest, sha256_digest(&trust_store_bytes));
        assert_eq!(stage.outputs[0].digest, sha256_digest(&signature_bytes));
        assert!(stage.detail.contains("verified signer"));
    }

    #[test]
    fn cryptographic_failure_is_truthful_failed_evidence() {
        let mut signature = sign(unsigned_signature());
        let mut bytes = decode_exact::<64>(&signature.signature).expect("signature bytes");
        bytes[0] ^= 1;
        signature.signature = BASE64.encode(bytes);

        let stage = evaluate(&signature, &policy(), &trust_store()).expect("truthful failure");
        assert!(!stage.ok);
        assert!(stage.detail.contains("does not verify"));
    }

    #[test]
    fn untrusted_signer_and_key_window_fail_truthfully() {
        let signature = sign(unsigned_signature());
        let mut untrusted = trust_store();
        untrusted.keys[0].key_id = "different-key".into();
        let stage = evaluate(&signature, &policy(), &untrusted).expect("untrusted result");
        assert!(!stage.ok);
        assert!(stage.detail.contains("not explicitly trusted"));

        let mut narrow_window = trust_store();
        narrow_window.keys[0].not_after_unix = EXPIRES - 1;
        let stage = evaluate(&signature, &policy(), &narrow_window).expect("key window result");
        assert!(!stage.ok);
        assert!(stage.detail.contains("complete signature lifetime"));
    }

    #[test]
    fn every_signature_validity_policy_is_applied() {
        let cases = [
            {
                let mut value = unsigned_signature();
                value.expires_at_unix = value.issued_at_unix;
                value
            },
            {
                let mut value = unsigned_signature();
                value.expires_at_unix = value.issued_at_unix + 7_201;
                value
            },
            {
                let mut value = unsigned_signature();
                value.issued_at_unix = COMPLETED + 1;
                value.expires_at_unix = COMPLETED + 3_601;
                value
            },
            {
                let mut value = unsigned_signature();
                value.expires_at_unix = COMPLETED - 1;
                value
            },
            {
                let mut value = unsigned_signature();
                value.expires_at_unix = COMPLETED + 299;
                value
            },
        ];
        for signature in cases.map(sign) {
            assert!(
                !evaluate(&signature, &policy(), &trust_store())
                    .expect("truthful validity result")
                    .ok
            );
        }
    }

    #[test]
    fn executable_and_signed_identity_drift_are_rejected() {
        let signature = sign(unsigned_signature());
        let signature_bytes = serde_json::to_vec(&signature).expect("artifact signature bytes");
        let policy_bytes = serde_json::to_vec(&policy()).expect("artifact policy bytes");
        let trust_store_bytes = serde_json::to_vec(&trust_store()).expect("trust store bytes");
        let error = evaluate_signed_artifact(
            CertificationArtifactSignatureEvidence {
                plugin_executable_bytes: b"wrong executable",
                artifact_signature_bytes: &signature_bytes,
                signature_policy_bytes: &policy_bytes,
                artifact_trust_store_bytes: &trust_store_bytes,
            },
            &subject(),
            producer(),
            STARTED,
            COMPLETED,
        )
        .expect_err("executable drift");
        assert_eq!(error.code, "certification.artifactExecutable");

        let mut drifted = unsigned_signature();
        drifted.artifact.version = "9.9.9".into();
        assert_eq!(
            evaluate(&sign(drifted), &policy(), &trust_store())
                .expect_err("signed identity drift")
                .code,
            "certification.artifactSignature"
        );
    }

    #[test]
    fn invalid_policy_and_trust_store_contracts_fail_closed() {
        let signature = sign(unsigned_signature());
        let policy_mutations: [fn(&mut CertificationArtifactSignaturePolicy); 5] = [
            |value| value.schema_version = 2,
            |value| value.policy_id = "invalid policy".into(),
            |value| value.algorithm = "rsa".into(),
            |value| value.maximum_signature_lifetime_seconds = 0,
            |value| value.minimum_remaining_validity_seconds = 7_201,
        ];
        for mutate in policy_mutations {
            let mut invalid = policy();
            mutate(&mut invalid);
            assert_eq!(
                evaluate(&signature, &invalid, &trust_store())
                    .expect_err("invalid policy")
                    .code,
                "certification.artifactPolicy"
            );
        }

        let mut empty = trust_store();
        empty.keys.clear();
        assert_eq!(
            evaluate(&signature, &policy(), &empty)
                .expect_err("empty trust store")
                .code,
            "certification.artifactTrustStore"
        );

        let mut duplicate = trust_store();
        duplicate.keys.push(duplicate.keys[0].clone());
        assert_eq!(
            evaluate(&signature, &policy(), &duplicate)
                .expect_err("duplicate trust key")
                .code,
            "certification.artifactTrustKey"
        );

        let mut invalid_key = trust_store();
        invalid_key.keys[0].public_key = BASE64.encode([0; 31]);
        assert_eq!(
            evaluate(&signature, &policy(), &invalid_key)
                .expect_err("invalid public key material")
                .code,
            "certification.artifactTrustKey"
        );

        let mut weak_key = trust_store();
        weak_key.keys[0].public_key = BASE64.encode([0; 32]);
        assert_eq!(
            evaluate(&signature, &policy(), &weak_key)
                .expect_err("weak public key")
                .code,
            "certification.artifactTrustKey"
        );
    }

    #[test]
    fn malformed_ambiguous_unknown_and_oversized_documents_are_rejected() {
        let signature = sign(unsigned_signature());
        let signature_bytes = serde_json::to_vec(&signature).expect("artifact signature bytes");
        let policy_bytes = serde_json::to_vec(&policy()).expect("artifact policy bytes");
        let trust_store_bytes = serde_json::to_vec(&trust_store()).expect("trust store bytes");
        let duplicate_policy = br#"{"schemaVersion":1,"schemaVersion":1}"#;
        let unknown_signature = br#"{"schemaVersion":1,"unknownSecurityField":true}"#;

        let evaluate_bytes = |signature_bytes: &[u8], policy_bytes: &[u8], store_bytes: &[u8]| {
            evaluate_signed_artifact(
                CertificationArtifactSignatureEvidence {
                    plugin_executable_bytes: EXECUTABLE,
                    artifact_signature_bytes: signature_bytes,
                    signature_policy_bytes: policy_bytes,
                    artifact_trust_store_bytes: store_bytes,
                },
                &subject(),
                producer(),
                STARTED,
                COMPLETED,
            )
        };

        assert_eq!(
            evaluate_bytes(&signature_bytes, duplicate_policy, &trust_store_bytes)
                .expect_err("duplicate policy")
                .code,
            "certification.artifactPolicyJson"
        );
        assert_eq!(
            evaluate_bytes(unknown_signature, &policy_bytes, &trust_store_bytes)
                .expect_err("unknown signature field")
                .code,
            "certification.artifactSignatureJson"
        );
        assert_eq!(
            evaluate_bytes(
                &vec![b' '; MAX_ARTIFACT_SIGNATURE_BYTES + 1],
                &policy_bytes,
                &trust_store_bytes,
            )
            .expect_err("oversized signature")
            .code,
            "certification.artifactSignatureSize"
        );
        assert_eq!(
            evaluate_bytes(
                &signature_bytes,
                &policy_bytes,
                &vec![b' '; MAX_ARTIFACT_TRUST_STORE_BYTES + 1],
            )
            .expect_err("oversized trust store")
            .code,
            "certification.artifactTrustStoreSize"
        );
    }

    #[test]
    fn signing_message_excludes_signature_and_binds_identity() {
        let signature = unsigned_signature();
        let mut changed_signature = signature.clone();
        changed_signature.signature = BASE64.encode([1; 64]);
        assert_eq!(
            artifact_signature_signing_message(&signature),
            artifact_signature_signing_message(&changed_signature)
        );

        let mut changed_identity = signature.clone();
        changed_identity.artifact.platform = "windows-x64".into();
        assert_ne!(
            artifact_signature_signing_message(&signature),
            artifact_signature_signing_message(&changed_identity)
        );
    }

    #[test]
    fn shared_signing_message_vectors_are_stable() {
        let vectors: ArtifactSignatureVectors = serde_json::from_str(include_str!(
            "../../../conformance/certification-artifact-signature-v1.cases.json"
        ))
        .expect("artifact signature vectors");
        assert_eq!(vectors.schema_version, 1);
        assert_eq!(
            vectors.algorithm,
            "tokensaver-artifact-signature-message-v1"
        );
        assert!(!vectors.cases.is_empty());
        for case in vectors.cases {
            let message = artifact_signature_signing_message(&case.artifact_signature);
            assert_eq!(message.len(), case.expected_message_length, "{}", case.name);
            assert_eq!(
                sha256_digest(&message),
                case.expected_message_sha256,
                "{}",
                case.name
            );
        }
    }
}
