use crate::certification::{CertificationRequirement, CertificationSubject};
use crate::certification_pipeline::{
    CertificationEvidenceReference, CertificationStageEvidence, CertificationStageProducer,
    CertificationStageSubject, certification_rule, sha256_digest, validate_stage,
};
use crate::manifest::{
    MANIFEST_MAX_BYTES, PluginManifest, ValidationError, effective_time_budget_ms,
    validate_manifest,
};
use crate::superec::validate_unambiguous_json;
use serde::{Deserialize, Serialize};

const MAX_ADMIN_METADATA_BYTES: usize = 256 << 10;
const MAX_ADMIN_PLATFORMS: usize = 512;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationAdminPolicyMetadata {
    pub schema_version: u32,
    pub subject: CertificationStageSubject,
    pub manifest_digest: String,
    pub runtime_kind: String,
    pub runtime_platforms: Vec<String>,
    pub runtime_argument_count: u32,
    pub capability_kinds: Vec<String>,
    pub declared_max_input_bytes: i64,
    pub declared_time_budget_ms: i64,
    pub effective_time_budget_ms: u32,
    pub permission_count: u32,
    pub integrity_algorithm: Option<String>,
    pub integrity_covered_platforms: Vec<String>,
    pub integrity_complete: bool,
    pub generated_at_unix: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct CertificationAdminPolicyEvidence<'a> {
    pub manifest_bytes: &'a [u8],
    pub metadata_bytes: &'a [u8],
}

/// Verify that admin-policy metadata is an exact, privacy-safe projection of plugin.json.
///
/// The evaluator does not apply an enterprise policy. It exposes only bounded control metadata
/// and exact integrity coverage so a separately authenticated host policy can decide whether the
/// release is allowed. It performs no network, filesystem, installation, or activation action.
pub fn evaluate_admin_policy_metadata(
    evidence: CertificationAdminPolicyEvidence<'_>,
    subject: &CertificationSubject,
    producer: CertificationStageProducer,
    started_at_unix: u64,
    completed_at_unix: u64,
) -> Result<CertificationStageEvidence, ValidationError> {
    let manifest = parse_manifest(evidence.manifest_bytes)?;
    validate_manifest(&manifest)?;
    validate_manifest_subject(&manifest, subject)?;

    let expected = project_metadata(
        &manifest,
        evidence.manifest_bytes,
        subject,
        completed_at_unix,
    )?;
    let metadata = parse_metadata(evidence.metadata_bytes)?;
    if metadata != expected
        || !valid_evidence_time(
            metadata.generated_at_unix,
            started_at_unix,
            completed_at_unix,
        )
    {
        return Err(admin_error(
            "certification.adminMetadata",
            "admin policy metadata does not match the exact manifest projection or stage time",
            "Regenerate metadata from the exact validated manifest and bounded stage time.",
        ));
    }

    let ok = metadata.integrity_complete;
    let detail = format!(
        "admin metadata: {} runtime platforms, {} capability kinds, {} arguments, {} integrity-covered platforms",
        metadata.runtime_platforms.len(),
        metadata.capability_kinds.len(),
        metadata.runtime_argument_count,
        metadata.integrity_covered_platforms.len()
    );
    let remediation = if ok {
        "regenerate admin metadata from the exact manifest for every release"
    } else {
        "publish exact sha256 integrity for every non-empty runtime platform entry"
    };
    let stage = CertificationStageEvidence {
        schema_version: 1,
        requirement: CertificationRequirement::AdminPolicyMetadata,
        subject: subject.into(),
        rule: certification_rule(CertificationRequirement::AdminPolicyMetadata).into(),
        producer,
        started_at_unix,
        completed_at_unix,
        ok,
        inputs: vec![CertificationEvidenceReference {
            name: "plugin-manifest".into(),
            digest: sha256_digest(evidence.manifest_bytes),
        }],
        outputs: vec![CertificationEvidenceReference {
            name: "admin-policy-metadata".into(),
            digest: sha256_digest(evidence.metadata_bytes),
        }],
        detail,
        remediation: remediation.into(),
    };
    validate_stage(&stage, subject)?;
    Ok(stage)
}

fn parse_manifest(bytes: &[u8]) -> Result<PluginManifest, ValidationError> {
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MANIFEST_MAX_BYTES {
        return Err(admin_error(
            "certification.adminManifestSize",
            "plugin manifest is empty or exceeds 64 KiB",
            "Use the exact bounded plugin.json accepted by Level 1 validation.",
        ));
    }
    validate_unambiguous_json(bytes).map_err(|error| {
        admin_error(
            "certification.adminManifestJson",
            format!("plugin manifest is ambiguous or invalid JSON: {error}"),
            "Remove duplicate members and trailing JSON from plugin.json.",
        )
    })?;
    serde_json::from_slice(bytes).map_err(|error| {
        admin_error(
            "certification.adminManifestJson",
            format!("plugin manifest does not match the v1 contract: {error}"),
            "Use schemas/plugin-manifest.v1.json and the shared host validation corpus.",
        )
    })
}

fn parse_metadata(bytes: &[u8]) -> Result<CertificationAdminPolicyMetadata, ValidationError> {
    if bytes.is_empty() || bytes.len() > MAX_ADMIN_METADATA_BYTES {
        return Err(admin_error(
            "certification.adminMetadataSize",
            "admin policy metadata is empty or exceeds 256 KiB",
            "Use one bounded certification-admin-policy-metadata.v1.json document.",
        ));
    }
    validate_unambiguous_json(bytes).map_err(|error| {
        admin_error(
            "certification.adminMetadataJson",
            format!("admin policy metadata is ambiguous or invalid JSON: {error}"),
            "Remove duplicate members and trailing JSON from admin policy metadata.",
        )
    })?;
    serde_json::from_slice(bytes).map_err(|error| {
        admin_error(
            "certification.adminMetadataJson",
            format!(
                "admin policy metadata does not match schemas/certification-admin-policy-metadata.v1.json: {error}"
            ),
            "Use the exact versioned admin policy metadata contract.",
        )
    })
}

fn validate_manifest_subject(
    manifest: &PluginManifest,
    subject: &CertificationSubject,
) -> Result<(), ValidationError> {
    let subject_entry = manifest.runtime.entry.get(&subject.platform);
    if manifest.id != subject.plugin_id
        || manifest.version != subject.version
        || manifest.api_version != i64::from(subject.api_version)
        || subject_entry.is_none_or(String::is_empty)
    {
        return Err(admin_error(
            "certification.adminManifestSubject",
            "plugin manifest identity or subject platform does not match the certification subject",
            "Use the exact validated package manifest for this plugin release and platform.",
        ));
    }
    if manifest
        .integrity
        .as_ref()
        .and_then(|integrity| integrity.digests.get(&subject.platform))
        .is_some_and(|digest| digest != &subject.artifact_digest)
    {
        return Err(admin_error(
            "certification.adminManifestArtifact",
            "plugin manifest integrity conflicts with the immutable subject executable",
            "Regenerate plugin.json integrity from the exact subject executable.",
        ));
    }
    Ok(())
}

fn project_metadata(
    manifest: &PluginManifest,
    manifest_bytes: &[u8],
    subject: &CertificationSubject,
    generated_at_unix: u64,
) -> Result<CertificationAdminPolicyMetadata, ValidationError> {
    if manifest.runtime.entry.len() > MAX_ADMIN_PLATFORMS
        || manifest
            .runtime
            .entry
            .keys()
            .any(|platform| !valid_platform_token(platform))
        || manifest.integrity.as_ref().is_some_and(|integrity| {
            integrity
                .digests
                .keys()
                .any(|platform| !valid_platform_token(platform))
        })
    {
        return Err(admin_error(
            "certification.adminPlatforms",
            "plugin manifest contains too many or invalid runtime platform identities",
            "Publish at most 512 ASCII platform tokens using letters, digits, dot, underscore, or hyphen.",
        ));
    }
    let runtime_platforms = manifest.runtime.entry.keys().cloned().collect::<Vec<_>>();
    let mut capability_kinds = manifest.capabilities.kinds.clone();
    capability_kinds.sort();
    let (integrity_algorithm, integrity_covered_platforms, integrity_complete) =
        if let Some(integrity) = &manifest.integrity {
            let covered = integrity.digests.keys().cloned().collect::<Vec<_>>();
            let complete = integrity.algorithm == "sha256"
                && manifest.runtime.entry.iter().all(|(platform, entry)| {
                    !entry.is_empty() && integrity.digests.contains_key(platform)
                })
                && integrity.digests.len() == manifest.runtime.entry.len()
                && integrity
                    .digests
                    .get(&subject.platform)
                    .is_some_and(|digest| digest == &subject.artifact_digest);
            (Some(integrity.algorithm.clone()), covered, complete)
        } else {
            (None, Vec::new(), false)
        };
    Ok(CertificationAdminPolicyMetadata {
        schema_version: 1,
        subject: subject.into(),
        manifest_digest: sha256_digest(manifest_bytes),
        runtime_kind: manifest.runtime.kind.clone(),
        runtime_platforms,
        runtime_argument_count: portable_count(manifest.runtime.args.len())?,
        capability_kinds,
        declared_max_input_bytes: manifest.capabilities.max_input_bytes,
        declared_time_budget_ms: manifest.limits.time_budget_ms,
        effective_time_budget_ms: effective_time_budget_ms(manifest),
        permission_count: portable_count(manifest.permissions.len())?,
        integrity_algorithm,
        integrity_covered_platforms,
        integrity_complete,
        generated_at_unix,
    })
}

fn portable_count(value: usize) -> Result<u32, ValidationError> {
    u32::try_from(value).map_err(|_| {
        admin_error(
            "certification.adminMetadata",
            "admin metadata count is not portable",
            "Use bounded manifest arrays with unsigned 32-bit counts.",
        )
    })
}

fn valid_platform_token(value: &str) -> bool {
    (1..=160).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_evidence_time(value: u64, started_at_unix: u64, completed_at_unix: u64) -> bool {
    value != 0
        && started_at_unix != 0
        && completed_at_unix >= started_at_unix
        && value >= started_at_unix
        && value <= completed_at_unix
}

fn admin_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> ValidationError {
    ValidationError::new(code, message, remediation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const STARTED: u64 = 2_000_000_000;
    const COMPLETED: u64 = 2_000_000_060;

    fn subject() -> CertificationSubject {
        let artifact_digest = sha256_digest(b"exact plugin executable");
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
            id: "com.tokensaver.admin-metadata-reviewer".into(),
            version: "1.0.0".into(),
            environment_digest: sha256_digest(b"trusted admin metadata environment"),
        }
    }

    fn manifest_value(subject: &CertificationSubject, with_integrity: bool) -> Value {
        let mut manifest = json!({
            "apiVersion": 1,
            "id": subject.plugin_id,
            "name": "Example plugin",
            "version": subject.version,
            "creator": { "name": "Example" },
            "permissions": [],
            "runtime": {
                "kind": "executable",
                "entry": {
                    "windows-x64": "bin/windows/plugin.exe",
                    "linux-x64": "bin/linux/plugin"
                },
                "args": ["--stdio"]
            },
            "capabilities": {
                "kinds": ["status", "build"],
                "maxInputBytes": 16777216
            },
            "limits": { "timeBudgetMs": 250 }
        });
        if with_integrity {
            manifest["integrity"] = json!({
                "algorithm": "sha256",
                "digests": {
                    "linux-x64": subject.artifact_digest,
                    "windows-x64": sha256_digest(b"exact Windows executable")
                }
            });
        }
        manifest
    }

    fn metadata_bytes(manifest_bytes: &[u8], subject: &CertificationSubject) -> Vec<u8> {
        let manifest: PluginManifest = serde_json::from_slice(manifest_bytes).expect("manifest");
        serde_json::to_vec(
            &project_metadata(&manifest, manifest_bytes, subject, COMPLETED).expect("metadata"),
        )
        .expect("metadata bytes")
    }

    fn evaluate_manifest(
        manifest: &Value,
        subject: &CertificationSubject,
    ) -> Result<CertificationStageEvidence, ValidationError> {
        let manifest_bytes = serde_json::to_vec(manifest).expect("manifest bytes");
        let metadata_bytes = metadata_bytes(&manifest_bytes, subject);
        evaluate_admin_policy_metadata(
            CertificationAdminPolicyEvidence {
                manifest_bytes: &manifest_bytes,
                metadata_bytes: &metadata_bytes,
            },
            subject,
            producer(),
            STARTED,
            COMPLETED,
        )
    }

    #[test]
    fn exact_admin_metadata_is_deterministic_and_integrity_complete() {
        let subject = subject();
        let manifest = manifest_value(&subject, true);
        let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest bytes");
        let metadata_bytes = metadata_bytes(&manifest_bytes, &subject);
        let stage = evaluate_manifest(&manifest, &subject).expect("admin metadata");
        assert!(stage.ok);
        assert_eq!(stage.inputs[0].digest, sha256_digest(&manifest_bytes));
        assert_eq!(stage.outputs[0].digest, sha256_digest(&metadata_bytes));

        let metadata: CertificationAdminPolicyMetadata =
            serde_json::from_slice(&metadata_bytes).expect("metadata");
        assert_eq!(metadata.capability_kinds, ["build", "status"]);
        assert_eq!(metadata.runtime_argument_count, 1);
        assert_eq!(metadata.effective_time_budget_ms, 250);
        assert!(metadata.integrity_complete);
    }

    #[test]
    fn legacy_manifest_without_complete_integrity_fails_truthfully() {
        let subject = subject();
        let stage = evaluate_manifest(&manifest_value(&subject, false), &subject)
            .expect("truthful admin metadata result");
        assert!(!stage.ok);
        assert!(stage.remediation.contains("integrity"));

        let mut partial = manifest_value(&subject, true);
        partial["integrity"]["digests"]
            .as_object_mut()
            .expect("digests")
            .remove("windows-x64");
        let stage = evaluate_manifest(&partial, &subject).expect("truthful partial integrity");
        assert!(!stage.ok);
    }

    #[test]
    fn subject_artifact_and_report_drift_are_rejected() {
        let subject = subject();
        let manifest = manifest_value(&subject, true);
        let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest bytes");
        let mut metadata: CertificationAdminPolicyMetadata =
            serde_json::from_slice(&metadata_bytes(&manifest_bytes, &subject)).expect("metadata");
        metadata.runtime_argument_count += 1;
        let tampered_metadata_bytes = serde_json::to_vec(&metadata).expect("metadata bytes");
        assert_eq!(
            evaluate_admin_policy_metadata(
                CertificationAdminPolicyEvidence {
                    manifest_bytes: &manifest_bytes,
                    metadata_bytes: &tampered_metadata_bytes,
                },
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
            .expect_err("report drift")
            .code,
            "certification.adminMetadata"
        );

        let mut wrong_artifact = manifest;
        wrong_artifact["integrity"]["digests"]["linux-x64"] =
            json!(sha256_digest(b"wrong executable"));
        let wrong_bytes = serde_json::to_vec(&wrong_artifact).expect("wrong manifest bytes");
        let wrong_metadata = metadata_bytes(&wrong_bytes, &subject);
        assert_eq!(
            evaluate_admin_policy_metadata(
                CertificationAdminPolicyEvidence {
                    manifest_bytes: &wrong_bytes,
                    metadata_bytes: &wrong_metadata,
                },
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
            .expect_err("artifact drift")
            .code,
            "certification.adminManifestArtifact"
        );
    }

    #[test]
    fn ambiguous_unknown_oversized_and_wrong_platform_evidence_is_rejected() {
        let subject = subject();
        let manifest = manifest_value(&subject, true);
        let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest bytes");
        let valid_metadata = metadata_bytes(&manifest_bytes, &subject);
        let duplicate_manifest = br#"{"apiVersion":1,"apiVersion":1}"#;
        let unknown_metadata = br#"{"schemaVersion":1,"unknownSecurityField":true}"#;

        let evaluate = |manifest_bytes: &[u8], metadata_bytes: &[u8]| {
            evaluate_admin_policy_metadata(
                CertificationAdminPolicyEvidence {
                    manifest_bytes,
                    metadata_bytes,
                },
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
        };
        assert_eq!(
            evaluate(duplicate_manifest, &valid_metadata)
                .expect_err("duplicate manifest")
                .code,
            "certification.adminManifestJson"
        );
        assert_eq!(
            evaluate(&manifest_bytes, unknown_metadata)
                .expect_err("unknown metadata")
                .code,
            "certification.adminMetadataJson"
        );
        assert_eq!(
            evaluate(
                &vec![b' '; MANIFEST_MAX_BYTES as usize + 1],
                &valid_metadata
            )
            .expect_err("oversized manifest")
            .code,
            "certification.adminManifestSize"
        );

        let mut invalid_platform = manifest.clone();
        invalid_platform["runtime"]["entry"]
            .as_object_mut()
            .expect("entry")
            .insert("bad\nplatform".into(), json!("bin/bad"));
        let invalid_platform_bytes =
            serde_json::to_vec(&invalid_platform).expect("invalid platform bytes");
        assert_eq!(
            evaluate(&invalid_platform_bytes, &valid_metadata)
                .expect_err("invalid platform token")
                .code,
            "certification.adminPlatforms"
        );

        let mut wrong_platform = manifest;
        wrong_platform["runtime"]["entry"]
            .as_object_mut()
            .expect("entry")
            .remove("linux-x64");
        let wrong_bytes = serde_json::to_vec(&wrong_platform).expect("wrong manifest bytes");
        let wrong_metadata = metadata_bytes(&wrong_bytes, &subject);
        assert_eq!(
            evaluate(&wrong_bytes, &wrong_metadata)
                .expect_err("wrong subject platform")
                .code,
            "certification.adminManifestSubject"
        );
    }
}
