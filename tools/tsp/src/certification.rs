use crate::manifest::ValidationError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;

pub const CERTIFICATION_POLICY_ID: &str = "com.tokensaver.plugin-certification";
pub const CERTIFICATION_POLICY_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CertificationLevel {
    Conformant = 1,
    Certified = 2,
    EnterpriseCertified = 3,
}

impl CertificationLevel {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn requirements(self) -> &'static [CertificationRequirement] {
        match self {
            Self::Conformant => &LEVEL_1_REQUIREMENTS,
            Self::Certified => &LEVEL_2_REQUIREMENTS,
            Self::EnterpriseCertified => &LEVEL_3_REQUIREMENTS,
        }
    }
}

impl TryFrom<u8> for CertificationLevel {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Conformant),
            2 => Ok(Self::Certified),
            3 => Ok(Self::EnterpriseCertified),
            _ => Err("certification level must be 1, 2, or 3"),
        }
    }
}

impl Serialize for CertificationLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for CertificationLevel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificationRequirement {
    ManifestValidation,
    TsppLifecycle,
    SafetyContract,
    PublicCorpusBenchmark,
    ProtocolFuzzing,
    ReproducibleBuild,
    SignedArtifact,
    Sbom,
    LicenseProvenance,
    AdminPolicyMetadata,
}

const LEVEL_1_REQUIREMENTS: [CertificationRequirement; 3] = [
    CertificationRequirement::ManifestValidation,
    CertificationRequirement::TsppLifecycle,
    CertificationRequirement::SafetyContract,
];

const LEVEL_2_REQUIREMENTS: [CertificationRequirement; 7] = [
    CertificationRequirement::ManifestValidation,
    CertificationRequirement::TsppLifecycle,
    CertificationRequirement::SafetyContract,
    CertificationRequirement::PublicCorpusBenchmark,
    CertificationRequirement::ProtocolFuzzing,
    CertificationRequirement::ReproducibleBuild,
    CertificationRequirement::SignedArtifact,
];

const LEVEL_3_REQUIREMENTS: [CertificationRequirement; 10] = [
    CertificationRequirement::ManifestValidation,
    CertificationRequirement::TsppLifecycle,
    CertificationRequirement::SafetyContract,
    CertificationRequirement::PublicCorpusBenchmark,
    CertificationRequirement::ProtocolFuzzing,
    CertificationRequirement::ReproducibleBuild,
    CertificationRequirement::SignedArtifact,
    CertificationRequirement::Sbom,
    CertificationRequirement::LicenseProvenance,
    CertificationRequirement::AdminPolicyMetadata,
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationSubject {
    pub plugin_id: String,
    pub version: String,
    pub platform: String,
    pub api_version: u32,
    pub artifact_digest: String,
    pub package_digest: String,
    pub release_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationAuthority {
    pub issuer_id: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub revocation_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationCheck {
    pub requirement: CertificationRequirement,
    pub ok: bool,
    pub rule: String,
    pub evidence_digest: String,
    pub detail: String,
    pub remediation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationReport {
    pub schema_version: u32,
    pub ok: bool,
    pub certification_level: CertificationLevel,
    pub subject: CertificationSubject,
    pub authority: CertificationAuthority,
    pub checks: Vec<CertificationCheck>,
}

/// Validates the versioned certification evidence contract and its immutable package subject.
///
/// This is structural compliance validation, not authorization. A caller must independently
/// authenticate the issuer and consult the revocation registry before trusting the report.
pub fn validate_certification_report(
    report: &CertificationReport,
    expected_subject: &CertificationSubject,
) -> Result<(), ValidationError> {
    validate_certification_report_contract(report, expected_subject, true)
}

/// Validates one immutable certification subject without accepting any issuer authority.
pub fn validate_certification_subject(
    subject: &CertificationSubject,
) -> Result<(), ValidationError> {
    validate_subject(subject)
}

pub(crate) fn validate_certification_report_structure(
    report: &CertificationReport,
    expected_subject: &CertificationSubject,
) -> Result<(), ValidationError> {
    validate_certification_report_contract(report, expected_subject, false)
}

fn validate_certification_report_contract(
    report: &CertificationReport,
    expected_subject: &CertificationSubject,
    require_success: bool,
) -> Result<(), ValidationError> {
    if report.schema_version != 1 {
        return Err(certification_error(
            "certification.schemaVersion",
            "certification report schemaVersion must be 1",
            "Regenerate evidence with a workbench that emits certification-report.v1.json.",
        ));
    }
    if &report.subject != expected_subject {
        return Err(certification_error(
            "certification.subject",
            "certification subject does not match the immutable package identity",
            "Use evidence issued for the exact plugin id, version, platform, API major, and package digest.",
        ));
    }
    validate_subject(&report.subject)?;
    validate_authority(&report.authority)?;

    let required = report
        .certification_level
        .requirements()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    let mut ordered = Vec::with_capacity(report.checks.len());
    let mut failed = None;
    for check in &report.checks {
        if !actual.insert(check.requirement) {
            return Err(certification_error(
                "certification.duplicateRequirement",
                "certification report contains a duplicate requirement",
                "Emit exactly one check for every requirement at the claimed level.",
            ));
        }
        if !valid_token(&check.rule, 1, 128)
            || !valid_digest(&check.evidence_digest)
            || !valid_text(&check.detail, 1, 1024)
            || !valid_text(&check.remediation, 1, 1024)
        {
            return Err(certification_error(
                "certification.checkContract",
                "certification check is missing a bounded rule, evidence digest, detail, or remediation",
                "Emit a stable rule id, SHA-256 evidence digest, human detail, and actionable remediation for every check.",
            ));
        }
        if !check.ok && failed.is_none() {
            failed = Some(check);
        }
        ordered.push(check.requirement);
    }
    if actual != required || ordered.as_slice() != report.certification_level.requirements() {
        return Err(certification_error(
            "certification.requirements",
            "certification report does not contain the exact prerequisite set for its claimed level",
            "Run every requirement for the claimed level, including all lower-level prerequisites.",
        ));
    }
    if require_success {
        if let Some(check) = failed {
            return Err(ValidationError::new(
                "certification.failedRule",
                format!(
                    "certification rule failed: {}; remediation: {}",
                    check.rule, check.remediation
                ),
                "Apply the reported remediation and rerun the complete certification pipeline.",
            ));
        }
    }
    if report.ok != failed.is_none() {
        return Err(certification_error(
            "certification.result",
            "certification report result does not match its requirement results",
            "Regenerate the report so its overall result matches its requirement results.",
        ));
    }
    Ok(())
}

pub(crate) fn validate_subject(subject: &CertificationSubject) -> Result<(), ValidationError> {
    if !valid_text(&subject.plugin_id, 1, 128)
        || !valid_text(&subject.version, 1, 128)
        || !valid_text(&subject.platform, 1, 64)
        || subject.api_version != 1
        || !valid_digest(&subject.artifact_digest)
        || !valid_digest(&subject.package_digest)
        || !crate::identity::valid_release_id(&subject.release_id)
        || subject.release_id
            != crate::identity::release_id(
                &subject.plugin_id,
                &subject.version,
                &subject.platform,
                &subject.artifact_digest,
            )
    {
        return Err(certification_error(
            "certification.subjectContract",
            "certification subject is not a valid immutable TSPP v1 package identity",
            "Record a bounded plugin id, version, platform, API major 1, and lowercase SHA-256 package digest.",
        ));
    }
    Ok(())
}

fn validate_authority(authority: &CertificationAuthority) -> Result<(), ValidationError> {
    if !valid_token(&authority.issuer_id, 1, 128)
        || authority.policy_id != CERTIFICATION_POLICY_ID
        || authority.policy_version != CERTIFICATION_POLICY_VERSION
        || !valid_token(&authority.revocation_id, 1, 128)
    {
        return Err(certification_error(
            "certification.authority",
            "certification authority or policy identity is invalid",
            "Use the current TokenSaver certification policy and immutable release and revocation ids from the trusted issuer.",
        ));
    }
    Ok(())
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

fn certification_error(
    code: &'static str,
    message: &'static str,
    remediation: &'static str,
) -> ValidationError {
    ValidationError::new(code, message, remediation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn subject() -> CertificationSubject {
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
        subject
    }

    fn report(level: CertificationLevel) -> CertificationReport {
        CertificationReport {
            schema_version: 1,
            ok: true,
            certification_level: level,
            subject: subject(),
            authority: CertificationAuthority {
                issuer_id: "com.tokensaver.registry".into(),
                policy_id: CERTIFICATION_POLICY_ID.into(),
                policy_version: CERTIFICATION_POLICY_VERSION,
                revocation_id: "revocation:0123456789abcdef".into(),
            },
            checks: level
                .requirements()
                .iter()
                .enumerate()
                .map(|(index, requirement)| CertificationCheck {
                    requirement: *requirement,
                    ok: true,
                    rule: format!("certification.rule{index}"),
                    evidence_digest: digest(char::from(b'a' + (index % 6) as u8)),
                    detail: "verified by the certification pipeline".into(),
                    remediation: "rerun the named certification pipeline stage".into(),
                })
                .collect(),
        }
    }

    #[test]
    fn all_levels_require_the_complete_hierarchy() {
        for level in [
            CertificationLevel::Conformant,
            CertificationLevel::Certified,
            CertificationLevel::EnterpriseCertified,
        ] {
            let report = report(level);
            validate_certification_report(&report, &subject()).expect("valid report");
        }
    }

    #[test]
    fn missing_duplicate_and_failed_requirements_are_rejected() {
        let mut missing = report(CertificationLevel::Certified);
        missing.checks.pop();
        assert_eq!(
            validate_certification_report(&missing, &subject())
                .expect_err("missing requirement")
                .code,
            "certification.requirements"
        );

        let mut reordered = report(CertificationLevel::Certified);
        reordered.checks.swap(0, 1);
        assert_eq!(
            validate_certification_report(&reordered, &subject())
                .expect_err("non-canonical requirement order")
                .code,
            "certification.requirements"
        );

        let mut duplicate = report(CertificationLevel::Certified);
        duplicate.checks.push(duplicate.checks[0].clone());
        assert_eq!(
            validate_certification_report(&duplicate, &subject())
                .expect_err("duplicate requirement")
                .code,
            "certification.duplicateRequirement"
        );

        let mut failed = report(CertificationLevel::Certified);
        failed.checks[0].ok = false;
        failed.ok = false;
        let error = validate_certification_report(&failed, &subject()).expect_err("failed rule");
        assert_eq!(error.code, "certification.failedRule");
        assert!(error.message.contains(&failed.checks[0].rule));
        assert!(error.message.contains(&failed.checks[0].remediation));

        let mut inconsistent = report(CertificationLevel::Conformant);
        inconsistent.ok = false;
        assert_eq!(
            validate_certification_report(&inconsistent, &subject())
                .expect_err("inconsistent result")
                .code,
            "certification.result"
        );
    }

    #[test]
    fn subject_policy_and_evidence_tampering_are_rejected() {
        let mut wrong_subject = subject();
        wrong_subject.package_digest = digest('f');
        assert_eq!(
            validate_certification_report(
                &report(CertificationLevel::EnterpriseCertified),
                &wrong_subject,
            )
            .expect_err("subject tampering")
            .code,
            "certification.subject"
        );

        let mut wrong_policy = report(CertificationLevel::Conformant);
        wrong_policy.authority.policy_version += 1;
        assert_eq!(
            validate_certification_report(&wrong_policy, &subject())
                .expect_err("wrong policy")
                .code,
            "certification.authority"
        );

        let mut bad_evidence = report(CertificationLevel::Conformant);
        bad_evidence.checks[0].evidence_digest = "sha256:not-a-digest".into();
        assert_eq!(
            validate_certification_report(&bad_evidence, &subject())
                .expect_err("bad evidence")
                .code,
            "certification.checkContract"
        );

        let mut bad_release = report(CertificationLevel::Conformant);
        bad_release.subject.release_id = format!("tsr1_{}", "f".repeat(64));
        let expected = bad_release.subject.clone();
        assert_eq!(
            validate_certification_report(&bad_release, &expected)
                .expect_err("release identity drift")
                .code,
            "certification.subjectContract"
        );
    }

    #[test]
    fn numeric_level_serialization_is_bounded() {
        assert_eq!(
            serde_json::to_string(&CertificationLevel::EnterpriseCertified).expect("serialize"),
            "3"
        );
        assert!(serde_json::from_str::<CertificationLevel>("0").is_err());
        assert!(serde_json::from_str::<CertificationLevel>("4").is_err());
    }
}
