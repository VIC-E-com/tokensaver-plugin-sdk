use crate::certification::{CertificationRequirement, CertificationSubject};
use crate::certification_pipeline::{
    CertificationEvidenceReference, CertificationStageEvidence, CertificationStageProducer,
    CertificationStageSubject, certification_rule, sha256_digest, validate_stage,
};
use crate::manifest::ValidationError;
use crate::superec::validate_unambiguous_json;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const MAX_SBOM_BYTES: usize = 16 << 20;
const MAX_SBOM_REPORT_BYTES: usize = 256 << 10;
const MAX_SBOM_POLICY_BYTES: usize = 64 << 10;
const MAX_LICENSE_REPORT_BYTES: usize = 256 << 10;
const MAX_LICENSE_POLICY_BYTES: usize = 128 << 10;
const MAX_COMPONENTS: usize = 100_000;
const MAX_LICENSE_IDS: usize = 512;
const CYCLONEDX_FORMAT: &str = "CycloneDX";
const CYCLONEDX_SPEC_VERSION: &str = "1.6";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationSbomPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub format: String,
    pub spec_version: String,
    pub maximum_components: u32,
    pub require_component_hashes: bool,
    pub require_component_licenses: bool,
    pub require_component_purls: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationSbomReport {
    pub schema_version: u32,
    pub subject: CertificationStageSubject,
    pub policy_digest: String,
    pub sbom_digest: String,
    pub format: String,
    pub spec_version: String,
    pub component_count: u32,
    pub components_with_sha256: u32,
    pub components_with_licenses: u32,
    pub components_with_purls: u32,
    pub generated_at_unix: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct CertificationSbomEvidence<'a> {
    pub package_bytes: &'a [u8],
    pub sbom_bytes: &'a [u8],
    pub report_bytes: &'a [u8],
    pub policy_bytes: &'a [u8],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationLicensePolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub allowed_spdx_ids: Vec<String>,
    pub denied_spdx_ids: Vec<String>,
    pub maximum_components: u32,
    pub require_all_components_licensed: bool,
    pub require_component_provenance: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationLicenseProvenanceReport {
    pub schema_version: u32,
    pub subject: CertificationStageSubject,
    pub sbom_digest: String,
    pub policy_digest: String,
    pub component_count: u32,
    pub licensed_components: u32,
    pub provenance_components: u32,
    pub denied_components: u32,
    pub unknown_license_components: u32,
    pub missing_license_components: u32,
    pub missing_provenance_components: u32,
    pub observed_spdx_ids: Vec<String>,
    pub reviewed_at_unix: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct CertificationLicenseEvidence<'a> {
    pub sbom_bytes: &'a [u8],
    pub report_bytes: &'a [u8],
    pub policy_bytes: &'a [u8],
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxBom {
    bom_format: String,
    spec_version: String,
    version: u64,
    metadata: CycloneDxMetadata,
    #[serde(default)]
    components: Vec<CycloneDxComponent>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxMetadata {
    component: CycloneDxComponent,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxComponent {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    #[serde(rename = "type")]
    component_type: String,
    name: String,
    version: String,
    #[serde(default)]
    hashes: Vec<CycloneDxHash>,
    #[serde(default)]
    licenses: Vec<CycloneDxLicenseChoice>,
    purl: Option<String>,
    #[serde(default)]
    components: Vec<CycloneDxComponent>,
}

#[derive(Clone, Debug, Deserialize)]
struct CycloneDxHash {
    alg: String,
    content: String,
}

#[derive(Clone, Debug, Deserialize)]
struct CycloneDxLicenseChoice {
    license: Option<CycloneDxLicense>,
    expression: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct CycloneDxLicense {
    id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SbomMetrics {
    component_count: u32,
    components_with_sha256: u32,
    components_with_licenses: u32,
    components_with_purls: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LicenseMetrics {
    component_count: u32,
    licensed_components: u32,
    provenance_components: u32,
    denied_components: u32,
    unknown_license_components: u32,
    missing_license_components: u32,
    missing_provenance_components: u32,
    observed_spdx_ids: Vec<String>,
}

/// Evaluate an exact CycloneDX 1.6 SBOM against a strict, digest-bound policy and report.
///
/// The evaluator parses evidence only. It performs no build, network, filesystem, package,
/// installation, provenance, permission, or activation action.
pub fn evaluate_sbom(
    evidence: CertificationSbomEvidence<'_>,
    subject: &CertificationSubject,
    producer: CertificationStageProducer,
    started_at_unix: u64,
    completed_at_unix: u64,
) -> Result<CertificationStageEvidence, ValidationError> {
    if evidence.package_bytes.is_empty()
        || sha256_digest(evidence.package_bytes) != subject.package_digest
    {
        return Err(supply_error(
            "certification.sbomPackage",
            "SBOM evidence is not bound to the immutable subject package bytes",
            "Use the exact package named by the certification subject.",
        ));
    }
    let policy: CertificationSbomPolicy = parse_document(
        evidence.policy_bytes,
        MAX_SBOM_POLICY_BYTES,
        "certification.sbomPolicySize",
        "certification.sbomPolicyJson",
        "SBOM policy",
        "schemas/certification-sbom-policy.v1.json",
    )?;
    validate_sbom_policy(&policy)?;
    let sbom = parse_sbom(evidence.sbom_bytes)?;
    validate_sbom_identity(&sbom, subject)?;
    let metrics = analyze_sbom(&sbom)?;
    let report: CertificationSbomReport = parse_document(
        evidence.report_bytes,
        MAX_SBOM_REPORT_BYTES,
        "certification.sbomReportSize",
        "certification.sbomReportJson",
        "SBOM report",
        "schemas/certification-sbom-report.v1.json",
    )?;
    validate_sbom_report(
        &report,
        &metrics,
        &policy,
        &evidence,
        subject,
        started_at_unix,
        completed_at_unix,
    )?;

    let ok = metrics.component_count <= policy.maximum_components
        && (!policy.require_component_hashes
            || metrics.components_with_sha256 == metrics.component_count)
        && (!policy.require_component_licenses
            || metrics.components_with_licenses == metrics.component_count)
        && (!policy.require_component_purls
            || metrics.components_with_purls == metrics.component_count);
    let detail = format!(
        "CycloneDX {} SBOM: {} components, {} with SHA-256, {} with licenses, {} with purls",
        sbom.spec_version,
        metrics.component_count,
        metrics.components_with_sha256,
        metrics.components_with_licenses,
        metrics.components_with_purls,
    );
    let stage = CertificationStageEvidence {
        schema_version: 1,
        requirement: CertificationRequirement::Sbom,
        subject: subject.into(),
        rule: certification_rule(CertificationRequirement::Sbom).into(),
        producer,
        started_at_unix,
        completed_at_unix,
        ok,
        inputs: vec![
            CertificationEvidenceReference {
                name: "plugin-package".into(),
                digest: subject.package_digest.clone(),
            },
            CertificationEvidenceReference {
                name: "sbom-policy".into(),
                digest: sha256_digest(evidence.policy_bytes),
            },
        ],
        outputs: vec![
            CertificationEvidenceReference {
                name: "sbom".into(),
                digest: sha256_digest(evidence.sbom_bytes),
            },
            CertificationEvidenceReference {
                name: "sbom-report".into(),
                digest: sha256_digest(evidence.report_bytes),
            },
        ],
        detail,
        remediation: if ok {
            "regenerate and review the exact SBOM for every immutable release"
        } else {
            "supply bounded CycloneDX components with SHA-256 hashes, SPDX licenses, and purl provenance required by policy"
        }
        .into(),
    };
    validate_stage(&stage, subject)?;
    Ok(stage)
}

/// Evaluate SPDX license allowlisting and component provenance from an exact accepted SBOM.
pub fn evaluate_license_provenance(
    evidence: CertificationLicenseEvidence<'_>,
    subject: &CertificationSubject,
    producer: CertificationStageProducer,
    started_at_unix: u64,
    completed_at_unix: u64,
) -> Result<CertificationStageEvidence, ValidationError> {
    let policy: CertificationLicensePolicy = parse_document(
        evidence.policy_bytes,
        MAX_LICENSE_POLICY_BYTES,
        "certification.licensePolicySize",
        "certification.licensePolicyJson",
        "license policy",
        "schemas/certification-license-policy.v1.json",
    )?;
    validate_license_policy(&policy)?;
    let sbom = parse_sbom(evidence.sbom_bytes)?;
    validate_sbom_identity(&sbom, subject)?;
    let metrics = analyze_licenses(&sbom, &policy)?;
    let report: CertificationLicenseProvenanceReport = parse_document(
        evidence.report_bytes,
        MAX_LICENSE_REPORT_BYTES,
        "certification.licenseReportSize",
        "certification.licenseReportJson",
        "license provenance report",
        "schemas/certification-license-provenance-report.v1.json",
    )?;
    validate_license_report(
        &report,
        &metrics,
        &evidence,
        subject,
        started_at_unix,
        completed_at_unix,
    )?;

    let ok = metrics.component_count <= policy.maximum_components
        && metrics.denied_components == 0
        && metrics.unknown_license_components == 0
        && (!policy.require_all_components_licensed || metrics.missing_license_components == 0)
        && (!policy.require_component_provenance || metrics.missing_provenance_components == 0);
    let detail = format!(
        "license provenance: {} components, {} licensed, {} with provenance, {} denied, {} unknown",
        metrics.component_count,
        metrics.licensed_components,
        metrics.provenance_components,
        metrics.denied_components,
        metrics.unknown_license_components,
    );
    let stage = CertificationStageEvidence {
        schema_version: 1,
        requirement: CertificationRequirement::LicenseProvenance,
        subject: subject.into(),
        rule: certification_rule(CertificationRequirement::LicenseProvenance).into(),
        producer,
        started_at_unix,
        completed_at_unix,
        ok,
        inputs: vec![
            CertificationEvidenceReference {
                name: "sbom".into(),
                digest: sha256_digest(evidence.sbom_bytes),
            },
            CertificationEvidenceReference {
                name: "license-policy".into(),
                digest: sha256_digest(evidence.policy_bytes),
            },
        ],
        outputs: vec![CertificationEvidenceReference {
            name: "license-provenance-report".into(),
            digest: sha256_digest(evidence.report_bytes),
        }],
        detail,
        remediation: if ok {
            "review the exact SBOM against the current license policy for every release"
        } else {
            "remove denied or unknown licenses and add SPDX license, purl, and SHA-256 provenance for every component"
        }
        .into(),
    };
    validate_stage(&stage, subject)?;
    Ok(stage)
}

fn parse_sbom(bytes: &[u8]) -> Result<CycloneDxBom, ValidationError> {
    parse_document(
        bytes,
        MAX_SBOM_BYTES,
        "certification.sbomSize",
        "certification.sbomJson",
        "CycloneDX SBOM",
        "CycloneDX 1.6 JSON",
    )
}

fn parse_document<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
    size_code: &'static str,
    json_code: &'static str,
    document_name: &str,
    schema_name: &str,
) -> Result<T, ValidationError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(supply_error(
            size_code,
            format!("{document_name} is empty or exceeds {maximum} bytes"),
            "Use one bounded certification evidence document.",
        ));
    }
    validate_unambiguous_json(bytes).map_err(|error| {
        supply_error(
            json_code,
            format!("{document_name} is ambiguous or invalid JSON: {error}"),
            "Remove duplicate members and trailing JSON from certification evidence.",
        )
    })?;
    serde_json::from_slice(bytes).map_err(|error| {
        supply_error(
            json_code,
            format!("{document_name} does not match {schema_name}: {error}"),
            "Use the exact versioned evidence contract.",
        )
    })
}

fn validate_sbom_policy(policy: &CertificationSbomPolicy) -> Result<(), ValidationError> {
    if policy.schema_version != 1
        || !valid_token(&policy.policy_id)
        || policy.format != CYCLONEDX_FORMAT
        || policy.spec_version != CYCLONEDX_SPEC_VERSION
        || policy.maximum_components == 0
        || policy.maximum_components as usize > MAX_COMPONENTS
        || !policy.require_component_hashes
        || !policy.require_component_licenses
        || !policy.require_component_purls
    {
        return Err(supply_error(
            "certification.sbomPolicy",
            "SBOM policy identity, format, component bound, or completeness requirements are invalid",
            "Require CycloneDX 1.6 and hashes, licenses, and purls for at most 100000 components.",
        ));
    }
    Ok(())
}

fn validate_license_policy(policy: &CertificationLicensePolicy) -> Result<(), ValidationError> {
    if policy.schema_version != 1
        || !valid_token(&policy.policy_id)
        || policy.allowed_spdx_ids.is_empty()
        || policy.allowed_spdx_ids.len() > MAX_LICENSE_IDS
        || policy.denied_spdx_ids.len() > MAX_LICENSE_IDS
        || policy.maximum_components == 0
        || policy.maximum_components as usize > MAX_COMPONENTS
        || !policy.require_all_components_licensed
        || !policy.require_component_provenance
        || !sorted_unique_spdx(&policy.allowed_spdx_ids)
        || !sorted_unique_spdx(&policy.denied_spdx_ids)
        || policy
            .allowed_spdx_ids
            .iter()
            .any(|id| policy.denied_spdx_ids.binary_search(id).is_ok())
    {
        return Err(supply_error(
            "certification.licensePolicy",
            "license policy identity, SPDX sets, component bound, or completeness requirements are invalid",
            "Use sorted disjoint SPDX allow and deny lists and require complete license and provenance evidence.",
        ));
    }
    Ok(())
}

fn validate_sbom_identity(
    sbom: &CycloneDxBom,
    subject: &CertificationSubject,
) -> Result<(), ValidationError> {
    let root = &sbom.metadata.component;
    if sbom.bom_format != CYCLONEDX_FORMAT
        || sbom.spec_version != CYCLONEDX_SPEC_VERSION
        || sbom.version == 0
        || root.component_type != "application"
        || root.bom_ref != subject.release_id
        || root.name != subject.plugin_id
        || root.version != subject.version
        || !has_sha256(root, &subject.package_digest)
    {
        return Err(supply_error(
            "certification.sbomSubject",
            "CycloneDX SBOM root does not identify the immutable certification subject package",
            "Bind the application root to release id, plugin id, version, and exact package SHA-256.",
        ));
    }
    Ok(())
}

fn analyze_sbom(sbom: &CycloneDxBom) -> Result<SbomMetrics, ValidationError> {
    let components = collect_components(sbom)?;
    let component_count = portable_count(components.len(), "certification.sbomComponents")?;
    Ok(SbomMetrics {
        component_count,
        components_with_sha256: portable_count(
            components
                .iter()
                .filter(|component| component_has_sha256(component))
                .count(),
            "certification.sbomComponents",
        )?,
        components_with_licenses: portable_count(
            components
                .iter()
                .filter(|component| component_has_spdx_license(component))
                .count(),
            "certification.sbomComponents",
        )?,
        components_with_purls: portable_count(
            components
                .iter()
                .filter(|component| valid_purl(component.purl.as_deref()))
                .count(),
            "certification.sbomComponents",
        )?,
    })
}

fn analyze_licenses(
    sbom: &CycloneDxBom,
    policy: &CertificationLicensePolicy,
) -> Result<LicenseMetrics, ValidationError> {
    let components = collect_components(sbom)?;
    let mut licensed_components = 0usize;
    let mut provenance_components = 0usize;
    let mut denied_components = 0usize;
    let mut unknown_license_components = 0usize;
    let mut missing_license_components = 0usize;
    let mut missing_provenance_components = 0usize;
    let mut observed_spdx_ids = BTreeSet::new();

    for component in &components {
        let ids = component_spdx_ids(component);
        if ids.is_empty() {
            missing_license_components += 1;
        } else {
            licensed_components += 1;
        }
        let mut denied = false;
        let mut unknown = component
            .licenses
            .iter()
            .any(|choice| choice.expression.is_some());
        for id in ids {
            observed_spdx_ids.insert(id.to_owned());
            if policy.denied_spdx_ids.binary_search(&id.to_owned()).is_ok() {
                denied = true;
            } else if policy
                .allowed_spdx_ids
                .binary_search(&id.to_owned())
                .is_err()
            {
                unknown = true;
            }
        }
        denied_components += usize::from(denied);
        unknown_license_components += usize::from(unknown);

        let has_provenance =
            component_has_sha256(component) && valid_purl(component.purl.as_deref());
        if has_provenance {
            provenance_components += 1;
        } else {
            missing_provenance_components += 1;
        }
    }

    Ok(LicenseMetrics {
        component_count: portable_count(components.len(), "certification.licenseComponents")?,
        licensed_components: portable_count(
            licensed_components,
            "certification.licenseComponents",
        )?,
        provenance_components: portable_count(
            provenance_components,
            "certification.licenseComponents",
        )?,
        denied_components: portable_count(denied_components, "certification.licenseComponents")?,
        unknown_license_components: portable_count(
            unknown_license_components,
            "certification.licenseComponents",
        )?,
        missing_license_components: portable_count(
            missing_license_components,
            "certification.licenseComponents",
        )?,
        missing_provenance_components: portable_count(
            missing_provenance_components,
            "certification.licenseComponents",
        )?,
        observed_spdx_ids: observed_spdx_ids.into_iter().collect(),
    })
}

fn collect_components(sbom: &CycloneDxBom) -> Result<Vec<&CycloneDxComponent>, ValidationError> {
    let mut result = Vec::new();
    let mut stack = Vec::new();
    let mut bom_refs = BTreeSet::new();
    stack.push(&sbom.metadata.component);
    stack.extend(sbom.components.iter().rev());
    while let Some(component) = stack.pop() {
        if result.len() >= MAX_COMPONENTS
            || !valid_component_identity(component)
            || !bom_refs.insert(component.bom_ref.as_str())
        {
            return Err(supply_error(
                "certification.sbomComponents",
                "CycloneDX components are oversized, duplicated, or missing stable identity",
                "Use at most 100000 components with unique bom-ref, type, name, and version.",
            ));
        }
        result.push(component);
        stack.extend(component.components.iter().rev());
    }
    Ok(result)
}

fn validate_sbom_report(
    report: &CertificationSbomReport,
    metrics: &SbomMetrics,
    policy: &CertificationSbomPolicy,
    evidence: &CertificationSbomEvidence<'_>,
    subject: &CertificationSubject,
    started_at_unix: u64,
    completed_at_unix: u64,
) -> Result<(), ValidationError> {
    if report.schema_version != 1
        || report.subject != CertificationStageSubject::from(subject)
        || report.policy_digest != sha256_digest(evidence.policy_bytes)
        || report.sbom_digest != sha256_digest(evidence.sbom_bytes)
        || report.format != policy.format
        || report.spec_version != policy.spec_version
        || report.component_count != metrics.component_count
        || report.components_with_sha256 != metrics.components_with_sha256
        || report.components_with_licenses != metrics.components_with_licenses
        || report.components_with_purls != metrics.components_with_purls
        || !valid_evidence_time(report.generated_at_unix, started_at_unix, completed_at_unix)
    {
        return Err(supply_error(
            "certification.sbomReport",
            "SBOM report subject, digests, counters, format, or generation time do not match exact evidence",
            "Regenerate the report from the exact package, SBOM, policy, and bounded stage time.",
        ));
    }
    Ok(())
}

fn validate_license_report(
    report: &CertificationLicenseProvenanceReport,
    metrics: &LicenseMetrics,
    evidence: &CertificationLicenseEvidence<'_>,
    subject: &CertificationSubject,
    started_at_unix: u64,
    completed_at_unix: u64,
) -> Result<(), ValidationError> {
    if report.schema_version != 1
        || report.subject != CertificationStageSubject::from(subject)
        || report.sbom_digest != sha256_digest(evidence.sbom_bytes)
        || report.policy_digest != sha256_digest(evidence.policy_bytes)
        || report.component_count != metrics.component_count
        || report.licensed_components != metrics.licensed_components
        || report.provenance_components != metrics.provenance_components
        || report.denied_components != metrics.denied_components
        || report.unknown_license_components != metrics.unknown_license_components
        || report.missing_license_components != metrics.missing_license_components
        || report.missing_provenance_components != metrics.missing_provenance_components
        || report.observed_spdx_ids != metrics.observed_spdx_ids
        || !valid_evidence_time(report.reviewed_at_unix, started_at_unix, completed_at_unix)
    {
        return Err(supply_error(
            "certification.licenseReport",
            "license report subject, digests, counters, SPDX ids, or review time do not match exact evidence",
            "Regenerate the report from the exact SBOM, policy, and bounded stage time.",
        ));
    }
    Ok(())
}

fn valid_evidence_time(value: u64, started_at_unix: u64, completed_at_unix: u64) -> bool {
    value != 0
        && started_at_unix != 0
        && completed_at_unix >= started_at_unix
        && value >= started_at_unix
        && value <= completed_at_unix
}

fn valid_component_identity(component: &CycloneDxComponent) -> bool {
    (1..=1_024).contains(&component.bom_ref.len())
        && component
            .bom_ref
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        && valid_token(&component.component_type)
        && valid_text(&component.name)
        && valid_text(&component.version)
}

fn component_has_sha256(component: &CycloneDxComponent) -> bool {
    component.hashes.iter().any(|hash| {
        hash.alg == "SHA-256"
            && hash.content.len() == 64
            && hash
                .content
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn has_sha256(component: &CycloneDxComponent, digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|expected| {
        component
            .hashes
            .iter()
            .any(|hash| hash.alg == "SHA-256" && hash.content == expected)
    })
}

fn component_has_spdx_license(component: &CycloneDxComponent) -> bool {
    !component_spdx_ids(component).is_empty()
}

fn component_spdx_ids(component: &CycloneDxComponent) -> Vec<&str> {
    component
        .licenses
        .iter()
        .filter_map(|choice| choice.license.as_ref()?.id.as_deref())
        .filter(|id| valid_spdx_id(id))
        .collect()
}

fn valid_purl(value: Option<&str>) -> bool {
    value.is_some_and(|purl| {
        (5..=512).contains(&purl.len())
            && purl.starts_with("pkg:")
            && purl.bytes().all(|byte| byte.is_ascii_graphic())
    })
}

fn sorted_unique_spdx(values: &[String]) -> bool {
    values.iter().all(|value| valid_spdx_id(value))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_spdx_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
}

fn valid_token(value: &str) -> bool {
    (1..=160).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
}

fn valid_text(value: &str) -> bool {
    (1..=512).contains(&value.len())
        && !value.contains('\0')
        && !value.chars().any(char::is_control)
}

fn portable_count(value: usize, code: &'static str) -> Result<u32, ValidationError> {
    u32::try_from(value).map_err(|_| {
        supply_error(
            code,
            "component count is not portable",
            "Use at most 100000 bounded components.",
        )
    })
}

fn supply_error(
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

    const PACKAGE: &[u8] = b"exact immutable plugin package";
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
            package_digest: sha256_digest(PACKAGE),
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
            id: "com.tokensaver.supply-chain-reviewer".into(),
            version: "1.0.0".into(),
            environment_digest: sha256_digest(b"trusted supply-chain review environment"),
        }
    }

    fn sbom_policy() -> CertificationSbomPolicy {
        CertificationSbomPolicy {
            schema_version: 1,
            policy_id: "com.tokensaver.certification.sbom.v1".into(),
            format: CYCLONEDX_FORMAT.into(),
            spec_version: CYCLONEDX_SPEC_VERSION.into(),
            maximum_components: 100,
            require_component_hashes: true,
            require_component_licenses: true,
            require_component_purls: true,
        }
    }

    fn license_policy() -> CertificationLicensePolicy {
        CertificationLicensePolicy {
            schema_version: 1,
            policy_id: "com.tokensaver.certification.license.v1".into(),
            allowed_spdx_ids: vec!["Apache-2.0".into(), "MIT".into()],
            denied_spdx_ids: vec!["GPL-3.0-only".into()],
            maximum_components: 100,
            require_all_components_licensed: true,
            require_component_provenance: true,
        }
    }

    fn component(
        bom_ref: &str,
        name: &str,
        version: &str,
        license_id: Option<&str>,
        purl: Option<&str>,
        hash: Option<&str>,
    ) -> Value {
        let mut component = json!({
            "type": "library",
            "bom-ref": bom_ref,
            "name": name,
            "version": version,
            "hashes": [],
            "licenses": []
        });
        if let Some(hash) = hash {
            component["hashes"] = json!([{ "alg": "SHA-256", "content": hash }]);
        }
        if let Some(license_id) = license_id {
            component["licenses"] = json!([{ "license": { "id": license_id } }]);
        }
        if let Some(purl) = purl {
            component["purl"] = json!(purl);
        }
        component
    }

    fn sbom_value(subject: &CertificationSubject) -> Value {
        let package_hash = subject
            .package_digest
            .strip_prefix("sha256:")
            .expect("package digest");
        json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:12345678-1234-4234-8234-123456789abc",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "bom-ref": subject.release_id,
                    "name": subject.plugin_id,
                    "version": subject.version,
                    "hashes": [{ "alg": "SHA-256", "content": package_hash }],
                    "licenses": [{ "license": { "id": "Apache-2.0" } }],
                    "purl": "pkg:generic/com.example.plugin@1.2.3"
                }
            },
            "components": [component(
                "pkg:cargo/example-dependency@2.0.0",
                "example-dependency",
                "2.0.0",
                Some("MIT"),
                Some("pkg:cargo/example-dependency@2.0.0"),
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            )]
        })
    }

    fn sbom_report(
        sbom_bytes: &[u8],
        policy_bytes: &[u8],
        subject: &CertificationSubject,
    ) -> CertificationSbomReport {
        let sbom = parse_sbom(sbom_bytes).expect("SBOM");
        let metrics = analyze_sbom(&sbom).expect("SBOM metrics");
        CertificationSbomReport {
            schema_version: 1,
            subject: subject.into(),
            policy_digest: sha256_digest(policy_bytes),
            sbom_digest: sha256_digest(sbom_bytes),
            format: CYCLONEDX_FORMAT.into(),
            spec_version: CYCLONEDX_SPEC_VERSION.into(),
            component_count: metrics.component_count,
            components_with_sha256: metrics.components_with_sha256,
            components_with_licenses: metrics.components_with_licenses,
            components_with_purls: metrics.components_with_purls,
            generated_at_unix: COMPLETED,
        }
    }

    fn license_report(
        sbom_bytes: &[u8],
        policy: &CertificationLicensePolicy,
        policy_bytes: &[u8],
        subject: &CertificationSubject,
    ) -> CertificationLicenseProvenanceReport {
        let sbom = parse_sbom(sbom_bytes).expect("SBOM");
        let metrics = analyze_licenses(&sbom, policy).expect("license metrics");
        CertificationLicenseProvenanceReport {
            schema_version: 1,
            subject: subject.into(),
            sbom_digest: sha256_digest(sbom_bytes),
            policy_digest: sha256_digest(policy_bytes),
            component_count: metrics.component_count,
            licensed_components: metrics.licensed_components,
            provenance_components: metrics.provenance_components,
            denied_components: metrics.denied_components,
            unknown_license_components: metrics.unknown_license_components,
            missing_license_components: metrics.missing_license_components,
            missing_provenance_components: metrics.missing_provenance_components,
            observed_spdx_ids: metrics.observed_spdx_ids,
            reviewed_at_unix: COMPLETED,
        }
    }

    fn evaluate_sbom_value(
        sbom: &Value,
        policy: &CertificationSbomPolicy,
    ) -> Result<CertificationStageEvidence, ValidationError> {
        let subject = subject();
        let sbom_bytes = serde_json::to_vec(sbom).expect("SBOM bytes");
        let policy_bytes = serde_json::to_vec(policy).expect("policy bytes");
        let report_bytes = serde_json::to_vec(&sbom_report(&sbom_bytes, &policy_bytes, &subject))
            .expect("report bytes");
        evaluate_sbom(
            CertificationSbomEvidence {
                package_bytes: PACKAGE,
                sbom_bytes: &sbom_bytes,
                report_bytes: &report_bytes,
                policy_bytes: &policy_bytes,
            },
            &subject,
            producer(),
            STARTED,
            COMPLETED,
        )
    }

    fn evaluate_license_value(
        sbom: &Value,
        policy: &CertificationLicensePolicy,
    ) -> Result<CertificationStageEvidence, ValidationError> {
        let subject = subject();
        let sbom_bytes = serde_json::to_vec(sbom).expect("SBOM bytes");
        let policy_bytes = serde_json::to_vec(policy).expect("policy bytes");
        let report_bytes = serde_json::to_vec(&license_report(
            &sbom_bytes,
            policy,
            &policy_bytes,
            &subject,
        ))
        .expect("report bytes");
        evaluate_license_provenance(
            CertificationLicenseEvidence {
                sbom_bytes: &sbom_bytes,
                report_bytes: &report_bytes,
                policy_bytes: &policy_bytes,
            },
            &subject,
            producer(),
            STARTED,
            COMPLETED,
        )
    }

    #[test]
    fn passing_sbom_binds_exact_package_policy_sbom_and_report() {
        let subject = subject();
        let sbom = sbom_value(&subject);
        let policy = sbom_policy();
        let sbom_bytes = serde_json::to_vec(&sbom).expect("SBOM bytes");
        let policy_bytes = serde_json::to_vec(&policy).expect("policy bytes");
        let report = sbom_report(&sbom_bytes, &policy_bytes, &subject);
        let report_bytes = serde_json::to_vec(&report).expect("report bytes");

        let stage = evaluate_sbom_value(&sbom, &policy).expect("SBOM evidence");
        assert!(stage.ok);
        assert_eq!(stage.inputs[0].digest, subject.package_digest);
        assert_eq!(stage.inputs[1].digest, sha256_digest(&policy_bytes));
        assert_eq!(stage.outputs[0].digest, sha256_digest(&sbom_bytes));
        assert_eq!(stage.outputs[1].digest, sha256_digest(&report_bytes));
        assert!(stage.detail.contains("2 components"));
    }

    #[test]
    fn incomplete_sbom_is_a_truthful_failed_stage() {
        let subject = subject();
        let mut sbom = sbom_value(&subject);
        sbom["components"][0]
            .as_object_mut()
            .expect("component")
            .remove("purl");
        let stage = evaluate_sbom_value(&sbom, &sbom_policy()).expect("truthful SBOM result");
        assert!(!stage.ok);
        assert!(stage.detail.contains("1 with purls"));
    }

    #[test]
    fn package_subject_and_report_drift_are_rejected() {
        let subject = subject();
        let sbom = sbom_value(&subject);
        let policy = sbom_policy();
        let sbom_bytes = serde_json::to_vec(&sbom).expect("SBOM bytes");
        let policy_bytes = serde_json::to_vec(&policy).expect("policy bytes");
        let mut report = sbom_report(&sbom_bytes, &policy_bytes, &subject);
        let report_bytes = serde_json::to_vec(&report).expect("report bytes");

        let error = evaluate_sbom(
            CertificationSbomEvidence {
                package_bytes: b"wrong package",
                sbom_bytes: &sbom_bytes,
                report_bytes: &report_bytes,
                policy_bytes: &policy_bytes,
            },
            &subject,
            producer(),
            STARTED,
            COMPLETED,
        )
        .expect_err("package drift");
        assert_eq!(error.code, "certification.sbomPackage");

        let mut wrong_subject_sbom = sbom;
        wrong_subject_sbom["metadata"]["component"]["version"] = json!("9.9.9");
        let wrong_subject_bytes =
            serde_json::to_vec(&wrong_subject_sbom).expect("wrong subject SBOM");
        report.sbom_digest = sha256_digest(&wrong_subject_bytes);
        let report_bytes = serde_json::to_vec(&report).expect("report bytes");
        let error = evaluate_sbom(
            CertificationSbomEvidence {
                package_bytes: PACKAGE,
                sbom_bytes: &wrong_subject_bytes,
                report_bytes: &report_bytes,
                policy_bytes: &policy_bytes,
            },
            &subject,
            producer(),
            STARTED,
            COMPLETED,
        )
        .expect_err("subject drift");
        assert_eq!(error.code, "certification.sbomSubject");

        let mut report = sbom_report(&sbom_bytes, &policy_bytes, &subject);
        report.components_with_sha256 -= 1;
        let report_bytes = serde_json::to_vec(&report).expect("report bytes");
        let error = evaluate_sbom(
            CertificationSbomEvidence {
                package_bytes: PACKAGE,
                sbom_bytes: &sbom_bytes,
                report_bytes: &report_bytes,
                policy_bytes: &policy_bytes,
            },
            &subject,
            producer(),
            STARTED,
            COMPLETED,
        )
        .expect_err("report drift");
        assert_eq!(error.code, "certification.sbomReport");
    }

    #[test]
    fn passing_license_review_recomputes_every_component() {
        let subject = subject();
        let sbom = sbom_value(&subject);
        let policy = license_policy();
        let sbom_bytes = serde_json::to_vec(&sbom).expect("SBOM bytes");
        let policy_bytes = serde_json::to_vec(&policy).expect("policy bytes");
        let report = license_report(&sbom_bytes, &policy, &policy_bytes, &subject);
        let report_bytes = serde_json::to_vec(&report).expect("report bytes");

        let stage = evaluate_license_value(&sbom, &policy).expect("license evidence");
        assert!(stage.ok);
        assert_eq!(stage.inputs[0].digest, sha256_digest(&sbom_bytes));
        assert_eq!(stage.inputs[1].digest, sha256_digest(&policy_bytes));
        assert_eq!(stage.outputs[0].digest, sha256_digest(&report_bytes));
        assert_eq!(report.observed_spdx_ids, ["Apache-2.0", "MIT"]);
    }

    #[test]
    fn denied_unknown_missing_and_unprovenanced_components_fail_truthfully() {
        let subject = subject();
        let mutations: [fn(&mut Value); 4] = [
            |sbom| sbom["components"][0]["licenses"][0]["license"]["id"] = json!("GPL-3.0-only"),
            |sbom| {
                sbom["components"][0]["licenses"] =
                    json!([{ "license": { "id": "LicenseRef-Unknown" } }])
            },
            |sbom| sbom["components"][0]["licenses"] = json!([]),
            |sbom| {
                sbom["components"][0]
                    .as_object_mut()
                    .expect("component")
                    .remove("purl");
            },
        ];
        for mutate in mutations {
            let mut sbom = sbom_value(&subject);
            mutate(&mut sbom);
            let stage =
                evaluate_license_value(&sbom, &license_policy()).expect("truthful license result");
            assert!(!stage.ok);
        }
    }

    #[test]
    fn license_report_policy_and_component_identity_tampering_fail_closed() {
        let subject = subject();
        let sbom = sbom_value(&subject);
        let policy = license_policy();
        let sbom_bytes = serde_json::to_vec(&sbom).expect("SBOM bytes");
        let policy_bytes = serde_json::to_vec(&policy).expect("policy bytes");
        let mut report = license_report(&sbom_bytes, &policy, &policy_bytes, &subject);
        report.provenance_components -= 1;
        let report_bytes = serde_json::to_vec(&report).expect("report bytes");
        assert_eq!(
            evaluate_license_provenance(
                CertificationLicenseEvidence {
                    sbom_bytes: &sbom_bytes,
                    report_bytes: &report_bytes,
                    policy_bytes: &policy_bytes,
                },
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
            .expect_err("report drift")
            .code,
            "certification.licenseReport"
        );

        let mut bad_policy = policy;
        bad_policy.allowed_spdx_ids.reverse();
        assert_eq!(
            evaluate_license_value(&sbom, &bad_policy)
                .expect_err("unsorted policy")
                .code,
            "certification.licensePolicy"
        );

        let mut duplicate = sbom;
        duplicate["components"][0]["bom-ref"] = json!(subject.release_id);
        let duplicate_bytes = serde_json::to_vec(&duplicate).expect("duplicate SBOM bytes");
        let valid_sbom = sbom_value(&subject);
        let valid_sbom_bytes = serde_json::to_vec(&valid_sbom).expect("valid SBOM bytes");
        let valid_policy = license_policy();
        let valid_policy_bytes =
            serde_json::to_vec(&valid_policy).expect("valid license policy bytes");
        let valid_report_bytes = serde_json::to_vec(&license_report(
            &valid_sbom_bytes,
            &valid_policy,
            &valid_policy_bytes,
            &subject,
        ))
        .expect("valid license report bytes");
        assert_eq!(
            evaluate_license_provenance(
                CertificationLicenseEvidence {
                    sbom_bytes: &duplicate_bytes,
                    report_bytes: &valid_report_bytes,
                    policy_bytes: &valid_policy_bytes,
                },
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
            .expect_err("duplicate bom-ref")
            .code,
            "certification.sbomComponents"
        );
    }

    #[test]
    fn ambiguous_unknown_and_oversized_evidence_are_rejected() {
        let subject = subject();
        let sbom = sbom_value(&subject);
        let sbom_bytes = serde_json::to_vec(&sbom).expect("SBOM bytes");
        let policy = sbom_policy();
        let policy_bytes = serde_json::to_vec(&policy).expect("policy bytes");
        let report_bytes = serde_json::to_vec(&sbom_report(&sbom_bytes, &policy_bytes, &subject))
            .expect("report bytes");
        let duplicate_policy = br#"{"schemaVersion":1,"schemaVersion":1}"#;
        let unknown_report = br#"{"schemaVersion":1,"unknownSecurityField":true}"#;

        let evaluate_bytes = |sbom_bytes: &[u8], report_bytes: &[u8], policy_bytes: &[u8]| {
            evaluate_sbom(
                CertificationSbomEvidence {
                    package_bytes: PACKAGE,
                    sbom_bytes,
                    report_bytes,
                    policy_bytes,
                },
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
        };

        assert_eq!(
            evaluate_bytes(&sbom_bytes, &report_bytes, duplicate_policy)
                .expect_err("duplicate policy")
                .code,
            "certification.sbomPolicyJson"
        );
        assert_eq!(
            evaluate_bytes(&sbom_bytes, unknown_report, &policy_bytes)
                .expect_err("unknown report field")
                .code,
            "certification.sbomReportJson"
        );
        assert_eq!(
            evaluate_bytes(
                &vec![b' '; MAX_SBOM_BYTES + 1],
                &report_bytes,
                &policy_bytes,
            )
            .expect_err("oversized SBOM")
            .code,
            "certification.sbomSize"
        );
    }
}
