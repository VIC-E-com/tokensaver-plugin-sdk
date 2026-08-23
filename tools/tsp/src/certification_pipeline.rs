use crate::bench::{BenchReport, LatencySummary};
use crate::certification::{
    CertificationAuthority, CertificationCheck, CertificationLevel, CertificationReport,
    CertificationRequirement, CertificationSubject, validate_certification_report_structure,
};
use crate::manifest::ValidationError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_STAGE_EVIDENCE_BYTES: usize = 2 << 20;
const MAX_PIPELINE_EVIDENCE_BYTES: usize = 16 << 20;
const MAX_STAGE_REFERENCES: usize = 32;
const MAX_STAGE_DURATION_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_BENCHMARK_REPORT_BYTES: usize = 8 << 20;
const MAX_BENCHMARK_POLICY_BYTES: usize = 64 << 10;
const MAX_BENCHMARK_CASES: usize = 100_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationStageSubject {
    pub plugin_id: String,
    pub version: String,
    pub platform: String,
    pub api_version: u32,
    pub artifact_digest: String,
    pub package_digest: String,
    pub release_id: String,
}

impl From<&CertificationSubject> for CertificationStageSubject {
    fn from(subject: &CertificationSubject) -> Self {
        Self {
            plugin_id: subject.plugin_id.clone(),
            version: subject.version.clone(),
            platform: subject.platform.clone(),
            api_version: subject.api_version,
            artifact_digest: subject.artifact_digest.clone(),
            package_digest: subject.package_digest.clone(),
            release_id: subject.release_id.clone(),
        }
    }
}

impl CertificationStageSubject {
    fn matches(&self, subject: &CertificationSubject) -> bool {
        self == &Self::from(subject)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationStageProducer {
    pub id: String,
    pub version: String,
    pub environment_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationEvidenceReference {
    pub name: String,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationStageEvidence {
    pub schema_version: u32,
    pub requirement: CertificationRequirement,
    pub subject: CertificationStageSubject,
    pub rule: String,
    pub producer: CertificationStageProducer,
    pub started_at_unix: u64,
    pub completed_at_unix: u64,
    pub ok: bool,
    pub inputs: Vec<CertificationEvidenceReference>,
    pub outputs: Vec<CertificationEvidenceReference>,
    pub detail: String,
    pub remediation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationBenchmarkPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub corpus_id: String,
    pub corpus_digest: String,
    pub minimum_cases: u64,
    pub minimum_iterations: u32,
    pub minimum_input_bytes: u64,
    pub minimum_savings_basis_points: u32,
    pub maximum_p95_latency_us: u64,
}

/// Stable rule identity for a cumulative certification requirement.
pub const fn certification_rule(requirement: CertificationRequirement) -> &'static str {
    match requirement {
        CertificationRequirement::ManifestValidation => {
            "certification.level1.manifest-validation.v1"
        }
        CertificationRequirement::TsppLifecycle => "certification.level1.tspp-lifecycle.v1",
        CertificationRequirement::SafetyContract => "certification.level1.safety-contract.v1",
        CertificationRequirement::PublicCorpusBenchmark => {
            "certification.level2.public-corpus-benchmark.v1"
        }
        CertificationRequirement::ProtocolFuzzing => "certification.level2.protocol-fuzzing.v1",
        CertificationRequirement::ReproducibleBuild => "certification.level2.reproducible-build.v1",
        CertificationRequirement::SignedArtifact => "certification.level2.signed-artifact.v1",
        CertificationRequirement::Sbom => "certification.level3.sbom.v1",
        CertificationRequirement::LicenseProvenance => "certification.level3.license-provenance.v1",
        CertificationRequirement::AdminPolicyMetadata => {
            "certification.level3.admin-policy-metadata.v1"
        }
    }
}

/// Evaluates exact public-corpus benchmark bytes against an exact versioned policy document.
pub fn evaluate_public_corpus_benchmark(
    benchmark_report_bytes: &[u8],
    benchmark_policy_bytes: &[u8],
    subject: &CertificationSubject,
    producer: CertificationStageProducer,
    started_at_unix: u64,
    completed_at_unix: u64,
) -> Result<CertificationStageEvidence, ValidationError> {
    let report = parse_benchmark_report(benchmark_report_bytes)?;
    validate_benchmark_report(&report, subject)?;
    let policy = parse_benchmark_policy(benchmark_policy_bytes)?;
    validate_benchmark_policy(&policy)?;

    let case_count = u64::try_from(report.cases.len()).map_err(|_| {
        pipeline_error(
            "certification.benchmarkReport",
            "benchmark case count is not portable",
            "Use a bounded public corpus with at most 100000 cases.",
        )
    })?;
    let input_bytes = u64::try_from(report.totals.input_bytes).map_err(|_| {
        pipeline_error(
            "certification.benchmarkReport",
            "benchmark input byte count is not portable",
            "Use a benchmark report with unsigned 64-bit byte totals.",
        )
    })?;
    let savings_basis_points =
        savings_basis_points(report.totals.saved_bytes, report.totals.input_bytes)?;
    let p95_latency_us = u64::try_from(report.totals.latency_us.p95_us).map_err(|_| {
        pipeline_error(
            "certification.benchmarkReport",
            "benchmark p95 latency is not portable",
            "Use an unsigned 64-bit microsecond latency value.",
        )
    })?;
    let ok = case_count >= policy.minimum_cases
        && report.iterations >= policy.minimum_iterations
        && input_bytes >= policy.minimum_input_bytes
        && savings_basis_points >= policy.minimum_savings_basis_points
        && p95_latency_us <= policy.maximum_p95_latency_us;
    let detail = format!(
        "public corpus {}: {} cases, {} iterations, {} input bytes, {}.{:02}% weighted savings, {} us p95 latency",
        policy.corpus_id,
        case_count,
        report.iterations,
        input_bytes,
        savings_basis_points / 100,
        savings_basis_points % 100,
        p95_latency_us
    );
    let remediation = if ok {
        "rerun the exact public corpus and policy for every release"
    } else {
        "meet every case, iteration, input-size, weighted-savings, and p95-latency threshold in the named policy"
    };
    let stage = CertificationStageEvidence {
        schema_version: 1,
        requirement: CertificationRequirement::PublicCorpusBenchmark,
        subject: subject.into(),
        rule: certification_rule(CertificationRequirement::PublicCorpusBenchmark).into(),
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
                name: "public-corpus".into(),
                digest: policy.corpus_digest,
            },
            CertificationEvidenceReference {
                name: "benchmark-policy".into(),
                digest: sha256_digest(benchmark_policy_bytes),
            },
        ],
        outputs: vec![CertificationEvidenceReference {
            name: "benchmark-report".into(),
            digest: sha256_digest(benchmark_report_bytes),
        }],
        detail,
        remediation: remediation.into(),
    };
    validate_stage(&stage, subject)?;
    Ok(stage)
}

/// Assembles exact stage evidence into a deterministic unsigned certification report.
///
/// This function does not run stages, sign evidence, authenticate an issuer, assign provenance,
/// install, or activate a plugin. Only a separately trusted issuer can authorize the resulting
/// report by signing its exact bytes and distributing current revocation evidence.
pub fn assemble_certification_report(
    level: CertificationLevel,
    subject: &CertificationSubject,
    authority: CertificationAuthority,
    stage_documents: &[Vec<u8>],
) -> Result<CertificationReport, ValidationError> {
    let requirements = level.requirements();
    if stage_documents.len() != requirements.len() {
        return Err(pipeline_error(
            "certification.pipelineRequirements",
            "certification pipeline evidence does not contain the exact cumulative stage count",
            "Provide one versioned stage document for every requirement at the claimed level.",
        ));
    }
    let total_bytes = stage_documents
        .iter()
        .try_fold(0usize, |total, document| total.checked_add(document.len()))
        .ok_or_else(|| {
            pipeline_error(
                "certification.pipelineSize",
                "certification pipeline evidence size overflowed",
                "Use bounded stage documents from the trusted certification pipeline.",
            )
        })?;
    if total_bytes > MAX_PIPELINE_EVIDENCE_BYTES {
        return Err(pipeline_error(
            "certification.pipelineSize",
            "certification pipeline evidence exceeds the 16 MiB aggregate limit",
            "Keep exact cumulative stage evidence within 16 MiB.",
        ));
    }

    let mut stages = Vec::with_capacity(stage_documents.len());
    let mut checks = Vec::with_capacity(stage_documents.len());
    for (index, (document, expected_requirement)) in stage_documents
        .iter()
        .zip(requirements.iter().copied())
        .enumerate()
    {
        let stage = parse_stage_document(document)?;
        if stage.requirement != expected_requirement {
            return Err(ValidationError::new(
                "certification.pipelineOrder",
                format!(
                    "certification stage {} is {:?}, expected {:?}",
                    index, stage.requirement, expected_requirement
                ),
                "Emit every cumulative requirement once in canonical certification-level order.",
            ));
        }
        validate_stage(&stage, subject)?;
        checks.push(CertificationCheck {
            requirement: stage.requirement,
            ok: stage.ok,
            rule: stage.rule.clone(),
            evidence_digest: sha256_digest(document),
            detail: stage.detail.clone(),
            remediation: stage.remediation.clone(),
        });
        stages.push(stage);
    }
    validate_cross_stage_bindings(&stages)?;

    let report = CertificationReport {
        schema_version: 1,
        ok: checks.iter().all(|check| check.ok),
        certification_level: level,
        subject: subject.clone(),
        authority,
        checks,
    };
    validate_certification_report_structure(&report, subject)?;
    Ok(report)
}

fn parse_benchmark_report(bytes: &[u8]) -> Result<BenchReport, ValidationError> {
    if bytes.is_empty() || bytes.len() > MAX_BENCHMARK_REPORT_BYTES {
        return Err(pipeline_error(
            "certification.benchmarkReportSize",
            "benchmark report is empty or exceeds the 8 MiB certification limit",
            "Use one bounded benchmark-report.v1.json document.",
        ));
    }
    crate::superec::validate_unambiguous_json(bytes).map_err(|error| {
        ValidationError::new(
            "certification.benchmarkReportJson",
            format!("benchmark report is not unambiguous JSON: {error}"),
            "Remove duplicate members and trailing JSON from benchmark evidence.",
        )
    })?;
    serde_json::from_slice(bytes).map_err(|error| {
        ValidationError::new(
            "certification.benchmarkReportJson",
            format!("benchmark report does not match its v1 contract: {error}"),
            "Use schemas/benchmark-report.v1.json.",
        )
    })
}

fn parse_benchmark_policy(bytes: &[u8]) -> Result<CertificationBenchmarkPolicy, ValidationError> {
    if bytes.is_empty() || bytes.len() > MAX_BENCHMARK_POLICY_BYTES {
        return Err(pipeline_error(
            "certification.benchmarkPolicySize",
            "benchmark policy is empty or exceeds the 64 KiB certification limit",
            "Use one bounded certification-benchmark-policy.v1.json document.",
        ));
    }
    crate::superec::validate_unambiguous_json(bytes).map_err(|error| {
        ValidationError::new(
            "certification.benchmarkPolicyJson",
            format!("benchmark policy is not unambiguous JSON: {error}"),
            "Remove duplicate members and trailing JSON from benchmark policy.",
        )
    })?;
    serde_json::from_slice(bytes).map_err(|error| {
        ValidationError::new(
            "certification.benchmarkPolicyJson",
            format!("benchmark policy does not match its v1 contract: {error}"),
            "Use schemas/certification-benchmark-policy.v1.json without unknown fields.",
        )
    })
}

fn validate_benchmark_policy(policy: &CertificationBenchmarkPolicy) -> Result<(), ValidationError> {
    if policy.schema_version != 1
        || !valid_token(&policy.policy_id)
        || !valid_token(&policy.corpus_id)
        || !valid_digest(&policy.corpus_digest)
        || !(1..=MAX_BENCHMARK_CASES as u64).contains(&policy.minimum_cases)
        || !(1..=crate::bench::MAX_ITERATIONS).contains(&policy.minimum_iterations)
        || policy.minimum_input_bytes == 0
        || policy.minimum_savings_basis_points > 10_000
        || !(1..=60_000_000).contains(&policy.maximum_p95_latency_us)
    {
        return Err(pipeline_error(
            "certification.benchmarkPolicy",
            "benchmark certification policy identity or thresholds are invalid",
            "Use bounded v1 public-corpus thresholds with basis-point savings and microsecond latency.",
        ));
    }
    Ok(())
}

fn validate_benchmark_report(
    report: &BenchReport,
    subject: &CertificationSubject,
) -> Result<(), ValidationError> {
    if report.schema_version != 1
        || !report.ok
        || report.plugin_id != subject.plugin_id
        || report.version != subject.version
        || report.platform != subject.platform
        || report.release_id != subject.release_id
        || report.artifact_digest != subject.artifact_digest
        || !(1..=crate::bench::MAX_ITERATIONS).contains(&report.iterations)
        || report.cases.is_empty()
        || report.cases.len() > MAX_BENCHMARK_CASES
        || !valid_benchmark_text(&report.fixture_directory, 4096)
        || report.duration_ms > u128::from(MAX_STAGE_DURATION_SECONDS) * 1_000
    {
        return Err(pipeline_error(
            "certification.benchmarkReport",
            "benchmark report identity, version, corpus size, or duration is invalid",
            "Run the bounded v1 benchmark against the exact immutable plugin release.",
        ));
    }

    let mut names = BTreeSet::new();
    let mut expected_input = 0usize;
    let mut expected_output = 0usize;
    let mut expected_pass = 0usize;
    let mut expected_optimize = 0usize;
    for case in &report.cases {
        if !valid_benchmark_text(&case.name, 256)
            || !valid_benchmark_text(&case.path, 4096)
            || !names.insert(case.name.as_str())
            || case.iterations != report.iterations
            || case.input_bytes == 0
            || case.output_bytes > case.input_bytes
            || case.saved_bytes != case.input_bytes - case.output_bytes
            || !percentage_matches(case.savings_percent, case.saved_bytes, case.input_bytes)
            || case.activation_attempt_ids.len() != report.iterations as usize
            || case
                .activation_attempt_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != case.activation_attempt_ids.len()
            || case
                .activation_attempt_ids
                .iter()
                .any(|id| !crate::identity::valid_activation_attempt_id(id))
            || !valid_latency(&case.latency_us)
        {
            return Err(pipeline_error(
                "certification.benchmarkCase",
                "benchmark case identity, accounting, activation ids, or latency is invalid",
                "Regenerate the benchmark report from deterministic golden fixtures.",
            ));
        }
        match case.action {
            crate::protocol::OptimizeAction::Pass if case.output_bytes != case.input_bytes => {
                return Err(pipeline_error(
                    "certification.benchmarkCase",
                    "a pass benchmark case changed the output byte count",
                    "Regenerate the report with host-verified pass behavior.",
                ));
            }
            crate::protocol::OptimizeAction::Optimize
                if case.output_bytes == 0
                    || (case.output_bytes as u128) * 100 > (case.input_bytes as u128) * 80 =>
            {
                return Err(pipeline_error(
                    "certification.benchmarkCase",
                    "an optimized benchmark case violates the host safety reduction threshold",
                    "Regenerate the report with non-empty output at least 20 percent smaller.",
                ));
            }
            crate::protocol::OptimizeAction::Pass => {
                expected_pass = expected_pass.saturating_add(report.iterations as usize);
            }
            crate::protocol::OptimizeAction::Optimize => {
                expected_optimize = expected_optimize.saturating_add(report.iterations as usize);
            }
        }
        expected_input = expected_input
            .checked_add(
                case.input_bytes
                    .checked_mul(report.iterations as usize)
                    .ok_or_else(benchmark_accounting_overflow)?,
            )
            .ok_or_else(benchmark_accounting_overflow)?;
        expected_output = expected_output
            .checked_add(
                case.output_bytes
                    .checked_mul(report.iterations as usize)
                    .ok_or_else(benchmark_accounting_overflow)?,
            )
            .ok_or_else(benchmark_accounting_overflow)?;
    }
    let expected_samples = report
        .cases
        .len()
        .checked_mul(report.iterations as usize)
        .ok_or_else(benchmark_accounting_overflow)?;
    let expected_saved = expected_input.saturating_sub(expected_output);
    if report.totals.samples != expected_samples
        || report.totals.input_bytes != expected_input
        || report.totals.output_bytes != expected_output
        || report.totals.saved_bytes != expected_saved
        || report.totals.pass_samples != expected_pass
        || report.totals.optimize_samples != expected_optimize
        || expected_pass.saturating_add(expected_optimize) != expected_samples
        || !percentage_matches(
            report.totals.savings_percent,
            expected_saved,
            expected_input,
        )
        || !valid_latency(&report.totals.latency_us)
    {
        return Err(pipeline_error(
            "certification.benchmarkTotals",
            "benchmark totals do not exactly match their case accounting",
            "Regenerate totals directly from the repeated golden benchmark samples.",
        ));
    }
    Ok(())
}

fn valid_latency(latency: &LatencySummary) -> bool {
    latency.minimum_us <= latency.p50_us
        && latency.p50_us <= latency.p95_us
        && latency.p95_us <= latency.p99_us
        && latency.p99_us <= latency.maximum_us
        && (latency.minimum_us..=latency.maximum_us).contains(&latency.mean_us)
}

fn percentage_matches(value: f64, saved: usize, input: usize) -> bool {
    if !value.is_finite() || !(0.0..=100.0).contains(&value) || input == 0 {
        return false;
    }
    let expected = saved as f64 * 100.0 / input as f64;
    (value - expected).abs() <= f64::EPSILON * expected.abs().max(1.0) * 8.0
}

fn savings_basis_points(saved: usize, input: usize) -> Result<u32, ValidationError> {
    if input == 0 || saved > input {
        return Err(pipeline_error(
            "certification.benchmarkTotals",
            "benchmark byte totals cannot produce a savings rate",
            "Regenerate benchmark totals from non-empty public-corpus input.",
        ));
    }
    let basis_points = (saved as u128)
        .checked_mul(10_000)
        .and_then(|value| value.checked_div(input as u128))
        .ok_or_else(benchmark_accounting_overflow)?;
    u32::try_from(basis_points).map_err(|_| benchmark_accounting_overflow())
}

fn valid_benchmark_text(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len())
        && !value.contains('\0')
        && !value.chars().any(char::is_control)
}

fn benchmark_accounting_overflow() -> ValidationError {
    pipeline_error(
        "certification.benchmarkAccounting",
        "benchmark accounting overflowed a portable integer",
        "Use bounded public-corpus cases and sample counts.",
    )
}

fn parse_stage_document(bytes: &[u8]) -> Result<CertificationStageEvidence, ValidationError> {
    if bytes.is_empty() || bytes.len() > MAX_STAGE_EVIDENCE_BYTES {
        return Err(pipeline_error(
            "certification.stageSize",
            "certification stage evidence is empty or exceeds the 2 MiB limit",
            "Use one bounded certification-stage-evidence.v1.json document.",
        ));
    }
    crate::superec::validate_unambiguous_json(bytes).map_err(|error| {
        ValidationError::new(
            "certification.stageJson",
            format!("certification stage evidence is not unambiguous JSON: {error}"),
            "Remove duplicate members and trailing JSON from stage evidence.",
        )
    })?;
    serde_json::from_slice(bytes).map_err(|error| {
        ValidationError::new(
            "certification.stageJson",
            format!("certification stage evidence does not match its v1 contract: {error}"),
            "Use schemas/certification-stage-evidence.v1.json without unknown security fields.",
        )
    })
}

pub(crate) fn validate_stage(
    stage: &CertificationStageEvidence,
    expected_subject: &CertificationSubject,
) -> Result<(), ValidationError> {
    crate::certification::validate_subject(expected_subject)?;
    if stage.schema_version != 1
        || !stage.subject.matches(expected_subject)
        || stage.rule != certification_rule(stage.requirement)
        || !valid_token(&stage.producer.id)
        || !valid_token(&stage.producer.version)
        || !valid_digest(&stage.producer.environment_digest)
        || stage.started_at_unix == 0
        || stage.completed_at_unix < stage.started_at_unix
        || stage
            .completed_at_unix
            .saturating_sub(stage.started_at_unix)
            > MAX_STAGE_DURATION_SECONDS
        || !valid_text(&stage.detail)
        || !valid_text(&stage.remediation)
    {
        return Err(pipeline_error(
            "certification.stageContract",
            "certification stage identity, producer, timing, rule, or text is invalid",
            "Use the exact subject, stable requirement rule, bounded producer, and a stage duration no longer than seven days.",
        ));
    }
    validate_references(&stage.inputs)?;
    validate_references(&stage.outputs)?;
    validate_stage_layout(stage)?;
    validate_subject_bindings(stage, expected_subject)
}

fn validate_references(
    references: &[CertificationEvidenceReference],
) -> Result<(), ValidationError> {
    if references.is_empty() || references.len() > MAX_STAGE_REFERENCES {
        return Err(pipeline_error(
            "certification.stageReferences",
            "certification stage reference count is invalid",
            "Use 1 to 32 canonical named input and output digests.",
        ));
    }
    let mut names = BTreeSet::new();
    for reference in references {
        if !valid_token(&reference.name)
            || !valid_digest(&reference.digest)
            || !names.insert(reference.name.as_str())
        {
            return Err(pipeline_error(
                "certification.stageReferences",
                "certification stage contains an invalid or duplicate evidence reference",
                "Use unique stable names and lowercase SHA-256 digests for every reference.",
            ));
        }
    }
    Ok(())
}

fn validate_stage_layout(stage: &CertificationStageEvidence) -> Result<(), ValidationError> {
    let (inputs, outputs): (&[&str], &[&str]) = match stage.requirement {
        CertificationRequirement::ManifestValidation => {
            (&["plugin-manifest"], &["manifest-validation-report"])
        }
        CertificationRequirement::TsppLifecycle => {
            (&["plugin-executable"], &["tspp-lifecycle-report"])
        }
        CertificationRequirement::SafetyContract => {
            (&["plugin-executable"], &["safety-contract-report"])
        }
        CertificationRequirement::PublicCorpusBenchmark => (
            &["plugin-package", "public-corpus", "benchmark-policy"],
            &["benchmark-report"],
        ),
        CertificationRequirement::ProtocolFuzzing => (
            &["plugin-executable", "protocol-corpus", "fuzz-policy"],
            &["fuzz-report"],
        ),
        CertificationRequirement::ReproducibleBuild => (
            &["plugin-package", "source-tree", "build-policy"],
            &["build-report", "rebuilt-package-a", "rebuilt-package-b"],
        ),
        CertificationRequirement::SignedArtifact => (
            &[
                "plugin-executable",
                "signature-policy",
                "artifact-trust-store",
            ],
            &["artifact-signature"],
        ),
        CertificationRequirement::Sbom => {
            (&["plugin-package", "sbom-policy"], &["sbom", "sbom-report"])
        }
        CertificationRequirement::LicenseProvenance => {
            (&["sbom", "license-policy"], &["license-provenance-report"])
        }
        CertificationRequirement::AdminPolicyMetadata => {
            (&["plugin-manifest"], &["admin-policy-metadata"])
        }
    };
    if !reference_names_match(&stage.inputs, inputs)
        || !reference_names_match(&stage.outputs, outputs)
    {
        return Err(pipeline_error(
            "certification.stageLayout",
            "certification stage does not contain the exact canonical input and output references",
            "Use the versioned reference names and order required for this certification stage.",
        ));
    }
    Ok(())
}

fn reference_names_match(references: &[CertificationEvidenceReference], expected: &[&str]) -> bool {
    references.len() == expected.len()
        && references
            .iter()
            .zip(expected)
            .all(|(reference, expected)| reference.name == *expected)
}

fn validate_subject_bindings(
    stage: &CertificationStageEvidence,
    subject: &CertificationSubject,
) -> Result<(), ValidationError> {
    let binding_is_valid = match stage.requirement {
        CertificationRequirement::ManifestValidation
        | CertificationRequirement::LicenseProvenance
        | CertificationRequirement::AdminPolicyMetadata => true,
        CertificationRequirement::TsppLifecycle
        | CertificationRequirement::SafetyContract
        | CertificationRequirement::ProtocolFuzzing
        | CertificationRequirement::SignedArtifact => {
            stage.inputs[0].digest == subject.artifact_digest
        }
        CertificationRequirement::PublicCorpusBenchmark
        | CertificationRequirement::ReproducibleBuild
        | CertificationRequirement::Sbom => stage.inputs[0].digest == subject.package_digest,
    };
    let reproducible_is_valid = stage.requirement != CertificationRequirement::ReproducibleBuild
        || !stage.ok
        || (stage.outputs[1].digest == subject.package_digest
            && stage.outputs[2].digest == subject.package_digest);
    if !binding_is_valid || !reproducible_is_valid {
        return Err(pipeline_error(
            "certification.stageSubjectBinding",
            "certification stage evidence is not bound to the subject artifact or package digest",
            "Run the stage against the exact executable and package named by the certification subject.",
        ));
    }
    Ok(())
}

fn validate_cross_stage_bindings(
    stages: &[CertificationStageEvidence],
) -> Result<(), ValidationError> {
    let manifest_digest = stages
        .iter()
        .find(|stage| stage.requirement == CertificationRequirement::ManifestValidation)
        .map(|stage| stage.inputs[0].digest.as_str());
    if let Some(admin) = stages
        .iter()
        .find(|stage| stage.requirement == CertificationRequirement::AdminPolicyMetadata)
    {
        if manifest_digest != Some(admin.inputs[0].digest.as_str()) {
            return Err(pipeline_error(
                "certification.pipelineBinding",
                "admin policy metadata was not produced from the validated plugin manifest",
                "Use the exact manifest digest from the manifest-validation stage.",
            ));
        }
    }
    let sbom_digest = stages
        .iter()
        .find(|stage| stage.requirement == CertificationRequirement::Sbom)
        .map(|stage| stage.outputs[0].digest.as_str());
    if let Some(license) = stages
        .iter()
        .find(|stage| stage.requirement == CertificationRequirement::LicenseProvenance)
    {
        if sbom_digest != Some(license.inputs[0].digest.as_str()) {
            return Err(pipeline_error(
                "certification.pipelineBinding",
                "license provenance was not reviewed against the generated SBOM",
                "Use the exact SBOM digest from the SBOM stage.",
            ));
        }
    }
    Ok(())
}

pub(crate) fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_token(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
}

fn valid_text(value: &str) -> bool {
    (1..=1024).contains(&value.len())
        && !value.contains('\0')
        && !value.chars().any(char::is_control)
}

fn pipeline_error(
    code: &'static str,
    message: &'static str,
    remediation: &'static str,
) -> ValidationError {
    ValidationError::new(code, message, remediation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::{BenchCaseReport, BenchTotals};
    use crate::certification::{
        CERTIFICATION_POLICY_ID, CERTIFICATION_POLICY_VERSION, validate_certification_report,
    };
    use crate::certification_admin::{
        CertificationAdminPolicyEvidence, CertificationAdminPolicyMetadata,
        evaluate_admin_policy_metadata,
    };
    use crate::certification_artifact::{
        ARTIFACT_SIGNATURE_ALGORITHM, CertificationArtifactSignature,
        CertificationArtifactSignatureEvidence, CertificationArtifactSignaturePolicy,
        CertificationArtifactTrustStore, TrustedArtifactSigningKey,
        artifact_signature_signing_message, evaluate_signed_artifact,
    };
    use crate::certification_fuzz::{
        CERTIFICATION_FUZZ_PROTOCOL, CertificationFuzzCase, CertificationFuzzCaseClass,
        CertificationFuzzCorpus, CertificationFuzzEngine, CertificationFuzzEvidence,
        CertificationFuzzExecutionLimits, CertificationFuzzPolicy, CertificationFuzzReport,
        evaluate_protocol_fuzzing,
    };
    use crate::certification_supply_chain::{
        CertificationLicenseEvidence, CertificationLicensePolicy,
        CertificationLicenseProvenanceReport, CertificationSbomEvidence, CertificationSbomPolicy,
        CertificationSbomReport, evaluate_license_provenance, evaluate_sbom,
    };
    use crate::protocol::OptimizeAction;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use ed25519_dalek::{Signer, SigningKey};

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn subject() -> CertificationSubject {
        let mut subject = CertificationSubject {
            plugin_id: "com.example.plugin".into(),
            version: "1.2.3".into(),
            platform: "linux-x64".into(),
            api_version: 1,
            artifact_digest: digest('a'),
            package_digest: digest('b'),
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

    fn authority() -> CertificationAuthority {
        CertificationAuthority {
            issuer_id: "com.tokensaver.registry".into(),
            policy_id: CERTIFICATION_POLICY_ID.into(),
            policy_version: CERTIFICATION_POLICY_VERSION,
            revocation_id: "cert:release:0123456789abcdef".into(),
        }
    }

    fn reference(name: &str, byte: char) -> CertificationEvidenceReference {
        CertificationEvidenceReference {
            name: name.into(),
            digest: digest(byte),
        }
    }

    fn stage(
        requirement: CertificationRequirement,
        subject: &CertificationSubject,
    ) -> CertificationStageEvidence {
        let (inputs, outputs) = match requirement {
            CertificationRequirement::ManifestValidation => (
                vec![reference("plugin-manifest", '1')],
                vec![reference("manifest-validation-report", '2')],
            ),
            CertificationRequirement::TsppLifecycle => (
                vec![reference("plugin-executable", 'a')],
                vec![reference("tspp-lifecycle-report", '3')],
            ),
            CertificationRequirement::SafetyContract => (
                vec![reference("plugin-executable", 'a')],
                vec![reference("safety-contract-report", '4')],
            ),
            CertificationRequirement::PublicCorpusBenchmark => (
                vec![
                    reference("plugin-package", 'b'),
                    reference("public-corpus", 'd'),
                    reference("benchmark-policy", 'e'),
                ],
                vec![reference("benchmark-report", '5')],
            ),
            CertificationRequirement::ProtocolFuzzing => (
                vec![
                    reference("plugin-executable", 'a'),
                    reference("protocol-corpus", 'd'),
                    reference("fuzz-policy", 'e'),
                ],
                vec![reference("fuzz-report", '6')],
            ),
            CertificationRequirement::ReproducibleBuild => (
                vec![
                    reference("plugin-package", 'b'),
                    reference("source-tree", 'e'),
                    reference("build-policy", 'f'),
                ],
                vec![
                    reference("build-report", '6'),
                    reference("rebuilt-package-a", 'b'),
                    reference("rebuilt-package-b", 'b'),
                ],
            ),
            CertificationRequirement::SignedArtifact => (
                vec![
                    reference("plugin-executable", 'a'),
                    reference("signature-policy", 'e'),
                    reference("artifact-trust-store", 'd'),
                ],
                vec![reference("artifact-signature", 'f')],
            ),
            CertificationRequirement::Sbom => (
                vec![
                    reference("plugin-package", 'b'),
                    reference("sbom-policy", 'e'),
                ],
                vec![reference("sbom", '7'), reference("sbom-report", '6')],
            ),
            CertificationRequirement::LicenseProvenance => (
                vec![reference("sbom", '7'), reference("license-policy", 'e')],
                vec![reference("license-provenance-report", '8')],
            ),
            CertificationRequirement::AdminPolicyMetadata => (
                vec![reference("plugin-manifest", '1')],
                vec![reference("admin-policy-metadata", '9')],
            ),
        };
        CertificationStageEvidence {
            schema_version: 1,
            requirement,
            subject: subject.into(),
            rule: certification_rule(requirement).into(),
            producer: CertificationStageProducer {
                id: "com.tokensaver.certification-worker".into(),
                version: "1.0.0".into(),
                environment_digest: digest('c'),
            },
            started_at_unix: 2_000_000_000,
            completed_at_unix: 2_000_000_060,
            ok: true,
            inputs,
            outputs,
            detail: "stage passed against the immutable package subject".into(),
            remediation: "rerun this stage with the current trusted pipeline".into(),
        }
    }

    fn documents(level: CertificationLevel) -> Vec<Vec<u8>> {
        let subject = subject();
        level
            .requirements()
            .iter()
            .copied()
            .map(|requirement| {
                serde_json::to_vec(&stage(requirement, &subject)).expect("stage document")
            })
            .collect()
    }

    fn latency() -> LatencySummary {
        LatencySummary {
            minimum_us: 20,
            p50_us: 40,
            p95_us: 80,
            p99_us: 90,
            maximum_us: 100,
            mean_us: 50,
        }
    }

    fn benchmark_report(subject: &CertificationSubject) -> BenchReport {
        BenchReport {
            schema_version: 1,
            ok: true,
            plugin_id: subject.plugin_id.clone(),
            version: subject.version.clone(),
            platform: subject.platform.clone(),
            release_id: subject.release_id.clone(),
            artifact_digest: subject.artifact_digest.clone(),
            fixture_directory: "public-corpus/v1".into(),
            iterations: 10,
            cases: vec![BenchCaseReport {
                name: "representative-build".into(),
                path: "public-corpus/v1/representative-build.case.json".into(),
                iterations: 10,
                input_bytes: 1_000,
                output_bytes: 500,
                saved_bytes: 500,
                savings_percent: 50.0,
                action: OptimizeAction::Optimize,
                activation_attempt_ids: (0..10).map(|index| format!("tsa1_{index:032x}")).collect(),
                latency_us: latency(),
            }],
            totals: BenchTotals {
                samples: 10,
                input_bytes: 10_000,
                output_bytes: 5_000,
                saved_bytes: 5_000,
                savings_percent: 50.0,
                pass_samples: 0,
                optimize_samples: 10,
                latency_us: latency(),
            },
            duration_ms: 1_000,
        }
    }

    fn benchmark_policy() -> CertificationBenchmarkPolicy {
        CertificationBenchmarkPolicy {
            schema_version: 1,
            policy_id: "com.tokensaver.certification.public-corpus.v1".into(),
            corpus_id: "com.tokensaver.public-corpus.v1".into(),
            corpus_digest: digest('d'),
            minimum_cases: 1,
            minimum_iterations: 10,
            minimum_input_bytes: 10_000,
            minimum_savings_basis_points: 5_000,
            maximum_p95_latency_us: 100,
        }
    }

    fn producer() -> CertificationStageProducer {
        CertificationStageProducer {
            id: "com.tokensaver.certification-worker".into(),
            version: "1.0.0".into(),
            environment_digest: digest('c'),
        }
    }

    #[test]
    fn level_two_report_accepts_real_fuzz_and_artifact_signature_evidence() {
        let executable = b"exact Level 2 plugin executable";
        let fuzz_case = |id: &str, class| CertificationFuzzCase {
            id: id.into(),
            class,
            input_base64: BASE64.encode(id.as_bytes()),
        };
        let corpus = serde_json::to_vec(&CertificationFuzzCorpus {
            schema_version: 1,
            corpus_id: "com.tokensaver.tspp-fuzz-corpus.v1".into(),
            protocol: CERTIFICATION_FUZZ_PROTOCOL.into(),
            repetitions: 200,
            limits: CertificationFuzzExecutionLimits {
                maximum_execution_milliseconds: 250,
                maximum_memory_bytes: 256 << 20,
                maximum_stdout_bytes: 1 << 20,
                maximum_stderr_bytes: 1 << 20,
                required_sanitizers: vec!["address".into()],
            },
            cases: vec![
                fuzz_case("malformed-1", CertificationFuzzCaseClass::Malformed),
                fuzz_case("malformed-2", CertificationFuzzCaseClass::Malformed),
                fuzz_case("malformed-3", CertificationFuzzCaseClass::Malformed),
                fuzz_case("valid-1", CertificationFuzzCaseClass::Valid),
                fuzz_case("valid-2", CertificationFuzzCaseClass::Valid),
            ],
        })
        .expect("fuzz corpus bytes");
        let mut subject = subject();
        subject.artifact_digest = sha256_digest(executable);
        subject.release_id = crate::identity::release_id(
            &subject.plugin_id,
            &subject.version,
            &subject.platform,
            &subject.artifact_digest,
        );
        let policy = CertificationFuzzPolicy {
            schema_version: 1,
            policy_id: "com.tokensaver.certification.protocol-fuzz.v1".into(),
            protocol: "TSPP/1".into(),
            corpus_id: "com.tokensaver.tspp-fuzz-corpus.v1".into(),
            corpus_digest: sha256_digest(&corpus),
            minimum_executions: 1_000,
            minimum_valid_inputs: 400,
            minimum_malformed_inputs: 600,
            minimum_coverage_basis_points: 9_000,
            maximum_duration_milliseconds: 60_000,
        };
        let fuzz_report = CertificationFuzzReport {
            schema_version: 1,
            subject: (&subject).into(),
            protocol: "TSPP/1".into(),
            engine: CertificationFuzzEngine {
                id: "cargo-fuzz-libfuzzer".into(),
                version: "0.12.0".into(),
                active_sanitizers: vec!["address".into()],
            },
            corpus_digest: sha256_digest(&corpus),
            started_at_unix: 2_000_000_000,
            completed_at_unix: 2_000_000_060,
            total_executions: 1_000,
            valid_inputs: 400,
            valid_inputs_accepted: 400,
            malformed_inputs: 600,
            malformed_inputs_rejected: 600,
            coverage_basis_points: 9_000,
            crashes: 0,
            hangs: 0,
            sanitizer_failures: 0,
            memory_limit_violations: 0,
            stdout_protocol_violations: 0,
            stderr_limit_violations: 0,
            deadline_violations: 0,
            unreaped_processes: 0,
            duration_milliseconds: 59_500,
        };
        let fuzz_report_bytes = serde_json::to_vec(&fuzz_report).expect("fuzz report bytes");
        let fuzz_policy_bytes = serde_json::to_vec(&policy).expect("fuzz policy bytes");
        let fuzz_stage = evaluate_protocol_fuzzing(
            CertificationFuzzEvidence {
                report_bytes: &fuzz_report_bytes,
                policy_bytes: &fuzz_policy_bytes,
                plugin_executable_bytes: executable,
                protocol_corpus_bytes: &corpus,
            },
            &subject,
            producer(),
            2_000_000_000,
            2_000_000_060,
        )
        .expect("real protocol-fuzz evidence");

        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let signature_policy = CertificationArtifactSignaturePolicy {
            schema_version: 1,
            policy_id: "com.tokensaver.certification.artifact-signature.v1".into(),
            algorithm: ARTIFACT_SIGNATURE_ALGORITHM.into(),
            maximum_signature_lifetime_seconds: 7_200,
            minimum_remaining_validity_seconds: 300,
        };
        let artifact_trust_store = CertificationArtifactTrustStore {
            schema_version: 1,
            keys: vec![TrustedArtifactSigningKey {
                signer_id: "com.example.publisher".into(),
                key_id: "release-2026".into(),
                public_key: BASE64.encode(signing_key.verifying_key().as_bytes()),
                not_before_unix: 1_999_999_800,
                not_after_unix: 2_000_003_700,
            }],
        };
        let mut artifact_signature = CertificationArtifactSignature {
            schema_version: 1,
            artifact: (&subject).into(),
            signer_id: "com.example.publisher".into(),
            key_id: "release-2026".into(),
            issued_at_unix: 1_999_999_900,
            expires_at_unix: 2_000_003_600,
            algorithm: ARTIFACT_SIGNATURE_ALGORITHM.into(),
            signature: BASE64.encode([0; 64]),
        };
        artifact_signature.signature = BASE64.encode(
            signing_key
                .sign(&artifact_signature_signing_message(&artifact_signature))
                .to_bytes(),
        );
        let artifact_signature_bytes =
            serde_json::to_vec(&artifact_signature).expect("artifact signature bytes");
        let signature_policy_bytes =
            serde_json::to_vec(&signature_policy).expect("signature policy bytes");
        let artifact_trust_store_bytes =
            serde_json::to_vec(&artifact_trust_store).expect("artifact trust store bytes");
        let artifact_stage = evaluate_signed_artifact(
            CertificationArtifactSignatureEvidence {
                plugin_executable_bytes: executable,
                artifact_signature_bytes: &artifact_signature_bytes,
                signature_policy_bytes: &signature_policy_bytes,
                artifact_trust_store_bytes: &artifact_trust_store_bytes,
            },
            &subject,
            producer(),
            2_000_000_000,
            2_000_000_060,
        )
        .expect("real artifact-signature evidence");

        let mut documents = CertificationLevel::Certified
            .requirements()
            .iter()
            .copied()
            .map(|requirement| {
                let mut generated = stage(requirement, &subject);
                for input in &mut generated.inputs {
                    if input.name == "plugin-executable" {
                        input.digest = subject.artifact_digest.clone();
                    }
                }
                serde_json::to_vec(&generated).expect("stage document")
            })
            .collect::<Vec<_>>();
        let fuzz_index = CertificationLevel::Certified
            .requirements()
            .iter()
            .position(|requirement| *requirement == CertificationRequirement::ProtocolFuzzing)
            .expect("protocol-fuzz requirement");
        documents[fuzz_index] = serde_json::to_vec(&fuzz_stage).expect("fuzz stage document");
        let artifact_index = CertificationLevel::Certified
            .requirements()
            .iter()
            .position(|requirement| *requirement == CertificationRequirement::SignedArtifact)
            .expect("signed-artifact requirement");
        documents[artifact_index] =
            serde_json::to_vec(&artifact_stage).expect("artifact stage document");

        let report = assemble_certification_report(
            CertificationLevel::Certified,
            &subject,
            authority(),
            &documents,
        )
        .expect("complete Level 2 report");
        assert!(report.ok);
        validate_certification_report(&report, &subject).expect("accepted Level 2 report");
    }

    #[test]
    fn enterprise_report_accepts_real_supply_chain_and_admin_evidence() {
        let package = b"exact Enterprise plugin package";
        let mut subject = subject();
        subject.package_digest = sha256_digest(package);
        let package_hash = subject
            .package_digest
            .strip_prefix("sha256:")
            .expect("package digest");
        let sbom = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
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
            "components": [{
                "type": "library",
                "bom-ref": "pkg:cargo/dependency@2.0.0",
                "name": "dependency",
                "version": "2.0.0",
                "hashes": [{
                    "alg": "SHA-256",
                    "content": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }],
                "licenses": [{ "license": { "id": "MIT" } }],
                "purl": "pkg:cargo/dependency@2.0.0"
            }]
        });
        let sbom_bytes = serde_json::to_vec(&sbom).expect("SBOM bytes");
        let sbom_policy = CertificationSbomPolicy {
            schema_version: 1,
            policy_id: "com.tokensaver.certification.sbom.v1".into(),
            format: "CycloneDX".into(),
            spec_version: "1.6".into(),
            maximum_components: 100,
            require_component_hashes: true,
            require_component_licenses: true,
            require_component_purls: true,
        };
        let sbom_policy_bytes = serde_json::to_vec(&sbom_policy).expect("SBOM policy bytes");
        let sbom_report = CertificationSbomReport {
            schema_version: 1,
            subject: (&subject).into(),
            policy_digest: sha256_digest(&sbom_policy_bytes),
            sbom_digest: sha256_digest(&sbom_bytes),
            format: "CycloneDX".into(),
            spec_version: "1.6".into(),
            component_count: 2,
            components_with_sha256: 2,
            components_with_licenses: 2,
            components_with_purls: 2,
            generated_at_unix: 2_000_000_060,
        };
        let sbom_report_bytes = serde_json::to_vec(&sbom_report).expect("SBOM report bytes");
        let sbom_stage = evaluate_sbom(
            CertificationSbomEvidence {
                package_bytes: package,
                sbom_bytes: &sbom_bytes,
                report_bytes: &sbom_report_bytes,
                policy_bytes: &sbom_policy_bytes,
            },
            &subject,
            producer(),
            2_000_000_000,
            2_000_000_060,
        )
        .expect("real SBOM evidence");

        let license_policy = CertificationLicensePolicy {
            schema_version: 1,
            policy_id: "com.tokensaver.certification.license.v1".into(),
            allowed_spdx_ids: vec!["Apache-2.0".into(), "MIT".into()],
            denied_spdx_ids: vec!["GPL-3.0-only".into()],
            maximum_components: 100,
            require_all_components_licensed: true,
            require_component_provenance: true,
        };
        let license_policy_bytes =
            serde_json::to_vec(&license_policy).expect("license policy bytes");
        let license_report = CertificationLicenseProvenanceReport {
            schema_version: 1,
            subject: (&subject).into(),
            sbom_digest: sha256_digest(&sbom_bytes),
            policy_digest: sha256_digest(&license_policy_bytes),
            component_count: 2,
            licensed_components: 2,
            provenance_components: 2,
            denied_components: 0,
            unknown_license_components: 0,
            missing_license_components: 0,
            missing_provenance_components: 0,
            observed_spdx_ids: vec!["Apache-2.0".into(), "MIT".into()],
            reviewed_at_unix: 2_000_000_060,
        };
        let license_report_bytes =
            serde_json::to_vec(&license_report).expect("license report bytes");
        let license_stage = evaluate_license_provenance(
            CertificationLicenseEvidence {
                sbom_bytes: &sbom_bytes,
                report_bytes: &license_report_bytes,
                policy_bytes: &license_policy_bytes,
            },
            &subject,
            producer(),
            2_000_000_000,
            2_000_000_060,
        )
        .expect("real license evidence");

        let manifest = serde_json::json!({
            "apiVersion": 1,
            "id": subject.plugin_id,
            "name": "Example plugin",
            "version": subject.version,
            "creator": { "name": "Example" },
            "permissions": [],
            "runtime": {
                "kind": "executable",
                "entry": { "linux-x64": "bin/linux/plugin" }
            },
            "capabilities": {
                "kinds": ["log", "build"],
                "maxInputBytes": 16777216
            },
            "limits": { "timeBudgetMs": 250 },
            "integrity": {
                "algorithm": "sha256",
                "digests": { "linux-x64": subject.artifact_digest }
            }
        });
        let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest bytes");
        let admin_metadata = CertificationAdminPolicyMetadata {
            schema_version: 1,
            subject: (&subject).into(),
            manifest_digest: sha256_digest(&manifest_bytes),
            runtime_kind: "executable".into(),
            runtime_platforms: vec!["linux-x64".into()],
            runtime_argument_count: 0,
            capability_kinds: vec!["build".into(), "log".into()],
            declared_max_input_bytes: 16_777_216,
            declared_time_budget_ms: 250,
            effective_time_budget_ms: 250,
            permission_count: 0,
            integrity_algorithm: Some("sha256".into()),
            integrity_covered_platforms: vec!["linux-x64".into()],
            integrity_complete: true,
            generated_at_unix: 2_000_000_060,
        };
        let admin_metadata_bytes =
            serde_json::to_vec(&admin_metadata).expect("admin metadata bytes");
        let admin_stage = evaluate_admin_policy_metadata(
            CertificationAdminPolicyEvidence {
                manifest_bytes: &manifest_bytes,
                metadata_bytes: &admin_metadata_bytes,
            },
            &subject,
            producer(),
            2_000_000_000,
            2_000_000_060,
        )
        .expect("real admin metadata evidence");

        let mut documents = CertificationLevel::EnterpriseCertified
            .requirements()
            .iter()
            .copied()
            .map(|requirement| {
                let mut generated = stage(requirement, &subject);
                for input in &mut generated.inputs {
                    if input.name == "plugin-executable" {
                        input.digest = subject.artifact_digest.clone();
                    } else if input.name == "plugin-package" {
                        input.digest = subject.package_digest.clone();
                    } else if input.name == "plugin-manifest" {
                        input.digest = sha256_digest(&manifest_bytes);
                    }
                }
                if requirement == CertificationRequirement::ReproducibleBuild {
                    generated.outputs[1].digest = subject.package_digest.clone();
                    generated.outputs[2].digest = subject.package_digest.clone();
                }
                serde_json::to_vec(&generated).expect("stage document")
            })
            .collect::<Vec<_>>();
        let sbom_index = CertificationLevel::EnterpriseCertified
            .requirements()
            .iter()
            .position(|requirement| *requirement == CertificationRequirement::Sbom)
            .expect("SBOM requirement");
        documents[sbom_index] = serde_json::to_vec(&sbom_stage).expect("SBOM stage");
        let license_index = CertificationLevel::EnterpriseCertified
            .requirements()
            .iter()
            .position(|requirement| *requirement == CertificationRequirement::LicenseProvenance)
            .expect("license requirement");
        documents[license_index] = serde_json::to_vec(&license_stage).expect("license stage");
        let admin_index = CertificationLevel::EnterpriseCertified
            .requirements()
            .iter()
            .position(|requirement| *requirement == CertificationRequirement::AdminPolicyMetadata)
            .expect("admin policy metadata requirement");
        documents[admin_index] = serde_json::to_vec(&admin_stage).expect("admin metadata stage");

        let report = assemble_certification_report(
            CertificationLevel::EnterpriseCertified,
            &subject,
            authority(),
            &documents,
        )
        .expect("complete Enterprise report");
        assert!(report.ok);
        validate_certification_report(&report, &subject).expect("accepted Enterprise report");
    }

    #[test]
    fn public_corpus_evaluator_computes_thresholds_and_exact_evidence_digests() {
        let subject = subject();
        let benchmark_bytes =
            serde_json::to_vec(&benchmark_report(&subject)).expect("benchmark bytes");
        let policy_bytes = serde_json::to_vec(&benchmark_policy()).expect("policy bytes");
        let stage = evaluate_public_corpus_benchmark(
            &benchmark_bytes,
            &policy_bytes,
            &subject,
            producer(),
            2_000_000_000,
            2_000_000_060,
        )
        .expect("benchmark evaluation");
        assert!(stage.ok);
        assert!(stage.detail.contains("50.00% weighted savings"));
        assert_eq!(stage.inputs[1].digest, digest('d'));
        assert_eq!(stage.inputs[2].digest, sha256_digest(&policy_bytes));
        assert_eq!(stage.outputs[0].digest, sha256_digest(&benchmark_bytes));

        let mut strict_policy = benchmark_policy();
        strict_policy.minimum_savings_basis_points = 5_001;
        let strict_bytes = serde_json::to_vec(&strict_policy).expect("strict policy");
        let failed = evaluate_public_corpus_benchmark(
            &benchmark_bytes,
            &strict_bytes,
            &subject,
            producer(),
            2_000_000_000,
            2_000_000_060,
        )
        .expect("truthful threshold failure");
        assert!(!failed.ok);
    }

    #[test]
    fn public_corpus_evaluator_rejects_inconsistent_accounting_and_policy() {
        let subject = subject();
        let mut report = benchmark_report(&subject);
        report.totals.saved_bytes += 1;
        let report_bytes = serde_json::to_vec(&report).expect("inconsistent report");
        let policy_bytes = serde_json::to_vec(&benchmark_policy()).expect("policy bytes");
        assert_eq!(
            evaluate_public_corpus_benchmark(
                &report_bytes,
                &policy_bytes,
                &subject,
                producer(),
                2_000_000_000,
                2_000_000_060,
            )
            .expect_err("inconsistent accounting")
            .code,
            "certification.benchmarkTotals"
        );

        let mut unknown_policy = serde_json::to_value(benchmark_policy()).expect("policy value");
        unknown_policy["unknownSecurityField"] = serde_json::json!(true);
        let unknown_bytes = serde_json::to_vec(&unknown_policy).expect("unknown policy");
        let valid_report =
            serde_json::to_vec(&benchmark_report(&subject)).expect("valid benchmark");
        assert_eq!(
            evaluate_public_corpus_benchmark(
                &valid_report,
                &unknown_bytes,
                &subject,
                producer(),
                2_000_000_000,
                2_000_000_060,
            )
            .expect_err("unknown policy")
            .code,
            "certification.benchmarkPolicyJson"
        );
    }

    #[test]
    fn level_two_and_three_reports_bind_exact_cumulative_stage_bytes() {
        for level in [
            CertificationLevel::Certified,
            CertificationLevel::EnterpriseCertified,
        ] {
            let subject = subject();
            let documents = documents(level);
            let report = assemble_certification_report(level, &subject, authority(), &documents)
                .expect("certification report");
            assert!(report.ok);
            assert_eq!(report.checks.len(), level.requirements().len());
            for (check, document) in report.checks.iter().zip(&documents) {
                assert_eq!(check.evidence_digest, sha256_digest(document));
                assert_eq!(check.rule, certification_rule(check.requirement));
            }
            validate_certification_report(&report, &subject).expect("accepted report contract");
        }
    }

    #[test]
    fn failed_stage_produces_truthful_rejectable_report() {
        let subject = subject();
        let mut documents = documents(CertificationLevel::Certified);
        let mut benchmark: CertificationStageEvidence =
            serde_json::from_slice(&documents[3]).expect("benchmark stage");
        benchmark.ok = false;
        benchmark.detail = "public corpus savings threshold was not met".into();
        benchmark.remediation = "improve output quality and rerun the public corpus".into();
        documents[3] = serde_json::to_vec(&benchmark).expect("failed benchmark");
        let report = assemble_certification_report(
            CertificationLevel::Certified,
            &subject,
            authority(),
            &documents,
        )
        .expect("truthful failed report");
        assert!(!report.ok);
        assert!(!report.checks[3].ok);
        assert_eq!(
            validate_certification_report(&report, &subject)
                .expect_err("failed certification")
                .code,
            "certification.failedRule"
        );
    }

    #[test]
    fn missing_reordered_and_unknown_stage_documents_are_rejected() {
        let subject = subject();
        let mut missing = documents(CertificationLevel::Certified);
        missing.pop();
        assert_eq!(
            assemble_certification_report(
                CertificationLevel::Certified,
                &subject,
                authority(),
                &missing,
            )
            .expect_err("missing stage")
            .code,
            "certification.pipelineRequirements"
        );

        let mut reordered = documents(CertificationLevel::Certified);
        reordered.swap(3, 4);
        assert_eq!(
            assemble_certification_report(
                CertificationLevel::Certified,
                &subject,
                authority(),
                &reordered,
            )
            .expect_err("reordered stage")
            .code,
            "certification.pipelineOrder"
        );

        let documents = documents(CertificationLevel::Certified);
        let mut unknown: serde_json::Value =
            serde_json::from_slice(&documents[0]).expect("stage value");
        unknown["unknownSecurityField"] = serde_json::json!(true);
        let mut unknown_documents = documents.clone();
        unknown_documents[0] = serde_json::to_vec(&unknown).expect("unknown stage");
        assert_eq!(
            assemble_certification_report(
                CertificationLevel::Certified,
                &subject,
                authority(),
                &unknown_documents,
            )
            .expect_err("unknown field")
            .code,
            "certification.stageJson"
        );
    }

    #[test]
    fn subject_reproducibility_and_cross_stage_bindings_fail_closed() {
        let subject = subject();
        let mut executable = documents(CertificationLevel::Certified);
        let mut lifecycle: CertificationStageEvidence =
            serde_json::from_slice(&executable[1]).expect("lifecycle stage");
        lifecycle.inputs[0].digest = digest('f');
        executable[1] = serde_json::to_vec(&lifecycle).expect("lifecycle document");
        assert_eq!(
            assemble_certification_report(
                CertificationLevel::Certified,
                &subject,
                authority(),
                &executable,
            )
            .expect_err("wrong executable")
            .code,
            "certification.stageSubjectBinding"
        );

        let mut reproducible = documents(CertificationLevel::Certified);
        let mut build: CertificationStageEvidence =
            serde_json::from_slice(&reproducible[5]).expect("build stage");
        build.outputs[1].digest = digest('f');
        reproducible[5] = serde_json::to_vec(&build).expect("build document");
        assert_eq!(
            assemble_certification_report(
                CertificationLevel::Certified,
                &subject,
                authority(),
                &reproducible,
            )
            .expect_err("non-reproducible package")
            .code,
            "certification.stageSubjectBinding"
        );

        let mut failed_reproducible = documents(CertificationLevel::Certified);
        let mut failed_build: CertificationStageEvidence =
            serde_json::from_slice(&failed_reproducible[5]).expect("build stage");
        failed_build.ok = false;
        failed_build.outputs[1].digest = digest('e');
        failed_build.outputs[2].digest = digest('f');
        failed_reproducible[5] = serde_json::to_vec(&failed_build).expect("failed build document");
        let failed_report = assemble_certification_report(
            CertificationLevel::Certified,
            &subject,
            authority(),
            &failed_reproducible,
        )
        .expect("truthful failed reproducible-build report");
        assert!(
            !failed_report
                .checks
                .iter()
                .find(|check| { check.requirement == CertificationRequirement::ReproducibleBuild })
                .expect("reproducible-build check")
                .ok
        );
        assert_eq!(
            validate_certification_report(&failed_report, &subject)
                .expect_err("failed report cannot certify")
                .code,
            "certification.failedRule"
        );

        let mut enterprise = documents(CertificationLevel::EnterpriseCertified);
        let mut license: CertificationStageEvidence =
            serde_json::from_slice(&enterprise[8]).expect("license stage");
        license.inputs[0].digest = digest('f');
        enterprise[8] = serde_json::to_vec(&license).expect("license document");
        assert_eq!(
            assemble_certification_report(
                CertificationLevel::EnterpriseCertified,
                &subject,
                authority(),
                &enterprise,
            )
            .expect_err("wrong SBOM")
            .code,
            "certification.pipelineBinding"
        );
    }

    #[test]
    fn malformed_references_timing_and_oversized_evidence_are_rejected() {
        let subject = subject();
        let mut malformed = documents(CertificationLevel::Certified);
        let mut benchmark: CertificationStageEvidence =
            serde_json::from_slice(&malformed[3]).expect("benchmark stage");
        benchmark.inputs.swap(0, 1);
        malformed[3] = serde_json::to_vec(&benchmark).expect("benchmark document");
        assert_eq!(
            assemble_certification_report(
                CertificationLevel::Certified,
                &subject,
                authority(),
                &malformed,
            )
            .expect_err("noncanonical references")
            .code,
            "certification.stageLayout"
        );

        let mut timing = documents(CertificationLevel::Certified);
        let mut manifest: CertificationStageEvidence =
            serde_json::from_slice(&timing[0]).expect("manifest stage");
        manifest.completed_at_unix = manifest.started_at_unix - 1;
        timing[0] = serde_json::to_vec(&manifest).expect("timing document");
        assert_eq!(
            assemble_certification_report(
                CertificationLevel::Certified,
                &subject,
                authority(),
                &timing,
            )
            .expect_err("invalid timing")
            .code,
            "certification.stageContract"
        );

        let mut oversized = documents(CertificationLevel::Certified);
        oversized[0] = vec![b' '; MAX_STAGE_EVIDENCE_BYTES + 1];
        assert_eq!(
            assemble_certification_report(
                CertificationLevel::Certified,
                &subject,
                authority(),
                &oversized,
            )
            .expect_err("oversized stage")
            .code,
            "certification.stageSize"
        );
    }
}
