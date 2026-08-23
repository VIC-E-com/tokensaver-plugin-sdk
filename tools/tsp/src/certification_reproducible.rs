use crate::certification::{CertificationRequirement, CertificationSubject};
use crate::certification_pipeline::{
    CertificationEvidenceReference, CertificationStageEvidence, CertificationStageProducer,
    CertificationStageSubject, certification_rule, sha256_digest, validate_stage,
};
use crate::manifest::ValidationError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const MAX_BUILD_REPORT_BYTES: usize = 2 << 20;
const MAX_BUILD_POLICY_BYTES: usize = 64 << 10;
const MAX_BUILD_DURATION_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_BUILD_DURATION_MILLISECONDS: u64 = MAX_BUILD_DURATION_SECONDS * 1_000;
const REQUIRED_INDEPENDENT_BUILDS: u32 = 2;
const MAX_OBSERVED_VIOLATIONS: u64 = 1_000_000_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationReproducibleBuildPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub required_independent_builds: u32,
    pub require_distinct_environments: bool,
    pub maximum_build_duration_milliseconds: u64,
    pub maximum_total_duration_milliseconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationReproducibleBuildAttempt {
    pub slot: String,
    pub attempt_id: String,
    pub builder_id: String,
    pub builder_version: String,
    pub environment_digest: String,
    pub package_digest: String,
    pub exit_code: i32,
    pub network_accesses: u64,
    pub undeclared_inputs: u64,
    pub duration_milliseconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationReproducibleBuildReport {
    pub schema_version: u32,
    pub subject: CertificationStageSubject,
    pub source_digest: String,
    pub policy_digest: String,
    pub started_at_unix: u64,
    pub completed_at_unix: u64,
    pub duration_milliseconds: u64,
    pub builds: Vec<CertificationReproducibleBuildAttempt>,
}

#[derive(Clone, Copy, Debug)]
pub struct CertificationReproducibleBuildEvidence<'a> {
    pub report_bytes: &'a [u8],
    pub policy_bytes: &'a [u8],
    pub source_tree_bytes: &'a [u8],
    pub subject_package_bytes: &'a [u8],
    pub rebuilt_package_a_bytes: &'a [u8],
    pub rebuilt_package_b_bytes: &'a [u8],
}

/// Evaluates exact clean-room build evidence without executing a build.
///
/// A trusted CI runner supplies the source, subject package, two independently rebuilt packages,
/// report, and policy. This evaluator verifies their exact identities and computes a truthful
/// unsigned stage result. It does not build, sign, certify, install, or activate a plugin.
pub fn evaluate_reproducible_build(
    evidence: CertificationReproducibleBuildEvidence<'_>,
    subject: &CertificationSubject,
    producer: CertificationStageProducer,
    started_at_unix: u64,
    completed_at_unix: u64,
) -> Result<CertificationStageEvidence, ValidationError> {
    let CertificationReproducibleBuildEvidence {
        report_bytes,
        policy_bytes,
        source_tree_bytes,
        subject_package_bytes,
        rebuilt_package_a_bytes,
        rebuilt_package_b_bytes,
    } = evidence;
    let policy = parse_policy(policy_bytes)?;
    validate_policy(&policy)?;
    let report = parse_report(report_bytes)?;

    if source_tree_bytes.is_empty() {
        return Err(build_error(
            "certification.reproducibleSource",
            "reproducible-build source tree is empty",
            "Use the exact non-empty immutable source archive supplied to both builders.",
        ));
    }
    if subject_package_bytes.is_empty()
        || sha256_digest(subject_package_bytes) != subject.package_digest
    {
        return Err(build_error(
            "certification.reproducibleSubjectPackage",
            "reproducible-build evidence is not bound to the subject package bytes",
            "Use the exact package named by the certification subject.",
        ));
    }
    let source_digest = sha256_digest(source_tree_bytes);
    let policy_digest = sha256_digest(policy_bytes);
    let output_digests = [
        sha256_digest(rebuilt_package_a_bytes),
        sha256_digest(rebuilt_package_b_bytes),
    ];
    validate_report(
        &report,
        ReportValidationContext {
            subject,
            source_digest: &source_digest,
            policy_digest: &policy_digest,
            output_digests: &output_digests,
            started_at_unix,
            completed_at_unix,
        },
    )?;

    let environments = report
        .builds
        .iter()
        .map(|build| build.environment_digest.as_str())
        .collect::<BTreeSet<_>>();
    let attempts = report
        .builds
        .iter()
        .map(|build| build.attempt_id.as_str())
        .collect::<BTreeSet<_>>();
    let builds_pass = report.builds.iter().all(|build| {
        build.exit_code == 0
            && build.network_accesses == 0
            && build.undeclared_inputs == 0
            && build.duration_milliseconds <= policy.maximum_build_duration_milliseconds
    });
    let outputs_match = output_digests
        .iter()
        .all(|digest| digest == &subject.package_digest);
    let ok = report.builds.len() == policy.required_independent_builds as usize
        && attempts.len() == report.builds.len()
        && (!policy.require_distinct_environments || environments.len() == report.builds.len())
        && report.duration_milliseconds <= policy.maximum_total_duration_milliseconds
        && builds_pass
        && outputs_match;
    let detail = format!(
        "reproducible build: {} independent attempts, {} distinct environments, {} ms total, outputs {}",
        report.builds.len(),
        environments.len(),
        report.duration_milliseconds,
        if outputs_match {
            "match the subject package"
        } else {
            "differ from the subject package"
        }
    );
    let remediation = if ok {
        "rerun both independent clean-room builds for every source and package release"
    } else {
        "produce two successful network-isolated builds from declared inputs in distinct environments whose exact package bytes match the subject"
    };
    let stage = CertificationStageEvidence {
        schema_version: 1,
        requirement: CertificationRequirement::ReproducibleBuild,
        subject: subject.into(),
        rule: certification_rule(CertificationRequirement::ReproducibleBuild).into(),
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
                name: "source-tree".into(),
                digest: source_digest,
            },
            CertificationEvidenceReference {
                name: "build-policy".into(),
                digest: policy_digest,
            },
        ],
        outputs: vec![
            CertificationEvidenceReference {
                name: "build-report".into(),
                digest: sha256_digest(report_bytes),
            },
            CertificationEvidenceReference {
                name: "rebuilt-package-a".into(),
                digest: output_digests[0].clone(),
            },
            CertificationEvidenceReference {
                name: "rebuilt-package-b".into(),
                digest: output_digests[1].clone(),
            },
        ],
        detail,
        remediation: remediation.into(),
    };
    validate_stage(&stage, subject)?;
    Ok(stage)
}

fn parse_policy(bytes: &[u8]) -> Result<CertificationReproducibleBuildPolicy, ValidationError> {
    parse_json(
        bytes,
        MAX_BUILD_POLICY_BYTES,
        "certification.reproduciblePolicySize",
        "certification.reproduciblePolicyJson",
        "reproducible-build policy",
        "64 KiB",
        "schemas/certification-reproducible-build-policy.v1.json",
    )
}

fn parse_report(bytes: &[u8]) -> Result<CertificationReproducibleBuildReport, ValidationError> {
    parse_json(
        bytes,
        MAX_BUILD_REPORT_BYTES,
        "certification.reproducibleReportSize",
        "certification.reproducibleReportJson",
        "reproducible-build report",
        "2 MiB",
        "schemas/certification-reproducible-build-report.v1.json",
    )
}

fn parse_json<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    maximum: usize,
    size_code: &'static str,
    json_code: &'static str,
    document_name: &'static str,
    size_name: &'static str,
    schema_name: &'static str,
) -> Result<T, ValidationError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(build_error(
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

fn validate_policy(policy: &CertificationReproducibleBuildPolicy) -> Result<(), ValidationError> {
    if policy.schema_version != 1
        || !valid_token(&policy.policy_id)
        || policy.required_independent_builds != REQUIRED_INDEPENDENT_BUILDS
        || !policy.require_distinct_environments
        || !(1..=MAX_BUILD_DURATION_MILLISECONDS)
            .contains(&policy.maximum_build_duration_milliseconds)
        || !(1..=MAX_BUILD_DURATION_MILLISECONDS)
            .contains(&policy.maximum_total_duration_milliseconds)
        || policy.maximum_build_duration_milliseconds > policy.maximum_total_duration_milliseconds
    {
        return Err(build_error(
            "certification.reproduciblePolicy",
            "reproducible-build policy identity or isolation thresholds are invalid",
            "Require exactly two distinct clean-room builds with bounded per-build and total durations.",
        ));
    }
    Ok(())
}

struct ReportValidationContext<'a> {
    subject: &'a CertificationSubject,
    source_digest: &'a str,
    policy_digest: &'a str,
    output_digests: &'a [String; 2],
    started_at_unix: u64,
    completed_at_unix: u64,
}

fn validate_report(
    report: &CertificationReproducibleBuildReport,
    context: ReportValidationContext<'_>,
) -> Result<(), ValidationError> {
    let ReportValidationContext {
        subject,
        source_digest,
        policy_digest,
        output_digests,
        started_at_unix,
        completed_at_unix,
    } = context;
    if report.schema_version != 1
        || report.subject != CertificationStageSubject::from(subject)
        || report.source_digest != source_digest
        || report.policy_digest != policy_digest
        || report.builds.len() != REQUIRED_INDEPENDENT_BUILDS as usize
    {
        return Err(build_error(
            "certification.reproducibleReport",
            "reproducible-build report version, subject, source, policy, or build count is invalid",
            "Use a v1 report for the exact subject, source, policy, and two rebuilt packages.",
        ));
    }
    if report.started_at_unix == 0
        || report.started_at_unix != started_at_unix
        || report.completed_at_unix != completed_at_unix
        || report.completed_at_unix < report.started_at_unix
        || report
            .completed_at_unix
            .saturating_sub(report.started_at_unix)
            > MAX_BUILD_DURATION_SECONDS
        || report.duration_milliseconds > MAX_BUILD_DURATION_MILLISECONDS
        || report.duration_milliseconds
            > report
                .completed_at_unix
                .saturating_sub(report.started_at_unix)
                .saturating_mul(1_000)
                .saturating_add(999)
    {
        return Err(build_error(
            "certification.reproducibleTiming",
            "reproducible-build timing is inconsistent or outside the seven-day bound",
            "Bind the report and stage to the same bounded runner timestamps and duration.",
        ));
    }
    for (index, build) in report.builds.iter().enumerate() {
        let expected_slot = if index == 0 { "a" } else { "b" };
        if build.slot != expected_slot
            || !valid_token(&build.attempt_id)
            || !valid_token(&build.builder_id)
            || !valid_token(&build.builder_version)
            || !valid_digest(&build.environment_digest)
            || build.package_digest != output_digests[index]
            || build.network_accesses > MAX_OBSERVED_VIOLATIONS
            || build.undeclared_inputs > MAX_OBSERVED_VIOLATIONS
            || build.duration_milliseconds > report.duration_milliseconds.saturating_add(999)
        {
            return Err(build_error(
                "certification.reproducibleBuild",
                "reproducible-build attempt identity, digest, counters, slot, or duration is invalid",
                "Regenerate the report from two bounded canonical clean-room build attempts.",
            ));
        }
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

fn valid_token(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
}

fn build_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> ValidationError {
    ValidationError::new(code, message, remediation)
}

#[cfg(test)]
mod tests {
    use super::*;

    type ReportMutation = fn(&mut CertificationReproducibleBuildReport);

    const SOURCE: &[u8] = b"exact immutable source archive";
    const PACKAGE: &[u8] = b"exact reproducible plugin package";
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
            id: "com.tokensaver.reproducible-builder".into(),
            version: "1.0.0".into(),
            environment_digest: sha256_digest(b"trusted evaluator environment"),
        }
    }

    fn policy() -> CertificationReproducibleBuildPolicy {
        CertificationReproducibleBuildPolicy {
            schema_version: 1,
            policy_id: "com.tokensaver.certification.reproducible-build.v1".into(),
            required_independent_builds: 2,
            require_distinct_environments: true,
            maximum_build_duration_milliseconds: 30_000,
            maximum_total_duration_milliseconds: 60_000,
        }
    }

    fn attempt(slot: &str, package_digest: String) -> CertificationReproducibleBuildAttempt {
        CertificationReproducibleBuildAttempt {
            slot: slot.into(),
            attempt_id: format!("attempt-{slot}"),
            builder_id: "com.tokensaver.clean-room-builder".into(),
            builder_version: "1.0.0".into(),
            environment_digest: sha256_digest(format!("environment-{slot}").as_bytes()),
            package_digest,
            exit_code: 0,
            network_accesses: 0,
            undeclared_inputs: 0,
            duration_milliseconds: 25_000,
        }
    }

    fn report(
        subject: &CertificationSubject,
        policy_bytes: &[u8],
        output_a: &[u8],
        output_b: &[u8],
    ) -> CertificationReproducibleBuildReport {
        CertificationReproducibleBuildReport {
            schema_version: 1,
            subject: subject.into(),
            source_digest: sha256_digest(SOURCE),
            policy_digest: sha256_digest(policy_bytes),
            started_at_unix: STARTED,
            completed_at_unix: COMPLETED,
            duration_milliseconds: 59_500,
            builds: vec![
                attempt("a", sha256_digest(output_a)),
                attempt("b", sha256_digest(output_b)),
            ],
        }
    }

    fn evaluate(
        report: &CertificationReproducibleBuildReport,
        policy: &CertificationReproducibleBuildPolicy,
        output_a: &[u8],
        output_b: &[u8],
    ) -> Result<CertificationStageEvidence, ValidationError> {
        let report_bytes = serde_json::to_vec(report).expect("build report bytes");
        let policy_bytes = serde_json::to_vec(policy).expect("build policy bytes");
        evaluate_reproducible_build(
            CertificationReproducibleBuildEvidence {
                report_bytes: &report_bytes,
                policy_bytes: &policy_bytes,
                source_tree_bytes: SOURCE,
                subject_package_bytes: PACKAGE,
                rebuilt_package_a_bytes: output_a,
                rebuilt_package_b_bytes: output_b,
            },
            &subject(),
            producer(),
            STARTED,
            COMPLETED,
        )
    }

    fn matching_report() -> (
        CertificationReproducibleBuildPolicy,
        CertificationReproducibleBuildReport,
    ) {
        let policy = policy();
        let policy_bytes = serde_json::to_vec(&policy).expect("build policy bytes");
        let report = report(&subject(), &policy_bytes, PACKAGE, PACKAGE);
        (policy, report)
    }

    #[test]
    fn passing_build_binds_every_exact_evidence_digest() {
        let (policy, report) = matching_report();
        let report_bytes = serde_json::to_vec(&report).expect("build report bytes");
        let policy_bytes = serde_json::to_vec(&policy).expect("build policy bytes");
        let stage = evaluate(&report, &policy, PACKAGE, PACKAGE).expect("build evaluation");

        assert!(stage.ok);
        assert_eq!(stage.inputs[0].digest, sha256_digest(PACKAGE));
        assert_eq!(stage.inputs[1].digest, sha256_digest(SOURCE));
        assert_eq!(stage.inputs[2].digest, sha256_digest(&policy_bytes));
        assert_eq!(stage.outputs[0].digest, sha256_digest(&report_bytes));
        assert_eq!(stage.outputs[1].digest, sha256_digest(PACKAGE));
        assert_eq!(stage.outputs[2].digest, sha256_digest(PACKAGE));
        assert!(stage.detail.contains("2 independent attempts"));
        assert!(stage.detail.contains("match the subject package"));
    }

    #[test]
    fn differing_output_is_a_truthful_failed_stage() {
        let different = b"different rebuilt package";
        let policy = policy();
        let policy_bytes = serde_json::to_vec(&policy).expect("build policy bytes");
        let report = report(&subject(), &policy_bytes, PACKAGE, different);
        let stage = evaluate(&report, &policy, PACKAGE, different).expect("truthful build result");

        assert!(!stage.ok);
        assert_eq!(stage.outputs[2].digest, sha256_digest(different));
        assert!(stage.detail.contains("differ from the subject package"));
    }

    #[test]
    fn execution_isolation_and_policy_failures_are_truthful() {
        let mutations: [fn(&mut CertificationReproducibleBuildReport); 7] = [
            |value| value.builds[0].exit_code = 1,
            |value| value.builds[0].network_accesses = 1,
            |value| value.builds[0].undeclared_inputs = 1,
            |value| value.builds[0].duration_milliseconds = 30_001,
            |value| value.builds[1].attempt_id = value.builds[0].attempt_id.clone(),
            |value| value.builds[1].environment_digest = value.builds[0].environment_digest.clone(),
            |value| value.duration_milliseconds = 60_001,
        ];
        for mutate in mutations {
            let (policy, mut report) = matching_report();
            mutate(&mut report);
            assert!(
                !evaluate(&report, &policy, PACKAGE, PACKAGE)
                    .expect("truthful failure")
                    .ok
            );
        }
    }

    #[test]
    fn subject_package_source_policy_and_output_drift_are_rejected() {
        let (policy, report) = matching_report();
        let report_bytes = serde_json::to_vec(&report).expect("build report bytes");
        let policy_bytes = serde_json::to_vec(&policy).expect("build policy bytes");

        let error = evaluate_reproducible_build(
            CertificationReproducibleBuildEvidence {
                report_bytes: &report_bytes,
                policy_bytes: &policy_bytes,
                source_tree_bytes: SOURCE,
                subject_package_bytes: b"wrong package",
                rebuilt_package_a_bytes: PACKAGE,
                rebuilt_package_b_bytes: PACKAGE,
            },
            &subject(),
            producer(),
            STARTED,
            COMPLETED,
        )
        .expect_err("subject package drift");
        assert_eq!(error.code, "certification.reproducibleSubjectPackage");

        let mut drifted = report.clone();
        drifted.source_digest = sha256_digest(b"wrong source");
        assert_eq!(
            evaluate(&drifted, &policy, PACKAGE, PACKAGE)
                .expect_err("source drift")
                .code,
            "certification.reproducibleReport"
        );

        let mut drifted = report.clone();
        drifted.policy_digest = sha256_digest(b"wrong policy");
        assert_eq!(
            evaluate(&drifted, &policy, PACKAGE, PACKAGE)
                .expect_err("policy drift")
                .code,
            "certification.reproducibleReport"
        );

        let mut drifted = report;
        drifted.builds[0].package_digest = sha256_digest(b"unreported output");
        assert_eq!(
            evaluate(&drifted, &policy, PACKAGE, PACKAGE)
                .expect_err("output drift")
                .code,
            "certification.reproducibleBuild"
        );
    }

    #[test]
    fn empty_source_and_subject_identity_drift_are_rejected() {
        let (policy, report) = matching_report();
        let report_bytes = serde_json::to_vec(&report).expect("build report bytes");
        let policy_bytes = serde_json::to_vec(&policy).expect("build policy bytes");
        let mut drifted_subject = subject();
        drifted_subject.version = "9.9.9".into();

        let empty_source = evaluate_reproducible_build(
            CertificationReproducibleBuildEvidence {
                report_bytes: &report_bytes,
                policy_bytes: &policy_bytes,
                source_tree_bytes: b"",
                subject_package_bytes: PACKAGE,
                rebuilt_package_a_bytes: PACKAGE,
                rebuilt_package_b_bytes: PACKAGE,
            },
            &subject(),
            producer(),
            STARTED,
            COMPLETED,
        )
        .expect_err("empty source");
        assert_eq!(empty_source.code, "certification.reproducibleSource");

        assert_eq!(
            evaluate_reproducible_build(
                CertificationReproducibleBuildEvidence {
                    report_bytes: &report_bytes,
                    policy_bytes: &policy_bytes,
                    source_tree_bytes: SOURCE,
                    subject_package_bytes: PACKAGE,
                    rebuilt_package_a_bytes: PACKAGE,
                    rebuilt_package_b_bytes: PACKAGE,
                },
                &drifted_subject,
                producer(),
                STARTED,
                COMPLETED,
            )
            .expect_err("subject drift")
            .code,
            "certification.reproducibleReport"
        );
    }

    #[test]
    fn invalid_policy_contracts_fail_closed() {
        let mutations: [fn(&mut CertificationReproducibleBuildPolicy); 7] = [
            |value| value.schema_version = 2,
            |value| value.policy_id = "invalid policy id".into(),
            |value| value.required_independent_builds = 3,
            |value| value.require_distinct_environments = false,
            |value| value.maximum_build_duration_milliseconds = 0,
            |value| value.maximum_total_duration_milliseconds = 0,
            |value| value.maximum_build_duration_milliseconds = 60_001,
        ];
        for mutate in mutations {
            let (mut policy, report) = matching_report();
            mutate(&mut policy);
            assert_eq!(
                evaluate(&report, &policy, PACKAGE, PACKAGE)
                    .expect_err("invalid policy")
                    .code,
                "certification.reproduciblePolicy"
            );
        }
    }

    #[test]
    fn report_identity_timing_and_attempt_contracts_fail_closed() {
        let report_mutations: [(ReportMutation, &str); 8] = [
            (
                |value| value.schema_version = 2,
                "certification.reproducibleReport",
            ),
            (
                |value| value.builds.pop().map(drop).unwrap_or(()),
                "certification.reproducibleReport",
            ),
            (
                |value| value.started_at_unix = 0,
                "certification.reproducibleTiming",
            ),
            (
                |value| value.completed_at_unix += 1,
                "certification.reproducibleTiming",
            ),
            (
                |value| value.duration_milliseconds = 61_000,
                "certification.reproducibleTiming",
            ),
            (
                |value| value.builds[0].slot = "b".into(),
                "certification.reproducibleBuild",
            ),
            (
                |value| value.builds[0].environment_digest = "sha256:ABC".into(),
                "certification.reproducibleBuild",
            ),
            (
                |value| value.builds[0].duration_milliseconds = 60_500,
                "certification.reproducibleBuild",
            ),
        ];
        for (mutate, expected_code) in report_mutations {
            let (policy, mut report) = matching_report();
            mutate(&mut report);
            assert_eq!(
                evaluate(&report, &policy, PACKAGE, PACKAGE)
                    .expect_err("invalid report")
                    .code,
                expected_code
            );
        }
    }

    #[test]
    fn ambiguous_unknown_and_oversized_json_are_rejected() {
        let (policy, report) = matching_report();
        let report_bytes = serde_json::to_vec(&report).expect("build report bytes");
        let policy_bytes = serde_json::to_vec(&policy).expect("build policy bytes");
        let duplicate_policy = br#"{"schemaVersion":1,"schemaVersion":1}"#;
        let unknown_report = br#"{"schemaVersion":1,"unknownSecurityField":true}"#;

        let evaluate_bytes = |report_bytes: &[u8], policy_bytes: &[u8]| {
            evaluate_reproducible_build(
                CertificationReproducibleBuildEvidence {
                    report_bytes,
                    policy_bytes,
                    source_tree_bytes: SOURCE,
                    subject_package_bytes: PACKAGE,
                    rebuilt_package_a_bytes: PACKAGE,
                    rebuilt_package_b_bytes: PACKAGE,
                },
                &subject(),
                producer(),
                STARTED,
                COMPLETED,
            )
        };

        assert_eq!(
            evaluate_bytes(&report_bytes, duplicate_policy)
                .expect_err("duplicate policy")
                .code,
            "certification.reproduciblePolicyJson"
        );
        assert_eq!(
            evaluate_bytes(unknown_report, &policy_bytes)
                .expect_err("unknown report field")
                .code,
            "certification.reproducibleReportJson"
        );
        assert_eq!(
            evaluate_bytes(&vec![b' '; MAX_BUILD_REPORT_BYTES + 1], &policy_bytes)
                .expect_err("oversized report")
                .code,
            "certification.reproducibleReportSize"
        );
        assert_eq!(
            evaluate_bytes(&report_bytes, &vec![b' '; MAX_BUILD_POLICY_BYTES + 1])
                .expect_err("oversized policy")
                .code,
            "certification.reproduciblePolicySize"
        );
    }
}
