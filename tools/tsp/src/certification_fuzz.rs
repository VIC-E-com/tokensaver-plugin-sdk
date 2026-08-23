use crate::certification::{CertificationRequirement, CertificationSubject};
use crate::certification_pipeline::{
    CertificationEvidenceReference, CertificationStageEvidence, CertificationStageProducer,
    CertificationStageSubject, certification_rule, sha256_digest, validate_stage,
};
use crate::manifest::ValidationError;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CERTIFICATION_FUZZ_PROTOCOL: &str = "TSPP/1";
const MAX_FUZZ_REPORT_BYTES: usize = 2 << 20;
const MAX_FUZZ_POLICY_BYTES: usize = 64 << 10;
const MAX_FUZZ_CORPUS_BYTES: usize = 32 << 20;
const MAX_FUZZ_EXECUTIONS: u64 = 1_000_000_000;
const MAX_FUZZ_DURATION_MILLISECONDS: u64 = 7 * 24 * 60 * 60 * 1_000;
const MAX_FUZZ_CASES: usize = 100_000;
const MAX_FUZZ_REPETITIONS: u32 = 1_000_000;
const MAX_FUZZ_INPUT_BYTES: usize = 16 << 20;
const MAX_FUZZ_EXECUTION_MILLISECONDS: u64 = 60_000;
const MAX_FUZZ_MEMORY_BYTES: u64 = 16 << 30;
const MAX_FUZZ_STREAM_BYTES: u64 = 64 << 20;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificationFuzzCaseClass {
    Valid,
    Malformed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationFuzzCase {
    pub id: String,
    pub class: CertificationFuzzCaseClass,
    pub input_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationFuzzExecutionLimits {
    pub maximum_execution_milliseconds: u64,
    pub maximum_memory_bytes: u64,
    pub maximum_stdout_bytes: u64,
    pub maximum_stderr_bytes: u64,
    pub required_sanitizers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationFuzzCorpus {
    pub schema_version: u32,
    pub corpus_id: String,
    pub protocol: String,
    pub repetitions: u32,
    pub limits: CertificationFuzzExecutionLimits,
    pub cases: Vec<CertificationFuzzCase>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationFuzzEngine {
    pub id: String,
    pub version: String,
    pub active_sanitizers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationFuzzPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub protocol: String,
    pub corpus_id: String,
    pub corpus_digest: String,
    pub minimum_executions: u64,
    pub minimum_valid_inputs: u64,
    pub minimum_malformed_inputs: u64,
    pub minimum_coverage_basis_points: u32,
    pub maximum_duration_milliseconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationFuzzReport {
    pub schema_version: u32,
    pub subject: CertificationStageSubject,
    pub protocol: String,
    pub engine: CertificationFuzzEngine,
    pub corpus_digest: String,
    pub started_at_unix: u64,
    pub completed_at_unix: u64,
    pub total_executions: u64,
    pub valid_inputs: u64,
    pub valid_inputs_accepted: u64,
    pub malformed_inputs: u64,
    pub malformed_inputs_rejected: u64,
    pub coverage_basis_points: u32,
    pub crashes: u64,
    pub hangs: u64,
    pub sanitizer_failures: u64,
    pub memory_limit_violations: u64,
    pub stdout_protocol_violations: u64,
    pub stderr_limit_violations: u64,
    pub deadline_violations: u64,
    pub unreaped_processes: u64,
    pub duration_milliseconds: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct CertificationFuzzEvidence<'a> {
    pub report_bytes: &'a [u8],
    pub policy_bytes: &'a [u8],
    pub plugin_executable_bytes: &'a [u8],
    pub protocol_corpus_bytes: &'a [u8],
}

/// Evaluates exact protocol-fuzz evidence without executing untrusted plugin code.
///
/// The trusted fuzz runner supplies its exact report, policy, executable, and corpus bytes. This
/// evaluator independently verifies identities, accounting, thresholds, and safety outcomes, then
/// returns unsigned stage evidence. It does not certify, install, enable, or activate a plugin.
pub fn evaluate_protocol_fuzzing(
    evidence: CertificationFuzzEvidence<'_>,
    subject: &CertificationSubject,
    producer: CertificationStageProducer,
    started_at_unix: u64,
    completed_at_unix: u64,
) -> Result<CertificationStageEvidence, ValidationError> {
    let CertificationFuzzEvidence {
        report_bytes: fuzz_report_bytes,
        policy_bytes: fuzz_policy_bytes,
        plugin_executable_bytes,
        protocol_corpus_bytes,
    } = evidence;
    let report = parse_fuzz_report(fuzz_report_bytes)?;
    let policy = parse_certification_fuzz_policy(fuzz_policy_bytes)?;
    let corpus = parse_certification_fuzz_corpus(protocol_corpus_bytes)?;
    validate_certification_fuzz_plan(&policy, &corpus, protocol_corpus_bytes)?;

    if plugin_executable_bytes.is_empty()
        || sha256_digest(plugin_executable_bytes) != subject.artifact_digest
    {
        return Err(fuzz_error(
            "certification.fuzzArtifact",
            "protocol-fuzz evidence is not bound to the subject executable bytes",
            "Evaluate the exact executable named by the certification subject.",
        ));
    }
    let corpus_digest = sha256_digest(protocol_corpus_bytes);
    if report.corpus_digest != corpus_digest {
        return Err(fuzz_error(
            "certification.fuzzCorpus",
            "protocol-fuzz report, policy, and corpus bytes do not share one exact digest",
            "Run the named policy against the exact immutable protocol corpus.",
        ));
    }
    validate_fuzz_report(&report, subject, started_at_unix, completed_at_unix)?;
    validate_report_corpus(&report, &corpus)?;

    let safety_failures = safety_failure_count(&report)?;
    let ok = report.total_executions >= policy.minimum_executions
        && report.valid_inputs >= policy.minimum_valid_inputs
        && report.malformed_inputs >= policy.minimum_malformed_inputs
        && report.coverage_basis_points >= policy.minimum_coverage_basis_points
        && report.duration_milliseconds <= policy.maximum_duration_milliseconds
        && report.valid_inputs_accepted == report.valid_inputs
        && report.malformed_inputs_rejected == report.malformed_inputs
        && safety_failures == 0;
    let detail = format!(
        "protocol fuzz {}: {} executions, {}/{} valid accepted, {}/{} malformed rejected, {}.{:02}% coverage, {} ms, {} safety failures",
        policy.corpus_id,
        report.total_executions,
        report.valid_inputs_accepted,
        report.valid_inputs,
        report.malformed_inputs_rejected,
        report.malformed_inputs,
        report.coverage_basis_points / 100,
        report.coverage_basis_points % 100,
        report.duration_milliseconds,
        safety_failures,
    );
    let remediation = if ok {
        "rerun the exact protocol corpus and policy for every executable release"
    } else {
        "meet every execution, input-class, coverage, and duration threshold with complete acceptance and rejection and zero process or protocol safety failures"
    };
    let stage = CertificationStageEvidence {
        schema_version: 1,
        requirement: CertificationRequirement::ProtocolFuzzing,
        subject: subject.into(),
        rule: certification_rule(CertificationRequirement::ProtocolFuzzing).into(),
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
                name: "protocol-corpus".into(),
                digest: corpus_digest,
            },
            CertificationEvidenceReference {
                name: "fuzz-policy".into(),
                digest: sha256_digest(fuzz_policy_bytes),
            },
        ],
        outputs: vec![CertificationEvidenceReference {
            name: "fuzz-report".into(),
            digest: sha256_digest(fuzz_report_bytes),
        }],
        detail,
        remediation: remediation.into(),
    };
    validate_stage(&stage, subject)?;
    Ok(stage)
}

fn parse_fuzz_report(bytes: &[u8]) -> Result<CertificationFuzzReport, ValidationError> {
    parse_json(
        bytes,
        MAX_FUZZ_REPORT_BYTES,
        "certification.fuzzReportSize",
        "certification.fuzzReportJson",
        "protocol-fuzz report",
        "2 MiB",
        "schemas/certification-fuzz-report.v1.json",
    )
}

pub fn parse_certification_fuzz_policy(
    bytes: &[u8],
) -> Result<CertificationFuzzPolicy, ValidationError> {
    let policy = parse_json(
        bytes,
        MAX_FUZZ_POLICY_BYTES,
        "certification.fuzzPolicySize",
        "certification.fuzzPolicyJson",
        "protocol-fuzz policy",
        "64 KiB",
        "schemas/certification-fuzz-policy.v1.json",
    )?;
    validate_fuzz_policy(&policy)?;
    Ok(policy)
}

pub fn parse_certification_fuzz_corpus(
    bytes: &[u8],
) -> Result<CertificationFuzzCorpus, ValidationError> {
    let corpus = parse_json(
        bytes,
        MAX_FUZZ_CORPUS_BYTES,
        "certification.fuzzCorpusSize",
        "certification.fuzzCorpusJson",
        "protocol-fuzz corpus",
        "32 MiB",
        "schemas/certification-fuzz-corpus.v1.json",
    )?;
    validate_fuzz_corpus(&corpus)?;
    Ok(corpus)
}

pub fn decode_certification_fuzz_case(
    case: &CertificationFuzzCase,
) -> Result<Vec<u8>, ValidationError> {
    let input = BASE64.decode(&case.input_base64).map_err(|_| {
        fuzz_error(
            "certification.fuzzCorpusCase",
            "protocol-fuzz case input is not canonical standard base64",
            "Encode each bounded case input with padded standard base64.",
        )
    })?;
    if input.len() > MAX_FUZZ_INPUT_BYTES || BASE64.encode(&input) != case.input_base64 {
        return Err(fuzz_error(
            "certification.fuzzCorpusCase",
            "protocol-fuzz case input is oversized or not canonical standard base64",
            "Encode at most 16 MiB per case with padded standard base64.",
        ));
    }
    Ok(input)
}

pub fn validate_certification_fuzz_plan(
    policy: &CertificationFuzzPolicy,
    corpus: &CertificationFuzzCorpus,
    corpus_bytes: &[u8],
) -> Result<(), ValidationError> {
    validate_fuzz_policy(policy)?;
    validate_fuzz_corpus(corpus)?;
    if policy.corpus_digest != sha256_digest(corpus_bytes) {
        return Err(fuzz_error(
            "certification.fuzzCorpus",
            "protocol-fuzz policy and corpus bytes do not share one exact digest",
            "Run the named policy against the exact immutable protocol corpus bytes.",
        ));
    }
    validate_policy_corpus(policy, corpus)
}

pub fn validate_certification_fuzz_engine(
    engine: &CertificationFuzzEngine,
    corpus: &CertificationFuzzCorpus,
) -> Result<(), ValidationError> {
    if !valid_token(&engine.id)
        || !valid_token(&engine.version)
        || engine.active_sanitizers.is_empty()
        || engine
            .active_sanitizers
            .iter()
            .any(|sanitizer| !valid_sanitizer(sanitizer))
        || engine
            .active_sanitizers
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || !corpus
            .limits
            .required_sanitizers
            .iter()
            .all(|required| engine.active_sanitizers.binary_search(required).is_ok())
    {
        return Err(fuzz_error(
            "certification.fuzzEngine",
            "protocol-fuzz engine identity or active sanitizer set is invalid",
            "Use a bounded engine identity with sorted supported sanitizers covering the corpus requirements.",
        ));
    }
    Ok(())
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
        return Err(fuzz_error(
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

fn validate_fuzz_policy(policy: &CertificationFuzzPolicy) -> Result<(), ValidationError> {
    if policy.schema_version != 1
        || policy.protocol != CERTIFICATION_FUZZ_PROTOCOL
        || !valid_token(&policy.policy_id)
        || !valid_token(&policy.corpus_id)
        || !valid_digest(&policy.corpus_digest)
        || !(1..=MAX_FUZZ_EXECUTIONS).contains(&policy.minimum_executions)
        || !(1..=MAX_FUZZ_EXECUTIONS).contains(&policy.minimum_valid_inputs)
        || !(1..=MAX_FUZZ_EXECUTIONS).contains(&policy.minimum_malformed_inputs)
        || policy.minimum_coverage_basis_points > 10_000
        || !(1..=MAX_FUZZ_DURATION_MILLISECONDS).contains(&policy.maximum_duration_milliseconds)
    {
        return Err(fuzz_error(
            "certification.fuzzPolicy",
            "protocol-fuzz policy identity or thresholds are invalid",
            "Use bounded TSPP/1 execution, input-class, coverage, and duration thresholds.",
        ));
    }
    Ok(())
}

fn validate_fuzz_corpus(corpus: &CertificationFuzzCorpus) -> Result<(), ValidationError> {
    if corpus.schema_version != 1
        || corpus.protocol != CERTIFICATION_FUZZ_PROTOCOL
        || !valid_token(&corpus.corpus_id)
        || !(1..=MAX_FUZZ_REPETITIONS).contains(&corpus.repetitions)
        || corpus.cases.is_empty()
        || corpus.cases.len() > MAX_FUZZ_CASES
        || !(1..=MAX_FUZZ_EXECUTION_MILLISECONDS)
            .contains(&corpus.limits.maximum_execution_milliseconds)
        || !(1..=MAX_FUZZ_MEMORY_BYTES).contains(&corpus.limits.maximum_memory_bytes)
        || !(1..=MAX_FUZZ_STREAM_BYTES).contains(&corpus.limits.maximum_stdout_bytes)
        || !(1..=MAX_FUZZ_STREAM_BYTES).contains(&corpus.limits.maximum_stderr_bytes)
        || corpus.limits.required_sanitizers.is_empty()
    {
        return Err(fuzz_error(
            "certification.fuzzCorpus",
            "protocol-fuzz corpus identity, execution plan, or resource limits are invalid",
            "Use one bounded TSPP/1 corpus with nonzero cases, repetitions, limits, and sanitizers.",
        ));
    }
    let mut sanitizers = BTreeSet::new();
    let mut previous_sanitizer = None;
    for sanitizer in &corpus.limits.required_sanitizers {
        if !valid_sanitizer(sanitizer)
            || previous_sanitizer.is_some_and(|value: &str| value >= sanitizer)
            || !sanitizers.insert(sanitizer.as_str())
        {
            return Err(fuzz_error(
                "certification.fuzzCorpusSanitizers",
                "required fuzz sanitizers are invalid, duplicated, or not canonically sorted",
                "Use sorted unique sanitizer ids from the supported v1 sanitizer set.",
            ));
        }
        previous_sanitizer = Some(sanitizer);
    }

    let mut previous_case = None;
    let mut valid_cases = 0u64;
    let mut malformed_cases = 0u64;
    for case in &corpus.cases {
        if !valid_token(&case.id)
            || previous_case.is_some_and(|value: &str| value >= case.id.as_str())
        {
            return Err(fuzz_error(
                "certification.fuzzCorpusCase",
                "protocol-fuzz cases have invalid, duplicate, or noncanonical ids",
                "Use unique bounded case ids sorted by bytewise ascending order.",
            ));
        }
        decode_certification_fuzz_case(case)?;
        match case.class {
            CertificationFuzzCaseClass::Valid => valid_cases += 1,
            CertificationFuzzCaseClass::Malformed => malformed_cases += 1,
        }
        previous_case = Some(case.id.as_str());
    }
    if valid_cases == 0 || malformed_cases == 0 {
        return Err(fuzz_error(
            "certification.fuzzCorpusClass",
            "protocol-fuzz corpus must contain both valid and malformed cases",
            "Add at least one valid and one malformed TSPP/1 case.",
        ));
    }
    planned_execution_counts(corpus)?;
    Ok(())
}

fn validate_policy_corpus(
    policy: &CertificationFuzzPolicy,
    corpus: &CertificationFuzzCorpus,
) -> Result<(), ValidationError> {
    let (planned_total, planned_valid, planned_malformed) = planned_execution_counts(corpus)?;
    if policy.corpus_id != corpus.corpus_id
        || policy.minimum_executions > planned_total
        || policy.minimum_valid_inputs > planned_valid
        || policy.minimum_malformed_inputs > planned_malformed
    {
        return Err(fuzz_error(
            "certification.fuzzPolicyCorpus",
            "protocol-fuzz policy cannot be satisfied by the named corpus execution plan",
            "Bind policy thresholds to a corpus with enough valid and malformed executions.",
        ));
    }
    Ok(())
}

fn validate_report_corpus(
    report: &CertificationFuzzReport,
    corpus: &CertificationFuzzCorpus,
) -> Result<(), ValidationError> {
    validate_certification_fuzz_engine(&report.engine, corpus)?;
    let (planned_total, planned_valid, planned_malformed) = planned_execution_counts(corpus)?;
    if report.total_executions > planned_total
        || report.valid_inputs > planned_valid
        || report.malformed_inputs > planned_malformed
    {
        return Err(fuzz_error(
            "certification.fuzzReportCorpus",
            "protocol-fuzz report exceeds its corpus plan or lacks a required sanitizer",
            "Generate the report from the exact corpus plan with every required sanitizer active.",
        ));
    }
    Ok(())
}

fn planned_execution_counts(
    corpus: &CertificationFuzzCorpus,
) -> Result<(u64, u64, u64), ValidationError> {
    let repetitions = u64::from(corpus.repetitions);
    let valid = corpus
        .cases
        .iter()
        .filter(|case| case.class == CertificationFuzzCaseClass::Valid)
        .count() as u64;
    let malformed = corpus.cases.len() as u64 - valid;
    let planned_valid = valid
        .checked_mul(repetitions)
        .ok_or_else(fuzz_accounting_overflow)?;
    let planned_malformed = malformed
        .checked_mul(repetitions)
        .ok_or_else(fuzz_accounting_overflow)?;
    let planned_total = planned_valid
        .checked_add(planned_malformed)
        .ok_or_else(fuzz_accounting_overflow)?;
    if planned_total > MAX_FUZZ_EXECUTIONS {
        return Err(fuzz_error(
            "certification.fuzzCorpusExecutions",
            "protocol-fuzz corpus execution plan exceeds the one-billion execution bound",
            "Reduce cases or repetitions while preserving required policy coverage.",
        ));
    }
    Ok((planned_total, planned_valid, planned_malformed))
}

fn valid_sanitizer(value: &str) -> bool {
    matches!(
        value,
        "address" | "leak" | "memory" | "thread" | "undefined"
    )
}

fn validate_fuzz_report(
    report: &CertificationFuzzReport,
    subject: &CertificationSubject,
    started_at_unix: u64,
    completed_at_unix: u64,
) -> Result<(), ValidationError> {
    if report.schema_version != 1
        || report.subject != CertificationStageSubject::from(subject)
        || report.subject.api_version != 1
        || report.protocol != CERTIFICATION_FUZZ_PROTOCOL
        || !valid_token(&report.engine.id)
        || !valid_token(&report.engine.version)
        || !valid_digest(&report.corpus_digest)
    {
        return Err(fuzz_error(
            "certification.fuzzReport",
            "protocol-fuzz report version, subject, protocol, engine, or corpus identity is invalid",
            "Use a v1 TSPP/1 report for the exact immutable certification subject.",
        ));
    }
    if report.engine.active_sanitizers.is_empty()
        || report
            .engine
            .active_sanitizers
            .iter()
            .any(|sanitizer| !valid_sanitizer(sanitizer))
        || report
            .engine
            .active_sanitizers
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(fuzz_error(
            "certification.fuzzReportSanitizers",
            "protocol-fuzz report sanitizers are invalid, duplicated, or not canonically sorted",
            "Report the sorted unique supported sanitizers active for the complete campaign.",
        ));
    }
    if report.started_at_unix == 0
        || report.started_at_unix != started_at_unix
        || report.completed_at_unix != completed_at_unix
        || report.completed_at_unix < report.started_at_unix
        || report.duration_milliseconds > MAX_FUZZ_DURATION_MILLISECONDS
        || report.duration_milliseconds
            > report
                .completed_at_unix
                .saturating_sub(report.started_at_unix)
                .saturating_mul(1_000)
                .saturating_add(999)
    {
        return Err(fuzz_error(
            "certification.fuzzTiming",
            "protocol-fuzz timing is inconsistent or outside the seven-day bound",
            "Bind the report and stage to the same bounded runner timestamps and duration.",
        ));
    }
    let classified_inputs = report
        .valid_inputs
        .checked_add(report.malformed_inputs)
        .ok_or_else(fuzz_accounting_overflow)?;
    if report.total_executions > MAX_FUZZ_EXECUTIONS
        || report.total_executions != classified_inputs
        || report.valid_inputs_accepted > report.valid_inputs
        || report.malformed_inputs_rejected > report.malformed_inputs
        || report.coverage_basis_points > 10_000
    {
        return Err(fuzz_error(
            "certification.fuzzAccounting",
            "protocol-fuzz execution, input-class, acceptance, rejection, or coverage accounting is invalid",
            "Regenerate the report from bounded per-input fuzz-runner counters.",
        ));
    }
    for count in safety_counts(report) {
        if count > report.total_executions {
            return Err(fuzz_error(
                "certification.fuzzAccounting",
                "a protocol-fuzz safety counter exceeds total executions",
                "Regenerate the report from bounded per-execution safety counters.",
            ));
        }
    }
    Ok(())
}

fn safety_counts(report: &CertificationFuzzReport) -> [u64; 8] {
    [
        report.crashes,
        report.hangs,
        report.sanitizer_failures,
        report.memory_limit_violations,
        report.stdout_protocol_violations,
        report.stderr_limit_violations,
        report.deadline_violations,
        report.unreaped_processes,
    ]
}

fn safety_failure_count(report: &CertificationFuzzReport) -> Result<u64, ValidationError> {
    safety_counts(report)
        .into_iter()
        .try_fold(0u64, |total, count| total.checked_add(count))
        .ok_or_else(fuzz_accounting_overflow)
}

fn fuzz_accounting_overflow() -> ValidationError {
    fuzz_error(
        "certification.fuzzAccounting",
        "protocol-fuzz accounting overflowed an unsigned 64-bit integer",
        "Use bounded per-execution fuzz-runner counters.",
    )
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

fn fuzz_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> ValidationError {
    ValidationError::new(code, message, remediation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    const EXECUTABLE: &[u8] = b"exact plugin executable bytes";
    const STARTED: u64 = 2_000_000_000;
    const COMPLETED: u64 = 2_000_000_060;

    fn corpus() -> &'static [u8] {
        static CORPUS: LazyLock<Vec<u8>> = LazyLock::new(|| {
            serde_json::to_vec(&CertificationFuzzCorpus {
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
                    fuzz_case("malformed-1", CertificationFuzzCaseClass::Malformed, b""),
                    fuzz_case(
                        "malformed-2",
                        CertificationFuzzCaseClass::Malformed,
                        b"Content-Length: nope\r\n\r\n",
                    ),
                    fuzz_case(
                        "malformed-3",
                        CertificationFuzzCaseClass::Malformed,
                        b"Content-Length: 0\r\n\r\n",
                    ),
                    fuzz_case(
                        "valid-1",
                        CertificationFuzzCaseClass::Valid,
                        b"Content-Length: 2\r\n\r\n{}",
                    ),
                    fuzz_case(
                        "valid-2",
                        CertificationFuzzCaseClass::Valid,
                        b"Content-Length: 4\r\n\r\nnull",
                    ),
                ],
            })
            .expect("fuzz corpus bytes")
        });
        CORPUS.as_slice()
    }

    fn fuzz_case(
        id: &str,
        class: CertificationFuzzCaseClass,
        input: &[u8],
    ) -> CertificationFuzzCase {
        CertificationFuzzCase {
            id: id.into(),
            class,
            input_base64: BASE64.encode(input),
        }
    }

    fn subject() -> CertificationSubject {
        let artifact_digest = sha256_digest(EXECUTABLE);
        let mut subject = CertificationSubject {
            plugin_id: "com.example.plugin".into(),
            version: "1.2.3".into(),
            platform: "linux-x64".into(),
            api_version: 1,
            artifact_digest,
            package_digest: sha256_digest(b"exact package bytes"),
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
            id: "com.tokensaver.certification-fuzzer".into(),
            version: "1.0.0".into(),
            environment_digest: sha256_digest(b"immutable runner environment"),
        }
    }

    fn policy() -> CertificationFuzzPolicy {
        CertificationFuzzPolicy {
            schema_version: 1,
            policy_id: "com.tokensaver.certification.protocol-fuzz.v1".into(),
            protocol: CERTIFICATION_FUZZ_PROTOCOL.into(),
            corpus_id: "com.tokensaver.tspp-fuzz-corpus.v1".into(),
            corpus_digest: sha256_digest(corpus()),
            minimum_executions: 1_000,
            minimum_valid_inputs: 400,
            minimum_malformed_inputs: 600,
            minimum_coverage_basis_points: 9_000,
            maximum_duration_milliseconds: 60_000,
        }
    }

    fn report(subject: &CertificationSubject) -> CertificationFuzzReport {
        CertificationFuzzReport {
            schema_version: 1,
            subject: subject.into(),
            protocol: CERTIFICATION_FUZZ_PROTOCOL.into(),
            engine: CertificationFuzzEngine {
                id: "cargo-fuzz-libfuzzer".into(),
                version: "0.12.0".into(),
                active_sanitizers: vec!["address".into(), "undefined".into()],
            },
            corpus_digest: sha256_digest(corpus()),
            started_at_unix: STARTED,
            completed_at_unix: COMPLETED,
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
        }
    }

    fn evaluate(
        report: &CertificationFuzzReport,
        policy: &CertificationFuzzPolicy,
    ) -> Result<CertificationStageEvidence, ValidationError> {
        let report_bytes = serde_json::to_vec(report).expect("fuzz report bytes");
        let policy_bytes = serde_json::to_vec(policy).expect("fuzz policy bytes");
        evaluate_protocol_fuzzing(
            evidence(&report_bytes, &policy_bytes, EXECUTABLE, corpus()),
            &subject(),
            producer(),
            STARTED,
            COMPLETED,
        )
    }

    fn evidence<'a>(
        report_bytes: &'a [u8],
        policy_bytes: &'a [u8],
        plugin_executable_bytes: &'a [u8],
        protocol_corpus_bytes: &'a [u8],
    ) -> CertificationFuzzEvidence<'a> {
        CertificationFuzzEvidence {
            report_bytes,
            policy_bytes,
            plugin_executable_bytes,
            protocol_corpus_bytes,
        }
    }

    #[test]
    fn passing_report_binds_every_exact_evidence_digest() {
        let subject = subject();
        let report_bytes = serde_json::to_vec(&report(&subject)).expect("fuzz report bytes");
        let policy_bytes = serde_json::to_vec(&policy()).expect("fuzz policy bytes");
        let stage = evaluate_protocol_fuzzing(
            evidence(&report_bytes, &policy_bytes, EXECUTABLE, corpus()),
            &subject,
            producer(),
            STARTED,
            COMPLETED,
        )
        .expect("protocol-fuzz evaluation");
        assert!(stage.ok);
        assert_eq!(stage.inputs[0].digest, sha256_digest(EXECUTABLE));
        assert_eq!(stage.inputs[1].digest, sha256_digest(corpus()));
        assert_eq!(stage.inputs[2].digest, sha256_digest(&policy_bytes));
        assert_eq!(stage.outputs[0].digest, sha256_digest(&report_bytes));
        assert!(stage.detail.contains("1000 executions"));
        assert!(stage.detail.contains("0 safety failures"));
    }

    #[test]
    fn unmet_policy_threshold_is_a_truthful_failed_stage() {
        let subject = subject();
        let mut strict = policy();
        strict.minimum_coverage_basis_points = 9_001;
        let stage = evaluate(&report(&subject), &strict).expect("truthful threshold result");
        assert!(!stage.ok);
    }

    #[test]
    fn every_process_and_protocol_safety_failure_fails_the_stage() {
        let subject = subject();
        let mutations: [fn(&mut CertificationFuzzReport); 8] = [
            |value| value.crashes = 1,
            |value| value.hangs = 1,
            |value| value.sanitizer_failures = 1,
            |value| value.memory_limit_violations = 1,
            |value| value.stdout_protocol_violations = 1,
            |value| value.stderr_limit_violations = 1,
            |value| value.deadline_violations = 1,
            |value| value.unreaped_processes = 1,
        ];
        for mutate in mutations {
            let mut failed = report(&subject);
            mutate(&mut failed);
            assert!(
                !evaluate(&failed, &policy())
                    .expect("truthful safety result")
                    .ok
            );
        }
    }

    #[test]
    fn incomplete_acceptance_and_rejection_fail_without_corrupting_evidence() {
        let subject = subject();
        let mut incomplete_valid = report(&subject);
        incomplete_valid.valid_inputs_accepted -= 1;
        assert!(
            !evaluate(&incomplete_valid, &policy())
                .expect("valid rejection")
                .ok
        );

        let mut incomplete_malformed = report(&subject);
        incomplete_malformed.malformed_inputs_rejected -= 1;
        assert!(
            !evaluate(&incomplete_malformed, &policy())
                .expect("malformed acceptance")
                .ok
        );
    }

    #[test]
    fn inconsistent_accounting_is_rejected() {
        let subject = subject();
        let mut cases = vec![report(&subject), report(&subject), report(&subject)];
        cases[0].total_executions += 1;
        cases[1].valid_inputs_accepted = cases[1].valid_inputs + 1;
        cases[2].malformed_inputs_rejected = cases[2].malformed_inputs + 1;
        for invalid in cases {
            assert_eq!(
                evaluate(&invalid, &policy())
                    .expect_err("invalid fuzz accounting")
                    .code,
                "certification.fuzzAccounting"
            );
        }

        let mut overflow = report(&subject);
        overflow.valid_inputs = u64::MAX;
        overflow.malformed_inputs = 1;
        overflow.total_executions = u64::MAX;
        assert_eq!(
            evaluate(&overflow, &policy())
                .expect_err("overflowing classification accounting")
                .code,
            "certification.fuzzAccounting"
        );

        let mut impossible_safety_count = report(&subject);
        impossible_safety_count.crashes = impossible_safety_count.total_executions + 1;
        assert_eq!(
            evaluate(&impossible_safety_count, &policy())
                .expect_err("impossible safety count")
                .code,
            "certification.fuzzAccounting"
        );
    }

    #[test]
    fn timing_protocol_and_policy_contracts_fail_closed() {
        let subject = subject();
        let mut wrong_protocol = report(&subject);
        wrong_protocol.protocol = "TSPP/2".into();
        assert_eq!(
            evaluate(&wrong_protocol, &policy())
                .expect_err("wrong report protocol")
                .code,
            "certification.fuzzReport"
        );

        let mut wrong_policy_protocol = policy();
        wrong_policy_protocol.protocol = "TSPP/2".into();
        assert_eq!(
            evaluate(&report(&subject), &wrong_policy_protocol)
                .expect_err("wrong policy protocol")
                .code,
            "certification.fuzzPolicy"
        );

        let mut inconsistent_time = report(&subject);
        inconsistent_time.completed_at_unix += 1;
        assert_eq!(
            evaluate(&inconsistent_time, &policy())
                .expect_err("inconsistent report and stage time")
                .code,
            "certification.fuzzTiming"
        );

        let mut duration_policy = policy();
        duration_policy.maximum_duration_milliseconds = 59_499;
        assert!(
            !evaluate(&report(&subject), &duration_policy)
                .expect("truthful duration threshold result")
                .ok
        );
    }

    #[test]
    fn subject_executable_and_corpus_drift_are_rejected() {
        let subject = subject();
        let mut drifted_subject = report(&subject);
        drifted_subject.subject.version = "9.9.9".into();
        assert_eq!(
            evaluate(&drifted_subject, &policy())
                .expect_err("subject drift")
                .code,
            "certification.fuzzReport"
        );

        let mut drifted_report_corpus = report(&subject);
        drifted_report_corpus.corpus_digest = sha256_digest(b"different corpus");
        assert_eq!(
            evaluate(&drifted_report_corpus, &policy())
                .expect_err("report corpus drift")
                .code,
            "certification.fuzzCorpus"
        );

        let report_bytes = serde_json::to_vec(&report(&subject)).expect("report bytes");
        let policy_bytes = serde_json::to_vec(&policy()).expect("policy bytes");
        assert_eq!(
            evaluate_protocol_fuzzing(
                evidence(
                    &report_bytes,
                    &policy_bytes,
                    b"different executable",
                    corpus(),
                ),
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
            .expect_err("artifact drift")
            .code,
            "certification.fuzzArtifact"
        );
        assert_eq!(
            evaluate_protocol_fuzzing(
                evidence(
                    &report_bytes,
                    &policy_bytes,
                    EXECUTABLE,
                    b"different corpus",
                ),
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
            .expect_err("corpus drift")
            .code,
            "certification.fuzzCorpusJson"
        );
    }

    #[test]
    fn corpus_plan_cases_limits_and_sanitizers_fail_closed() {
        let parsed =
            || serde_json::from_slice::<CertificationFuzzCorpus>(corpus()).expect("parsed corpus");

        let mut unsorted_cases = parsed();
        unsorted_cases.cases.swap(0, 1);
        assert_eq!(
            parse_certification_fuzz_corpus(
                &serde_json::to_vec(&unsorted_cases).expect("unsorted corpus")
            )
            .expect_err("unsorted cases")
            .code,
            "certification.fuzzCorpusCase"
        );

        let mut invalid_base64 = parsed();
        invalid_base64.cases[0].input_base64 = "%%%".into();
        assert_eq!(
            parse_certification_fuzz_corpus(
                &serde_json::to_vec(&invalid_base64).expect("invalid base64 corpus")
            )
            .expect_err("invalid case base64")
            .code,
            "certification.fuzzCorpusCase"
        );

        let mut one_class = parsed();
        for case in &mut one_class.cases {
            case.class = CertificationFuzzCaseClass::Malformed;
        }
        assert_eq!(
            parse_certification_fuzz_corpus(
                &serde_json::to_vec(&one_class).expect("one-class corpus")
            )
            .expect_err("missing valid class")
            .code,
            "certification.fuzzCorpusClass"
        );

        let mut invalid_limits = parsed();
        invalid_limits.limits.maximum_execution_milliseconds = 0;
        assert_eq!(
            parse_certification_fuzz_corpus(
                &serde_json::to_vec(&invalid_limits).expect("invalid limits corpus")
            )
            .expect_err("zero execution limit")
            .code,
            "certification.fuzzCorpus"
        );

        let mut invalid_sanitizers = parsed();
        invalid_sanitizers.limits.required_sanitizers = vec!["undefined".into(), "address".into()];
        assert_eq!(
            parse_certification_fuzz_corpus(
                &serde_json::to_vec(&invalid_sanitizers).expect("invalid sanitizer corpus")
            )
            .expect_err("unsorted sanitizers")
            .code,
            "certification.fuzzCorpusSanitizers"
        );

        let mut impossible_policy = policy();
        impossible_policy.minimum_valid_inputs += 1;
        assert_eq!(
            validate_certification_fuzz_plan(&impossible_policy, &parsed(), corpus())
                .expect_err("impossible policy")
                .code,
            "certification.fuzzPolicyCorpus"
        );

        let mut over_plan = report(&subject());
        over_plan.total_executions += 1;
        over_plan.malformed_inputs += 1;
        over_plan.malformed_inputs_rejected += 1;
        assert_eq!(
            evaluate(&over_plan, &policy())
                .expect_err("report exceeds corpus plan")
                .code,
            "certification.fuzzReportCorpus"
        );

        let mut missing_sanitizer = report(&subject());
        missing_sanitizer.engine.active_sanitizers = vec!["undefined".into()];
        assert_eq!(
            evaluate(&missing_sanitizer, &policy())
                .expect_err("required sanitizer missing")
                .code,
            "certification.fuzzEngine"
        );
    }

    #[test]
    fn ambiguous_unknown_and_oversized_documents_are_rejected() {
        let subject = subject();
        let policy_bytes = serde_json::to_vec(&policy()).expect("policy bytes");
        let report_bytes = serde_json::to_vec(&report(&subject)).expect("report bytes");

        let mut unknown_corpus =
            serde_json::from_slice::<serde_json::Value>(corpus()).expect("corpus value");
        unknown_corpus["unknownSecurityField"] = serde_json::json!(true);
        assert_eq!(
            parse_certification_fuzz_corpus(
                &serde_json::to_vec(&unknown_corpus).expect("unknown corpus")
            )
            .expect_err("unknown corpus field")
            .code,
            "certification.fuzzCorpusJson"
        );
        assert_eq!(
            parse_certification_fuzz_corpus(br#"{"schemaVersion":1,"schemaVersion":1}"#)
                .expect_err("duplicate corpus member")
                .code,
            "certification.fuzzCorpusJson"
        );

        let mut unknown_report = serde_json::to_value(report(&subject)).expect("report value");
        unknown_report["unknownSecurityField"] = serde_json::json!(true);
        let unknown_report_bytes = serde_json::to_vec(&unknown_report).expect("unknown report");
        assert_eq!(
            evaluate_protocol_fuzzing(
                evidence(&unknown_report_bytes, &policy_bytes, EXECUTABLE, corpus()),
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
            .expect_err("unknown report field")
            .code,
            "certification.fuzzReportJson"
        );

        let mut unknown_policy = serde_json::to_value(policy()).expect("policy value");
        unknown_policy["unknownSecurityField"] = serde_json::json!(true);
        let unknown_policy_bytes = serde_json::to_vec(&unknown_policy).expect("unknown policy");
        assert_eq!(
            evaluate_protocol_fuzzing(
                evidence(&report_bytes, &unknown_policy_bytes, EXECUTABLE, corpus()),
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
            .expect_err("unknown policy field")
            .code,
            "certification.fuzzPolicyJson"
        );
        assert_eq!(
            evaluate_protocol_fuzzing(
                evidence(
                    &report_bytes,
                    br#"{"schemaVersion":1,"schemaVersion":1}"#,
                    EXECUTABLE,
                    corpus(),
                ),
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
            .expect_err("duplicate policy member")
            .code,
            "certification.fuzzPolicyJson"
        );

        assert_eq!(
            evaluate_protocol_fuzzing(
                evidence(
                    br#"{"schemaVersion":1,"schemaVersion":1}"#,
                    &policy_bytes,
                    EXECUTABLE,
                    corpus(),
                ),
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
            .expect_err("duplicate report member")
            .code,
            "certification.fuzzReportJson"
        );
        let oversized_report = vec![b' '; MAX_FUZZ_REPORT_BYTES + 1];
        assert_eq!(
            evaluate_protocol_fuzzing(
                evidence(&oversized_report, &policy_bytes, EXECUTABLE, corpus()),
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
            .expect_err("oversized report")
            .code,
            "certification.fuzzReportSize"
        );
        let oversized_policy = vec![b' '; MAX_FUZZ_POLICY_BYTES + 1];
        assert_eq!(
            evaluate_protocol_fuzzing(
                evidence(&report_bytes, &oversized_policy, EXECUTABLE, corpus()),
                &subject,
                producer(),
                STARTED,
                COMPLETED,
            )
            .expect_err("oversized policy")
            .code,
            "certification.fuzzPolicySize"
        );
        let oversized_corpus = vec![b' '; MAX_FUZZ_CORPUS_BYTES + 1];
        assert_eq!(
            parse_certification_fuzz_corpus(&oversized_corpus)
                .expect_err("oversized corpus")
                .code,
            "certification.fuzzCorpusSize"
        );
    }
}
