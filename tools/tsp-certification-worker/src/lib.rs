//! Trusted orchestration for TokenSaver protocol-fuzz certification campaigns.
//!
//! The worker owns deterministic accounting and evidence construction. A separately hardened
//! platform executor owns process confinement, sanitizer instrumentation, deadlines, termination,
//! and reap. The generated report is always passed through the independent workbench evaluator.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tsp_workbench::{
    CERTIFICATION_FUZZ_PROTOCOL, CertificationFuzzCaseClass, CertificationFuzzEngine,
    CertificationFuzzEvidence, CertificationFuzzExecutionLimits, CertificationFuzzReport,
    CertificationStageEvidence, CertificationStageProducer, CertificationSubject, ValidationError,
    decode_certification_fuzz_case, evaluate_protocol_fuzzing, parse_certification_fuzz_corpus,
    parse_certification_fuzz_policy, validate_certification_fuzz_engine,
    validate_certification_fuzz_plan, validate_certification_subject,
};

const MAX_WORKER_DURATION_MILLISECONDS: u64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificationFuzzDisposition {
    Accepted,
    Rejected,
    NoDecision,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CertificationFuzzSafetyObservations {
    pub crash: bool,
    pub hang: bool,
    pub sanitizer_failure: bool,
    pub memory_limit_violation: bool,
    pub stdout_protocol_violation: bool,
    pub stderr_limit_violation: bool,
    pub deadline_violation: bool,
    pub unreaped_process: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificationFuzzExecutionOutcome {
    pub disposition: CertificationFuzzDisposition,
    pub safety: CertificationFuzzSafetyObservations,
}

#[derive(Clone, Copy, Debug)]
pub struct CertificationFuzzExecution<'a> {
    pub ordinal: u64,
    pub repetition: u32,
    pub case_id: &'a str,
    pub class: CertificationFuzzCaseClass,
    pub input: &'a [u8],
    pub subject: &'a CertificationSubject,
    pub limits: &'a CertificationFuzzExecutionLimits,
    pub execution_deadline_milliseconds: u64,
    pub remaining_campaign_milliseconds: u64,
}

/// Platform boundary for an independently hardened process/sanitizer executor.
///
/// Implementations must create a fresh confined process for every execution, apply every supplied
/// resource bound, kill on deadline, drain bounded output, and reap before returning. Error details
/// are never copied into certification evidence.
pub trait CertificationFuzzExecutor: Send + Sync {
    type Error;

    fn engine(&self) -> Result<CertificationFuzzEngine, Self::Error>;

    fn execute(
        &self,
        execution: CertificationFuzzExecution<'_>,
    ) -> Result<CertificationFuzzExecutionOutcome, Self::Error>;

    fn coverage_basis_points(&self) -> Result<u32, Self::Error>;
}

#[derive(Clone, Debug)]
pub struct CertificationFuzzWorkerInput<'a> {
    pub subject: &'a CertificationSubject,
    pub plugin_executable_bytes: &'a [u8],
    pub corpus_bytes: &'a [u8],
    pub policy_bytes: &'a [u8],
    pub producer: CertificationStageProducer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificationFuzzWorkerOutput {
    pub report: CertificationFuzzReport,
    pub report_bytes: Vec<u8>,
    pub stage: CertificationStageEvidence,
}

pub fn run_certification_fuzz_worker<E: CertificationFuzzExecutor + ?Sized>(
    input: CertificationFuzzWorkerInput<'_>,
    executor: &E,
) -> Result<CertificationFuzzWorkerOutput, ValidationError> {
    run_with_clock(input, executor, &SystemClock)
}

fn run_with_clock<E, C>(
    input: CertificationFuzzWorkerInput<'_>,
    executor: &E,
    clock: &C,
) -> Result<CertificationFuzzWorkerOutput, ValidationError>
where
    E: CertificationFuzzExecutor + ?Sized,
    C: WorkerClock,
{
    validate_certification_subject(input.subject)?;
    if input.plugin_executable_bytes.is_empty()
        || sha256_digest(input.plugin_executable_bytes) != input.subject.artifact_digest
    {
        return Err(worker_error(
            "certification.fuzzWorkerArtifact",
            "protocol-fuzz worker executable bytes do not match the immutable subject",
            "Run the worker against the exact executable named by the certification subject.",
        ));
    }
    let policy = parse_certification_fuzz_policy(input.policy_bytes)?;
    let corpus = parse_certification_fuzz_corpus(input.corpus_bytes)?;
    validate_certification_fuzz_plan(&policy, &corpus, input.corpus_bytes)?;
    let engine = executor.engine().map_err(|_| executor_error())?;
    validate_certification_fuzz_engine(&engine, &corpus)?;

    let started_at_unix = clock.now_unix().map_err(|_| clock_error())?;
    if started_at_unix == 0 {
        return Err(clock_error());
    }
    let started = clock.mark();
    let mut counters = Counters::default();
    let mut stop = false;

    for repetition in 0..corpus.repetitions {
        for case in &corpus.cases {
            let elapsed = clock.elapsed_milliseconds(started);
            let Some(remaining) = policy.maximum_duration_milliseconds.checked_sub(elapsed) else {
                stop = true;
                break;
            };
            if remaining == 0 {
                stop = true;
                break;
            }
            let input_bytes = decode_certification_fuzz_case(case)?;
            let outcome = executor
                .execute(CertificationFuzzExecution {
                    ordinal: counters.total_executions,
                    repetition,
                    case_id: &case.id,
                    class: case.class,
                    input: &input_bytes,
                    subject: input.subject,
                    limits: &corpus.limits,
                    execution_deadline_milliseconds: corpus
                        .limits
                        .maximum_execution_milliseconds
                        .min(remaining),
                    remaining_campaign_milliseconds: remaining,
                })
                .map_err(|_| executor_error())?;
            counters.record(case.class, outcome)?;
            if outcome.safety.unreaped_process {
                stop = true;
                break;
            }
        }
        if stop {
            break;
        }
    }

    let coverage_basis_points = executor
        .coverage_basis_points()
        .map_err(|_| executor_error())?;
    if coverage_basis_points > 10_000 {
        return Err(worker_error(
            "certification.fuzzWorkerCoverage",
            "protocol-fuzz executor returned coverage outside 0 to 10000 basis points",
            "Return one bounded coverage measurement from the trusted instrumentation backend.",
        ));
    }
    let duration_milliseconds = clock.elapsed_milliseconds(started);
    if duration_milliseconds > MAX_WORKER_DURATION_MILLISECONDS {
        return Err(clock_error());
    }
    let completed_at_unix = clock.now_unix().map_err(|_| clock_error())?;
    if completed_at_unix < started_at_unix {
        return Err(clock_error());
    }

    let report = CertificationFuzzReport {
        schema_version: 1,
        subject: input.subject.into(),
        protocol: CERTIFICATION_FUZZ_PROTOCOL.into(),
        engine,
        corpus_digest: sha256_digest(input.corpus_bytes),
        started_at_unix,
        completed_at_unix,
        total_executions: counters.total_executions,
        valid_inputs: counters.valid_inputs,
        valid_inputs_accepted: counters.valid_inputs_accepted,
        malformed_inputs: counters.malformed_inputs,
        malformed_inputs_rejected: counters.malformed_inputs_rejected,
        coverage_basis_points,
        crashes: counters.crashes,
        hangs: counters.hangs,
        sanitizer_failures: counters.sanitizer_failures,
        memory_limit_violations: counters.memory_limit_violations,
        stdout_protocol_violations: counters.stdout_protocol_violations,
        stderr_limit_violations: counters.stderr_limit_violations,
        deadline_violations: counters.deadline_violations,
        unreaped_processes: counters.unreaped_processes,
        duration_milliseconds,
    };
    let report_bytes = serde_json::to_vec(&report).map_err(|_| {
        worker_error(
            "certification.fuzzWorkerSerialization",
            "protocol-fuzz worker report could not be serialized",
            "Retry with the bounded v1 report contract and reject missing evidence.",
        )
    })?;
    let stage = evaluate_protocol_fuzzing(
        CertificationFuzzEvidence {
            report_bytes: &report_bytes,
            policy_bytes: input.policy_bytes,
            plugin_executable_bytes: input.plugin_executable_bytes,
            protocol_corpus_bytes: input.corpus_bytes,
        },
        input.subject,
        input.producer,
        started_at_unix,
        completed_at_unix,
    )?;
    Ok(CertificationFuzzWorkerOutput {
        report,
        report_bytes,
        stage,
    })
}

#[derive(Default)]
struct Counters {
    total_executions: u64,
    valid_inputs: u64,
    valid_inputs_accepted: u64,
    malformed_inputs: u64,
    malformed_inputs_rejected: u64,
    crashes: u64,
    hangs: u64,
    sanitizer_failures: u64,
    memory_limit_violations: u64,
    stdout_protocol_violations: u64,
    stderr_limit_violations: u64,
    deadline_violations: u64,
    unreaped_processes: u64,
}

impl Counters {
    fn record(
        &mut self,
        class: CertificationFuzzCaseClass,
        outcome: CertificationFuzzExecutionOutcome,
    ) -> Result<(), ValidationError> {
        increment(&mut self.total_executions)?;
        match class {
            CertificationFuzzCaseClass::Valid => {
                increment(&mut self.valid_inputs)?;
                if outcome.disposition == CertificationFuzzDisposition::Accepted {
                    increment(&mut self.valid_inputs_accepted)?;
                }
            }
            CertificationFuzzCaseClass::Malformed => {
                increment(&mut self.malformed_inputs)?;
                if outcome.disposition == CertificationFuzzDisposition::Rejected {
                    increment(&mut self.malformed_inputs_rejected)?;
                }
            }
        }
        let safety = outcome.safety;
        increment_if(&mut self.crashes, safety.crash)?;
        increment_if(&mut self.hangs, safety.hang)?;
        increment_if(&mut self.sanitizer_failures, safety.sanitizer_failure)?;
        increment_if(
            &mut self.memory_limit_violations,
            safety.memory_limit_violation,
        )?;
        increment_if(
            &mut self.stdout_protocol_violations,
            safety.stdout_protocol_violation,
        )?;
        increment_if(
            &mut self.stderr_limit_violations,
            safety.stderr_limit_violation,
        )?;
        increment_if(&mut self.deadline_violations, safety.deadline_violation)?;
        increment_if(&mut self.unreaped_processes, safety.unreaped_process)
    }
}

fn increment(value: &mut u64) -> Result<(), ValidationError> {
    *value = value.checked_add(1).ok_or_else(|| {
        worker_error(
            "certification.fuzzWorkerAccounting",
            "protocol-fuzz worker counter overflowed",
            "Keep the campaign within the bounded v1 corpus execution plan.",
        )
    })?;
    Ok(())
}

fn increment_if(value: &mut u64, condition: bool) -> Result<(), ValidationError> {
    if condition {
        increment(value)?;
    }
    Ok(())
}

trait WorkerClock {
    type Mark: Copy;

    fn now_unix(&self) -> Result<u64, ()>;
    fn mark(&self) -> Self::Mark;
    fn elapsed_milliseconds(&self, mark: Self::Mark) -> u64;
}

struct SystemClock;

impl WorkerClock for SystemClock {
    type Mark = Instant;

    fn now_unix(&self) -> Result<u64, ()> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| ())
    }

    fn mark(&self) -> Self::Mark {
        Instant::now()
    }

    fn elapsed_milliseconds(&self, mark: Self::Mark) -> u64 {
        u64::try_from(mark.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

fn executor_error() -> ValidationError {
    worker_error(
        "certification.fuzzWorkerExecutor",
        "the confined protocol-fuzz executor could not complete the campaign",
        "Restore the trusted sandbox and instrumentation backend, then rerun without issuing evidence.",
    )
}

fn clock_error() -> ValidationError {
    worker_error(
        "certification.fuzzWorkerClock",
        "protocol-fuzz worker time is unavailable, reversed, or outside the seven-day bound",
        "Restore trusted wall and monotonic clocks, then rerun without issuing evidence.",
    )
}

fn worker_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> ValidationError {
    ValidationError::new(code, message, remediation)
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use tsp_workbench::{
        CertificationFuzzCase, CertificationFuzzCorpus, CertificationFuzzExecutionLimits,
        CertificationFuzzPolicy, release_id,
    };

    const EXECUTABLE: &[u8] = b"exact worker executable";
    const STARTED: u64 = 2_000_000_000;

    #[derive(Clone)]
    struct TestClock {
        elapsed: Arc<AtomicU64>,
    }

    impl WorkerClock for TestClock {
        type Mark = u64;

        fn now_unix(&self) -> Result<u64, ()> {
            Ok(STARTED + self.elapsed.load(Ordering::SeqCst) / 1_000)
        }

        fn mark(&self) -> Self::Mark {
            self.elapsed.load(Ordering::SeqCst)
        }

        fn elapsed_milliseconds(&self, mark: Self::Mark) -> u64 {
            self.elapsed.load(Ordering::SeqCst).saturating_sub(mark)
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ExecutionRequest {
        ordinal: u64,
        repetition: u32,
        case_id: String,
        execution_deadline_milliseconds: u64,
        remaining_campaign_milliseconds: u64,
    }

    struct FakeExecutor {
        clock: TestClock,
        advance_milliseconds: u64,
        outcomes: Mutex<VecDeque<Result<CertificationFuzzExecutionOutcome, &'static str>>>,
        requests: Mutex<Vec<ExecutionRequest>>,
        coverage: Result<u32, &'static str>,
    }

    impl CertificationFuzzExecutor for FakeExecutor {
        type Error = &'static str;

        fn engine(&self) -> Result<CertificationFuzzEngine, Self::Error> {
            Ok(CertificationFuzzEngine {
                id: "com.tokensaver.confined-fuzzer".into(),
                version: "1.0.0".into(),
                active_sanitizers: vec!["address".into(), "undefined".into()],
            })
        }

        fn execute(
            &self,
            execution: CertificationFuzzExecution<'_>,
        ) -> Result<CertificationFuzzExecutionOutcome, Self::Error> {
            self.requests
                .lock()
                .expect("requests")
                .push(ExecutionRequest {
                    ordinal: execution.ordinal,
                    repetition: execution.repetition,
                    case_id: execution.case_id.into(),
                    execution_deadline_milliseconds: execution.execution_deadline_milliseconds,
                    remaining_campaign_milliseconds: execution.remaining_campaign_milliseconds,
                });
            self.clock
                .elapsed
                .fetch_add(self.advance_milliseconds, Ordering::SeqCst);
            self.outcomes
                .lock()
                .expect("outcomes")
                .pop_front()
                .unwrap_or_else(|| Ok(expected_outcome(execution.class)))
        }

        fn coverage_basis_points(&self) -> Result<u32, Self::Error> {
            self.coverage
        }
    }

    fn expected_outcome(class: CertificationFuzzCaseClass) -> CertificationFuzzExecutionOutcome {
        CertificationFuzzExecutionOutcome {
            disposition: match class {
                CertificationFuzzCaseClass::Valid => CertificationFuzzDisposition::Accepted,
                CertificationFuzzCaseClass::Malformed => CertificationFuzzDisposition::Rejected,
            },
            safety: CertificationFuzzSafetyObservations::default(),
        }
    }

    fn subject() -> CertificationSubject {
        let artifact_digest = sha256_digest(EXECUTABLE);
        CertificationSubject {
            plugin_id: "com.example.plugin".into(),
            version: "1.2.3".into(),
            platform: "linux-x64".into(),
            api_version: 1,
            release_id: release_id("com.example.plugin", "1.2.3", "linux-x64", &artifact_digest),
            artifact_digest,
            package_digest: sha256_digest(b"exact package"),
        }
    }

    fn corpus(repetitions: u32) -> Vec<u8> {
        serde_json::to_vec(&CertificationFuzzCorpus {
            schema_version: 1,
            corpus_id: "com.tokensaver.tspp-fuzz-corpus.v1".into(),
            protocol: CERTIFICATION_FUZZ_PROTOCOL.into(),
            repetitions,
            limits: CertificationFuzzExecutionLimits {
                maximum_execution_milliseconds: 250,
                maximum_memory_bytes: 256 << 20,
                maximum_stdout_bytes: 1 << 20,
                maximum_stderr_bytes: 1 << 20,
                required_sanitizers: vec!["address".into()],
            },
            cases: vec![
                CertificationFuzzCase {
                    id: "malformed".into(),
                    class: CertificationFuzzCaseClass::Malformed,
                    input_base64: BASE64.encode(b"invalid frame"),
                },
                CertificationFuzzCase {
                    id: "valid".into(),
                    class: CertificationFuzzCaseClass::Valid,
                    input_base64: BASE64.encode(b"valid frame"),
                },
            ],
        })
        .expect("corpus bytes")
    }

    fn policy(corpus: &[u8], repetitions: u32, maximum_duration: u64) -> Vec<u8> {
        serde_json::to_vec(&CertificationFuzzPolicy {
            schema_version: 1,
            policy_id: "com.tokensaver.certification.protocol-fuzz.v1".into(),
            protocol: CERTIFICATION_FUZZ_PROTOCOL.into(),
            corpus_id: "com.tokensaver.tspp-fuzz-corpus.v1".into(),
            corpus_digest: sha256_digest(corpus),
            minimum_executions: u64::from(repetitions) * 2,
            minimum_valid_inputs: u64::from(repetitions),
            minimum_malformed_inputs: u64::from(repetitions),
            minimum_coverage_basis_points: 9_000,
            maximum_duration_milliseconds: maximum_duration,
        })
        .expect("policy bytes")
    }

    fn producer() -> CertificationStageProducer {
        CertificationStageProducer {
            id: "com.tokensaver.certification-worker".into(),
            version: "1.0.0".into(),
            environment_digest: sha256_digest(b"immutable worker environment"),
        }
    }

    fn executor(
        clock: TestClock,
        outcomes: Vec<Result<CertificationFuzzExecutionOutcome, &'static str>>,
    ) -> FakeExecutor {
        FakeExecutor {
            clock,
            advance_milliseconds: 1,
            outcomes: Mutex::new(outcomes.into()),
            requests: Mutex::new(Vec::new()),
            coverage: Ok(9_500),
        }
    }

    fn run(
        repetitions: u32,
        maximum_duration: u64,
        executor: &FakeExecutor,
        clock: &TestClock,
    ) -> Result<CertificationFuzzWorkerOutput, ValidationError> {
        let corpus = corpus(repetitions);
        let policy = policy(&corpus, repetitions, maximum_duration);
        run_with_clock(
            CertificationFuzzWorkerInput {
                subject: &subject(),
                plugin_executable_bytes: EXECUTABLE,
                corpus_bytes: &corpus,
                policy_bytes: &policy,
                producer: producer(),
            },
            executor,
            clock,
        )
    }

    #[test]
    fn deterministic_campaign_recomputes_counts_and_passes_the_real_evaluator() {
        let clock = TestClock {
            elapsed: Arc::new(AtomicU64::new(0)),
        };
        let executor = executor(clock.clone(), Vec::new());
        let output = run(2, 1_000, &executor, &clock).expect("worker output");
        assert!(output.stage.ok);
        assert_eq!(output.report.total_executions, 4);
        assert_eq!(output.report.valid_inputs_accepted, 2);
        assert_eq!(output.report.malformed_inputs_rejected, 2);
        assert_eq!(output.report.coverage_basis_points, 9_500);
        assert_eq!(
            serde_json::from_slice::<CertificationFuzzReport>(&output.report_bytes)
                .expect("report bytes"),
            output.report
        );
        let requests = executor.requests.into_inner().expect("requests");
        assert_eq!(
            requests
                .iter()
                .map(|request| (
                    request.ordinal,
                    request.repetition,
                    request.case_id.as_str()
                ))
                .collect::<Vec<_>>(),
            [
                (0, 0, "malformed"),
                (1, 0, "valid"),
                (2, 1, "malformed"),
                (3, 1, "valid"),
            ]
        );
    }

    #[test]
    fn every_safety_observation_produces_truthful_failed_evidence() {
        let mutations: [fn(&mut CertificationFuzzSafetyObservations); 8] = [
            |value| value.crash = true,
            |value| value.hang = true,
            |value| value.sanitizer_failure = true,
            |value| value.memory_limit_violation = true,
            |value| value.stdout_protocol_violation = true,
            |value| value.stderr_limit_violation = true,
            |value| value.deadline_violation = true,
            |value| value.unreaped_process = true,
        ];
        for mutate in mutations {
            let clock = TestClock {
                elapsed: Arc::new(AtomicU64::new(0)),
            };
            let mut safety = CertificationFuzzSafetyObservations::default();
            mutate(&mut safety);
            let executor = executor(
                clock.clone(),
                vec![Ok(CertificationFuzzExecutionOutcome {
                    disposition: CertificationFuzzDisposition::Rejected,
                    safety,
                })],
            );
            let output = run(1, 1_000, &executor, &clock).expect("truthful failed evidence");
            assert!(!output.stage.ok);
        }
    }

    #[test]
    fn incomplete_dispositions_and_campaign_deadline_fail_truthfully() {
        let clock = TestClock {
            elapsed: Arc::new(AtomicU64::new(0)),
        };
        let mut executor = executor(
            clock.clone(),
            vec![Ok(CertificationFuzzExecutionOutcome {
                disposition: CertificationFuzzDisposition::NoDecision,
                safety: CertificationFuzzSafetyObservations::default(),
            })],
        );
        executor.advance_milliseconds = 4;
        let output = run(2, 5, &executor, &clock).expect("bounded deadline report");
        assert!(!output.stage.ok);
        assert_eq!(output.report.total_executions, 2);
        let requests = executor.requests.into_inner().expect("requests");
        assert_eq!(requests[0].execution_deadline_milliseconds, 5);
        assert_eq!(requests[0].remaining_campaign_milliseconds, 5);
        assert_eq!(requests[1].execution_deadline_milliseconds, 1);
        assert_eq!(requests[1].remaining_campaign_milliseconds, 1);
    }

    #[test]
    fn executor_and_coverage_failures_are_bounded_and_do_not_leak() {
        let clock = TestClock {
            elapsed: Arc::new(AtomicU64::new(0)),
        };
        let failed_executor = executor(clock.clone(), vec![Err("private executor diagnostic")]);
        let error = run(1, 1_000, &failed_executor, &clock).expect_err("executor failure");
        assert_eq!(error.code, "certification.fuzzWorkerExecutor");
        assert!(!error.message.contains("private executor diagnostic"));

        let mut executor = executor(clock.clone(), Vec::new());
        executor.coverage = Err("private coverage diagnostic");
        let error = run(1, 1_000, &executor, &clock).expect_err("coverage failure");
        assert_eq!(error.code, "certification.fuzzWorkerExecutor");
        assert!(!error.message.contains("private coverage diagnostic"));
    }

    #[test]
    fn invalid_subject_artifact_and_plan_fail_before_execution() {
        let clock = TestClock {
            elapsed: Arc::new(AtomicU64::new(0)),
        };
        let executor = executor(clock.clone(), Vec::new());
        let corpus = corpus(1);
        let policy = policy(&corpus, 1, 1_000);
        let mut invalid_subject = subject();
        invalid_subject.release_id = format!("tsr1_{}", "f".repeat(64));
        let error = run_with_clock(
            CertificationFuzzWorkerInput {
                subject: &invalid_subject,
                plugin_executable_bytes: EXECUTABLE,
                corpus_bytes: &corpus,
                policy_bytes: &policy,
                producer: producer(),
            },
            &executor,
            &clock,
        )
        .expect_err("invalid subject");
        assert_eq!(error.code, "certification.subjectContract");

        let error = run_with_clock(
            CertificationFuzzWorkerInput {
                subject: &subject(),
                plugin_executable_bytes: b"wrong executable",
                corpus_bytes: &corpus,
                policy_bytes: &policy,
                producer: producer(),
            },
            &executor,
            &clock,
        )
        .expect_err("artifact drift");
        assert_eq!(error.code, "certification.fuzzWorkerArtifact");
        assert!(executor.requests.into_inner().expect("requests").is_empty());
    }

    #[test]
    fn worker_and_executor_interfaces_are_thread_safe() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FakeExecutor>();
        assert_send_sync::<CertificationFuzzWorkerOutput>();
    }
}
