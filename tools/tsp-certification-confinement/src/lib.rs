//! Fail-closed adapter between protocol-fuzz orchestration and native confinement drivers.
//!
//! Native drivers remain trusted infrastructure. This crate validates their immutable profile and
//! observations, derives safety findings, and deliberately provides no ordinary-process fallback.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::fmt;
use tokensaver_certification_worker::{
    CertificationFuzzDisposition, CertificationFuzzExecution, CertificationFuzzExecutionOutcome,
    CertificationFuzzExecutor, CertificationFuzzSafetyObservations,
};
use tsp_workbench::CertificationFuzzEngine;

const PROFILE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NativeConfinementPlatform {
    Windows,
    Linux,
    Macos,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NativeConfinementControl {
    FreshProcess,
    FilesystemIsolation,
    NetworkIsolation,
    ProcessTreeIsolation,
    MemoryHardLimit,
    StdoutHardLimit,
    StderrHardLimit,
    DeadlineTermination,
    GuaranteedReap,
    WindowsAppContainer,
    WindowsJobObject,
    LinuxMountNamespace,
    LinuxNetworkNamespace,
    LinuxPidNamespace,
    LinuxSeccomp,
    LinuxLandlock,
    LinuxCgroupV2,
    MacosSandboxProfile,
    MacosProcessGroup,
    MacosResourceLimits,
}

const WINDOWS_CONTROLS: &[NativeConfinementControl] = &[
    NativeConfinementControl::FreshProcess,
    NativeConfinementControl::FilesystemIsolation,
    NativeConfinementControl::NetworkIsolation,
    NativeConfinementControl::ProcessTreeIsolation,
    NativeConfinementControl::MemoryHardLimit,
    NativeConfinementControl::StdoutHardLimit,
    NativeConfinementControl::StderrHardLimit,
    NativeConfinementControl::DeadlineTermination,
    NativeConfinementControl::GuaranteedReap,
    NativeConfinementControl::WindowsAppContainer,
    NativeConfinementControl::WindowsJobObject,
];

const LINUX_CONTROLS: &[NativeConfinementControl] = &[
    NativeConfinementControl::FreshProcess,
    NativeConfinementControl::FilesystemIsolation,
    NativeConfinementControl::NetworkIsolation,
    NativeConfinementControl::ProcessTreeIsolation,
    NativeConfinementControl::MemoryHardLimit,
    NativeConfinementControl::StdoutHardLimit,
    NativeConfinementControl::StderrHardLimit,
    NativeConfinementControl::DeadlineTermination,
    NativeConfinementControl::GuaranteedReap,
    NativeConfinementControl::LinuxMountNamespace,
    NativeConfinementControl::LinuxNetworkNamespace,
    NativeConfinementControl::LinuxPidNamespace,
    NativeConfinementControl::LinuxSeccomp,
    NativeConfinementControl::LinuxLandlock,
    NativeConfinementControl::LinuxCgroupV2,
];

const MACOS_CONTROLS: &[NativeConfinementControl] = &[
    NativeConfinementControl::FreshProcess,
    NativeConfinementControl::FilesystemIsolation,
    NativeConfinementControl::NetworkIsolation,
    NativeConfinementControl::ProcessTreeIsolation,
    NativeConfinementControl::MemoryHardLimit,
    NativeConfinementControl::StdoutHardLimit,
    NativeConfinementControl::StderrHardLimit,
    NativeConfinementControl::DeadlineTermination,
    NativeConfinementControl::GuaranteedReap,
    NativeConfinementControl::MacosSandboxProfile,
    NativeConfinementControl::MacosProcessGroup,
    NativeConfinementControl::MacosResourceLimits,
];

pub fn required_native_confinement_controls(
    platform: NativeConfinementPlatform,
) -> &'static [NativeConfinementControl] {
    match platform {
        NativeConfinementPlatform::Windows => WINDOWS_CONTROLS,
        NativeConfinementPlatform::Linux => LINUX_CONTROLS,
        NativeConfinementPlatform::Macos => MACOS_CONTROLS,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeConfinementProfile {
    pub schema_version: u32,
    pub backend_id: String,
    pub backend_version: String,
    pub platform: NativeConfinementPlatform,
    pub policy_digest: String,
    pub controls: Vec<NativeConfinementControl>,
    pub engine: CertificationFuzzEngine,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeTermination {
    Exited(i32),
    Signaled(u32),
    Exception(u32),
    DeadlineKilled,
    MemoryLimitKilled,
}

#[derive(Clone, Debug)]
pub struct NativeConfinementRequest<'a> {
    pub attempt_id: String,
    pub execution: CertificationFuzzExecution<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeConfinementObservation {
    pub attempt_id: String,
    pub policy_digest: String,
    pub applied_controls: Vec<NativeConfinementControl>,
    pub active_sanitizers: Vec<String>,
    pub termination: NativeTermination,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_milliseconds: u64,
    pub peak_memory_bytes: u64,
    pub stdout_limit_exceeded: bool,
    pub stdout_protocol_violation: bool,
    pub stderr_limit_exceeded: bool,
    pub sanitizer_failure: bool,
    pub process_reaped: bool,
}

pub trait NativeConfinementDriver: Send + Sync {
    type Error;

    fn profile(&self) -> Result<NativeConfinementProfile, Self::Error>;

    fn execute(
        &self,
        request: NativeConfinementRequest<'_>,
    ) -> Result<NativeConfinementObservation, Self::Error>;

    fn coverage_basis_points(&self) -> Result<u32, Self::Error>;
}

pub trait CertificationProtocolOracle: Send + Sync {
    type Error;

    fn assess(
        &self,
        execution: CertificationFuzzExecution<'_>,
        observation: &NativeConfinementObservation,
    ) -> Result<CertificationProtocolAssessment, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificationProtocolAssessment {
    pub disposition: CertificationFuzzDisposition,
    pub stdout_protocol_violation: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeConfinementErrorKind {
    UnsupportedPlatform,
    InvalidProfile,
    ProfileDrift,
    InvalidExecution,
    DriverFailure,
    InvalidObservation,
    OracleFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeConfinementError {
    kind: NativeConfinementErrorKind,
}

impl NativeConfinementError {
    pub fn kind(self) -> NativeConfinementErrorKind {
        self.kind
    }

    fn new(kind: NativeConfinementErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Display for NativeConfinementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("native certification confinement failed closed")
    }
}

impl std::error::Error for NativeConfinementError {}

pub fn validate_native_confinement_profile(
    profile: &NativeConfinementProfile,
    expected_platform: NativeConfinementPlatform,
) -> Result<(), NativeConfinementError> {
    if profile.schema_version != PROFILE_SCHEMA_VERSION
        || profile.platform != expected_platform
        || !valid_token(&profile.backend_id)
        || !valid_version(&profile.backend_version)
        || !valid_digest(&profile.policy_digest)
        || profile.controls != required_native_confinement_controls(expected_platform)
        || !valid_engine(&profile.engine)
    {
        return Err(NativeConfinementError::new(
            NativeConfinementErrorKind::InvalidProfile,
        ));
    }
    Ok(())
}

pub struct NativeCertificationFuzzExecutor<D, O> {
    driver: D,
    oracle: O,
    profile: NativeConfinementProfile,
}

impl<D, O> NativeCertificationFuzzExecutor<D, O>
where
    D: NativeConfinementDriver,
    O: CertificationProtocolOracle,
{
    pub fn new(driver: D, oracle: O) -> Result<Self, NativeConfinementError> {
        let platform = current_native_platform()?;
        let profile = driver
            .profile()
            .map_err(|_| NativeConfinementError::new(NativeConfinementErrorKind::DriverFailure))?;
        validate_native_confinement_profile(&profile, platform)?;
        Ok(Self {
            driver,
            oracle,
            profile,
        })
    }

    fn current_profile(&self) -> Result<NativeConfinementProfile, NativeConfinementError> {
        let current = self
            .driver
            .profile()
            .map_err(|_| NativeConfinementError::new(NativeConfinementErrorKind::DriverFailure))?;
        if current != self.profile {
            return Err(NativeConfinementError::new(
                NativeConfinementErrorKind::ProfileDrift,
            ));
        }
        Ok(current)
    }
}

impl<D, O> CertificationFuzzExecutor for NativeCertificationFuzzExecutor<D, O>
where
    D: NativeConfinementDriver,
    O: CertificationProtocolOracle,
{
    type Error = NativeConfinementError;

    fn engine(&self) -> Result<CertificationFuzzEngine, Self::Error> {
        Ok(self.current_profile()?.engine)
    }

    fn execute(
        &self,
        execution: CertificationFuzzExecution<'_>,
    ) -> Result<CertificationFuzzExecutionOutcome, Self::Error> {
        let profile = self.current_profile()?;
        if !subject_matches_platform(&execution.subject.platform, profile.platform) {
            return Err(NativeConfinementError::new(
                NativeConfinementErrorKind::InvalidExecution,
            ));
        }
        let attempt_id = confinement_attempt_id(execution);
        let observation = self
            .driver
            .execute(NativeConfinementRequest {
                attempt_id: attempt_id.clone(),
                execution,
            })
            .map_err(|_| NativeConfinementError::new(NativeConfinementErrorKind::DriverFailure))?;
        validate_observation(&profile, execution, &attempt_id, &observation)?;

        let crash = matches!(
            observation.termination,
            NativeTermination::Signaled(_) | NativeTermination::Exception(_)
        );
        let deadline = matches!(observation.termination, NativeTermination::DeadlineKilled)
            || observation.duration_milliseconds > execution.execution_deadline_milliseconds;
        let memory = matches!(
            observation.termination,
            NativeTermination::MemoryLimitKilled
        ) || observation.peak_memory_bytes > execution.limits.maximum_memory_bytes;
        let unreaped = !observation.process_reaped;
        let mut safety = CertificationFuzzSafetyObservations {
            crash,
            hang: deadline,
            sanitizer_failure: observation.sanitizer_failure,
            memory_limit_violation: memory,
            stdout_protocol_violation: observation.stdout_limit_exceeded
                || observation.stdout_protocol_violation,
            stderr_limit_violation: observation.stderr_limit_exceeded,
            deadline_violation: deadline,
            unreaped_process: unreaped,
        };
        let disposition = if crash
            || deadline
            || memory
            || observation.sanitizer_failure
            || observation.stdout_limit_exceeded
            || observation.stdout_protocol_violation
            || observation.stderr_limit_exceeded
            || unreaped
        {
            CertificationFuzzDisposition::NoDecision
        } else {
            let assessment = self.oracle.assess(execution, &observation).map_err(|_| {
                NativeConfinementError::new(NativeConfinementErrorKind::OracleFailure)
            })?;
            if assessment.stdout_protocol_violation {
                safety.stdout_protocol_violation = true;
                CertificationFuzzDisposition::NoDecision
            } else {
                assessment.disposition
            }
        };
        Ok(CertificationFuzzExecutionOutcome {
            disposition,
            safety,
        })
    }

    fn coverage_basis_points(&self) -> Result<u32, Self::Error> {
        self.current_profile()?;
        self.driver
            .coverage_basis_points()
            .map_err(|_| NativeConfinementError::new(NativeConfinementErrorKind::DriverFailure))
    }
}

fn validate_observation(
    profile: &NativeConfinementProfile,
    execution: CertificationFuzzExecution<'_>,
    attempt_id: &str,
    observation: &NativeConfinementObservation,
) -> Result<(), NativeConfinementError> {
    let stdout_limit = usize::try_from(execution.limits.maximum_stdout_bytes)
        .map_err(|_| NativeConfinementError::new(NativeConfinementErrorKind::InvalidObservation))?;
    let stderr_limit = usize::try_from(execution.limits.maximum_stderr_bytes)
        .map_err(|_| NativeConfinementError::new(NativeConfinementErrorKind::InvalidObservation))?;
    if observation.attempt_id != attempt_id
        || observation.policy_digest != profile.policy_digest
        || observation.applied_controls != profile.controls
        || observation.active_sanitizers != profile.engine.active_sanitizers
        || observation.stdout.len() > stdout_limit
        || observation.stderr.len() > stderr_limit
        || (observation.stdout_limit_exceeded && observation.stdout.len() != stdout_limit)
        || (observation.stderr_limit_exceeded && observation.stderr.len() != stderr_limit)
    {
        return Err(NativeConfinementError::new(
            NativeConfinementErrorKind::InvalidObservation,
        ));
    }
    Ok(())
}

fn confinement_attempt_id(execution: CertificationFuzzExecution<'_>) -> String {
    let mut digest = Sha256::new();
    for bytes in [
        execution.subject.release_id.as_bytes(),
        &execution.ordinal.to_be_bytes(),
        &execution.repetition.to_be_bytes(),
        execution.case_id.as_bytes(),
    ] {
        digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(bytes);
    }
    format!("tsfa1_{:x}", digest.finalize())
}

fn subject_matches_platform(value: &str, platform: NativeConfinementPlatform) -> bool {
    match platform {
        NativeConfinementPlatform::Windows => value.starts_with("windows-"),
        NativeConfinementPlatform::Linux => value.starts_with("linux-"),
        NativeConfinementPlatform::Macos => value.starts_with("darwin-"),
    }
}

fn valid_engine(engine: &CertificationFuzzEngine) -> bool {
    valid_token(&engine.id)
        && valid_version(&engine.version)
        && !engine.active_sanitizers.is_empty()
        && engine.active_sanitizers.iter().all(|value| {
            matches!(
                value.as_str(),
                "address" | "leak" | "memory" | "thread" | "undefined"
            )
        })
        && engine
            .active_sanitizers
            .windows(2)
            .all(|values| values[0] < values[1])
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || b"._:/-".contains(&value))
}

fn valid_version(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let mut build_split = value.split('+');
    let Some(version_and_pre) = build_split.next() else {
        return false;
    };
    let build = build_split.next();
    if build_split.next().is_some() || build.is_some_and(|value| !valid_identifiers(value, false)) {
        return false;
    }
    let mut pre_split = version_and_pre.split('-');
    let Some(core) = pre_split.next() else {
        return false;
    };
    let pre = pre_split.next();
    if pre_split.next().is_some() || pre.is_some_and(|value| !valid_identifiers(value, true)) {
        return false;
    }
    let components = core.split('.').collect::<Vec<_>>();
    components.len() == 3 && components.into_iter().all(valid_numeric_identifier)
}

fn valid_identifiers(value: &str, reject_numeric_leading_zero: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|value| value.is_ascii_alphanumeric() || value == b'-')
                && (!reject_numeric_leading_zero
                    || !identifier.bytes().all(|value| value.is_ascii_digit())
                    || valid_numeric_identifier(identifier))
        })
}

fn valid_numeric_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|value| value.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
}

#[cfg(target_os = "windows")]
fn current_native_platform() -> Result<NativeConfinementPlatform, NativeConfinementError> {
    Ok(NativeConfinementPlatform::Windows)
}

#[cfg(target_os = "linux")]
fn current_native_platform() -> Result<NativeConfinementPlatform, NativeConfinementError> {
    Ok(NativeConfinementPlatform::Linux)
}

#[cfg(target_os = "macos")]
fn current_native_platform() -> Result<NativeConfinementPlatform, NativeConfinementError> {
    Ok(NativeConfinementPlatform::Macos)
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn current_native_platform() -> Result<NativeConfinementPlatform, NativeConfinementError> {
    Err(NativeConfinementError::new(
        NativeConfinementErrorKind::UnsupportedPlatform,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use tsp_workbench::{
        CertificationFuzzCaseClass, CertificationFuzzExecutionLimits, CertificationSubject,
        release_id,
    };

    #[derive(Clone, Copy, Debug)]
    enum Mutation {
        None,
        Attempt,
        Policy,
        Controls,
        Sanitizers,
        OversizedStdout,
        InconsistentStdoutFlag,
        Termination(NativeTermination),
        Slow,
        PeakMemory,
        StdoutLimit,
        StdoutProtocol,
        StderrLimit,
        Sanitizer,
        Unreaped,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct CapturedRequest {
        attempt_id: String,
        ordinal: u64,
        repetition: u32,
        case_id: String,
        input_bytes: usize,
    }

    struct DriverState {
        profile: Mutex<NativeConfinementProfile>,
        mutation: Mutex<Mutation>,
        requests: Mutex<Vec<CapturedRequest>>,
        execute_fails: AtomicBool,
        coverage_fails: AtomicBool,
    }

    #[derive(Clone)]
    struct FakeDriver {
        state: Arc<DriverState>,
    }

    impl NativeConfinementDriver for FakeDriver {
        type Error = &'static str;

        fn profile(&self) -> Result<NativeConfinementProfile, Self::Error> {
            Ok(self.state.profile.lock().expect("profile").clone())
        }

        fn execute(
            &self,
            request: NativeConfinementRequest<'_>,
        ) -> Result<NativeConfinementObservation, Self::Error> {
            if self.state.execute_fails.load(Ordering::SeqCst) {
                return Err("private native driver diagnostic");
            }
            self.state
                .requests
                .lock()
                .expect("requests")
                .push(CapturedRequest {
                    attempt_id: request.attempt_id.clone(),
                    ordinal: request.execution.ordinal,
                    repetition: request.execution.repetition,
                    case_id: request.execution.case_id.into(),
                    input_bytes: request.execution.input.len(),
                });
            let profile = self.state.profile.lock().expect("profile").clone();
            let mutation = *self.state.mutation.lock().expect("mutation");
            let mut observation = NativeConfinementObservation {
                attempt_id: request.attempt_id,
                policy_digest: profile.policy_digest,
                applied_controls: profile.controls,
                active_sanitizers: profile.engine.active_sanitizers,
                termination: NativeTermination::Exited(0),
                stdout: b"ok".to_vec(),
                stderr: Vec::new(),
                duration_milliseconds: 1,
                peak_memory_bytes: 1,
                stdout_limit_exceeded: false,
                stdout_protocol_violation: false,
                stderr_limit_exceeded: false,
                sanitizer_failure: false,
                process_reaped: true,
            };
            match mutation {
                Mutation::None => {}
                Mutation::Attempt => observation.attempt_id.push_str("-forged"),
                Mutation::Policy => observation.policy_digest = digest(b"another policy"),
                Mutation::Controls => {
                    observation.applied_controls.pop();
                }
                Mutation::Sanitizers => observation.active_sanitizers = vec!["undefined".into()],
                Mutation::OversizedStdout => observation.stdout = vec![b'!'; 9],
                Mutation::InconsistentStdoutFlag => observation.stdout_limit_exceeded = true,
                Mutation::Termination(termination) => observation.termination = termination,
                Mutation::Slow => {
                    observation.duration_milliseconds =
                        request.execution.execution_deadline_milliseconds + 1;
                }
                Mutation::PeakMemory => {
                    observation.peak_memory_bytes =
                        request.execution.limits.maximum_memory_bytes + 1;
                }
                Mutation::StdoutLimit => {
                    observation.stdout = vec![b'o'; 8];
                    observation.stdout_limit_exceeded = true;
                }
                Mutation::StdoutProtocol => observation.stdout_protocol_violation = true,
                Mutation::StderrLimit => {
                    observation.stderr = vec![b'e'; 8];
                    observation.stderr_limit_exceeded = true;
                }
                Mutation::Sanitizer => observation.sanitizer_failure = true,
                Mutation::Unreaped => observation.process_reaped = false,
            }
            Ok(observation)
        }

        fn coverage_basis_points(&self) -> Result<u32, Self::Error> {
            if self.state.coverage_fails.load(Ordering::SeqCst) {
                Err("private coverage diagnostic")
            } else {
                Ok(9_500)
            }
        }
    }

    #[derive(Clone)]
    struct FakeOracle {
        calls: Arc<AtomicU64>,
        fails: Arc<AtomicBool>,
        protocol_violation: Arc<AtomicBool>,
    }

    impl CertificationProtocolOracle for FakeOracle {
        type Error = &'static str;

        fn assess(
            &self,
            execution: CertificationFuzzExecution<'_>,
            _observation: &NativeConfinementObservation,
        ) -> Result<CertificationProtocolAssessment, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fails.load(Ordering::SeqCst) {
                Err("private oracle diagnostic")
            } else {
                Ok(CertificationProtocolAssessment {
                    disposition: match execution.class {
                        CertificationFuzzCaseClass::Valid => CertificationFuzzDisposition::Accepted,
                        CertificationFuzzCaseClass::Malformed => {
                            CertificationFuzzDisposition::Rejected
                        }
                    },
                    stdout_protocol_violation: self.protocol_violation.load(Ordering::SeqCst),
                })
            }
        }
    }

    fn digest(bytes: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    fn profile(platform: NativeConfinementPlatform) -> NativeConfinementProfile {
        NativeConfinementProfile {
            schema_version: PROFILE_SCHEMA_VERSION,
            backend_id: "com.tokensaver.native-confinement".into(),
            backend_version: "1.0.0".into(),
            platform,
            policy_digest: digest(b"immutable native sandbox policy"),
            controls: required_native_confinement_controls(platform).to_vec(),
            engine: CertificationFuzzEngine {
                id: "com.tokensaver.instrumented-fuzzer".into(),
                version: "1.0.0".into(),
                active_sanitizers: vec!["address".into(), "undefined".into()],
            },
        }
    }

    fn fake_driver() -> FakeDriver {
        FakeDriver {
            state: Arc::new(DriverState {
                profile: Mutex::new(profile(current_native_platform().expect("native platform"))),
                mutation: Mutex::new(Mutation::None),
                requests: Mutex::new(Vec::new()),
                execute_fails: AtomicBool::new(false),
                coverage_fails: AtomicBool::new(false),
            }),
        }
    }

    fn oracle() -> FakeOracle {
        FakeOracle {
            calls: Arc::new(AtomicU64::new(0)),
            fails: Arc::new(AtomicBool::new(false)),
            protocol_violation: Arc::new(AtomicBool::new(false)),
        }
    }

    fn subject() -> CertificationSubject {
        let artifact_digest = digest(b"exact executable");
        let platform = match current_native_platform().expect("native platform") {
            NativeConfinementPlatform::Windows => "windows-x64",
            NativeConfinementPlatform::Linux => "linux-x64",
            NativeConfinementPlatform::Macos => "darwin-x64",
        };
        CertificationSubject {
            plugin_id: "com.example.plugin".into(),
            version: "1.2.3".into(),
            platform: platform.into(),
            api_version: 1,
            release_id: release_id("com.example.plugin", "1.2.3", platform, &artifact_digest),
            artifact_digest,
            package_digest: digest(b"exact package"),
        }
    }

    fn limits() -> CertificationFuzzExecutionLimits {
        CertificationFuzzExecutionLimits {
            maximum_execution_milliseconds: 250,
            maximum_memory_bytes: 1_024,
            maximum_stdout_bytes: 8,
            maximum_stderr_bytes: 8,
            required_sanitizers: vec!["address".into()],
        }
    }

    fn execution<'a>(
        subject: &'a CertificationSubject,
        limits: &'a CertificationFuzzExecutionLimits,
    ) -> CertificationFuzzExecution<'a> {
        CertificationFuzzExecution {
            ordinal: 7,
            repetition: 2,
            case_id: "valid-case",
            class: CertificationFuzzCaseClass::Valid,
            input: b"wire input",
            subject,
            limits,
            execution_deadline_milliseconds: 200,
            remaining_campaign_milliseconds: 500,
        }
    }

    #[test]
    fn every_platform_requires_its_exact_canonical_control_profile() {
        for platform in [
            NativeConfinementPlatform::Windows,
            NativeConfinementPlatform::Linux,
            NativeConfinementPlatform::Macos,
        ] {
            let valid = profile(platform);
            validate_native_confinement_profile(&valid, platform).expect("valid profile");

            let mut missing = valid.clone();
            missing.controls.pop();
            assert_eq!(
                validate_native_confinement_profile(&missing, platform)
                    .expect_err("missing control")
                    .kind(),
                NativeConfinementErrorKind::InvalidProfile
            );
            let mut reordered = valid.clone();
            reordered.controls.swap(0, 1);
            assert!(validate_native_confinement_profile(&reordered, platform).is_err());
            let mut duplicated = valid.clone();
            duplicated.controls.push(duplicated.controls[0]);
            assert!(validate_native_confinement_profile(&duplicated, platform).is_err());
        }
        assert!(
            validate_native_confinement_profile(
                &profile(NativeConfinementPlatform::Windows),
                NativeConfinementPlatform::Linux,
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_identity_policy_and_engine_fail_before_executor_construction() {
        let mutations: [fn(&mut NativeConfinementProfile); 7] = [
            |value| value.schema_version = 2,
            |value| value.backend_id = "ambient backend".into(),
            |value| value.backend_version = "1.0".into(),
            |value| value.policy_digest = digest(b"short")[..40].into(),
            |value| value.engine.active_sanitizers.reverse(),
            |value| value.engine.active_sanitizers.clear(),
            |value| value.engine.version = "01.0.0".into(),
        ];
        for mutate in mutations {
            let driver = fake_driver();
            mutate(&mut driver.state.profile.lock().expect("profile"));
            assert_eq!(
                NativeCertificationFuzzExecutor::new(driver, oracle())
                    .err()
                    .expect("invalid profile")
                    .kind(),
                NativeConfinementErrorKind::InvalidProfile
            );
        }
    }

    #[test]
    fn successful_execution_binds_attempt_and_uses_separate_oracle() {
        let driver = fake_driver();
        let oracle = oracle();
        let executor =
            NativeCertificationFuzzExecutor::new(driver.clone(), oracle.clone()).expect("executor");
        let subject = subject();
        let limits = limits();
        let outcome = executor
            .execute(execution(&subject, &limits))
            .expect("execution");
        assert_eq!(outcome.disposition, CertificationFuzzDisposition::Accepted);
        assert_eq!(
            outcome.safety,
            CertificationFuzzSafetyObservations::default()
        );
        assert_eq!(oracle.calls.load(Ordering::SeqCst), 1);
        assert_eq!(executor.coverage_basis_points().expect("coverage"), 9_500);
        let requests = driver.state.requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].attempt_id.starts_with("tsfa1_"));
        assert_eq!(
            (
                &requests[0].ordinal,
                &requests[0].repetition,
                requests[0].case_id.as_str(),
                requests[0].input_bytes
            ),
            (&7, &2, "valid-case", 10),
        );
    }

    #[test]
    fn oracle_protocol_violation_becomes_truthful_no_decision() {
        let driver = fake_driver();
        let oracle = oracle();
        oracle.protocol_violation.store(true, Ordering::SeqCst);
        let executor =
            NativeCertificationFuzzExecutor::new(driver, oracle.clone()).expect("executor");
        let subject = subject();
        let limits = limits();
        let outcome = executor
            .execute(execution(&subject, &limits))
            .expect("protocol finding");
        assert_eq!(
            outcome.disposition,
            CertificationFuzzDisposition::NoDecision
        );
        assert!(outcome.safety.stdout_protocol_violation);
        assert_eq!(oracle.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_safety_observations_map_without_calling_the_oracle() {
        let cases = [
            Mutation::Termination(NativeTermination::Signaled(9)),
            Mutation::Termination(NativeTermination::Exception(0xc0000005)),
            Mutation::Termination(NativeTermination::DeadlineKilled),
            Mutation::Termination(NativeTermination::MemoryLimitKilled),
            Mutation::Slow,
            Mutation::PeakMemory,
            Mutation::StdoutLimit,
            Mutation::StdoutProtocol,
            Mutation::StderrLimit,
            Mutation::Sanitizer,
            Mutation::Unreaped,
        ];
        for mutation in cases {
            let driver = fake_driver();
            *driver.state.mutation.lock().expect("mutation") = mutation;
            let oracle = oracle();
            let executor =
                NativeCertificationFuzzExecutor::new(driver, oracle.clone()).expect("executor");
            let subject = subject();
            let limits = limits();
            let outcome = executor
                .execute(execution(&subject, &limits))
                .expect("truthful safety outcome");
            assert_eq!(
                outcome.disposition,
                CertificationFuzzDisposition::NoDecision
            );
            assert_ne!(
                outcome.safety,
                CertificationFuzzSafetyObservations::default()
            );
            assert_eq!(oracle.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn profile_and_observation_drift_fail_closed() {
        let driver = fake_driver();
        let executor =
            NativeCertificationFuzzExecutor::new(driver.clone(), oracle()).expect("executor");
        driver.state.profile.lock().expect("profile").policy_digest = digest(b"drifted policy");
        assert_eq!(
            executor.engine().expect_err("profile drift").kind(),
            NativeConfinementErrorKind::ProfileDrift
        );

        for mutation in [
            Mutation::Attempt,
            Mutation::Policy,
            Mutation::Controls,
            Mutation::Sanitizers,
            Mutation::OversizedStdout,
            Mutation::InconsistentStdoutFlag,
        ] {
            let driver = fake_driver();
            *driver.state.mutation.lock().expect("mutation") = mutation;
            let executor =
                NativeCertificationFuzzExecutor::new(driver, oracle()).expect("executor");
            let subject = subject();
            let limits = limits();
            assert_eq!(
                executor
                    .execute(execution(&subject, &limits))
                    .expect_err("invalid observation")
                    .kind(),
                NativeConfinementErrorKind::InvalidObservation
            );
        }
    }

    #[test]
    fn cross_platform_subject_fails_before_native_execution() {
        let driver = fake_driver();
        let executor =
            NativeCertificationFuzzExecutor::new(driver.clone(), oracle()).expect("executor");
        let mut subject = subject();
        subject.platform = match current_native_platform().expect("native platform") {
            NativeConfinementPlatform::Windows => "linux-x64".into(),
            NativeConfinementPlatform::Linux | NativeConfinementPlatform::Macos => {
                "windows-x64".into()
            }
        };
        let limits = limits();
        assert_eq!(
            executor
                .execute(execution(&subject, &limits))
                .expect_err("cross-platform subject")
                .kind(),
            NativeConfinementErrorKind::InvalidExecution
        );
        assert!(driver.state.requests.lock().expect("requests").is_empty());
    }

    #[test]
    fn driver_oracle_and_coverage_failures_are_bounded_and_thread_safe() {
        fn assert_thread_safe<T: Send + Sync>() {}
        assert_thread_safe::<NativeCertificationFuzzExecutor<FakeDriver, FakeOracle>>();

        let driver = fake_driver();
        driver.state.execute_fails.store(true, Ordering::SeqCst);
        let executor = NativeCertificationFuzzExecutor::new(driver, oracle()).expect("executor");
        let subject = subject();
        let limits = limits();
        let error = executor
            .execute(execution(&subject, &limits))
            .expect_err("driver failure");
        assert_eq!(error.kind(), NativeConfinementErrorKind::DriverFailure);
        assert!(!error.to_string().contains("private"));

        let driver = fake_driver();
        driver.state.coverage_fails.store(true, Ordering::SeqCst);
        let executor = NativeCertificationFuzzExecutor::new(driver, oracle()).expect("executor");
        assert_eq!(
            executor
                .coverage_basis_points()
                .expect_err("coverage failure")
                .kind(),
            NativeConfinementErrorKind::DriverFailure
        );

        let oracle = oracle();
        oracle.fails.store(true, Ordering::SeqCst);
        let executor =
            NativeCertificationFuzzExecutor::new(fake_driver(), oracle).expect("executor");
        assert_eq!(
            executor
                .execute(execution(&subject, &limits))
                .expect_err("oracle failure")
                .kind(),
            NativeConfinementErrorKind::OracleFailure
        );
    }
}
