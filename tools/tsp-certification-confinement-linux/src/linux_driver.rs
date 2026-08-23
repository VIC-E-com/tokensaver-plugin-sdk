use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokensaver_certification_confinement::{
    NativeConfinementDriver, NativeConfinementObservation, NativeConfinementPlatform,
    NativeConfinementProfile, NativeConfinementRequest, NativeTermination,
    required_native_confinement_controls,
};
use tsp_workbench::CertificationFuzzEngine;

const BACKEND_ID: &str = "tokensaver.linux-native";
const BACKEND_VERSION: &str = "1.0.0";
const POLICY: &[u8] = b"tokensaver-linux-confinement-policy-v1\0user+mount+network+pid-namespaces\0private-root\0landlock-deny-default\0seccomp-filter\0cgroup-v2-memory+pids\0pidfd-kill+reap\0bounded-stdio\0minimal-environment";
const ENV_ALLOWLIST: &[&str] = &[
    "ASAN_OPTIONS",
    "GCOV_PREFIX",
    "GCOV_PREFIX_STRIP",
    "HOME",
    "LLVM_PROFILE_FILE",
    "LSAN_OPTIONS",
    "MSAN_OPTIONS",
    "PATH",
    "TEMP",
    "TMP",
    "TMPDIR",
    "TSAN_OPTIONS",
    "UBSAN_OPTIONS",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxConfinementErrorKind {
    InvalidConfiguration,
    PreflightFailure,
    ArtifactFailure,
    ArtifactDrift,
    InvalidExecution,
    LaunchFailure,
    CoverageFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxConfinementError(LinuxConfinementErrorKind);

impl LinuxConfinementError {
    pub fn kind(self) -> LinuxConfinementErrorKind {
        self.0
    }
    fn new(kind: LinuxConfinementErrorKind) -> Self {
        Self(kind)
    }
}

impl fmt::Display for LinuxConfinementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Linux certification confinement failed closed")
    }
}

impl std::error::Error for LinuxConfinementError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxConfinementConfig {
    executable: PathBuf,
    sandbox_root: PathBuf,
    writable_directory: PathBuf,
    cgroup_parent: PathBuf,
    environment: Vec<(String, String)>,
    engine: CertificationFuzzEngine,
    policy_digest: String,
}

impl LinuxConfinementConfig {
    pub fn new(
        executable: impl AsRef<Path>,
        sandbox_root: impl AsRef<Path>,
        writable_directory: impl AsRef<Path>,
        cgroup_parent: impl AsRef<Path>,
        environment: BTreeMap<String, String>,
        engine: CertificationFuzzEngine,
    ) -> Result<Self, LinuxConfinementError> {
        let executable = canonical(executable.as_ref(), true)?;
        let sandbox_root = canonical(sandbox_root.as_ref(), false)?;
        let writable_directory = canonical(writable_directory.as_ref(), false)?;
        let cgroup_parent = canonical(cgroup_parent.as_ref(), false)?;
        if sandbox_root == writable_directory || executable.starts_with(&writable_directory) {
            return Err(LinuxConfinementError::new(
                LinuxConfinementErrorKind::InvalidConfiguration,
            ));
        }
        validate_engine(&engine)?;
        let environment = validate_environment(environment)?;
        let policy_digest = make_policy_digest(
            &executable,
            &sandbox_root,
            &writable_directory,
            &cgroup_parent,
            &environment,
            &engine,
        );
        Ok(Self {
            executable,
            sandbox_root,
            writable_directory,
            cgroup_parent,
            environment,
            engine,
            policy_digest,
        })
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }
    pub fn sandbox_root(&self) -> &Path {
        &self.sandbox_root
    }
    pub fn writable_directory(&self) -> &Path {
        &self.writable_directory
    }
    pub fn cgroup_parent(&self) -> &Path {
        &self.cgroup_parent
    }
    pub fn environment(&self) -> &[(String, String)] {
        &self.environment
    }
    pub fn engine(&self) -> &CertificationFuzzEngine {
        &self.engine
    }
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LinuxKernelExecution<'a> {
    pub attempt_id: &'a str,
    pub executable: &'a Path,
    pub sandbox_root: &'a Path,
    pub writable_directory: &'a Path,
    pub cgroup_parent: &'a Path,
    pub environment: &'a [(String, String)],
    pub arguments: &'a [String],
    pub input: &'a [u8],
    pub maximum_memory_bytes: u64,
    pub maximum_stdout_bytes: usize,
    pub maximum_stderr_bytes: usize,
    pub deadline: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxKernelObservation {
    pub termination: NativeTermination,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_milliseconds: u64,
    pub peak_memory_bytes: u64,
    pub stdout_limit_exceeded: bool,
    pub stderr_limit_exceeded: bool,
    pub process_reaped: bool,
}

pub trait LinuxConfinementKernel: Send + Sync {
    type Error;
    fn preflight(&self, config: &LinuxConfinementConfig) -> Result<(), Self::Error>;
    fn execute(
        &self,
        request: LinuxKernelExecution<'_>,
    ) -> Result<LinuxKernelObservation, Self::Error>;
}

pub trait LinuxCoverageReader: Send + Sync {
    type Error;
    fn coverage_basis_points(&self) -> Result<u32, Self::Error>;
}

pub struct LinuxNamespaceConfinementDriver<K, C> {
    config: LinuxConfinementConfig,
    kernel: K,
    coverage: C,
}

impl<K: LinuxConfinementKernel, C: LinuxCoverageReader> LinuxNamespaceConfinementDriver<K, C> {
    pub fn new(config: LinuxConfinementConfig, kernel: K, coverage: C) -> Self {
        Self {
            config,
            kernel,
            coverage,
        }
    }

    fn preflight(&self) -> Result<(), LinuxConfinementError> {
        self.kernel
            .preflight(&self.config)
            .map_err(|_| LinuxConfinementError::new(LinuxConfinementErrorKind::PreflightFailure))
    }
}

impl<K: LinuxConfinementKernel, C: LinuxCoverageReader> NativeConfinementDriver
    for LinuxNamespaceConfinementDriver<K, C>
{
    type Error = LinuxConfinementError;

    fn profile(&self) -> Result<NativeConfinementProfile, Self::Error> {
        self.preflight()?;
        Ok(NativeConfinementProfile {
            schema_version: 1,
            backend_id: BACKEND_ID.into(),
            backend_version: BACKEND_VERSION.into(),
            platform: NativeConfinementPlatform::Linux,
            policy_digest: self.config.policy_digest.clone(),
            controls: required_native_confinement_controls(NativeConfinementPlatform::Linux)
                .to_vec(),
            engine: self.config.engine.clone(),
        })
    }

    fn execute(
        &self,
        request: NativeConfinementRequest<'_>,
    ) -> Result<NativeConfinementObservation, Self::Error> {
        self.preflight()?;
        let execution = request.execution;
        if request.attempt_id.is_empty()
            || !valid_attempt_id(&request.attempt_id)
            || !execution.subject.platform.starts_with("linux-")
            || execution.execution_deadline_milliseconds == 0
            || execution.execution_deadline_milliseconds > execution.remaining_campaign_milliseconds
            || execution.limits.maximum_memory_bytes == 0
            || execution.limits.maximum_stdout_bytes == 0
            || execution.limits.maximum_stderr_bytes == 0
        {
            return Err(LinuxConfinementError::new(
                LinuxConfinementErrorKind::InvalidExecution,
            ));
        }
        verify_artifact(&self.config.executable, &execution.subject.artifact_digest)?;
        let stdout_limit = usize::try_from(execution.limits.maximum_stdout_bytes)
            .map_err(|_| LinuxConfinementError::new(LinuxConfinementErrorKind::InvalidExecution))?;
        let stderr_limit = usize::try_from(execution.limits.maximum_stderr_bytes)
            .map_err(|_| LinuxConfinementError::new(LinuxConfinementErrorKind::InvalidExecution))?;
        let observed = self
            .kernel
            .execute(LinuxKernelExecution {
                attempt_id: &request.attempt_id,
                executable: &self.config.executable,
                sandbox_root: &self.config.sandbox_root,
                writable_directory: &self.config.writable_directory,
                cgroup_parent: &self.config.cgroup_parent,
                environment: &self.config.environment,
                arguments: &[],
                input: execution.input,
                maximum_memory_bytes: execution.limits.maximum_memory_bytes,
                maximum_stdout_bytes: stdout_limit,
                maximum_stderr_bytes: stderr_limit,
                deadline: Duration::from_millis(execution.execution_deadline_milliseconds),
            })
            .map_err(|_| LinuxConfinementError::new(LinuxConfinementErrorKind::LaunchFailure))?;
        if !observed.process_reaped
            || observed.stdout.len() > stdout_limit
            || observed.stderr.len() > stderr_limit
            || (observed.stdout_limit_exceeded && observed.stdout.len() != stdout_limit)
            || (observed.stderr_limit_exceeded && observed.stderr.len() != stderr_limit)
        {
            return Err(LinuxConfinementError::new(
                LinuxConfinementErrorKind::LaunchFailure,
            ));
        }
        Ok(NativeConfinementObservation {
            attempt_id: request.attempt_id,
            policy_digest: self.config.policy_digest.clone(),
            applied_controls: required_native_confinement_controls(
                NativeConfinementPlatform::Linux,
            )
            .to_vec(),
            active_sanitizers: self.config.engine.active_sanitizers.clone(),
            termination: observed.termination,
            stdout: observed.stdout,
            sanitizer_failure: sanitizer_failure(
                &observed.stderr,
                &self.config.engine.active_sanitizers,
            ),
            stderr: observed.stderr,
            duration_milliseconds: observed.duration_milliseconds,
            peak_memory_bytes: observed.peak_memory_bytes,
            stdout_limit_exceeded: observed.stdout_limit_exceeded,
            stdout_protocol_violation: false,
            stderr_limit_exceeded: observed.stderr_limit_exceeded,
            process_reaped: true,
        })
    }

    fn coverage_basis_points(&self) -> Result<u32, Self::Error> {
        self.preflight()?;
        let value = self
            .coverage
            .coverage_basis_points()
            .map_err(|_| LinuxConfinementError::new(LinuxConfinementErrorKind::CoverageFailure))?;
        if value > 10_000 {
            return Err(LinuxConfinementError::new(
                LinuxConfinementErrorKind::CoverageFailure,
            ));
        }
        Ok(value)
    }
}

fn valid_attempt_id(value: &str) -> bool {
    let suffix = if value.len() == 70 && value.starts_with("tsfa1_") {
        &value[6..]
    } else if value.len() == 37 && value.starts_with("tsa1_") {
        &value[5..]
    } else {
        return false;
    };
    suffix
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn canonical(path: &Path, file: bool) -> Result<PathBuf, LinuxConfinementError> {
    let path = std::fs::canonicalize(path)
        .map_err(|_| LinuxConfinementError::new(LinuxConfinementErrorKind::InvalidConfiguration))?;
    let metadata = std::fs::metadata(&path)
        .map_err(|_| LinuxConfinementError::new(LinuxConfinementErrorKind::InvalidConfiguration))?;
    if !path.is_absolute() || metadata.is_file() != file {
        return Err(LinuxConfinementError::new(
            LinuxConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(path)
}

fn validate_engine(engine: &CertificationFuzzEngine) -> Result<(), LinuxConfinementError> {
    let token = |value: &str| {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
    };
    let parts: Vec<&str> = engine.version.split('.').collect();
    let version = parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (*p == "0" || !p.starts_with('0'))
                && p.parse::<u64>().is_ok()
        });
    let supported = |value: &str| {
        matches!(
            value,
            "address" | "leak" | "memory" | "thread" | "undefined"
        )
    };
    if !token(&engine.id)
        || !version
        || engine.active_sanitizers.is_empty()
        || engine.active_sanitizers.iter().any(|v| !supported(v))
        || !engine.active_sanitizers.windows(2).all(|v| v[0] < v[1])
    {
        return Err(LinuxConfinementError::new(
            LinuxConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(())
}

fn validate_environment(
    environment: BTreeMap<String, String>,
) -> Result<Vec<(String, String)>, LinuxConfinementError> {
    let allowed: BTreeSet<&str> = ENV_ALLOWLIST.iter().copied().collect();
    let mut result = Vec::new();
    for (name, value) in environment {
        if !allowed.contains(name.as_str())
            || value.is_empty()
            || name.contains('=')
            || name.contains('\0')
            || value.contains('\0')
        {
            return Err(LinuxConfinementError::new(
                LinuxConfinementErrorKind::InvalidConfiguration,
            ));
        }
        result.push((name, value));
    }
    result.sort();
    if result.len() > ENV_ALLOWLIST.len()
        || result
            .iter()
            .map(|(a, b)| a.len() + b.len() + 2)
            .sum::<usize>()
            > 32_768
    {
        return Err(LinuxConfinementError::new(
            LinuxConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(result)
}

fn make_policy_digest(
    executable: &Path,
    root: &Path,
    writable: &Path,
    cgroup: &Path,
    environment: &[(String, String)],
    engine: &CertificationFuzzEngine,
) -> String {
    let mut digest = Sha256::new();
    for value in [
        POLICY,
        executable.as_os_str().as_bytes(),
        root.as_os_str().as_bytes(),
        writable.as_os_str().as_bytes(),
        cgroup.as_os_str().as_bytes(),
        engine.id.as_bytes(),
        engine.version.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    for (name, value) in environment {
        for part in [name.as_bytes(), value.as_bytes()] {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part);
        }
    }
    for sanitizer in &engine.active_sanitizers {
        digest.update((sanitizer.len() as u64).to_be_bytes());
        digest.update(sanitizer.as_bytes());
    }
    format!("sha256:{:x}", digest.finalize())
}

fn verify_artifact(path: &Path, expected: &str) -> Result<(), LinuxConfinementError> {
    let mut file = File::open(path)
        .map_err(|_| LinuxConfinementError::new(LinuxConfinementErrorKind::ArtifactFailure))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| LinuxConfinementError::new(LinuxConfinementErrorKind::ArtifactFailure))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if format!("sha256:{:x}", digest.finalize()) != expected {
        return Err(LinuxConfinementError::new(
            LinuxConfinementErrorKind::ArtifactDrift,
        ));
    }
    Ok(())
}

fn sanitizer_failure(stderr: &[u8], active: &[String]) -> bool {
    let lower: Vec<u8> = stderr.iter().map(u8::to_ascii_lowercase).collect();
    active.iter().any(|value| {
        let markers: &[&[u8]] = match value.as_str() {
            "address" => &[b"addresssanitizer", b"asan:"],
            "leak" => &[b"leaksanitizer", b"lsan:"],
            "memory" => &[b"memorysanitizer", b"msan:"],
            "thread" => &[b"threadsanitizer", b"tsan:"],
            "undefined" => &[b"undefinedbehaviorsanitizer", b"ubsan:", b"runtime error:"],
            _ => &[],
        };
        markers
            .iter()
            .any(|m| lower.windows(m.len()).any(|v| v == *m))
    })
}

mod native;
pub use native::LinuxKernel;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use tokensaver_certification_worker::CertificationFuzzExecution;
    use tsp_workbench::{
        CertificationFuzzCaseClass, CertificationFuzzExecutionLimits, CertificationSubject,
    };

    #[derive(Clone)]
    struct FakeKernel(Arc<Mutex<State>>);

    struct State {
        preflights: usize,
        fail: bool,
        inputs: Vec<Vec<u8>>,
        observation: LinuxKernelObservation,
    }

    impl LinuxConfinementKernel for FakeKernel {
        type Error = ();
        fn preflight(&self, _config: &LinuxConfinementConfig) -> Result<(), Self::Error> {
            let mut state = self.0.lock().expect("state");
            state.preflights += 1;
            if state.fail { Err(()) } else { Ok(()) }
        }
        fn execute(
            &self,
            request: LinuxKernelExecution<'_>,
        ) -> Result<LinuxKernelObservation, Self::Error> {
            let mut state = self.0.lock().expect("state");
            state.inputs.push(request.input.to_vec());
            if state.fail {
                Err(())
            } else {
                Ok(state.observation.clone())
            }
        }
    }

    #[derive(Clone)]
    struct Coverage(Result<u32, ()>);
    impl LinuxCoverageReader for Coverage {
        type Error = ();
        fn coverage_basis_points(&self) -> Result<u32, Self::Error> {
            self.0
        }
    }

    fn fixture(bytes: &[u8]) -> (PathBuf, PathBuf) {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let root = std::env::temp_dir().join(format!(
            "tokensaver-linux-driver-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("root");
        let executable = root.join("plugin");
        std::fs::write(&executable, bytes).expect("executable");
        (root, executable)
    }

    fn engine() -> CertificationFuzzEngine {
        CertificationFuzzEngine {
            id: "clang.libfuzzer".into(),
            version: "1.2.3".into(),
            active_sanitizers: vec!["address".into(), "undefined".into()],
        }
    }

    fn config(root: &Path, executable: &Path) -> LinuxConfinementConfig {
        let work = root.join("work");
        std::fs::create_dir_all(&work).expect("work");
        LinuxConfinementConfig::new(
            executable,
            root,
            &work,
            root,
            BTreeMap::from([
                ("HOME".into(), "/nonexistent".into()),
                ("TMPDIR".into(), "/work".into()),
            ]),
            engine(),
        )
        .expect("config")
    }

    fn kernel() -> FakeKernel {
        FakeKernel(Arc::new(Mutex::new(State {
            preflights: 0,
            fail: false,
            inputs: Vec::new(),
            observation: LinuxKernelObservation {
                termination: NativeTermination::Exited(0),
                stdout: b"response".to_vec(),
                stderr: Vec::new(),
                duration_milliseconds: 4,
                peak_memory_bytes: 4096,
                stdout_limit_exceeded: false,
                stderr_limit_exceeded: false,
                process_reaped: true,
            },
        })))
    }

    fn subject(bytes: &[u8]) -> CertificationSubject {
        CertificationSubject {
            plugin_id: "com.example.plugin".into(),
            version: "1.0.0".into(),
            platform: "linux-x64".into(),
            api_version: 1,
            artifact_digest: format!("sha256:{:x}", Sha256::digest(bytes)),
            package_digest: format!("sha256:{:x}", Sha256::digest(b"package")),
            release_id: "release-1".into(),
        }
    }

    fn limits() -> CertificationFuzzExecutionLimits {
        CertificationFuzzExecutionLimits {
            maximum_execution_milliseconds: 500,
            maximum_memory_bytes: 64 << 20,
            maximum_stdout_bytes: 4096,
            maximum_stderr_bytes: 2048,
            required_sanitizers: vec!["address".into()],
        }
    }

    fn request<'a>(
        subject: &'a CertificationSubject,
        limits: &'a CertificationFuzzExecutionLimits,
        input: &'a [u8],
    ) -> NativeConfinementRequest<'a> {
        NativeConfinementRequest {
            attempt_id: format!("tsfa1_{}", "a".repeat(64)),
            execution: CertificationFuzzExecution {
                ordinal: 0,
                repetition: 0,
                case_id: "case",
                class: CertificationFuzzCaseClass::Malformed,
                input,
                subject,
                limits,
                execution_deadline_milliseconds: 500,
                remaining_campaign_milliseconds: 1000,
            },
        }
    }

    #[test]
    fn configuration_policy_and_environment_are_strict() {
        let bytes = b"artifact";
        let (root, executable) = fixture(bytes);
        assert_eq!(config(&root, &executable), config(&root, &executable));
        assert!(
            config(&root, &executable)
                .policy_digest()
                .starts_with("sha256:")
        );
        assert_eq!(
            LinuxConfinementConfig::new(
                &executable,
                &root,
                root.join("work"),
                &root,
                BTreeMap::from([("API_KEY".into(), "secret".into())]),
                engine()
            )
            .expect_err("ambient secret")
            .kind(),
            LinuxConfinementErrorKind::InvalidConfiguration
        );
        assert_eq!(
            LinuxConfinementConfig::new(
                &executable,
                &root,
                &root,
                &root,
                BTreeMap::new(),
                engine()
            )
            .expect_err("writable executable and shared roots")
            .kind(),
            LinuxConfinementErrorKind::InvalidConfiguration
        );
    }

    #[test]
    fn preflight_runs_before_every_operation_and_is_bounded() {
        let bytes = b"artifact";
        let (root, executable) = fixture(bytes);
        let kernel = kernel();
        let driver = LinuxNamespaceConfinementDriver::new(
            config(&root, &executable),
            kernel.clone(),
            Coverage(Ok(9000)),
        );
        driver.profile().expect("profile");
        driver.coverage_basis_points().expect("coverage");
        let subject = subject(bytes);
        let limits = limits();
        driver
            .execute(request(&subject, &limits, b"input"))
            .expect("execute");
        assert_eq!(kernel.0.lock().expect("state").preflights, 3);
        kernel.0.lock().expect("state").fail = true;
        let error = driver.profile().expect_err("preflight");
        assert_eq!(error.kind(), LinuxConfinementErrorKind::PreflightFailure);
        assert_eq!(
            error.to_string(),
            "Linux certification confinement failed closed"
        );
    }

    #[test]
    fn empty_input_and_sanitizer_findings_are_truthful() {
        let bytes = b"artifact";
        let (root, executable) = fixture(bytes);
        let kernel = kernel();
        kernel.0.lock().expect("state").observation.stderr =
            b"ERROR: AddressSanitizer: overflow".to_vec();
        let driver = LinuxNamespaceConfinementDriver::new(
            config(&root, &executable),
            kernel.clone(),
            Coverage(Ok(0)),
        );
        let subject = subject(bytes);
        let limits = limits();
        let observed = driver
            .execute(request(&subject, &limits, b""))
            .expect("empty fuzz input");
        assert!(observed.sanitizer_failure);
        assert_eq!(
            kernel.0.lock().expect("state").inputs,
            vec![Vec::<u8>::new()]
        );
    }

    #[test]
    fn artifact_drift_and_forged_observations_never_pass() {
        let bytes = b"artifact";
        let (root, executable) = fixture(bytes);
        let kernel = kernel();
        let driver = LinuxNamespaceConfinementDriver::new(
            config(&root, &executable),
            kernel.clone(),
            Coverage(Ok(0)),
        );
        std::fs::write(&executable, b"drift").expect("drift");
        let original_subject = subject(bytes);
        let limits = limits();
        assert_eq!(
            driver
                .execute(request(&original_subject, &limits, b"input"))
                .expect_err("drift")
                .kind(),
            LinuxConfinementErrorKind::ArtifactDrift
        );
        assert!(kernel.0.lock().expect("state").inputs.is_empty());

        let replacement = subject(b"drift");
        kernel.0.lock().expect("state").observation.process_reaped = false;
        assert_eq!(
            driver
                .execute(request(&replacement, &limits, b"input"))
                .expect_err("unreaped")
                .kind(),
            LinuxConfinementErrorKind::LaunchFailure
        );
    }

    #[test]
    fn coverage_overflow_and_thread_contract_fail_closed() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LinuxNamespaceConfinementDriver<FakeKernel, Coverage>>();
        let bytes = b"artifact";
        let (root, executable) = fixture(bytes);
        let driver = LinuxNamespaceConfinementDriver::new(
            config(&root, &executable),
            kernel(),
            Coverage(Ok(10_001)),
        );
        assert_eq!(
            driver.coverage_basis_points().expect_err("overflow").kind(),
            LinuxConfinementErrorKind::CoverageFailure
        );
    }

    #[test]
    fn attempt_id_cannot_escape_native_resource_names() {
        let bytes = b"artifact";
        let (root, executable) = fixture(bytes);
        let kernel = kernel();
        let driver = LinuxNamespaceConfinementDriver::new(
            config(&root, &executable),
            kernel.clone(),
            Coverage(Ok(0)),
        );
        let subject = subject(bytes);
        let limits = limits();
        let mut request = request(&subject, &limits, b"input");
        request.attempt_id = "../../escape".into();
        assert_eq!(
            driver
                .execute(request)
                .expect_err("unsafe attempt id")
                .kind(),
            LinuxConfinementErrorKind::InvalidExecution
        );
        assert!(kernel.0.lock().expect("state").inputs.is_empty());
    }
}
