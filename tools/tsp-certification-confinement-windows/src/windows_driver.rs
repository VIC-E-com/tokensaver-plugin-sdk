use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokensaver_certification_confinement::{
    NativeConfinementDriver, NativeConfinementObservation, NativeConfinementPlatform,
    NativeConfinementProfile, NativeConfinementRequest, NativeTermination,
    required_native_confinement_controls,
};
use tsp_workbench::CertificationFuzzEngine;

const PROFILE_SCHEMA_VERSION: u32 = 1;
const BACKEND_ID: &str = "tokensaver.windows-appcontainer-job";
const BACKEND_VERSION: &str = "1.0.0";
const MAX_ENVIRONMENT_UTF16_UNITS: usize = 32_767;
const MAX_APP_CONTAINER_NAME_UTF16_UNITS: usize = 256;
const ARTIFACT_READ_BUFFER_BYTES: usize = 64 * 1024;
const FIXED_PLUGIN_ENVIRONMENT_UTF16_UNITS: usize = 20;
const POLICY_DESCRIPTOR: &str = concat!(
    "tokensaver-windows-confinement-policy-v1\n",
    "create=suspended,no-window,unicode-environment,extended-startup-info\n",
    "appcontainer=derived-profile,zero-capabilities,no-loopback-exemption\n",
    "handles=explicit-stdin-stdout-stderr-only\n",
    "job=created-before-process,assigned-before-resume,active-process:1,",
    "process-memory-hard-limit,die-on-unhandled-exception,kill-on-close,no-breakaway\n",
    "ui=stable-cross-version-restrictions:0xff\n",
    "io=exact-stdin,bounded-stdout,bounded-stderr\n",
    "deadline=terminate-complete-job,bounded-reap,active-processes-zero\n",
    "memory-evidence=job-completion-port,limit-violation-query\n",
    "environment=systemroot,systemdrive,sandbox-localappdata,temp,sanitizer,coverage-allowlist,tokensaver-plugin-marker\n",
);

const ALLOWED_ENVIRONMENT_NAMES: &[&str] = &[
    "ASAN_OPTIONS",
    "GCOV_PREFIX",
    "GCOV_PREFIX_STRIP",
    "LLVM_PROFILE_FILE",
    "LOCALAPPDATA",
    "LSAN_OPTIONS",
    "MSAN_OPTIONS",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TSAN_OPTIONS",
    "UBSAN_OPTIONS",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsConfinementErrorKind {
    InvalidConfiguration,
    PreflightFailure,
    ArtifactFailure,
    ArtifactDrift,
    InvalidExecution,
    LaunchFailure,
    CoverageFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsConfinementError {
    kind: WindowsConfinementErrorKind,
}

impl WindowsConfinementError {
    pub fn kind(self) -> WindowsConfinementErrorKind {
        self.kind
    }

    fn new(kind: WindowsConfinementErrorKind) -> Self {
        Self { kind }
    }
}

impl fmt::Display for WindowsConfinementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Windows certification confinement failed closed")
    }
}

impl std::error::Error for WindowsConfinementError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsConfinementConfig {
    executable_path: PathBuf,
    working_directory: PathBuf,
    app_container_name: String,
    environment: Vec<(String, String)>,
    engine: CertificationFuzzEngine,
    policy_digest: String,
}

impl WindowsConfinementConfig {
    pub fn new(
        executable_path: impl AsRef<Path>,
        working_directory: impl AsRef<Path>,
        app_container_name: impl Into<String>,
        environment: BTreeMap<String, String>,
        engine: CertificationFuzzEngine,
    ) -> Result<Self, WindowsConfinementError> {
        let executable_path = canonical_file(executable_path.as_ref())?;
        let working_directory = canonical_directory(working_directory.as_ref())?;
        let app_container_name = app_container_name.into();
        validate_app_container_name(&app_container_name)?;
        validate_engine(&engine)?;
        let environment = canonical_environment(environment)?;
        validate_loader_environment(&environment, &working_directory)?;
        let policy_digest = policy_digest(
            &executable_path,
            &working_directory,
            &app_container_name,
            &environment,
            &engine,
        );
        Ok(Self {
            executable_path,
            working_directory,
            app_container_name,
            environment,
            engine,
            policy_digest,
        })
    }

    pub fn executable_path(&self) -> &Path {
        &self.executable_path
    }

    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    pub fn app_container_name(&self) -> &str {
        &self.app_container_name
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
pub struct WindowsKernelExecution<'a> {
    pub executable_path: &'a Path,
    pub working_directory: &'a Path,
    pub app_container_name: &'a str,
    pub environment: &'a [(String, String)],
    pub arguments: &'a [String],
    pub input: &'a [u8],
    pub maximum_memory_bytes: u64,
    pub maximum_stdout_bytes: usize,
    pub maximum_stderr_bytes: usize,
    pub deadline: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsKernelObservation {
    pub termination: NativeTermination,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_milliseconds: u64,
    pub peak_memory_bytes: u64,
    pub stdout_limit_exceeded: bool,
    pub stderr_limit_exceeded: bool,
    pub process_reaped: bool,
}

pub trait WindowsConfinementKernel: Send + Sync {
    type Error;

    fn preflight(&self, app_container_name: &str) -> Result<(), Self::Error>;

    fn execute(
        &self,
        execution: WindowsKernelExecution<'_>,
    ) -> Result<WindowsKernelObservation, Self::Error>;
}

pub trait WindowsCoverageReader: Send + Sync {
    type Error;

    fn coverage_basis_points(&self) -> Result<u32, Self::Error>;
}

pub struct WindowsAppContainerJobDriver<K, C> {
    config: WindowsConfinementConfig,
    kernel: K,
    coverage: C,
}

impl<K, C> WindowsAppContainerJobDriver<K, C>
where
    K: WindowsConfinementKernel,
    C: WindowsCoverageReader,
{
    pub fn new(config: WindowsConfinementConfig, kernel: K, coverage: C) -> Self {
        Self {
            config,
            kernel,
            coverage,
        }
    }

    pub fn config(&self) -> &WindowsConfinementConfig {
        &self.config
    }

    fn preflight(&self) -> Result<(), WindowsConfinementError> {
        self.kernel
            .preflight(self.config.app_container_name())
            .map_err(|_| {
                WindowsConfinementError::new(WindowsConfinementErrorKind::PreflightFailure)
            })
    }
}

impl<K, C> NativeConfinementDriver for WindowsAppContainerJobDriver<K, C>
where
    K: WindowsConfinementKernel,
    C: WindowsCoverageReader,
{
    type Error = WindowsConfinementError;

    fn profile(&self) -> Result<NativeConfinementProfile, Self::Error> {
        self.preflight()?;
        Ok(NativeConfinementProfile {
            schema_version: PROFILE_SCHEMA_VERSION,
            backend_id: BACKEND_ID.into(),
            backend_version: BACKEND_VERSION.into(),
            platform: NativeConfinementPlatform::Windows,
            policy_digest: self.config.policy_digest.clone(),
            controls: required_native_confinement_controls(NativeConfinementPlatform::Windows)
                .to_vec(),
            engine: self.config.engine.clone(),
        })
    }

    fn execute(
        &self,
        request: NativeConfinementRequest<'_>,
    ) -> Result<NativeConfinementObservation, Self::Error> {
        self.preflight()?;
        validate_execution(&request)?;
        verify_artifact(
            self.config.executable_path(),
            &request.execution.subject.artifact_digest,
        )?;
        let limits = request.execution.limits;
        let maximum_stdout_bytes = usize::try_from(limits.maximum_stdout_bytes).map_err(|_| {
            WindowsConfinementError::new(WindowsConfinementErrorKind::InvalidExecution)
        })?;
        let maximum_stderr_bytes = usize::try_from(limits.maximum_stderr_bytes).map_err(|_| {
            WindowsConfinementError::new(WindowsConfinementErrorKind::InvalidExecution)
        })?;
        let observation = self
            .kernel
            .execute(WindowsKernelExecution {
                executable_path: self.config.executable_path(),
                working_directory: self.config.working_directory(),
                app_container_name: self.config.app_container_name(),
                environment: self.config.environment(),
                arguments: &[],
                input: request.execution.input,
                maximum_memory_bytes: limits.maximum_memory_bytes,
                maximum_stdout_bytes,
                maximum_stderr_bytes,
                deadline: Duration::from_millis(request.execution.execution_deadline_milliseconds),
            })
            .map_err(|_| {
                WindowsConfinementError::new(WindowsConfinementErrorKind::LaunchFailure)
            })?;
        if observation.stdout.len() > maximum_stdout_bytes
            || observation.stderr.len() > maximum_stderr_bytes
            || (observation.stdout_limit_exceeded
                && observation.stdout.len() != maximum_stdout_bytes)
            || (observation.stderr_limit_exceeded
                && observation.stderr.len() != maximum_stderr_bytes)
            || !observation.process_reaped
        {
            return Err(WindowsConfinementError::new(
                WindowsConfinementErrorKind::LaunchFailure,
            ));
        }
        let sanitizer_failure =
            sanitizer_failure(&observation.stderr, &self.config.engine.active_sanitizers);
        Ok(NativeConfinementObservation {
            attempt_id: request.attempt_id,
            policy_digest: self.config.policy_digest.clone(),
            applied_controls: required_native_confinement_controls(
                NativeConfinementPlatform::Windows,
            )
            .to_vec(),
            active_sanitizers: self.config.engine.active_sanitizers.clone(),
            termination: observation.termination,
            stdout: observation.stdout,
            stderr: observation.stderr,
            duration_milliseconds: observation.duration_milliseconds,
            peak_memory_bytes: observation.peak_memory_bytes,
            stdout_limit_exceeded: observation.stdout_limit_exceeded,
            stdout_protocol_violation: false,
            stderr_limit_exceeded: observation.stderr_limit_exceeded,
            sanitizer_failure,
            process_reaped: true,
        })
    }

    fn coverage_basis_points(&self) -> Result<u32, Self::Error> {
        self.preflight()?;
        let value = self.coverage.coverage_basis_points().map_err(|_| {
            WindowsConfinementError::new(WindowsConfinementErrorKind::CoverageFailure)
        })?;
        if value > 10_000 {
            return Err(WindowsConfinementError::new(
                WindowsConfinementErrorKind::CoverageFailure,
            ));
        }
        Ok(value)
    }
}

fn canonical_file(path: &Path) -> Result<PathBuf, WindowsConfinementError> {
    let canonical = std::fs::canonicalize(path).map_err(|_| {
        WindowsConfinementError::new(WindowsConfinementErrorKind::InvalidConfiguration)
    })?;
    if !canonical.is_absolute()
        || !std::fs::metadata(&canonical)
            .map(|value| value.is_file())
            .unwrap_or(false)
    {
        return Err(WindowsConfinementError::new(
            WindowsConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(canonical)
}

fn canonical_directory(path: &Path) -> Result<PathBuf, WindowsConfinementError> {
    let canonical = std::fs::canonicalize(path).map_err(|_| {
        WindowsConfinementError::new(WindowsConfinementErrorKind::InvalidConfiguration)
    })?;
    if !canonical.is_absolute()
        || !std::fs::metadata(&canonical)
            .map(|value| value.is_dir())
            .unwrap_or(false)
    {
        return Err(WindowsConfinementError::new(
            WindowsConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(canonical)
}

fn validate_app_container_name(value: &str) -> Result<(), WindowsConfinementError> {
    let units = value.encode_utf16().count();
    if units == 0
        || units > MAX_APP_CONTAINER_NAME_UTF16_UNITS
        || value.chars().any(char::is_control)
        || value.contains('\0')
    {
        return Err(WindowsConfinementError::new(
            WindowsConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(())
}

fn validate_engine(engine: &CertificationFuzzEngine) -> Result<(), WindowsConfinementError> {
    let valid_token = |value: &str| {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
    };
    let valid_version = |value: &str| {
        let mut parts = value.split('.');
        let component = |part: Option<&str>| {
            part.is_some_and(|part| {
                !part.is_empty()
                    && part.bytes().all(|byte| byte.is_ascii_digit())
                    && (part == "0" || !part.starts_with('0'))
                    && part.parse::<u64>().is_ok()
            })
        };
        component(parts.next())
            && component(parts.next())
            && component(parts.next())
            && parts.next().is_none()
    };
    let supported = |value: &str| {
        matches!(
            value,
            "address" | "leak" | "memory" | "thread" | "undefined"
        )
    };
    if !valid_token(&engine.id)
        || !valid_version(&engine.version)
        || engine.active_sanitizers.is_empty()
        || engine
            .active_sanitizers
            .iter()
            .any(|value| !supported(value))
        || !engine
            .active_sanitizers
            .windows(2)
            .all(|values| values[0] < values[1])
    {
        return Err(WindowsConfinementError::new(
            WindowsConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(())
}

fn canonical_environment(
    environment: BTreeMap<String, String>,
) -> Result<Vec<(String, String)>, WindowsConfinementError> {
    let allowed: BTreeSet<&str> = ALLOWED_ENVIRONMENT_NAMES.iter().copied().collect();
    let mut seen = BTreeSet::new();
    let mut canonical = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        let name = name.to_ascii_uppercase();
        if !allowed.contains(name.as_str())
            || !seen.insert(name.clone())
            || value.is_empty()
            || value.contains('\0')
            || name.contains('=')
        {
            return Err(WindowsConfinementError::new(
                WindowsConfinementErrorKind::InvalidConfiguration,
            ));
        }
        canonical.push((name, value));
    }
    canonical.sort_by(|left, right| left.0.cmp(&right.0));
    if ["LOCALAPPDATA", "SYSTEMDRIVE", "SYSTEMROOT"]
        .iter()
        .any(|required| {
            canonical
                .binary_search_by_key(required, |value| value.0.as_str())
                .is_err()
        })
        || environment_utf16_units(&canonical).saturating_add(FIXED_PLUGIN_ENVIRONMENT_UTF16_UNITS)
            > MAX_ENVIRONMENT_UTF16_UNITS
    {
        return Err(WindowsConfinementError::new(
            WindowsConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(canonical)
}

fn environment_utf16_units(environment: &[(String, String)]) -> usize {
    environment.iter().fold(2usize, |total, (name, value)| {
        total
            .saturating_add(name.encode_utf16().count())
            .saturating_add(1)
            .saturating_add(value.encode_utf16().count())
            .saturating_add(1)
    })
}

fn validate_loader_environment(
    environment: &[(String, String)],
    working_directory: &Path,
) -> Result<(), WindowsConfinementError> {
    let value = |name: &str| {
        environment
            .binary_search_by_key(&name, |entry| entry.0.as_str())
            .ok()
            .map(|index| environment[index].1.as_str())
    };
    let local_app_data = value("LOCALAPPDATA").ok_or_else(|| {
        WindowsConfinementError::new(WindowsConfinementErrorKind::InvalidConfiguration)
    })?;
    if canonical_directory(Path::new(local_app_data))? != working_directory {
        return Err(WindowsConfinementError::new(
            WindowsConfinementErrorKind::InvalidConfiguration,
        ));
    }
    let system_drive = value("SYSTEMDRIVE").unwrap_or_default();
    let system_root = value("SYSTEMROOT").unwrap_or_default();
    let valid_drive = system_drive.len() == 2
        && system_drive.as_bytes()[0].is_ascii_alphabetic()
        && system_drive.as_bytes()[1] == b':';
    let root_prefix = system_root.get(..3).unwrap_or_default();
    if !valid_drive
        || !matches!(root_prefix.as_bytes().get(2).copied(), Some(b'\\' | b'/'))
        || !root_prefix[..2].eq_ignore_ascii_case(system_drive)
    {
        return Err(WindowsConfinementError::new(
            WindowsConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(())
}

fn policy_digest(
    executable: &Path,
    working_directory: &Path,
    app_container_name: &str,
    environment: &[(String, String)],
    engine: &CertificationFuzzEngine,
) -> String {
    let mut digest = Sha256::new();
    update_digest(&mut digest, POLICY_DESCRIPTOR.as_bytes());
    update_wide_path_digest(&mut digest, executable);
    update_wide_path_digest(&mut digest, working_directory);
    update_digest(&mut digest, app_container_name.as_bytes());
    for (name, value) in environment {
        update_digest(&mut digest, name.as_bytes());
        update_digest(&mut digest, value.as_bytes());
    }
    update_digest(&mut digest, engine.id.as_bytes());
    update_digest(&mut digest, engine.version.as_bytes());
    for sanitizer in &engine.active_sanitizers {
        update_digest(&mut digest, sanitizer.as_bytes());
    }
    format!("sha256:{:x}", digest.finalize())
}

fn update_digest(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn update_wide_path_digest(digest: &mut Sha256, path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    let mut bytes = Vec::new();
    for unit in path.as_os_str().encode_wide() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    update_digest(digest, &bytes);
}

fn validate_execution(
    request: &NativeConfinementRequest<'_>,
) -> Result<(), WindowsConfinementError> {
    let execution = request.execution;
    let limits = execution.limits;
    if request.attempt_id.is_empty()
        || request.attempt_id.len() > 128
        || !execution.subject.platform.starts_with("windows-")
        || limits.maximum_memory_bytes == 0
        || limits.maximum_stdout_bytes == 0
        || limits.maximum_stderr_bytes == 0
        || execution.execution_deadline_milliseconds == 0
        || execution.execution_deadline_milliseconds > execution.remaining_campaign_milliseconds
    {
        return Err(WindowsConfinementError::new(
            WindowsConfinementErrorKind::InvalidExecution,
        ));
    }
    Ok(())
}

fn verify_artifact(path: &Path, expected: &str) -> Result<(), WindowsConfinementError> {
    let mut file = File::open(path)
        .map_err(|_| WindowsConfinementError::new(WindowsConfinementErrorKind::ArtifactFailure))?;
    let metadata = file
        .metadata()
        .map_err(|_| WindowsConfinementError::new(WindowsConfinementErrorKind::ArtifactFailure))?;
    if !metadata.is_file() {
        return Err(WindowsConfinementError::new(
            WindowsConfinementErrorKind::ArtifactFailure,
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; ARTIFACT_READ_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer).map_err(|_| {
            WindowsConfinementError::new(WindowsConfinementErrorKind::ArtifactFailure)
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let actual = format!("sha256:{:x}", digest.finalize());
    if actual != expected {
        return Err(WindowsConfinementError::new(
            WindowsConfinementErrorKind::ArtifactDrift,
        ));
    }
    Ok(())
}

fn sanitizer_failure(stderr: &[u8], active: &[String]) -> bool {
    let lower: Vec<u8> = stderr.iter().map(u8::to_ascii_lowercase).collect();
    active.iter().any(|sanitizer| {
        let markers: &[&[u8]] = match sanitizer.as_str() {
            "address" => &[b"addresssanitizer", b"asan:"],
            "leak" => &[b"leaksanitizer", b"lsan:"],
            "memory" => &[b"memorysanitizer", b"msan:"],
            "thread" => &[b"threadsanitizer", b"tsan:"],
            "undefined" => &[b"undefinedbehaviorsanitizer", b"ubsan:", b"runtime error:"],
            _ => &[],
        };
        markers
            .iter()
            .any(|marker| lower.windows(marker.len()).any(|value| value == *marker))
    })
}

mod win32;

pub use win32::Win32Kernel;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use tokensaver_certification_worker::CertificationFuzzExecution;
    use tsp_workbench::{
        CertificationFuzzCaseClass, CertificationFuzzExecutionLimits, CertificationSubject,
    };

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct RecordedExecution {
        input: Vec<u8>,
        memory: u64,
        stdout: usize,
        stderr: usize,
        deadline: Duration,
        environment: Vec<(String, String)>,
    }

    #[derive(Clone)]
    struct FakeKernel {
        state: Arc<Mutex<FakeState>>,
    }

    struct FakeState {
        preflights: usize,
        fail_preflight: bool,
        fail_execute: bool,
        executions: Vec<RecordedExecution>,
        observation: WindowsKernelObservation,
    }

    impl WindowsConfinementKernel for FakeKernel {
        type Error = ();

        fn preflight(&self, _app_container_name: &str) -> Result<(), Self::Error> {
            let mut state = self.state.lock().expect("fake state");
            state.preflights += 1;
            if state.fail_preflight {
                Err(())
            } else {
                Ok(())
            }
        }

        fn execute(
            &self,
            execution: WindowsKernelExecution<'_>,
        ) -> Result<WindowsKernelObservation, Self::Error> {
            let mut state = self.state.lock().expect("fake state");
            state.executions.push(RecordedExecution {
                input: execution.input.to_vec(),
                memory: execution.maximum_memory_bytes,
                stdout: execution.maximum_stdout_bytes,
                stderr: execution.maximum_stderr_bytes,
                deadline: execution.deadline,
                environment: execution.environment.to_vec(),
            });
            if state.fail_execute {
                Err(())
            } else {
                Ok(state.observation.clone())
            }
        }
    }

    #[derive(Clone)]
    struct FakeCoverage(Result<u32, ()>);

    impl WindowsCoverageReader for FakeCoverage {
        type Error = ();

        fn coverage_basis_points(&self) -> Result<u32, Self::Error> {
            self.0
        }
    }

    fn fixture_file(bytes: &[u8]) -> (PathBuf, PathBuf) {
        static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);
        let root = std::env::temp_dir().join(format!(
            "tokensaver-windows-driver-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("fixture directory");
        let executable = root.join("plugin.exe");
        std::fs::write(&executable, bytes).expect("fixture executable");
        (root, executable)
    }

    fn engine() -> CertificationFuzzEngine {
        CertificationFuzzEngine {
            id: "clang-cl.libfuzzer".into(),
            version: "1.2.3".into(),
            active_sanitizers: vec!["address".into(), "undefined".into()],
        }
    }

    fn config(root: &Path, executable: &Path) -> WindowsConfinementConfig {
        WindowsConfinementConfig::new(
            executable,
            root,
            "com.tokensaver.certification.fuzz",
            BTreeMap::from([
                ("localappdata".into(), root.display().to_string()),
                ("SystemDrive".into(), "C:".into()),
                ("SystemRoot".into(), r"C:\Windows".into()),
                ("temp".into(), root.display().to_string()),
            ]),
            engine(),
        )
        .expect("configuration")
    }

    fn kernel() -> FakeKernel {
        FakeKernel {
            state: Arc::new(Mutex::new(FakeState {
                preflights: 0,
                fail_preflight: false,
                fail_execute: false,
                executions: Vec::new(),
                observation: WindowsKernelObservation {
                    termination: NativeTermination::Exited(0),
                    stdout: b"valid response".to_vec(),
                    stderr: Vec::new(),
                    duration_milliseconds: 7,
                    peak_memory_bytes: 4096,
                    stdout_limit_exceeded: false,
                    stderr_limit_exceeded: false,
                    process_reaped: true,
                },
            })),
        }
    }

    fn subject(artifact: &[u8]) -> CertificationSubject {
        CertificationSubject {
            plugin_id: "com.example.plugin".into(),
            version: "1.0.0".into(),
            platform: "windows-x64".into(),
            api_version: 1,
            artifact_digest: format!("sha256:{:x}", Sha256::digest(artifact)),
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

    fn execute<'a>(
        subject: &'a CertificationSubject,
        limits: &'a CertificationFuzzExecutionLimits,
        input: &'a [u8],
    ) -> NativeConfinementRequest<'a> {
        NativeConfinementRequest {
            attempt_id: "tsfa1_fixture".into(),
            execution: CertificationFuzzExecution {
                ordinal: 0,
                repetition: 0,
                case_id: "case-1",
                class: CertificationFuzzCaseClass::Valid,
                input,
                subject,
                limits,
                execution_deadline_milliseconds: 500,
                remaining_campaign_milliseconds: 1000,
            },
        }
    }

    #[test]
    fn configuration_is_strict_and_policy_digest_is_deterministic() {
        let artifact = b"immutable artifact";
        let (root, executable) = fixture_file(artifact);
        let first = config(&root, &executable);
        let second = config(&root, &executable);
        assert_eq!(first, second);
        assert!(first.policy_digest().starts_with("sha256:"));
        for environment in [
            BTreeMap::new(),
            BTreeMap::from([
                ("SYSTEMROOT".into(), r"C:\Windows".into()),
                ("API_KEY".into(), "secret".into()),
            ]),
            BTreeMap::from([
                ("LOCALAPPDATA".into(), root.display().to_string()),
                ("SYSTEMDRIVE".into(), "D:".into()),
                ("SYSTEMROOT".into(), r"C:\Windows".into()),
            ]),
        ] {
            assert_eq!(
                WindowsConfinementConfig::new(
                    &executable,
                    &root,
                    "com.tokensaver.certification.fuzz",
                    environment,
                    engine(),
                )
                .expect_err("invalid environment")
                .kind(),
                WindowsConfinementErrorKind::InvalidConfiguration
            );
        }
    }

    #[test]
    fn preflight_runs_before_every_operation_and_failures_are_bounded() {
        let artifact = b"immutable artifact";
        let (root, executable) = fixture_file(artifact);
        let kernel = kernel();
        let driver = WindowsAppContainerJobDriver::new(
            config(&root, &executable),
            kernel.clone(),
            FakeCoverage(Ok(9000)),
        );
        driver.profile().expect("profile");
        driver.coverage_basis_points().expect("coverage");
        let subject = subject(artifact);
        let limits = limits();
        driver
            .execute(execute(&subject, &limits, b"fuzz input"))
            .expect("execute");
        assert_eq!(kernel.state.lock().expect("state").preflights, 3);
        kernel.state.lock().expect("state").fail_preflight = true;
        let error = driver.profile().expect_err("preflight failure");
        assert_eq!(error.kind(), WindowsConfinementErrorKind::PreflightFailure);
        assert_eq!(
            error.to_string(),
            "Windows certification confinement failed closed"
        );
    }

    #[test]
    fn artifact_drift_short_circuits_before_launch() {
        let artifact = b"immutable artifact";
        let (root, executable) = fixture_file(artifact);
        let kernel = kernel();
        let driver = WindowsAppContainerJobDriver::new(
            config(&root, &executable),
            kernel.clone(),
            FakeCoverage(Ok(0)),
        );
        std::fs::write(&executable, b"changed").expect("drift artifact");
        let subject = subject(artifact);
        let limits = limits();
        assert_eq!(
            driver
                .execute(execute(&subject, &limits, b"input"))
                .expect_err("artifact drift")
                .kind(),
            WindowsConfinementErrorKind::ArtifactDrift
        );
        assert!(kernel.state.lock().expect("state").executions.is_empty());
    }

    #[test]
    fn exact_input_limits_environment_and_observation_are_forwarded() {
        let artifact = b"immutable artifact";
        let (root, executable) = fixture_file(artifact);
        let kernel = kernel();
        let driver = WindowsAppContainerJobDriver::new(
            config(&root, &executable),
            kernel.clone(),
            FakeCoverage(Ok(8123)),
        );
        let subject = subject(artifact);
        let limits = limits();
        let observation = driver
            .execute(execute(&subject, &limits, b"exact fuzz input"))
            .expect("execute");
        let state = kernel.state.lock().expect("state");
        assert_eq!(
            state.executions,
            vec![RecordedExecution {
                input: b"exact fuzz input".to_vec(),
                memory: 64 << 20,
                stdout: 4096,
                stderr: 2048,
                deadline: Duration::from_millis(500),
                environment: vec![
                    ("LOCALAPPDATA".into(), root.display().to_string()),
                    ("SYSTEMDRIVE".into(), "C:".into()),
                    ("SYSTEMROOT".into(), r"C:\Windows".into()),
                    ("TEMP".into(), root.display().to_string()),
                ],
            }]
        );
        assert_eq!(observation.attempt_id, "tsfa1_fixture");
        assert!(observation.process_reaped);
        drop(state);
        assert_eq!(driver.coverage_basis_points().expect("coverage"), 8123);
    }

    #[test]
    fn sanitizer_and_kernel_failures_fail_closed() {
        let artifact = b"immutable artifact";
        let (root, executable) = fixture_file(artifact);
        let kernel = kernel();
        kernel.state.lock().expect("state").observation.stderr =
            b"ERROR: AddressSanitizer: heap-use-after-free".to_vec();
        let driver = WindowsAppContainerJobDriver::new(
            config(&root, &executable),
            kernel.clone(),
            FakeCoverage(Err(())),
        );
        let subject = subject(artifact);
        let limits = limits();
        assert!(
            driver
                .execute(execute(&subject, &limits, b"input"))
                .expect("sanitizer observation")
                .sanitizer_failure
        );
        assert_eq!(
            driver
                .coverage_basis_points()
                .expect_err("coverage failure")
                .kind(),
            WindowsConfinementErrorKind::CoverageFailure
        );
        kernel.state.lock().expect("state").fail_execute = true;
        assert_eq!(
            driver
                .execute(execute(&subject, &limits, b"input"))
                .expect_err("kernel failure")
                .kind(),
            WindowsConfinementErrorKind::LaunchFailure
        );
    }

    #[test]
    fn empty_fuzz_input_is_forwarded_and_invalid_platform_is_rejected() {
        let artifact = b"immutable artifact";
        let (root, executable) = fixture_file(artifact);
        let kernel = kernel();
        let driver = WindowsAppContainerJobDriver::new(
            config(&root, &executable),
            kernel.clone(),
            FakeCoverage(Ok(0)),
        );
        let subject = subject(artifact);
        let limits = limits();
        driver
            .execute(execute(&subject, &limits, b""))
            .expect("empty malformed input is valid fuzz data");
        assert_eq!(
            kernel.state.lock().expect("state").executions[0].input,
            Vec::<u8>::new()
        );

        let mut foreign = subject.clone();
        foreign.platform = "linux-x64".into();
        assert_eq!(
            driver
                .execute(execute(&foreign, &limits, b"input"))
                .expect_err("foreign platform")
                .kind(),
            WindowsConfinementErrorKind::InvalidExecution
        );
        assert_eq!(kernel.state.lock().expect("state").executions.len(), 1);
    }

    #[test]
    fn artifact_disappearance_forged_bounds_and_coverage_overflow_fail_closed() {
        let artifact = b"immutable artifact";
        let (root, executable) = fixture_file(artifact);
        let forged_kernel = kernel();
        let config = config(&root, &executable);
        let subject = subject(artifact);
        let limits = limits();
        let driver = WindowsAppContainerJobDriver::new(
            config.clone(),
            forged_kernel.clone(),
            FakeCoverage(Ok(10_001)),
        );
        assert_eq!(
            driver
                .coverage_basis_points()
                .expect_err("coverage overflow")
                .kind(),
            WindowsConfinementErrorKind::CoverageFailure
        );

        forged_kernel
            .state
            .lock()
            .expect("state")
            .observation
            .stdout_limit_exceeded = true;
        assert_eq!(
            driver
                .execute(execute(&subject, &limits, b"input"))
                .expect_err("forged bounded observation")
                .kind(),
            WindowsConfinementErrorKind::LaunchFailure
        );

        let replacement_kernel = kernel();
        let missing_driver = WindowsAppContainerJobDriver::new(
            config,
            replacement_kernel.clone(),
            FakeCoverage(Ok(0)),
        );
        std::fs::remove_file(&executable).expect("remove artifact");
        assert_eq!(
            missing_driver
                .execute(execute(&subject, &limits, b"input"))
                .expect_err("missing artifact")
                .kind(),
            WindowsConfinementErrorKind::ArtifactFailure
        );
        assert!(
            replacement_kernel
                .state
                .lock()
                .expect("state")
                .executions
                .is_empty()
        );
    }

    #[test]
    fn concurrent_executions_keep_inputs_and_limits_isolated() {
        let artifact = b"immutable artifact";
        let (root, executable) = fixture_file(artifact);
        let kernel = kernel();
        let driver = Arc::new(WindowsAppContainerJobDriver::new(
            config(&root, &executable),
            kernel.clone(),
            FakeCoverage(Ok(9000)),
        ));
        let mut threads = Vec::new();
        for index in 0..16u8 {
            let driver = Arc::clone(&driver);
            threads.push(std::thread::spawn(move || {
                let subject = subject(artifact);
                let limits = limits();
                driver
                    .execute(execute(&subject, &limits, &[index]))
                    .expect("concurrent execution");
            }));
        }
        for thread in threads {
            thread.join().expect("thread");
        }
        let state = kernel.state.lock().expect("state");
        assert_eq!(state.executions.len(), 16);
        let mut inputs: Vec<Vec<u8>> = state
            .executions
            .iter()
            .map(|value| value.input.clone())
            .collect();
        inputs.sort();
        assert_eq!(
            inputs,
            (0..16u8).map(|value| vec![value]).collect::<Vec<_>>()
        );
    }

    #[test]
    fn driver_is_thread_safe() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WindowsAppContainerJobDriver<FakeKernel, FakeCoverage>>();
    }
}
