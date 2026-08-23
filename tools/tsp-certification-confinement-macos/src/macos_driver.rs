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

const BACKEND_ID: &str = "tokensaver.macos-native";
const BACKEND_VERSION: &str = "1.0.0";
const POLICY: &[u8] = b"tokensaver-macos-confinement-policy-v1\0sandbox-deny-default\0trusted-launcher\0process-group\0rlimit-address+data+nproc+files\0kill+wait4+group-proof\0bounded-stdio\0minimal-environment";
const ENV_ALLOWLIST: &[&str] = &[
    "ASAN_OPTIONS",
    "GCOV_PREFIX",
    "GCOV_PREFIX_STRIP",
    "HOME",
    "LANG",
    "LC_ALL",
    "LLVM_PROFILE_FILE",
    "LSAN_OPTIONS",
    "MSAN_OPTIONS",
    "PATH",
    "TEMP",
    "TMP",
    "TMPDIR",
    "TOKENSAVER_PLUGIN",
    "TSAN_OPTIONS",
    "UBSAN_OPTIONS",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosConfinementErrorKind {
    InvalidConfiguration,
    PreflightFailure,
    ArtifactFailure,
    ArtifactDrift,
    InvalidExecution,
    LaunchFailure,
    CoverageFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacosConfinementError(MacosConfinementErrorKind);

impl MacosConfinementError {
    pub fn kind(self) -> MacosConfinementErrorKind {
        self.0
    }

    fn new(kind: MacosConfinementErrorKind) -> Self {
        Self(kind)
    }
}

impl fmt::Display for MacosConfinementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("macOS certification confinement failed closed")
    }
}

impl std::error::Error for MacosConfinementError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacosConfinementConfig {
    executable: PathBuf,
    launcher: PathBuf,
    writable_directory: PathBuf,
    environment: Vec<(String, String)>,
    engine: CertificationFuzzEngine,
    executable_digest: String,
    launcher_digest: String,
    sandbox_profile: String,
    policy_digest: String,
}

impl MacosConfinementConfig {
    pub fn new(
        executable: impl AsRef<Path>,
        launcher: impl AsRef<Path>,
        writable_directory: impl AsRef<Path>,
        environment: BTreeMap<String, String>,
        engine: CertificationFuzzEngine,
    ) -> Result<Self, MacosConfinementError> {
        let executable = canonical(executable.as_ref(), true)?;
        let launcher = canonical(launcher.as_ref(), true)?;
        let writable_directory = canonical(writable_directory.as_ref(), false)?;
        if executable == launcher
            || executable.starts_with(&writable_directory)
            || launcher.starts_with(&writable_directory)
        {
            return Err(MacosConfinementError::new(
                MacosConfinementErrorKind::InvalidConfiguration,
            ));
        }
        validate_engine(&engine)?;
        let environment = validate_environment(environment)?;
        let executable_digest = digest_file(&executable)?;
        let launcher_digest = digest_file(&launcher)?;
        let sandbox_profile = make_sandbox_profile(&executable, &launcher, &writable_directory)?;
        let policy_digest = make_policy_digest(
            &executable,
            &launcher,
            &writable_directory,
            &environment,
            &engine,
            &executable_digest,
            &launcher_digest,
            &sandbox_profile,
        );
        Ok(Self {
            executable,
            launcher,
            writable_directory,
            environment,
            engine,
            executable_digest,
            launcher_digest,
            sandbox_profile,
            policy_digest,
        })
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn launcher(&self) -> &Path {
        &self.launcher
    }

    pub fn writable_directory(&self) -> &Path {
        &self.writable_directory
    }

    pub fn environment(&self) -> &[(String, String)] {
        &self.environment
    }

    pub fn engine(&self) -> &CertificationFuzzEngine {
        &self.engine
    }

    pub fn sandbox_profile(&self) -> &str {
        &self.sandbox_profile
    }

    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MacosKernelExecution<'a> {
    pub attempt_id: &'a str,
    pub executable: &'a Path,
    pub launcher: &'a Path,
    pub writable_directory: &'a Path,
    pub sandbox_profile: &'a str,
    pub environment: &'a [(String, String)],
    pub arguments: &'a [String],
    pub input: &'a [u8],
    pub maximum_memory_bytes: u64,
    pub maximum_stdout_bytes: usize,
    pub maximum_stderr_bytes: usize,
    pub deadline: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacosKernelObservation {
    pub termination: NativeTermination,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_milliseconds: u64,
    pub peak_memory_bytes: u64,
    pub stdout_limit_exceeded: bool,
    pub stderr_limit_exceeded: bool,
    pub process_reaped: bool,
}

pub trait MacosConfinementKernel: Send + Sync {
    type Error;

    fn preflight(&self, config: &MacosConfinementConfig) -> Result<(), Self::Error>;

    fn execute(
        &self,
        request: MacosKernelExecution<'_>,
    ) -> Result<MacosKernelObservation, Self::Error>;
}

pub trait MacosCoverageReader: Send + Sync {
    type Error;

    fn coverage_basis_points(&self) -> Result<u32, Self::Error>;
}

pub struct MacosSandboxConfinementDriver<K, C> {
    config: MacosConfinementConfig,
    kernel: K,
    coverage: C,
}

impl<K: MacosConfinementKernel, C: MacosCoverageReader> MacosSandboxConfinementDriver<K, C> {
    pub fn new(config: MacosConfinementConfig, kernel: K, coverage: C) -> Self {
        Self {
            config,
            kernel,
            coverage,
        }
    }

    fn preflight(&self) -> Result<(), MacosConfinementError> {
        verify_artifact(&self.config.executable, &self.config.executable_digest)?;
        verify_artifact(&self.config.launcher, &self.config.launcher_digest)?;
        self.kernel
            .preflight(&self.config)
            .map_err(|_| MacosConfinementError::new(MacosConfinementErrorKind::PreflightFailure))
    }
}

impl<K: MacosConfinementKernel, C: MacosCoverageReader> NativeConfinementDriver
    for MacosSandboxConfinementDriver<K, C>
{
    type Error = MacosConfinementError;

    fn profile(&self) -> Result<NativeConfinementProfile, Self::Error> {
        self.preflight()?;
        Ok(NativeConfinementProfile {
            schema_version: 1,
            backend_id: BACKEND_ID.into(),
            backend_version: BACKEND_VERSION.into(),
            platform: NativeConfinementPlatform::Macos,
            policy_digest: self.config.policy_digest.clone(),
            controls: required_native_confinement_controls(NativeConfinementPlatform::Macos)
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
        if !valid_attempt_id(&request.attempt_id)
            || !execution.subject.platform.starts_with("darwin-")
            || execution.execution_deadline_milliseconds == 0
            || execution.execution_deadline_milliseconds > execution.remaining_campaign_milliseconds
            || execution.limits.maximum_memory_bytes == 0
            || execution.limits.maximum_stdout_bytes == 0
            || execution.limits.maximum_stderr_bytes == 0
        {
            return Err(MacosConfinementError::new(
                MacosConfinementErrorKind::InvalidExecution,
            ));
        }
        verify_artifact(&self.config.executable, &execution.subject.artifact_digest)?;
        let stdout_limit = usize::try_from(execution.limits.maximum_stdout_bytes)
            .map_err(|_| MacosConfinementError::new(MacosConfinementErrorKind::InvalidExecution))?;
        let stderr_limit = usize::try_from(execution.limits.maximum_stderr_bytes)
            .map_err(|_| MacosConfinementError::new(MacosConfinementErrorKind::InvalidExecution))?;
        let observed = self
            .kernel
            .execute(MacosKernelExecution {
                attempt_id: &request.attempt_id,
                executable: &self.config.executable,
                launcher: &self.config.launcher,
                writable_directory: &self.config.writable_directory,
                sandbox_profile: &self.config.sandbox_profile,
                environment: &self.config.environment,
                arguments: &[],
                input: execution.input,
                maximum_memory_bytes: execution.limits.maximum_memory_bytes,
                maximum_stdout_bytes: stdout_limit,
                maximum_stderr_bytes: stderr_limit,
                deadline: Duration::from_millis(execution.execution_deadline_milliseconds),
            })
            .map_err(|_| MacosConfinementError::new(MacosConfinementErrorKind::LaunchFailure))?;
        if !observed.process_reaped
            || observed.stdout.len() > stdout_limit
            || observed.stderr.len() > stderr_limit
            || (observed.stdout_limit_exceeded && observed.stdout.len() != stdout_limit)
            || (observed.stderr_limit_exceeded && observed.stderr.len() != stderr_limit)
        {
            return Err(MacosConfinementError::new(
                MacosConfinementErrorKind::LaunchFailure,
            ));
        }
        Ok(NativeConfinementObservation {
            attempt_id: request.attempt_id,
            policy_digest: self.config.policy_digest.clone(),
            applied_controls: required_native_confinement_controls(
                NativeConfinementPlatform::Macos,
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
            .map_err(|_| MacosConfinementError::new(MacosConfinementErrorKind::CoverageFailure))?;
        if value > 10_000 {
            return Err(MacosConfinementError::new(
                MacosConfinementErrorKind::CoverageFailure,
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

fn canonical(path: &Path, file: bool) -> Result<PathBuf, MacosConfinementError> {
    let path = std::fs::canonicalize(path)
        .map_err(|_| MacosConfinementError::new(MacosConfinementErrorKind::InvalidConfiguration))?;
    let metadata = std::fs::metadata(&path)
        .map_err(|_| MacosConfinementError::new(MacosConfinementErrorKind::InvalidConfiguration))?;
    if !path.is_absolute() || metadata.is_file() != file {
        return Err(MacosConfinementError::new(
            MacosConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(path)
}

fn validate_engine(engine: &CertificationFuzzEngine) -> Result<(), MacosConfinementError> {
    let token = |value: &str| {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
    };
    let parts = engine.version.split('.').collect::<Vec<_>>();
    let version = parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (*part == "0" || !part.starts_with('0'))
                && part.parse::<u64>().is_ok()
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
        || engine
            .active_sanitizers
            .iter()
            .any(|value| !supported(value))
        || !engine
            .active_sanitizers
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(MacosConfinementError::new(
            MacosConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(())
}

fn validate_environment(
    environment: BTreeMap<String, String>,
) -> Result<Vec<(String, String)>, MacosConfinementError> {
    let allowed = ENV_ALLOWLIST.iter().copied().collect::<BTreeSet<_>>();
    let mut result = Vec::new();
    for (name, value) in environment {
        if !allowed.contains(name.as_str())
            || name.starts_with("DYLD_")
            || name.contains(['=', '\0'])
            || value.is_empty()
            || value.contains('\0')
        {
            return Err(MacosConfinementError::new(
                MacosConfinementErrorKind::InvalidConfiguration,
            ));
        }
        result.push((name, value));
    }
    result.sort();
    if result.len() > ENV_ALLOWLIST.len()
        || result
            .iter()
            .map(|(name, value)| name.len() + value.len() + 2)
            .sum::<usize>()
            > 32_768
    {
        return Err(MacosConfinementError::new(
            MacosConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(result)
}

fn make_sandbox_profile(
    executable: &Path,
    launcher: &Path,
    writable: &Path,
) -> Result<String, MacosConfinementError> {
    let executable = sandbox_literal(executable)?;
    let launcher = sandbox_literal(launcher)?;
    let writable = sandbox_literal(writable)?;
    let profile = format!(
        "(version 1)\n(deny default)\n(allow process-exec (literal \"{launcher}\") (literal \"{executable}\"))\n(deny process-fork)\n(deny network*)\n(allow file-read-metadata)\n(allow file-read* (literal \"{launcher}\") (literal \"{executable}\") (subpath \"/System\") (subpath \"/usr/lib\") (subpath \"/Library/Apple/System\"))\n(allow file-write* (subpath \"{writable}\"))\n(allow sysctl-read)\n(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))\n"
    );
    if profile.len() > 65_536 || profile.contains('\0') {
        return Err(MacosConfinementError::new(
            MacosConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(profile)
}

fn sandbox_literal(path: &Path) -> Result<String, MacosConfinementError> {
    let value = path.to_str().ok_or_else(|| {
        MacosConfinementError::new(MacosConfinementErrorKind::InvalidConfiguration)
    })?;
    if value.bytes().any(|byte| byte < b' ' || byte == 0x7f) {
        return Err(MacosConfinementError::new(
            MacosConfinementErrorKind::InvalidConfiguration,
        ));
    }
    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[allow(clippy::too_many_arguments)]
fn make_policy_digest(
    executable: &Path,
    launcher: &Path,
    writable: &Path,
    environment: &[(String, String)],
    engine: &CertificationFuzzEngine,
    executable_digest: &str,
    launcher_digest: &str,
    sandbox_profile: &str,
) -> String {
    let mut digest = Sha256::new();
    hash_part(&mut digest, POLICY);
    hash_path(&mut digest, executable);
    hash_path(&mut digest, launcher);
    hash_path(&mut digest, writable);
    for value in [
        engine.id.as_bytes(),
        engine.version.as_bytes(),
        executable_digest.as_bytes(),
        launcher_digest.as_bytes(),
        sandbox_profile.as_bytes(),
    ] {
        hash_part(&mut digest, value);
    }
    for (name, value) in environment {
        hash_part(&mut digest, name.as_bytes());
        hash_part(&mut digest, value.as_bytes());
    }
    for sanitizer in &engine.active_sanitizers {
        hash_part(&mut digest, sanitizer.as_bytes());
    }
    format!("sha256:{:x}", digest.finalize())
}

fn hash_path(digest: &mut Sha256, path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hash_part(digest, path.as_os_str().as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let bytes = path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>();
        hash_part(digest, &bytes);
    }
    #[cfg(not(any(unix, windows)))]
    hash_part(digest, path.to_string_lossy().as_bytes());
}

fn hash_part(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn digest_file(path: &Path) -> Result<String, MacosConfinementError> {
    let mut file = File::open(path)
        .map_err(|_| MacosConfinementError::new(MacosConfinementErrorKind::ArtifactFailure))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| MacosConfinementError::new(MacosConfinementErrorKind::ArtifactFailure))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn verify_artifact(path: &Path, expected: &str) -> Result<(), MacosConfinementError> {
    if digest_file(path)? != expected {
        return Err(MacosConfinementError::new(
            MacosConfinementErrorKind::ArtifactDrift,
        ));
    }
    Ok(())
}

fn sanitizer_failure(stderr: &[u8], active: &[String]) -> bool {
    let text = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    active.iter().any(|sanitizer| match sanitizer.as_str() {
        "address" => text.contains("addresssanitizer"),
        "leak" => text.contains("leaksanitizer"),
        "memory" => text.contains("memorysanitizer"),
        "thread" => text.contains("threadsanitizer"),
        "undefined" => {
            text.contains("undefinedbehaviorsanitizer") || text.contains("runtime error:")
        }
        _ => true,
    })
}

#[cfg(target_os = "macos")]
mod native;

#[cfg(target_os = "macos")]
pub use native::{MacosKernel, MacosKernelError};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokensaver_certification_worker::CertificationFuzzExecution;
    use tsp_workbench::{
        CertificationFuzzCaseClass, CertificationFuzzExecutionLimits, CertificationSubject,
    };

    #[derive(Clone, Default)]
    struct Kernel(Arc<Mutex<State>>);

    struct State {
        preflights: usize,
        requests: Vec<(String, Vec<u8>, u64, usize, usize, u64)>,
        fail_preflight: bool,
        fail_execute: bool,
        observation: MacosKernelObservation,
    }

    impl Default for State {
        fn default() -> Self {
            Self {
                preflights: 0,
                requests: Vec::new(),
                fail_preflight: false,
                fail_execute: false,
                observation: MacosKernelObservation {
                    termination: NativeTermination::Exited(0),
                    stdout: b"valid response".to_vec(),
                    stderr: Vec::new(),
                    duration_milliseconds: 1,
                    peak_memory_bytes: 1024,
                    stdout_limit_exceeded: false,
                    stderr_limit_exceeded: false,
                    process_reaped: true,
                },
            }
        }
    }

    impl MacosConfinementKernel for Kernel {
        type Error = &'static str;

        fn preflight(&self, _config: &MacosConfinementConfig) -> Result<(), Self::Error> {
            let mut state = self.0.lock().expect("state");
            state.preflights += 1;
            if state.fail_preflight {
                Err("private preflight")
            } else {
                Ok(())
            }
        }

        fn execute(
            &self,
            request: MacosKernelExecution<'_>,
        ) -> Result<MacosKernelObservation, Self::Error> {
            let mut state = self.0.lock().expect("state");
            state.requests.push((
                request.attempt_id.into(),
                request.input.to_vec(),
                request.maximum_memory_bytes,
                request.maximum_stdout_bytes,
                request.maximum_stderr_bytes,
                request.deadline.as_millis().try_into().unwrap_or(u64::MAX),
            ));
            if state.fail_execute {
                Err("private launch diagnostic")
            } else {
                Ok(state.observation.clone())
            }
        }
    }

    struct Coverage(u32);

    impl MacosCoverageReader for Coverage {
        type Error = &'static str;

        fn coverage_basis_points(&self) -> Result<u32, Self::Error> {
            Ok(self.0)
        }
    }

    fn subject(artifact: &[u8]) -> CertificationSubject {
        CertificationSubject {
            plugin_id: "com.example.plugin".into(),
            version: "1.0.0".into(),
            platform: "darwin-x64".into(),
            api_version: 1,
            artifact_digest: format!("sha256:{:x}", Sha256::digest(artifact)),
            package_digest: format!("sha256:{:x}", Sha256::digest(b"package")),
            release_id: "tsr1_fixture".into(),
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
            attempt_id: format!("tsfa1_{}", "0".repeat(64)),
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
    fn configuration_profile_environment_and_artifact_are_bound() {
        let fixture = Fixture::new();
        let config = fixture.config(BTreeMap::from([
            ("HOME".into(), "/nonexistent".into()),
            ("TMPDIR".into(), fixture.work.to_string_lossy().into_owned()),
            ("TOKENSAVER_PLUGIN".into(), "1".into()),
        ]));
        assert!(config.sandbox_profile().contains("(deny default)"));
        assert!(config.sandbox_profile().contains("(deny network*)"));
        assert!(!config.sandbox_profile().contains("/etc"));
        assert_eq!(config.environment()[0].0, "HOME");
        assert!(
            config
                .environment()
                .contains(&("TOKENSAVER_PLUGIN".into(), "1".into()))
        );
        let driver = MacosSandboxConfinementDriver::new(config, Kernel::default(), Coverage(9000));
        let profile = driver.profile().expect("profile");
        assert_eq!(profile.platform, NativeConfinementPlatform::Macos);
        assert_eq!(
            profile.controls,
            required_native_confinement_controls(NativeConfinementPlatform::Macos)
        );
        assert_eq!(driver.coverage_basis_points().expect("coverage"), 9000);
        assert!(
            fixture
                .config_result(BTreeMap::from([(
                    "AWS_SECRET_ACCESS_KEY".into(),
                    "secret".into()
                )]))
                .is_err()
        );
    }

    #[test]
    fn preflight_drift_bounds_and_thread_contract_fail_closed() {
        fn assert_thread_safe<T: Send + Sync>() {}
        assert_thread_safe::<MacosSandboxConfinementDriver<Kernel, Coverage>>();
        let fixture = Fixture::new();
        let config = fixture.config(BTreeMap::new());
        let kernel = Kernel::default();
        let driver = MacosSandboxConfinementDriver::new(config, kernel.clone(), Coverage(10_001));
        assert_eq!(
            driver.coverage_basis_points().expect_err("coverage").kind(),
            MacosConfinementErrorKind::CoverageFailure
        );
        kernel.0.lock().expect("state").fail_preflight = true;
        let error = driver.profile().expect_err("preflight");
        assert_eq!(error.kind(), MacosConfinementErrorKind::PreflightFailure);
        assert!(!error.to_string().contains("private"));
        kernel.0.lock().expect("state").fail_preflight = false;
        std::fs::write(&fixture.executable, b"drift").expect("drift");
        assert_eq!(
            driver.profile().expect_err("artifact drift").kind(),
            MacosConfinementErrorKind::ArtifactDrift
        );
    }

    #[test]
    fn execution_forwards_exact_identity_input_limits_and_observation() {
        let fixture = Fixture::new();
        let kernel = Kernel::default();
        let driver = MacosSandboxConfinementDriver::new(
            fixture.config(BTreeMap::new()),
            kernel.clone(),
            Coverage(8123),
        );
        let subject = subject(b"plugin");
        let limits = limits();
        let observed = driver
            .execute(request(&subject, &limits, b"exact fuzz input"))
            .expect("execution");
        assert_eq!(observed.stdout, b"valid response");
        assert_eq!(observed.peak_memory_bytes, 1024);
        assert_eq!(
            kernel.0.lock().expect("state").requests,
            vec![(
                format!("tsfa1_{}", "0".repeat(64)),
                b"exact fuzz input".to_vec(),
                64 << 20,
                4096,
                2048,
                500,
            )]
        );
    }

    #[test]
    fn package_platform_contract_uses_darwin_and_rejects_old_macos_spelling() {
        let fixture = Fixture::new();
        let kernel = Kernel::default();
        let driver = MacosSandboxConfinementDriver::new(
            fixture.config(BTreeMap::new()),
            kernel.clone(),
            Coverage(0),
        );
        let mut subject = subject(b"plugin");
        subject.platform = "macos-x64".into();
        let limits = limits();
        assert_eq!(
            driver
                .execute(request(&subject, &limits, b"input"))
                .expect_err("old platform spelling")
                .kind(),
            MacosConfinementErrorKind::InvalidExecution
        );
        assert!(kernel.0.lock().expect("state").requests.is_empty());
    }

    #[test]
    fn invalid_attempt_deadline_and_resource_limits_short_circuit() {
        let fixture = Fixture::new();
        let kernel = Kernel::default();
        let driver = MacosSandboxConfinementDriver::new(
            fixture.config(BTreeMap::new()),
            kernel.clone(),
            Coverage(0),
        );
        let subject = subject(b"plugin");
        for kind in 0..5 {
            let mut case_limits = limits();
            if kind == 3 {
                case_limits.maximum_memory_bytes = 0;
            } else if kind == 4 {
                case_limits.maximum_stdout_bytes = 0;
            }
            let mut candidate = request(&subject, &case_limits, b"input");
            match kind {
                0 => candidate.attempt_id = "invalid".into(),
                1 => candidate.execution.execution_deadline_milliseconds = 0,
                2 => candidate.execution.execution_deadline_milliseconds = 1001,
                _ => {}
            }
            assert_eq!(
                driver
                    .execute(candidate)
                    .expect_err("invalid execution")
                    .kind(),
                MacosConfinementErrorKind::InvalidExecution
            );
        }
        assert!(kernel.0.lock().expect("state").requests.is_empty());
    }

    #[test]
    fn forged_stream_bounds_and_unreaped_process_fail_closed() {
        let fixture = Fixture::new();
        let kernel = Kernel::default();
        let driver = MacosSandboxConfinementDriver::new(
            fixture.config(BTreeMap::new()),
            kernel.clone(),
            Coverage(0),
        );
        let subject = subject(b"plugin");
        let limits = limits();
        for mutate in 0..5 {
            let mut state = kernel.0.lock().expect("state");
            state.observation = State::default().observation;
            match mutate {
                0 => state.observation.process_reaped = false,
                1 => state.observation.stdout = vec![0; 4097],
                2 => state.observation.stderr = vec![0; 2049],
                3 => state.observation.stdout_limit_exceeded = true,
                _ => state.observation.stderr_limit_exceeded = true,
            }
            drop(state);
            assert_eq!(
                driver
                    .execute(request(&subject, &limits, b"input"))
                    .expect_err("forged observation")
                    .kind(),
                MacosConfinementErrorKind::LaunchFailure
            );
        }
    }

    #[test]
    fn sanitizer_and_private_kernel_failure_are_mapped_without_leakage() {
        let fixture = Fixture::new();
        let kernel = Kernel::default();
        let driver = MacosSandboxConfinementDriver::new(
            fixture.config(BTreeMap::new()),
            kernel.clone(),
            Coverage(0),
        );
        let subject = subject(b"plugin");
        let limits = limits();
        kernel.0.lock().expect("state").observation.stderr =
            b"ERROR: AddressSanitizer: heap-use-after-free".to_vec();
        assert!(
            driver
                .execute(request(&subject, &limits, b"input"))
                .expect("sanitizer observation")
                .sanitizer_failure
        );
        kernel.0.lock().expect("state").fail_execute = true;
        let error = driver
            .execute(request(&subject, &limits, b"input"))
            .expect_err("private launch failure");
        assert_eq!(error.kind(), MacosConfinementErrorKind::LaunchFailure);
        assert!(!error.to_string().contains("private"));
    }

    struct Fixture {
        root: PathBuf,
        executable: PathBuf,
        launcher: PathBuf,
        work: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "tokensaver-macos-config-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir(&root).expect("root");
            let executable = root.join("plugin");
            let launcher = root.join("launcher");
            let work = root.join("work");
            std::fs::write(&executable, b"plugin").expect("plugin");
            std::fs::write(&launcher, b"launcher").expect("launcher");
            std::fs::create_dir(&work).expect("work");
            Self {
                root,
                executable,
                launcher,
                work,
            }
        }

        fn config(&self, environment: BTreeMap<String, String>) -> MacosConfinementConfig {
            self.config_result(environment).expect("configuration")
        }

        fn config_result(
            &self,
            environment: BTreeMap<String, String>,
        ) -> Result<MacosConfinementConfig, MacosConfinementError> {
            MacosConfinementConfig::new(
                &self.executable,
                &self.launcher,
                &self.work,
                environment,
                CertificationFuzzEngine {
                    id: "macos.test".into(),
                    version: "1.0.0".into(),
                    active_sanitizers: vec!["address".into()],
                },
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}
