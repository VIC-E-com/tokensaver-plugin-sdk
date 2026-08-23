//! Trusted product runtime sidecar. It accepts exactly one bounded request,
//! invokes exactly one native confinement kernel, returns one bounded result,
//! and has no ordinary-process plugin fallback.

#![cfg_attr(not(windows), forbid(unsafe_code))]

mod platform;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokensaver_certification_confinement::NativeTermination;

const SCHEMA_VERSION: u32 = 1;
const MAXIMUM_REQUEST_BYTES: u64 = 40 << 20;
const MAXIMUM_INPUT_BYTES: usize = 24 << 20;
const MAXIMUM_STDOUT_BYTES: usize = 24 << 20;
const MAXIMUM_STDERR_BYTES: usize = 64 << 10;
const MAXIMUM_MEMORY_BYTES: u64 = 256 << 20;
const MAXIMUM_DEADLINE_MILLISECONDS: u64 = 1_250;
const MAXIMUM_ARGUMENTS: usize = 32;
const MAXIMUM_ARGUMENT_BYTES: usize = 4 << 10;
const MAXIMUM_IDENTITY_FILE_BYTES: u64 = 256 << 20;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    schema_version: u32,
    operation: String,
    attempt_id: String,
    plugin_id: String,
    release_id: String,
    platform: String,
    package_digest: String,
    artifact_digest: String,
    executable_path: String,
    release_path: String,
    work_path: String,
    arguments: Vec<String>,
    input: String,
    deadline_milliseconds: u64,
    maximum_memory_bytes: u64,
    maximum_stdout_bytes: usize,
    maximum_stderr_bytes: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Response {
    schema_version: u32,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observation: Option<Observation>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Observation {
    platform: String,
    attempt_id: String,
    artifact_digest: String,
    backend_id: String,
    policy_digest: String,
    stdout: String,
    stderr: String,
    exit_code: i32,
    duration_milliseconds: u64,
    peak_memory_bytes: u64,
    process_reaped: bool,
    deadline_exceeded: bool,
    memory_limit_exceeded: bool,
    stdout_limit_exceeded: bool,
    stderr_limit_exceeded: bool,
}

struct ValidatedRequest {
    request: Request,
    executable: PathBuf,
    release: PathBuf,
    work: PathBuf,
    input: Vec<u8>,
}

struct NativeResult {
    backend_id: &'static str,
    policy_digest: String,
    termination: NativeTermination,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    duration_milliseconds: u64,
    peak_memory_bytes: u64,
    stdout_limit_exceeded: bool,
    stderr_limit_exceeded: bool,
    process_reaped: bool,
}

fn main() {
    let response = run().unwrap_or_else(|code| Response {
        schema_version: SCHEMA_VERSION,
        ok: false,
        error: Some(code),
        observation: None,
    });
    if serde_json::to_writer(std::io::stdout().lock(), &response).is_err() {
        std::process::exit(2);
    }
}

fn run() -> Result<Response, &'static str> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAXIMUM_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "request_read")?;
    if bytes.is_empty() || bytes.len() as u64 > MAXIMUM_REQUEST_BYTES {
        return Err("request_size");
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| "request_json")?;
    let validated = validate(request)?;
    if validated.request.operation == "deprovision" {
        platform::deprovision(&validated)?;
        return Ok(Response {
            schema_version: SCHEMA_VERSION,
            ok: true,
            error: None,
            observation: None,
        });
    }
    let native = platform::execute(&validated)?;
    let (exit_code, deadline_exceeded, memory_limit_exceeded) = match native.termination {
        NativeTermination::Exited(code) => (code, false, false),
        NativeTermination::DeadlineKilled => (-1, true, false),
        NativeTermination::MemoryLimitKilled => (-1, false, true),
        NativeTermination::Signaled(_) | NativeTermination::Exception(_) => (-1, false, false),
    };
    Ok(Response {
        schema_version: SCHEMA_VERSION,
        ok: true,
        error: None,
        observation: Some(Observation {
            platform: validated.request.platform,
            attempt_id: validated.request.attempt_id,
            artifact_digest: validated.request.artifact_digest,
            backend_id: native.backend_id.into(),
            policy_digest: native.policy_digest,
            stdout: base64::engine::general_purpose::STANDARD.encode(native.stdout),
            stderr: base64::engine::general_purpose::STANDARD.encode(native.stderr),
            exit_code,
            duration_milliseconds: native.duration_milliseconds,
            peak_memory_bytes: native.peak_memory_bytes,
            process_reaped: native.process_reaped,
            deadline_exceeded,
            memory_limit_exceeded,
            stdout_limit_exceeded: native.stdout_limit_exceeded,
            stderr_limit_exceeded: native.stderr_limit_exceeded,
        }),
    })
}

fn validate(request: Request) -> Result<ValidatedRequest, &'static str> {
    if request.schema_version != SCHEMA_VERSION
        || (request.operation != "execute" && request.operation != "deprovision")
        || !valid_attempt_id(&request.attempt_id)
        || !valid_plugin_id(&request.plugin_id)
        || !valid_release_id(&request.release_id)
        || request.platform != platform::platform_key()
        || !valid_digest(&request.package_digest)
        || !valid_digest(&request.artifact_digest)
        || request.deadline_milliseconds == 0
        || request.deadline_milliseconds > MAXIMUM_DEADLINE_MILLISECONDS
        || request.maximum_memory_bytes == 0
        || request.maximum_memory_bytes > MAXIMUM_MEMORY_BYTES
        || request.maximum_stdout_bytes == 0
        || request.maximum_stdout_bytes > MAXIMUM_STDOUT_BYTES
        || request.maximum_stderr_bytes == 0
        || request.maximum_stderr_bytes > MAXIMUM_STDERR_BYTES
        || request.arguments.len() > MAXIMUM_ARGUMENTS
        || request
            .arguments
            .iter()
            .any(|value| value.len() > MAXIMUM_ARGUMENT_BYTES || value.contains('\0'))
    {
        return Err("request_invalid");
    }
    let input = base64::engine::general_purpose::STANDARD
        .decode(&request.input)
        .map_err(|_| "input_base64")?;
    if input.is_empty() || input.len() > MAXIMUM_INPUT_BYTES {
        return Err("input_size");
    }
    let executable = canonical_file(Path::new(&request.executable_path))?;
    let release = canonical_directory(Path::new(&request.release_path))?;
    let work = canonical_directory(Path::new(&request.work_path))?;
    if !executable.starts_with(&release)
        || work.starts_with(&release)
        || release.starts_with(&work)
        || digest_file(&executable)? != request.artifact_digest
        || digest_file(&release.join("package.tsplug"))? != request.package_digest
    {
        return Err("identity");
    }
    Ok(ValidatedRequest {
        request,
        executable,
        release,
        work,
        input,
    })
}

fn canonical_file(path: &Path) -> Result<PathBuf, &'static str> {
    let canonical = std::fs::canonicalize(path).map_err(|_| "path")?;
    if !canonical.is_absolute() || !canonical.is_file() {
        return Err("path");
    }
    Ok(canonical)
}

fn canonical_directory(path: &Path) -> Result<PathBuf, &'static str> {
    let canonical = std::fs::canonicalize(path).map_err(|_| "path")?;
    if !canonical.is_absolute() || !canonical.is_dir() {
        return Err("path");
    }
    Ok(canonical)
}

fn digest_file(path: &Path) -> Result<String, &'static str> {
    let mut file = File::open(path).map_err(|_| "identity")?;
    let metadata = file.metadata().map_err(|_| "identity")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAXIMUM_IDENTITY_FILE_BYTES {
        return Err("identity");
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 << 10];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer).map_err(|_| "identity")?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .filter(|value| *value <= MAXIMUM_IDENTITY_FILE_BYTES)
            .ok_or("identity")?;
        digest.update(&buffer[..read]);
    }
    if total != metadata.len() {
        return Err("identity");
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn valid_attempt_id(value: &str) -> bool {
    value.len() == 37
        && value.starts_with("tsa1_")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_plugin_id(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.split('.').count() >= 3
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !part.starts_with('-')
                && !part.ends_with('-')
        })
}

fn valid_release_id(value: &str) -> bool {
    value.len() == 69
        && value.starts_with("tsr1_")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn runtime_engine() -> tsp_workbench::CertificationFuzzEngine {
    tsp_workbench::CertificationFuzzEngine {
        id: "com.tokensaver.plugin-runtime".into(),
        version: "1.0.0".into(),
        // The native configuration type requires a stable non-empty instrumentation
        // identity. Product responses never claim sanitizer coverage from this field.
        active_sanitizers: vec!["undefined".into()],
    }
}

fn duration(request: &ValidatedRequest) -> Duration {
    Duration::from_millis(request.request.deadline_milliseconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn exact_request_validation_rehashes_package_and_executable() {
        let fixture = Fixture::new();
        let validated = validate(fixture.request()).expect("valid request");
        assert_eq!(validated.input, b"framed input");
        assert_eq!(
            validated.executable,
            std::fs::canonicalize(&fixture.executable).expect("canonical executable")
        );
        assert_eq!(
            validated.release,
            std::fs::canonicalize(&fixture.release).expect("canonical release")
        );
        assert_eq!(
            validated.work,
            std::fs::canonicalize(&fixture.work).expect("canonical work")
        );

        std::fs::write(&fixture.executable, b"changed").expect("mutate executable");
        assert!(matches!(validate(fixture.request()), Err("identity")));
    }

    #[test]
    fn request_limits_identifiers_paths_and_base64_fail_closed() {
        type Mutation = fn(&Fixture, &mut Request);
        let mutations: [(&str, Mutation); 19] = [
            ("schema", |_, value| value.schema_version = 2),
            ("operation", |_, value| value.operation = "fallback".into()),
            ("attempt", |_, value| value.attempt_id = "bad".into()),
            ("plugin", |_, value| value.plugin_id = "Bad Plugin".into()),
            ("release", |_, value| value.release_id = "bad".into()),
            ("platform", |_, value| value.platform = "other".into()),
            ("package digest", |_, value| {
                value.package_digest = "bad".into()
            }),
            ("artifact digest", |_, value| {
                value.artifact_digest = "bad".into()
            }),
            ("deadline zero", |_, value| value.deadline_milliseconds = 0),
            ("deadline high", |_, value| {
                value.deadline_milliseconds = 1_251
            }),
            ("memory high", |_, value| {
                value.maximum_memory_bytes = (256 << 20) + 1
            }),
            ("stdout high", |_, value| {
                value.maximum_stdout_bytes = (24 << 20) + 1
            }),
            ("stderr high", |_, value| {
                value.maximum_stderr_bytes = (64 << 10) + 1
            }),
            ("arguments count", |_, value| {
                value.arguments = vec![String::new(); 33]
            }),
            ("argument NUL", |_, value| {
                value.arguments = vec!["a\0b".into()]
            }),
            ("base64", |_, value| value.input = "***".into()),
            ("empty input", |_, value| value.input.clear()),
            ("executable escape", |fixture, value| {
                value.executable_path = fixture.work.to_string_lossy().into_owned()
            }),
            ("work overlap", |fixture, value| {
                value.work_path = fixture.release.to_string_lossy().into_owned()
            }),
        ];
        for (name, mutate) in mutations {
            let fixture = Fixture::new();
            let mut request = fixture.request();
            mutate(&fixture, &mut request);
            assert!(validate(request).is_err(), "{name} accepted");
        }
    }

    #[test]
    fn serde_contract_rejects_duplicate_unknown_and_trailing_members() {
        for data in [
            br#"{"schemaVersion":1,"schemaVersion":1}"#.as_slice(),
            br#"{"unknown":1}"#,
            br#"{}{}"#,
        ] {
            assert!(serde_json::from_slice::<Request>(data).is_err());
        }
    }

    #[test]
    fn identifier_and_digest_grammars_are_exact() {
        assert!(valid_attempt_id(&format!("tsa1_{}", "a".repeat(32))));
        assert!(!valid_attempt_id(&format!("tsa1_{}", "A".repeat(32))));
        assert!(valid_plugin_id("com.example.plugin-2"));
        assert!(!valid_plugin_id("com.example"));
        assert!(!valid_plugin_id("com..plugin"));
        assert!(valid_release_id(&format!("tsr1_{}", "b".repeat(64))));
        assert!(valid_digest(&format!("sha256:{}", "c".repeat(64))));
        assert!(!valid_digest(&format!("sha256:{}", "C".repeat(64))));
    }

    #[test]
    fn manifest_boundaries_match_the_public_v1_contract() {
        let fixture = Fixture::new();

        let mut request = fixture.request();
        request.arguments = vec![String::new(); MAXIMUM_ARGUMENTS];
        assert!(validate(request).is_ok(), "32 arguments must remain valid");

        let mut request = fixture.request();
        request.arguments = vec![String::new(); MAXIMUM_ARGUMENTS + 1];
        assert!(matches!(validate(request), Err("request_invalid")));

        let mut request = fixture.request();
        request.arguments = vec!["é".repeat(MAXIMUM_ARGUMENT_BYTES / 2)];
        assert!(
            validate(request).is_ok(),
            "4096 UTF-8 bytes must remain valid"
        );

        let mut request = fixture.request();
        request.arguments = vec![format!("{}a", "é".repeat(MAXIMUM_ARGUMENT_BYTES / 2))];
        assert!(matches!(validate(request), Err("request_invalid")));

        assert!(valid_plugin_id(&format!("com.example.{}", "a".repeat(63))));
        assert!(!valid_plugin_id(&format!("com.example.{}", "a".repeat(64))));
    }

    struct Fixture {
        root: PathBuf,
        release: PathBuf,
        executable: PathBuf,
        work: PathBuf,
        package_digest: String,
        artifact_digest: String,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "tokensaver-runtime-host-test-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos(),
                NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed),
            ));
            let release = root.join("release");
            let work = root.join("work");
            std::fs::create_dir_all(&release).expect("release");
            std::fs::create_dir(&work).expect("work");
            let executable = release.join(if cfg!(windows) {
                "plugin.exe"
            } else {
                "plugin"
            });
            std::fs::write(&executable, b"exact executable").expect("executable");
            std::fs::write(release.join("package.tsplug"), b"exact package").expect("package");
            let package_digest =
                digest_file(&release.join("package.tsplug")).expect("package digest");
            let artifact_digest = digest_file(&executable).expect("artifact digest");
            Self {
                root,
                release,
                executable,
                work,
                package_digest,
                artifact_digest,
            }
        }

        fn request(&self) -> Request {
            Request {
                schema_version: SCHEMA_VERSION,
                operation: "execute".into(),
                attempt_id: format!("tsa1_{}", "a".repeat(32)),
                plugin_id: "com.example.plugin".into(),
                release_id: format!("tsr1_{}", "b".repeat(64)),
                platform: platform::platform_key().into(),
                package_digest: self.package_digest.clone(),
                artifact_digest: self.artifact_digest.clone(),
                executable_path: self.executable.to_string_lossy().into_owned(),
                release_path: self.release.to_string_lossy().into_owned(),
                work_path: self.work.to_string_lossy().into_owned(),
                arguments: vec!["--tspp".into(), "two words".into(), String::new()],
                input: base64::engine::general_purpose::STANDARD.encode(b"framed input"),
                deadline_milliseconds: 500,
                maximum_memory_bytes: 128 << 20,
                maximum_stdout_bytes: 4096,
                maximum_stderr_bytes: 1024,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}
