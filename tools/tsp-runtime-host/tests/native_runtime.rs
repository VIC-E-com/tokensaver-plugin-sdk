#![cfg(any(windows, target_os = "linux", target_os = "macos"))]

use base64::Engine as _;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[test]
#[ignore = "requires native AppContainer or delegated Linux cgroup provisioning"]
fn shipped_host_rehashes_identity_and_preserves_io_and_arguments_inside_native_confinement() {
    let plugin_id = format!("com.tokensaver.runtime-integration-{}", std::process::id());
    let _profile = ProfileCleanup::new(&plugin_id);
    let root = unique_temp();
    let release = root.join("release");
    let work = root.join("work");
    std::fs::create_dir_all(&release).expect("release");
    std::fs::create_dir(&work).expect("work");
    make_private(&root);
    make_private(&release);
    make_private(&work);
    let executable = release.join(if cfg!(windows) {
        "plugin.exe"
    } else {
        "plugin"
    });
    std::fs::copy(
        env!("CARGO_BIN_EXE_tokensaver-runtime-echo-fixture"),
        &executable,
    )
    .expect("fixture copy");
    make_executable(&executable);
    let package = release.join("package.tsplug");
    std::fs::write(&package, b"exact package identity").expect("package");
    let platform = if cfg!(windows) {
        if cfg!(target_arch = "x86_64") {
            "windows-x64"
        } else {
            "windows-arm64"
        }
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "linux-x64"
    } else if cfg!(target_os = "linux") {
        "linux-arm64"
    } else if cfg!(target_arch = "x86_64") {
        "darwin-x64"
    } else {
        "darwin-arm64"
    };
    let arguments = [
        "plain".to_owned(),
        "two words".to_owned(),
        "quote\"and\\trailing\\".to_owned(),
        String::new(),
    ];
    let request = json!({
        "schemaVersion": 1,
        "operation": "execute",
        "attemptId": format!("tsa1_{}", "a".repeat(32)),
        "pluginId": plugin_id,
        "releaseId": format!("tsr1_{}", "b".repeat(64)),
        "platform": platform,
        "packageDigest": digest(&package),
        "artifactDigest": digest(&executable),
        "executablePath": executable,
        "releasePath": release,
        "workPath": work,
        "arguments": arguments,
        "input": base64::engine::general_purpose::STANDARD.encode(b"TS_ARGS"),
        "deadlineMilliseconds": 1_250,
        "maximumMemoryBytes": 256 << 20,
        "maximumStdoutBytes": 4096,
        "maximumStderrBytes": 4096
    });
    let output = invoke(&request);
    assert!(
        output.status.success(),
        "host failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("response JSON");
    assert_eq!(response["schemaVersion"], 1);
    assert_eq!(
        response["ok"],
        true,
        "runtime response: {response}; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(response["observation"]["platform"], platform);
    assert_eq!(response["observation"]["processReaped"], true);
    assert_eq!(response["observation"]["exitCode"], 0);
    let stdout = base64::engine::general_purpose::STANDARD
        .decode(response["observation"]["stdout"].as_str().expect("stdout"))
        .expect("stdout base64");
    assert_eq!(stdout, format!("1\n{}", arguments.join("\n")).as_bytes());

    let mut cleanup_request = request.clone();
    cleanup_request["operation"] = json!("deprovision");
    cleanup_request["attemptId"] = json!(format!("tsa1_{}", "c".repeat(32)));
    for _ in 0..2 {
        let cleanup = invoke(&cleanup_request);
        assert!(cleanup.status.success());
        let cleanup_response: serde_json::Value =
            serde_json::from_slice(&cleanup.stdout).expect("cleanup response");
        assert_eq!(cleanup_response["ok"], true, "{cleanup_response}");
        assert!(cleanup_response.get("observation").is_none());
    }
    std::fs::remove_dir_all(root).expect("cleanup");
}

fn invoke(request: &serde_json::Value) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tokensaver-plugin-runtime-host"));
    #[cfg(target_os = "macos")]
    command.env(
        "TOKENSAVER_PLUGIN_LIMIT_LAUNCHER",
        std::env::var_os("TOKENSAVER_PLUGIN_TEST_LIMIT_LAUNCHER")
            .expect("TOKENSAVER_PLUGIN_TEST_LIMIT_LAUNCHER"),
    );
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("runtime host");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&serde_json::to_vec(request).expect("request JSON"))
        .expect("request write");
    child.wait_with_output().expect("runtime host output")
}

fn digest(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("digest input");
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn unique_temp() -> PathBuf {
    std::env::temp_dir().join(format!(
        "tokensaver-runtime-native-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ))
}

#[cfg(unix)]
fn make_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("private mode");
}

#[cfg(windows)]
fn make_private(_: &Path) {}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500))
        .expect("executable mode");
}

#[cfg(windows)]
fn make_executable(_: &Path) {}

#[cfg(windows)]
struct ProfileCleanup {
    name: String,
}

#[cfg(windows)]
impl ProfileCleanup {
    fn new(plugin_id: &str) -> Self {
        let digest = format!("{:x}", Sha256::digest(plugin_id.as_bytes()));
        Self {
            name: format!("com.tokensaver.plugin.{}", &digest[..32]),
        }
    }
}

#[cfg(windows)]
impl Drop for ProfileCleanup {
    fn drop(&mut self) {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;
        let wide = std::ffi::OsStr::new(&self.name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: wide is a live NUL-terminated UTF-16 string.
        unsafe { DeleteAppContainerProfile(wide.as_ptr()) };
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct ProfileCleanup;

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ProfileCleanup {
    fn new(_: &str) -> Self {
        Self
    }
}
