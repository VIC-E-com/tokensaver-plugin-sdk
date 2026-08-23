#![cfg(target_os = "windows")]

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::net::TcpListener;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use tokensaver_certification_confinement::{
    NativeConfinementDriver, NativeConfinementRequest, NativeTermination,
};
use tokensaver_certification_confinement_windows::{
    Win32Kernel, WindowsAppContainerJobDriver, WindowsConfinementConfig, WindowsConfinementKernel,
    WindowsCoverageReader, WindowsKernelExecution,
};
use tokensaver_certification_worker::CertificationFuzzExecution;
use tsp_workbench::{
    CertificationFuzzCaseClass, CertificationFuzzEngine, CertificationFuzzExecutionLimits,
    CertificationSubject,
};
use windows_sys::Win32::Foundation::{LocalFree, S_OK};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{FreeSid, PSID};

struct Coverage;

impl WindowsCoverageReader for Coverage {
    type Error = ();

    fn coverage_basis_points(&self) -> Result<u32, Self::Error> {
        Ok(9000)
    }
}

struct AppContainerProfile {
    name: String,
    sid: String,
}

impl AppContainerProfile {
    fn create() -> Self {
        let name = format!(
            "com.tokensaver.certification.test.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let wide_name = wide(&name);
        let display = wide("TokenSaver confinement test");
        let description = wide("Ephemeral capability-free AppContainer test profile");
        let mut sid: PSID = std::ptr::null_mut();
        // SAFETY: all wide strings are NUL terminated and sid is a valid output pointer.
        let result = unsafe {
            CreateAppContainerProfile(
                wide_name.as_ptr(),
                display.as_ptr(),
                description.as_ptr(),
                std::ptr::null(),
                0,
                &mut sid,
            )
        };
        assert_eq!(
            result, S_OK,
            "CreateAppContainerProfile failed: {result:#x}"
        );
        assert!(!sid.is_null(), "AppContainer SID was not returned");
        let sid_string = sid_string(sid);
        // SAFETY: CreateAppContainerProfile returned this SID allocation.
        unsafe {
            FreeSid(sid);
        }
        Self {
            name,
            sid: sid_string,
        }
    }
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        let name = wide(&self.name);
        // SAFETY: name is a live NUL-terminated UTF-16 string.
        let result = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
        assert_eq!(
            result, S_OK,
            "DeleteAppContainerProfile failed: {result:#x}"
        );
    }
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn create() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tokensaver-windows-confinement-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir(&path).expect("test root");
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        for _ in 0..40 {
            if std::fs::remove_dir_all(&self.0).is_ok() || !self.0.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!("failed to remove native Windows test root");
    }
}

#[test]
#[ignore = "creates an ephemeral native AppContainer profile"]
fn real_appcontainer_job_enforces_identity_io_network_process_memory_deadline_and_reap() {
    let profile = AppContainerProfile::create();
    let root = TestRoot::create();
    let binaries = root.0.join("bin");
    let work = root.0.join("work");
    let denied = TestRoot::create();
    std::fs::create_dir(&binaries).expect("binary directory");
    std::fs::create_dir(&work).expect("work directory");
    let executable = binaries.join("fixture.exe");
    std::fs::copy(
        env!("CARGO_BIN_EXE_tsp-windows-confinement-fixture"),
        &executable,
    )
    .expect("copy fixture");
    let denied_file = denied.0.join("secret.txt");
    std::fs::write(&denied_file, b"must remain unreadable").expect("secret fixture");
    grant(&root.0, &profile.sid, "RX");
    grant(&binaries, &profile.sid, "(OI)(CI)RX");
    grant(&work, &profile.sid, "(OI)(CI)M");

    let system_root = std::env::var("SYSTEMROOT").expect("SYSTEMROOT");
    let system_drive = std::env::var("SYSTEMDRIVE").expect("SYSTEMDRIVE");
    let config = WindowsConfinementConfig::new(
        &executable,
        &work,
        &profile.name,
        BTreeMap::from([
            ("LOCALAPPDATA".into(), work.to_string_lossy().into_owned()),
            ("SYSTEMDRIVE".into(), system_drive),
            ("SYSTEMROOT".into(), system_root),
            ("TEMP".into(), work.to_string_lossy().into_owned()),
            ("TMP".into(), work.to_string_lossy().into_owned()),
        ]),
        CertificationFuzzEngine {
            id: "native.windows.integration".into(),
            version: "1.0.0".into(),
            active_sanitizers: vec!["address".into()],
        },
    )
    .expect("configuration");
    let driver = WindowsAppContainerJobDriver::new(config, Win32Kernel, Coverage);
    driver.profile().expect("native preflight");

    let probe = Win32Kernel
        .execute(WindowsKernelExecution {
            executable_path: driver.config().executable_path(),
            working_directory: driver.config().working_directory(),
            app_container_name: driver.config().app_container_name(),
            environment: driver.config().environment(),
            arguments: &[],
            input: b"native launch probe",
            maximum_memory_bytes: 64 << 20,
            maximum_stdout_bytes: 4096,
            maximum_stderr_bytes: 4096,
            deadline: std::time::Duration::from_secs(2),
        })
        .unwrap_or_else(|error| panic!("native kernel stage failed: {:?}", error.stage()));
    assert_eq!(probe.termination, NativeTermination::Exited(0));
    assert_eq!(probe.stdout, b"native launch probe");
    assert!(probe.stderr.is_empty());
    assert!(probe.process_reaped);

    let arguments = vec![
        "plain".to_string(),
        "two words".to_string(),
        "quote\"and\\trailing\\".to_string(),
        String::new(),
    ];
    let argument_probe = Win32Kernel
        .execute(WindowsKernelExecution {
            executable_path: driver.config().executable_path(),
            working_directory: driver.config().working_directory(),
            app_container_name: driver.config().app_container_name(),
            environment: driver.config().environment(),
            arguments: &arguments,
            input: b"TS_ARGS",
            maximum_memory_bytes: 64 << 20,
            maximum_stdout_bytes: 4096,
            maximum_stderr_bytes: 4096,
            deadline: std::time::Duration::from_secs(2),
        })
        .unwrap_or_else(|error| panic!("native argument probe: {:?}", error.stage()));
    assert_eq!(argument_probe.termination, NativeTermination::Exited(0));
    assert_eq!(argument_probe.stdout, arguments.join("\n").as_bytes());
    assert!(argument_probe.stderr.is_empty());
    assert!(argument_probe.process_reaped);

    for (ordinal, input, expected) in [
        (1, b"exact input".to_vec(), b"exact input".to_vec()),
        (2, b"TS_WORK".to_vec(), b"ok".to_vec()),
        (
            3,
            format!("TS_FS|{}", denied_file.display()).into_bytes(),
            b"ok".to_vec(),
        ),
        (4, b"TS_PROCESS".to_vec(), b"ok".to_vec()),
        (5, b"TS_THREAD".to_vec(), b"ok".to_vec()),
        (6, b"TS_ENV".to_vec(), b"ok".to_vec()),
    ] {
        let observed = execute(&driver, &executable, ordinal, &input, 4096, 2_000);
        assert_eq!(observed.termination, NativeTermination::Exited(0));
        assert_eq!(observed.stdout, expected);
        assert!(observed.stderr.is_empty());
        assert!(observed.process_reaped);
    }
    assert_eq!(
        std::fs::read(work.join("fixture-evidence")).expect("evidence"),
        b"evidence"
    );

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let network_input = format!(
        "TS_NETWORK|{}",
        listener.local_addr().expect("address").port()
    );
    let network = execute(
        &driver,
        &executable,
        7,
        network_input.as_bytes(),
        4096,
        2_000,
    );
    assert_eq!(network.termination, NativeTermination::Exited(0));
    assert_eq!(network.stdout, b"ok");
    assert!(
        listener.accept().is_err(),
        "AppContainer reached loopback listener"
    );

    let overflow = execute(&driver, &executable, 8, b"TS_OVERFLOW", 1024, 2_000);
    assert!(overflow.stdout_limit_exceeded);
    assert_eq!(overflow.stdout.len(), 1024);
    assert!(overflow.process_reaped);

    let stderr = execute(&driver, &executable, 9, b"TS_STDERR", 1024, 2_000);
    assert!(stderr.stderr_limit_exceeded);
    assert_eq!(stderr.stderr.len(), 4096);
    assert!(stderr.process_reaped);

    let deadline = execute(&driver, &executable, 10, b"TS_HANG", 1024, 100);
    assert_eq!(deadline.termination, NativeTermination::DeadlineKilled);
    assert!(deadline.process_reaped);

    let crash = execute(&driver, &executable, 11, b"TS_CRASH", 1024, 2_000);
    assert!(matches!(
        crash.termination,
        NativeTermination::Exited(_)
            | NativeTermination::Signaled(_)
            | NativeTermination::Exception(_)
    ));
    assert!(crash.process_reaped);

    let memory = execute(&driver, &executable, 12, b"TS_MEMORY", 1024, 5_000);
    assert_eq!(memory.termination, NativeTermination::MemoryLimitKilled);
    assert!(memory.peak_memory_bytes <= 64 << 20);
    assert!(memory.process_reaped);

    std::thread::scope(|scope| {
        let handles = (0usize..8)
            .map(|worker| {
                let driver = &driver;
                let executable = &executable;
                scope.spawn(move || {
                    let input = format!("concurrent-{worker}").into_bytes();
                    let observed = execute(driver, executable, 100 + worker, &input, 4096, 2_000);
                    assert_eq!(observed.termination, NativeTermination::Exited(0));
                    assert_eq!(observed.stdout, input);
                    assert!(observed.process_reaped);
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().expect("concurrent execution");
        }
    });
}

fn execute(
    driver: &WindowsAppContainerJobDriver<Win32Kernel, Coverage>,
    executable: &Path,
    ordinal: usize,
    input: &[u8],
    stdout_limit: u64,
    deadline: u64,
) -> tokensaver_certification_confinement::NativeConfinementObservation {
    let artifact_digest = format!(
        "sha256:{:x}",
        Sha256::digest(std::fs::read(executable).expect("read fixture"))
    );
    let subject = CertificationSubject {
        plugin_id: "com.tokensaver.windows-native-fixture".into(),
        version: "1.0.0".into(),
        platform: "windows-x64".into(),
        api_version: 1,
        artifact_digest,
        package_digest: format!("sha256:{:x}", Sha256::digest(b"package")),
        release_id: "tsr1_native_windows_fixture".into(),
    };
    let limits = CertificationFuzzExecutionLimits {
        maximum_execution_milliseconds: deadline,
        maximum_memory_bytes: 64 << 20,
        maximum_stdout_bytes: stdout_limit,
        maximum_stderr_bytes: 4096,
        required_sanitizers: vec!["address".into()],
    };
    driver
        .execute(NativeConfinementRequest {
            attempt_id: format!("tsfa1_{ordinal:064x}"),
            execution: CertificationFuzzExecution {
                ordinal: u64::try_from(ordinal).expect("ordinal"),
                repetition: 0,
                case_id: "native-windows",
                class: CertificationFuzzCaseClass::Valid,
                input,
                subject: &subject,
                limits: &limits,
                execution_deadline_milliseconds: deadline,
                remaining_campaign_milliseconds: deadline + 1_000,
            },
        })
        .expect("native execution")
}

fn grant(path: &Path, sid: &str, rights: &str) {
    let trustee = format!("*{sid}:{rights}");
    let output = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/grant", &trustee])
        .output()
        .expect("icacls");
    assert!(
        output.status.success(),
        "icacls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn sid_string(sid: PSID) -> String {
    let mut value = std::ptr::null_mut();
    // SAFETY: sid is valid and value is a valid output pointer.
    assert_ne!(unsafe { ConvertSidToStringSidW(sid, &mut value) }, 0);
    assert!(!value.is_null());
    let mut length = 0usize;
    // SAFETY: ConvertSidToStringSidW returned a NUL-terminated allocation.
    unsafe {
        while *value.add(length) != 0 {
            length += 1;
        }
    }
    // SAFETY: the allocation contains length initialized UTF-16 code units.
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
        .expect("SID string");
    // SAFETY: ConvertSidToStringSidW allocated value with LocalAlloc.
    assert!(unsafe { LocalFree(value.cast::<c_void>()) }.is_null());
    result
}

fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
