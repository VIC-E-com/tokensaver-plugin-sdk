#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokensaver_certification_confinement::NativeTermination;
use tokensaver_certification_confinement_macos::{
    MacosConfinementConfig, MacosConfinementKernel, MacosKernel, MacosKernelExecution,
    MacosKernelObservation,
};
use tsp_workbench::CertificationFuzzEngine;

#[test]
#[ignore = "requires native macOS sandbox-exec enforcement"]
fn real_kernel_enforces_io_deadline_filesystem_network_process_and_thread_controls() {
    let root = unique_temp("root");
    let work = root.join("work");
    std::fs::create_dir(&root).expect("root");
    std::fs::create_dir(&work).expect("work");
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700)).expect("work mode");
    let executable = copy_executable(
        env!("CARGO_BIN_EXE_tsp-macos-confinement-fixture"),
        &root.join("fixture"),
    );
    let launcher = copy_executable(
        env!("CARGO_BIN_EXE_tsp-macos-confinement-launcher"),
        &root.join("launcher"),
    );
    let config = MacosConfinementConfig::new(
        &executable,
        &launcher,
        &work,
        BTreeMap::from([
            ("HOME".into(), "/nonexistent".into()),
            ("LC_ALL".into(), "C".into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("TMPDIR".into(), work.to_string_lossy().into_owned()),
        ]),
        CertificationFuzzEngine {
            id: "native.integration".into(),
            version: "1.0.0".into(),
            active_sanitizers: vec!["address".into()],
        },
    )
    .expect("configuration");
    let kernel = MacosKernel;
    kernel.preflight(&config).expect("native preflight");

    for (ordinal, input) in [
        (1, b"macos exact input".as_slice()),
        (2, b"TS_FS".as_slice()),
        (3, b"TS_NETWORK".as_slice()),
        (4, b"TS_FORK".as_slice()),
        (5, b"TS_THREAD".as_slice()),
        (6, b"TS_WORK".as_slice()),
    ] {
        let observed = execute(&kernel, &config, ordinal, input, 4096, 2_000);
        assert_eq!(observed.termination, NativeTermination::Exited(0));
        assert_eq!(
            observed.stdout,
            if ordinal == 1 { input } else { b"ok" }.to_vec()
        );
        assert!(observed.stderr.is_empty());
        assert!(observed.process_reaped);
    }
    assert_eq!(
        std::fs::read(work.join("fixture-evidence")).expect("evidence"),
        b"evidence"
    );

    let arguments = [
        "plain".to_owned(),
        "two words".to_owned(),
        "quote\"and\\trailing\\".to_owned(),
        String::new(),
    ];
    let observed = execute_with_arguments(&kernel, &config, 7, b"TS_ARGS", 4096, 2_000, &arguments);
    assert_eq!(observed.termination, NativeTermination::Exited(0));
    assert_eq!(observed.stdout, arguments.join("\n").as_bytes());
    assert!(observed.stderr.is_empty());
    assert!(observed.process_reaped);

    let overflow = execute(&kernel, &config, 10, b"TS_OVERFLOW", 1024, 2_000);
    assert!(overflow.stdout_limit_exceeded);
    assert_eq!(overflow.stdout.len(), 1024);
    assert!(overflow.process_reaped);

    let stderr = execute(&kernel, &config, 11, b"TS_STDERR", 1024, 2_000);
    assert!(stderr.stderr_limit_exceeded);
    assert_eq!(stderr.stderr.len(), 4096);
    assert!(stderr.process_reaped);

    let deadline = execute(&kernel, &config, 12, b"TS_HANG", 1024, 100);
    assert_eq!(deadline.termination, NativeTermination::DeadlineKilled);
    assert!(deadline.duration_milliseconds < 2_000);
    assert!(deadline.process_reaped);

    let crash = execute(&kernel, &config, 13, b"TS_CRASH", 1024, 2_000);
    assert!(matches!(crash.termination, NativeTermination::Signaled(_)));
    assert!(crash.process_reaped);

    let memory = execute(&kernel, &config, 14, b"TS_MEMORY", 1024, 2_000);
    assert!(!matches!(memory.termination, NativeTermination::Exited(0)));
    assert!(memory.peak_memory_bytes <= 128 << 20);
    assert!(memory.process_reaped);

    std::thread::scope(|scope| {
        let handles = (0usize..8)
            .map(|worker| {
                let kernel = &kernel;
                let config = &config;
                scope.spawn(move || {
                    let input = format!("concurrent-{worker}").into_bytes();
                    let observed = execute(kernel, config, 100 + worker, &input, 4096, 2_000);
                    assert_eq!(observed.termination, NativeTermination::Exited(0));
                    assert_eq!(observed.stdout, input);
                    assert!(observed.stderr.is_empty());
                    assert!(observed.process_reaped);
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().expect("concurrent confinement execution");
        }
    });

    std::fs::remove_dir_all(root).expect("cleanup");
}

fn execute(
    kernel: &MacosKernel,
    config: &MacosConfinementConfig,
    ordinal: usize,
    input: &[u8],
    stdout: usize,
    deadline_ms: u64,
) -> MacosKernelObservation {
    execute_with_arguments(kernel, config, ordinal, input, stdout, deadline_ms, &[])
}

fn execute_with_arguments(
    kernel: &MacosKernel,
    config: &MacosConfinementConfig,
    ordinal: usize,
    input: &[u8],
    stdout: usize,
    deadline_ms: u64,
    arguments: &[String],
) -> MacosKernelObservation {
    let attempt_id = format!("tsfa1_{ordinal:064x}");
    kernel
        .execute(MacosKernelExecution {
            attempt_id: &attempt_id,
            executable: config.executable(),
            launcher: config.launcher(),
            writable_directory: config.writable_directory(),
            sandbox_profile: config.sandbox_profile(),
            environment: config.environment(),
            arguments,
            input,
            maximum_memory_bytes: 128 << 20,
            maximum_stdout_bytes: stdout,
            maximum_stderr_bytes: 4096,
            deadline: Duration::from_millis(deadline_ms),
        })
        .expect("native execution")
}

fn copy_executable(source: impl AsRef<Path>, destination: &Path) -> PathBuf {
    std::fs::copy(source, destination).expect("copy executable");
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o500))
        .expect("executable mode");
    destination.into()
}

fn unique_temp(kind: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "tokensaver-macos-integration-{}-{kind}",
        std::process::id()
    ))
}
