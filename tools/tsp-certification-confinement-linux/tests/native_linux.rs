#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use tokensaver_certification_confinement::NativeTermination;
use tokensaver_certification_confinement_linux::{
    LinuxConfinementConfig, LinuxConfinementKernel, LinuxKernel, LinuxKernelExecution,
};
use tsp_workbench::CertificationFuzzEngine;

#[test]
#[ignore = "requires a delegated modern-kernel cgroup v2 parent"]
fn real_kernel_enforces_io_deadline_filesystem_network_process_and_thread_controls() {
    let cgroup = PathBuf::from(
        std::env::var_os("TOKENSAVER_LINUX_TEST_CGROUP")
            .expect("TOKENSAVER_LINUX_TEST_CGROUP must name a delegated cgroup v2 parent"),
    );
    let root = unique_temp("root");
    let work = unique_temp("work");
    let executable_directory = unique_temp("executable");
    std::fs::create_dir(&root).expect("sandbox root");
    std::fs::create_dir(&work).expect("writable directory");
    std::fs::create_dir(&executable_directory).expect("executable directory");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("sandbox mode");
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700)).expect("writable mode");
    let executable = executable_directory.join("fixture");
    std::fs::copy(
        env!("CARGO_BIN_EXE_tsp-linux-confinement-fixture"),
        &executable,
    )
    .expect("copy fixture");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("fixture mode");
    let config = LinuxConfinementConfig::new(
        &executable,
        &root,
        &work,
        &cgroup,
        BTreeMap::from([
            ("HOME".into(), "/nonexistent".into()),
            ("TMPDIR".into(), "/work".into()),
        ]),
        CertificationFuzzEngine {
            id: "native.integration".into(),
            version: "1.0.0".into(),
            active_sanitizers: vec!["address".into()],
        },
    )
    .expect("configuration");
    let kernel = LinuxKernel;
    kernel.preflight(&config).expect("production preflight");

    for (index, input) in [
        b"exact input".as_slice(),
        b"TS_FS",
        b"TS_WORK",
        b"TS_NETWORK",
        b"TS_FORK",
        b"TS_THREAD",
    ]
    .into_iter()
    .enumerate()
    {
        let observed = execute(&kernel, &config, index, input, 4096, 2_000);
        assert_eq!(observed.termination, NativeTermination::Exited(0));
        assert_eq!(observed.stdout, if index == 0 { input } else { b"ok" });
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

    let stderr = execute(&kernel, &config, 13, b"TS_STDERR", 1024, 2_000);
    assert!(stderr.stderr_limit_exceeded);
    assert_eq!(stderr.stderr.len(), 4096);
    assert!(stderr.process_reaped);

    let deadline = execute(&kernel, &config, 11, b"TS_HANG", 1024, 100);
    assert_eq!(deadline.termination, NativeTermination::DeadlineKilled);
    assert!(deadline.duration_milliseconds < 5_000);
    assert!(deadline.process_reaped);

    let crash = execute(&kernel, &config, 12, b"TS_CRASH", 1024, 2_000);
    assert!(matches!(crash.termination, NativeTermination::Signaled(_)));
    assert!(crash.process_reaped);

    let memory = execute(&kernel, &config, 14, b"TS_MEMORY", 1024, 5_000);
    assert_eq!(memory.termination, NativeTermination::MemoryLimitKilled);
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
    assert_eq!(std::fs::read_dir(&root).expect("root entries").count(), 0);
    assert_eq!(
        std::fs::read_dir(&cgroup)
            .expect("cgroup entries")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .count(),
        0
    );

    std::fs::remove_dir_all(&root).expect("root cleanup");
    std::fs::remove_dir_all(&work).expect("work cleanup");
    std::fs::remove_dir_all(&executable_directory).expect("executable cleanup");
}

fn execute(
    kernel: &LinuxKernel,
    config: &LinuxConfinementConfig,
    ordinal: usize,
    input: &[u8],
    stdout: usize,
    deadline_ms: u64,
) -> tokensaver_certification_confinement_linux::LinuxKernelObservation {
    execute_with_arguments(kernel, config, ordinal, input, stdout, deadline_ms, &[])
}

fn execute_with_arguments(
    kernel: &LinuxKernel,
    config: &LinuxConfinementConfig,
    ordinal: usize,
    input: &[u8],
    stdout: usize,
    deadline_ms: u64,
    arguments: &[String],
) -> tokensaver_certification_confinement_linux::LinuxKernelObservation {
    let attempt_id = format!("tsfa1_{ordinal:064x}");
    kernel
        .execute(LinuxKernelExecution {
            attempt_id: &attempt_id,
            executable: config.executable(),
            sandbox_root: config.sandbox_root(),
            writable_directory: config.writable_directory(),
            cgroup_parent: config.cgroup_parent(),
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

fn unique_temp(kind: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "tokensaver-linux-integration-{}-{kind}",
        std::process::id()
    ))
}
