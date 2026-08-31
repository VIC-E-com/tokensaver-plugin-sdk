use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tsp_workbench::{
    OptimizeAction, OptimizeRequest, bench_plugin, load_and_resolve, package_plugin, platform_key,
    run_fixture, test_plugin, validate_plugin,
};

struct TestDirectory(PathBuf);

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn caveman_plugin_passes_real_process_fixture_and_package_contracts() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = TestDirectory(std::env::temp_dir().join(format!(
        "tokensaver-caveman-plugin-{}-{unique}",
        std::process::id()
    )));
    fs::create_dir_all(directory.0.join("wiki")).expect("create plugin test directory");

    let mut manifest: Value =
        serde_json::from_str(include_str!("../plugin.json")).expect("parse manifest");
    manifest["runtime"]["entry"][platform_key()] =
        Value::String(env!("CARGO_BIN_EXE_tokensaver-caveman-plugin").to_owned());
    fs::write(
        directory.0.join("plugin.json"),
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");
    fs::write(
        directory.0.join("plugin.superec"),
        include_bytes!("../plugin.superec"),
    )
    .expect("write SUPEREC");
    fs::write(
        directory.0.join("wiki/index.md"),
        include_bytes!("../wiki/index.md"),
    )
    .expect("write OKF root");
    fs::write(
        directory.0.join("wiki/plugin.md"),
        include_bytes!("../wiki/plugin.md"),
    )
    .expect("write OKF page");

    let plugin = load_and_resolve(&directory.0).expect("resolve real executable");
    let validation = validate_plugin(&plugin).expect("validate real process");
    assert!(validation.ok);
    assert_eq!(validation.plugin_id, "com.vic-e.tokensaver.caveman");
    assert_eq!(validation.certification_level.as_u8(), 1);

    let fixture_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let tests = test_plugin(&plugin, &fixture_directory).expect("run exact golden fixtures");
    assert!(tests.ok, "{tests:#?}");
    assert_eq!(tests.failed, 0);
    assert_eq!(tests.passed, 6);

    let benchmark =
        bench_plugin(&plugin, &fixture_directory, 10).expect("benchmark deterministic fixtures");
    assert!(benchmark.ok, "{benchmark:#?}");
    assert_eq!(benchmark.totals.samples, 60);
    assert!(benchmark.totals.savings_percent >= 20.0);

    let compacted = include_str!("../fixtures/already-compacted.input.txt");
    let pass = run_fixture(
        &plugin,
        OptimizeRequest {
            kind: "log".into(),
            program: "caveman".into(),
            exit_code: 0,
            content: compacted.as_bytes().to_vec(),
        },
    )
    .expect("run pass-through fixture");
    assert_eq!(pass.action, OptimizeAction::Pass);

    let first_path = directory.0.join("caveman-first.tsplug");
    let second_path = directory.0.join("caveman-second.tsplug");
    let first = package_plugin(&plugin, &first_path).expect("package plugin first time");
    let second = package_plugin(&plugin, &second_path).expect("package plugin second time");
    assert!(first.ok && second.ok);
    assert!(first.reproducible && second.reproducible);
    assert_eq!(first.plugin_id, "com.vic-e.tokensaver.caveman");
    assert_eq!(
        fs::read(&first_path).expect("read first package"),
        fs::read(&second_path).expect("read second package")
    );
    assert!(
        fs::read(first_path)
            .expect("read package header")
            .starts_with(b"PK\x03\x04")
    );
}
