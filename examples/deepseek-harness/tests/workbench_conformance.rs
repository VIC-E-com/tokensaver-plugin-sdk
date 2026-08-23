use serde_json::Value;
use std::fs;
use std::path::PathBuf;
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
fn deepseek_harness_plugin_passes_real_process_and_package_contracts() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = TestDirectory(std::env::temp_dir().join(format!(
        "tokensaver-deepseek-harness-plugin-{}-{unique}",
        std::process::id()
    )));
    fs::create_dir_all(directory.0.join("wiki")).expect("create plugin test directory");

    let mut manifest: Value =
        serde_json::from_str(include_str!("../plugin.json")).expect("parse manifest");
    manifest["runtime"]["entry"][platform_key()] =
        Value::String(env!("CARGO_BIN_EXE_tokensaver-deepseek-harness-plugin").to_owned());
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
    assert_eq!(
        validation.plugin_id,
        "com.vic-e.tokensaver.deepseek-harness"
    );
    assert_eq!(validation.certification_level.as_u8(), 1);

    let input = (0..140)
        .map(|index| match index {
            90 => "warning: optional provider unavailable".to_owned(),
            115 => "Test Files  40 passed (40)".to_owned(),
            116 => "Tests  800 passed (800)".to_owned(),
            117 => "Duration  11.2s".to_owned(),
            _ => format!("@deepseek-ai/dsh-package routine task output {index}"),
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let request = OptimizeRequest {
        kind: "test".into(),
        program: "pnpm.cmd".into(),
        exit_code: 0,
        content: input.into_bytes(),
    };
    let run = run_fixture(&plugin, request.clone()).expect("run real plugin process");
    assert_eq!(run.action, OptimizeAction::Optimize);
    assert!(
        run.output
            .contains("warning: optional provider unavailable")
    );
    assert!(run.output.contains("Test Files  40 passed (40)"));
    assert!(
        run.output
            .contains("routine DeepSeek Harness lines omitted")
    );
    assert!(run.savings_percent >= 20.0);

    let fixtures = directory.0.join("fixtures");
    fs::create_dir(&fixtures).expect("create fixtures");
    fs::write(fixtures.join("workspace.input.txt"), &request.content).expect("write input");
    fs::write(fixtures.join("workspace.golden.txt"), &run.output).expect("write golden");
    fs::write(
        fixtures.join("workspace.case.json"),
        br#"{"schemaVersion":1,"name":"DeepSeek Harness workspace output","kind":"test","program":"pnpm","exitCode":0,"input":"workspace.input.txt","expectedAction":"optimize","expectedOutput":"workspace.golden.txt"}"#,
    )
    .expect("write fixture descriptor");

    let tests = test_plugin(&plugin, &fixtures).expect("run exact golden fixture");
    assert!(tests.ok);
    assert_eq!(tests.passed, 1);
    let benchmark = bench_plugin(&plugin, &fixtures, 2).expect("benchmark deterministic fixture");
    assert!(benchmark.ok);
    assert_eq!(benchmark.totals.samples, 2);
    assert!(benchmark.totals.savings_percent >= 20.0);

    let package_path = directory.0.join("deepseek-harness.tsplug");
    let package = package_plugin(&plugin, &package_path).expect("package plugin");
    assert!(package.ok);
    assert!(package.reproducible);
    assert_eq!(package.plugin_id, "com.vic-e.tokensaver.deepseek-harness");
    assert!(
        fs::read(package_path)
            .expect("read package")
            .starts_with(b"PK\x03\x04")
    );
}
