use serde_json::Value;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tsp_workbench::{
    OptimizeAction, OptimizeRequest, assemble_package_catalog, bench_plugin, load_and_resolve,
    package_plugin, platform_key, run_cli, run_fixture, test_plugin, validate_plugin,
};

struct TestDirectory(PathBuf);

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn packaged_ponytails_passes_real_process_conformance() {
    let superec: Value = serde_json::from_str(include_str!("../plugin.superec"))
        .expect("parse Ponytails SUPEREC graph");
    assert_eq!(superec["format"], "SUPEREC");
    assert_eq!(superec["specVersion"], "0.1.0");
    assert_eq!(
        superec["resources"][0]["identifiers"][0]["value"],
        "com.vic-e.tokensaver.ponytails"
    );
    assert!(include_str!("../wiki/index.md").contains("okf_version: \"0.2\""));

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = TestDirectory(std::env::temp_dir().join(format!(
        "tokensaver-tsp-ponytails-{}-{unique}",
        std::process::id()
    )));
    fs::create_dir_all(&directory.0).expect("create test plugin directory");

    let mut manifest: Value = serde_json::from_str(include_str!("../plugin.json"))
        .expect("parse checked-in Ponytails manifest");
    manifest["runtime"]["entry"][platform_key()] =
        Value::String(env!("CARGO_BIN_EXE_ponytails").to_string());
    let manifest_path = directory.0.join("plugin.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize test manifest"),
    )
    .expect("write test manifest");
    fs::write(
        directory.0.join("plugin.superec"),
        include_bytes!("../plugin.superec"),
    )
    .expect("write test SUPEREC graph");
    fs::create_dir(directory.0.join("wiki")).expect("create test OKF directory");
    fs::write(
        directory.0.join("wiki/index.md"),
        include_bytes!("../wiki/index.md"),
    )
    .expect("write test OKF index");

    let plugin = load_and_resolve(&manifest_path).expect("resolve packaged Ponytails");
    let report = validate_plugin(&plugin).expect("Ponytails Level 1 conformance");
    assert_eq!(report.schema_version, 1);
    assert!(report.ok);
    assert_eq!(report.certification_level.as_u8(), 1);
    assert_eq!(report.plugin_id, "com.vic-e.tokensaver.ponytails");
    assert_eq!(report.version, "0.1.1");
    assert_eq!(report.release_id, plugin.release_id);
    assert_eq!(report.artifact_digest, plugin.artifact_digest);
    assert_eq!(
        report
            .checks
            .iter()
            .filter(|check| check.activation_attempt_id.is_some())
            .count(),
        3
    );
    assert_eq!(
        report
            .checks
            .iter()
            .map(|check| check.name.as_str())
            .collect::<Vec<_>>(),
        [
            "manifest",
            "runtime",
            "superec",
            "lifecycle",
            "pre-initialize",
            "malformed-input"
        ]
    );

    assert_eq!(
        run_cli([
            OsString::from("tsp"),
            OsString::from("validate"),
            manifest_path.clone().into_os_string(),
            OsString::from("--json"),
        ]),
        0,
        "CLI validation should succeed for packaged Ponytails"
    );

    let input = (0..100)
        .map(|index| {
            if index == 52 {
                "ERROR failure".to_owned()
            } else {
                format!("line {index}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let expected = [
        (0..10)
            .map(|index| format!("line {index}"))
            .collect::<Vec<_>>(),
        vec!["... 37 lines omitted ...".into()],
        (47..57)
            .map(|index| {
                if index == 52 {
                    "ERROR failure".into()
                } else {
                    format!("line {index}")
                }
            })
            .collect::<Vec<_>>(),
        vec!["... 23 lines omitted ...".into()],
        (80..100)
            .map(|index| format!("line {index}"))
            .collect::<Vec<_>>(),
    ]
    .concat()
    .join("\n");
    let run = run_fixture(
        &plugin,
        OptimizeRequest {
            kind: "test".into(),
            program: r"C:\workspace\cargo.exe".into(),
            exit_code: 1,
            content: input.as_bytes().to_vec(),
        },
    )
    .expect("run Ponytails fixture");
    assert_eq!(run.schema_version, 1);
    assert_eq!(run.release_id, plugin.release_id);
    assert_eq!(run.artifact_digest, plugin.artifact_digest);
    assert!(tsp_workbench::valid_activation_attempt_id(
        &run.activation_attempt_id
    ));
    assert_eq!(run.action, OptimizeAction::Optimize);
    assert_eq!(run.output, expected);
    assert!(run.savings_percent >= 20.0);

    let fixtures = directory.0.join("fixtures");
    fs::create_dir(&fixtures).expect("create fixture directory");
    fs::write(fixtures.join("failure.input.txt"), &input).expect("write input fixture");
    fs::write(fixtures.join("failure.golden.txt"), &expected).expect("write golden fixture");
    fs::write(
        fixtures.join("failure.case.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schemaVersion": 1,
            "name": "failure context",
            "kind": "test",
            "program": "cargo",
            "exitCode": 1,
            "input": "failure.input.txt",
            "expectedAction": "optimize",
            "expectedOutput": "failure.golden.txt"
        }))
        .expect("serialize fixture descriptor"),
    )
    .expect("write fixture descriptor");
    let tests = test_plugin(&plugin, &fixtures).expect("run Ponytails golden tests");
    assert_eq!(tests.schema_version, 1);
    assert!(tests.ok);
    assert_eq!(tests.passed, 1);
    assert_eq!(tests.failed, 0);
    assert_eq!(tests.release_id, plugin.release_id);
    assert_eq!(tests.artifact_digest, plugin.artifact_digest);
    assert!(
        tests
            .cases
            .iter()
            .all(|case| tsp_workbench::valid_activation_attempt_id(&case.activation_attempt_id))
    );

    let benchmark = bench_plugin(&plugin, &fixtures, 2).expect("benchmark Ponytails");
    assert!(benchmark.ok);
    assert_eq!(benchmark.schema_version, 1);
    assert_eq!(benchmark.release_id, plugin.release_id);
    assert_eq!(benchmark.artifact_digest, plugin.artifact_digest);
    assert_eq!(benchmark.cases[0].activation_attempt_ids.len(), 2);
    assert!(
        benchmark.cases[0]
            .activation_attempt_ids
            .iter()
            .all(|id| tsp_workbench::valid_activation_attempt_id(id))
    );
    assert_eq!(benchmark.totals.samples, 2);
    assert_eq!(benchmark.totals.optimize_samples, 2);
    assert!(benchmark.totals.savings_percent >= 20.0);
    assert_eq!(
        run_cli([
            OsString::from("tsp"),
            OsString::from("bench"),
            manifest_path.clone().into_os_string(),
            OsString::from("--fixtures"),
            fixtures.clone().into_os_string(),
            OsString::from("--iterations"),
            OsString::from("2"),
            OsString::from("--json"),
        ]),
        0,
        "CLI benchmark should succeed for packaged Ponytails"
    );

    let package_path = directory.0.join("ponytails-library.tsplug");
    let package = package_plugin(&plugin, &package_path).expect("package Ponytails");
    assert!(package.ok);
    assert!(package.reproducible);
    assert_eq!(package.schema_version, 1);
    assert_eq!(package.certification_level.as_u8(), 1);
    assert_eq!(package.plugin_id, "com.vic-e.tokensaver.ponytails");
    assert_eq!(package.release_id, plugin.release_id);
    assert!(package.archive_digest.starts_with("sha256:"));
    assert!(
        package
            .files
            .iter()
            .any(|file| file.path == "plugin.superec")
    );
    assert!(
        package
            .files
            .iter()
            .any(|file| file.path == "wiki/index.md")
    );
    let package_bytes = fs::read(&package_path).expect("read package");
    assert!(package_bytes.starts_with(b"PK\x03\x04"));
    assert!(
        package_bytes
            .windows(b"\"integrity\"".len())
            .any(|window| window == b"\"integrity\"")
    );

    let cli_package_path = directory.0.join("ponytails-cli.tsplug");
    assert_eq!(
        run_cli([
            OsString::from("tsp"),
            OsString::from("package"),
            manifest_path.clone().into_os_string(),
            OsString::from("--output"),
            cli_package_path.clone().into_os_string(),
            OsString::from("--json"),
        ]),
        0,
        "CLI package should succeed for packaged Ponytails"
    );
    assert_eq!(
        package_bytes,
        fs::read(cli_package_path).expect("read CLI package"),
        "identical inputs must produce byte-identical packages"
    );

    let catalog_input = directory.0.join("catalog-input");
    fs::create_dir(&catalog_input).expect("create catalog input");
    let canonical_name = format!(
        "{}-{}-{}.tsplug",
        package.plugin_id, package.version, package.platform
    );
    let canonical_package = catalog_input.join(&canonical_name);
    fs::write(&canonical_package, &package_bytes).expect("write canonical package");
    let mut canonical_report = package.clone();
    canonical_report.archive = canonical_package.display().to_string();
    fs::write(
        catalog_input.join(format!("{canonical_name}.package-report.json")),
        serde_json::to_vec_pretty(&canonical_report).expect("serialize canonical report"),
    )
    .expect("write canonical report");
    let catalog_path = directory.0.join("ponytails-catalog.json");
    let catalog = assemble_package_catalog(&catalog_input, &catalog_path)
        .expect("assemble Ponytails package catalog");
    assert!(catalog.ok);
    assert_eq!(catalog.plugin_id, "com.vic-e.tokensaver.ponytails");
    assert_eq!(catalog.package_count, 1);
    assert_eq!(catalog.platforms, [platform_key()]);
    let catalog_bytes = fs::read(&catalog_path).expect("read package catalog");
    let catalog_document: Value =
        serde_json::from_slice(&catalog_bytes).expect("parse package catalog");
    assert_eq!(
        catalog_document["packages"][platform_key()]["digest"],
        package.archive_digest
    );

    let cli_catalog_path = directory.0.join("ponytails-cli-catalog.json");
    assert_eq!(
        run_cli([
            OsString::from("tsp"),
            OsString::from("catalog"),
            catalog_input.clone().into_os_string(),
            OsString::from("--output"),
            cli_catalog_path.clone().into_os_string(),
            OsString::from("--json"),
        ]),
        0,
        "CLI catalog assembly should succeed for packaged Ponytails"
    );
    assert_eq!(
        catalog_bytes,
        fs::read(cli_catalog_path).expect("read CLI catalog"),
        "identical package sets must produce byte-identical catalogs"
    );

    fs::write(&canonical_package, b"tampered package").expect("tamper canonical package");
    let tampered_catalog_path = directory.0.join("ponytails-tampered-catalog.json");
    let tamper_error = assemble_package_catalog(&catalog_input, &tampered_catalog_path)
        .expect_err("reject tampered Ponytails package");
    assert_eq!(tamper_error.code, "catalog.packageIntegrity");

    assert_eq!(
        run_cli([
            OsString::from("tsp"),
            OsString::from("run"),
            fixtures.join("failure.input.txt").into_os_string(),
            OsString::from("--plugin"),
            manifest_path.clone().into_os_string(),
            OsString::from("--kind"),
            OsString::from("test"),
            OsString::from("--exit-code"),
            OsString::from("1"),
            OsString::from("--json"),
        ]),
        0,
        "CLI run should succeed for packaged Ponytails"
    );
    assert_eq!(
        run_cli([
            OsString::from("tsp"),
            OsString::from("test"),
            manifest_path.into_os_string(),
            OsString::from("--fixtures"),
            fixtures.into_os_string(),
            OsString::from("--json"),
        ]),
        0,
        "CLI golden tests should succeed for packaged Ponytails"
    );
}
