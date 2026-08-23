//! TokenSaver Plugin SDK workbench.
//!
//! This crate contains public manifest and protocol conformance tooling only.
//! It intentionally contains no proprietary command-output optimization heuristics.

mod bench;
mod catalog;
mod certification;
mod certification_admin;
mod certification_artifact;
mod certification_distribution;
mod certification_fuzz;
mod certification_issuer;
mod certification_pipeline;
mod certification_reproducible;
mod certification_supply_chain;
mod certification_trust;
mod fixtures;
mod identity;
mod manifest;
mod package;
mod protocol;
mod scaffold;
mod superec;

pub use bench::{
    BenchCaseReport, BenchReport, BenchTotals, DEFAULT_ITERATIONS, LatencySummary, bench_plugin,
};
pub use catalog::{CatalogReport, PackageCatalog, PackageCatalogEntry, assemble_package_catalog};
pub use certification::{
    CERTIFICATION_POLICY_ID, CERTIFICATION_POLICY_VERSION, CertificationAuthority,
    CertificationCheck, CertificationLevel, CertificationReport, CertificationRequirement,
    CertificationSubject, validate_certification_report, validate_certification_subject,
};
pub use certification_admin::{
    CertificationAdminPolicyEvidence, CertificationAdminPolicyMetadata,
    evaluate_admin_policy_metadata,
};
pub use certification_artifact::{
    ARTIFACT_SIGNATURE_ALGORITHM, CertificationArtifactIdentity, CertificationArtifactSignature,
    CertificationArtifactSignatureEvidence, CertificationArtifactSignaturePolicy,
    CertificationArtifactTrustStore, MAX_ARTIFACT_SIGNATURE_LIFETIME_SECONDS,
    TrustedArtifactSigningKey, artifact_signature_signing_message, evaluate_signed_artifact,
};
pub use certification_distribution::{
    AuthenticatedCertificationSource, CertificationEvidenceDocuments,
    CertificationRevocationStateStore, fetch_verify_and_record_certification,
};
pub use certification_fuzz::{
    CERTIFICATION_FUZZ_PROTOCOL, CertificationFuzzCase, CertificationFuzzCaseClass,
    CertificationFuzzCorpus, CertificationFuzzEngine, CertificationFuzzEvidence,
    CertificationFuzzExecutionLimits, CertificationFuzzPolicy, CertificationFuzzReport,
    decode_certification_fuzz_case, evaluate_protocol_fuzzing, parse_certification_fuzz_corpus,
    parse_certification_fuzz_policy, validate_certification_fuzz_engine,
    validate_certification_fuzz_plan,
};
pub use certification_issuer::{
    CertificationEnvelopeValidity, CertificationIssuerIdentity, CertificationRevocationPublication,
    CertificationSigningProvider, CertificationSigningPurpose, CertificationSigningRequest,
    IssuedCertificationEnvelope, IssuedCertificationRevocations, issue_certification_envelope,
    issue_certification_revocations,
};
pub use certification_pipeline::{
    CertificationBenchmarkPolicy, CertificationEvidenceReference, CertificationStageEvidence,
    CertificationStageProducer, CertificationStageSubject, assemble_certification_report,
    certification_rule, evaluate_public_corpus_benchmark,
};
pub use certification_reproducible::{
    CertificationReproducibleBuildAttempt, CertificationReproducibleBuildEvidence,
    CertificationReproducibleBuildPolicy, CertificationReproducibleBuildReport,
    evaluate_reproducible_build,
};
pub use certification_supply_chain::{
    CertificationLicenseEvidence, CertificationLicensePolicy, CertificationLicenseProvenanceReport,
    CertificationSbomEvidence, CertificationSbomPolicy, CertificationSbomReport,
    evaluate_license_provenance, evaluate_sbom,
};
pub use certification_trust::{
    CERTIFICATION_SIGNATURE_ALGORITHM, CertificationDecisionContext, CertificationEnvelope,
    CertificationRevocation, CertificationRevocationList, CertificationTrustStore,
    MAX_CERTIFICATION_ENVELOPE_BYTES, MAX_CERTIFICATION_LIFETIME_SECONDS,
    MAX_CERTIFICATION_REPORT_BYTES, MAX_CERTIFICATION_REVOCATION_BYTES,
    MAX_REVOCATION_WINDOW_SECONDS, TrustedIssuerKey, TrustedKeyPurpose, VerifiedCertification,
    certification_envelope_signing_message, revocation_list_signing_message,
    verify_certification_evidence,
};
pub use fixtures::{FixtureCaseReport, TestReport, read_fixture_input, test_plugin};
pub use identity::{
    executable_digest, new_activation_attempt_id, release_id, valid_activation_attempt_id,
    valid_release_id,
};
pub use manifest::{
    PluginManifest, ResolvedPlugin, ValidationError, load_and_resolve, platform_key,
    validate_manifest,
};
pub use package::{PackageFileReport, PackageReport, default_package_path, package_plugin};
pub use protocol::{
    Check, OptimizeAction, OptimizeRequest, RunReport, ValidationReport, run_fixture,
    validate_plugin,
};
pub use scaffold::{NewOptions, NewReport, scaffold_plugin};

use serde::Serialize;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const EXIT_OK: i32 = 0;
const EXIT_FAILURE: i32 = 1;
const EXIT_USAGE: i32 = 2;

#[derive(Debug, Serialize)]
struct ErrorReport<'a> {
    ok: bool,
    command: &'a str,
    code: &'a str,
    message: &'a str,
    remediation: &'a str,
}

pub fn run_cli<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut args = args.into_iter().map(Into::into);
    let _program = args.next();
    let Some(command) = args.next() else {
        print_usage();
        return EXIT_USAGE;
    };
    let command = command.to_string_lossy();
    let remaining = args.collect::<Vec<_>>();
    match command.as_ref() {
        "help" | "--help" | "-h" => {
            print_usage();
            EXIT_OK
        }
        "validate" => run_validate(&remaining),
        "run" => run_one(&remaining),
        "test" => run_tests(&remaining),
        "bench" => run_bench(&remaining),
        "catalog" => run_catalog(&remaining),
        "package" => run_package(&remaining),
        "new" => run_new(&remaining),
        _ => {
            eprintln!("Unknown command: {command}");
            print_usage();
            EXIT_USAGE
        }
    }
}

fn run_catalog(args: &[OsString]) -> i32 {
    let json = args.iter().any(|value| value == "--json");
    let mut input = None;
    let mut output = None;
    let mut index = 0;
    while index < args.len() {
        let value = &args[index];
        match value.to_string_lossy().as_ref() {
            "--json" => {}
            "--help" | "-h" => {
                print_catalog_usage();
                return EXIT_OK;
            }
            "--output" => match option_value(args, &mut index) {
                Some(value) => output = Some(PathBuf::from(value)),
                None => return missing_option("catalog", json, "--output"),
            },
            option if option.starts_with('-') || input.is_some() => {
                return usage_error(
                    "catalog",
                    json,
                    "catalog accepts exactly one package directory",
                    "Run `tsp catalog --help` for command syntax.",
                );
            }
            _ => input = Some(PathBuf::from(value)),
        }
        index += 1;
    }
    let Some(input) = input else {
        return usage_error(
            "catalog",
            json,
            "catalog requires a package directory",
            "Pass a directory containing .tsplug files and their package reports.",
        );
    };
    let Some(output) = output else {
        return missing_option("catalog", json, "--output");
    };
    let report = match assemble_package_catalog(&input, &output) {
        Ok(report) => report,
        Err(error) => return validation_error("catalog", json, &error),
    };
    if json {
        print_json(&report);
    } else {
        println!("Cataloged {} {}", report.plugin_id, report.version);
        println!("  Catalog:  {}", report.catalog);
        println!("  Digest:   {}", report.catalog_digest);
        println!("  Packages: {}", report.package_count);
        println!("  No package was installed, enabled, or activated.");
    }
    EXIT_OK
}

fn run_bench(args: &[OsString]) -> i32 {
    let json = args.iter().any(|value| value == "--json");
    let mut plugin_path = None;
    let mut fixtures = None;
    let mut iterations = DEFAULT_ITERATIONS;
    let mut index = 0;
    while index < args.len() {
        let value = &args[index];
        match value.to_string_lossy().as_ref() {
            "--json" => {}
            "--help" | "-h" => {
                print_bench_usage();
                return EXIT_OK;
            }
            "--fixtures" => match option_value(args, &mut index) {
                Some(value) => fixtures = Some(PathBuf::from(value)),
                None => return missing_option("bench", json, "--fixtures"),
            },
            "--iterations" => match option_value(args, &mut index)
                .and_then(|value| value.to_string_lossy().parse::<u32>().ok())
                .filter(|value| (1..=bench::MAX_ITERATIONS).contains(value))
            {
                Some(value) => iterations = value,
                None => {
                    return usage_error(
                        "bench",
                        json,
                        "--iterations must be an integer between 1 and 100",
                        "Pass a bounded positive sample count.",
                    );
                }
            },
            option if option.starts_with('-') || plugin_path.is_some() => {
                return usage_error(
                    "bench",
                    json,
                    "bench accepts one plugin directory or plugin.json path",
                    "Run `tsp bench --help` for command syntax.",
                );
            }
            _ => plugin_path = Some(PathBuf::from(value)),
        }
        index += 1;
    }
    let plugin_path = plugin_path.unwrap_or_else(|| PathBuf::from("."));
    let plugin = match load_and_resolve(&plugin_path) {
        Ok(plugin) => plugin,
        Err(error) => return validation_error("bench", json, &error),
    };
    let fixtures = fixtures.unwrap_or_else(|| {
        plugin
            .manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("fixtures")
    });
    let report = match bench_plugin(&plugin, &fixtures, iterations) {
        Ok(report) => report,
        Err(error) => return validation_error("bench", json, &error),
    };
    if json {
        print_json(&report);
    } else {
        println!(
            "Benchmarking {} {} on {}: {} cases x {} iterations",
            report.plugin_id,
            report.version,
            report.platform,
            report.cases.len(),
            report.iterations
        );
        for case in &report.cases {
            println!(
                "  PASS {:<28} {:>7.2}% saved, p50 {:>6} us, p95 {:>6} us",
                case.name, case.savings_percent, case.latency_us.p50_us, case.latency_us.p95_us
            );
        }
        println!(
            "{} samples, {:.2}% saved, p50 {} us, p95 {} us",
            report.totals.samples,
            report.totals.savings_percent,
            report.totals.latency_us.p50_us,
            report.totals.latency_us.p95_us
        );
    }
    EXIT_OK
}

fn run_package(args: &[OsString]) -> i32 {
    let json = args.iter().any(|value| value == "--json");
    let mut plugin_path = None;
    let mut output = None;
    let mut index = 0;
    while index < args.len() {
        let value = &args[index];
        match value.to_string_lossy().as_ref() {
            "--json" => {}
            "--help" | "-h" => {
                print_package_usage();
                return EXIT_OK;
            }
            "--output" => match option_value(args, &mut index) {
                Some(value) => output = Some(PathBuf::from(value)),
                None => return missing_option("package", json, "--output"),
            },
            option if option.starts_with('-') || plugin_path.is_some() => {
                return usage_error(
                    "package",
                    json,
                    "package accepts one plugin directory or plugin.json path",
                    "Run `tsp package --help` for command syntax.",
                );
            }
            _ => plugin_path = Some(PathBuf::from(value)),
        }
        index += 1;
    }
    let plugin_path = plugin_path.unwrap_or_else(|| PathBuf::from("."));
    let plugin = match load_and_resolve(&plugin_path) {
        Ok(plugin) => plugin,
        Err(error) => return validation_error("package", json, &error),
    };
    let output = output.unwrap_or_else(|| default_package_path(&plugin));
    let report = match package_plugin(&plugin, &output) {
        Ok(report) => report,
        Err(error) => return validation_error("package", json, &error),
    };
    if json {
        print_json(&report);
    } else {
        println!(
            "Packaged {} {} for {}",
            report.plugin_id, report.version, report.platform
        );
        println!("  Archive: {}", report.archive);
        println!("  Digest:  {}", report.archive_digest);
        println!("  Files:   {}", report.files.len());
        println!("  Level 1 conformance verified; package was not installed or activated.");
    }
    EXIT_OK
}

fn run_validate(args: &[OsString]) -> i32 {
    let json = args.iter().any(|value| value == "--json");
    let mut path = None;
    for value in args {
        if value == "--json" {
        } else if value == "--help" || value == "-h" {
            print_validate_usage();
            return EXIT_OK;
        } else if value.to_string_lossy().starts_with('-') || path.is_some() {
            return usage_error(
                "validate",
                json,
                "validate accepts one plugin directory or plugin.json path",
                "Run `tsp validate --help` for command syntax.",
            );
        } else {
            path = Some(PathBuf::from(value));
        }
    }
    let path = path.unwrap_or_else(|| PathBuf::from("."));
    let resolved = match load_and_resolve(&path) {
        Ok(plugin) => plugin,
        Err(error) => return validation_error("validate", json, &error),
    };
    match validate_plugin(&resolved) {
        Ok(report) => {
            if json {
                print_json(&report);
            } else {
                println!(
                    "Validating {} {} for {}",
                    report.plugin_id, report.version, report.platform
                );
                for check in &report.checks {
                    println!("  PASS {:<30} {}", check.name, check.detail);
                }
                println!("Level 1 conformant: {}", report.plugin_id);
            }
            EXIT_OK
        }
        Err(error) => validation_error("validate", json, &error),
    }
}

fn run_one(args: &[OsString]) -> i32 {
    let json = args.iter().any(|value| value == "--json");
    let mut fixture = None;
    let mut plugin_path = PathBuf::from(".");
    let mut kind = None;
    let mut program = None;
    let mut exit_code = 0i32;
    let mut index = 0;
    while index < args.len() {
        let value = &args[index];
        match value.to_string_lossy().as_ref() {
            "--json" => {}
            "--help" | "-h" => {
                print_run_usage();
                return EXIT_OK;
            }
            "--plugin" => match option_value(args, &mut index) {
                Some(value) => plugin_path = PathBuf::from(value),
                None => return missing_option("run", json, "--plugin"),
            },
            "--kind" => match option_value(args, &mut index) {
                Some(value) => kind = Some(value.to_string_lossy().into_owned()),
                None => return missing_option("run", json, "--kind"),
            },
            "--program" => match option_value(args, &mut index) {
                Some(value) => program = Some(value.to_string_lossy().into_owned()),
                None => return missing_option("run", json, "--program"),
            },
            "--exit-code" => match option_value_allow_dash(args, &mut index)
                .and_then(|value| value.to_string_lossy().parse::<i32>().ok())
            {
                Some(value) => exit_code = value,
                None => {
                    return usage_error(
                        "run",
                        json,
                        "--exit-code requires a signed 32-bit integer",
                        "Pass a command exit code such as 0 or 1.",
                    );
                }
            },
            option if option.starts_with('-') || fixture.is_some() => {
                return usage_error(
                    "run",
                    json,
                    "run accepts exactly one fixture file",
                    "Run `tsp run --help` for command syntax.",
                );
            }
            _ => fixture = Some(PathBuf::from(value)),
        }
        index += 1;
    }
    let Some(fixture) = fixture else {
        return usage_error(
            "run",
            json,
            "run requires a fixture file",
            "Pass a recorded UTF-8 command-output file.",
        );
    };
    let plugin = match load_and_resolve(&plugin_path) {
        Ok(plugin) => plugin,
        Err(error) => return validation_error("run", json, &error),
    };
    let input = match read_fixture_input(&fixture) {
        Ok(input) => input,
        Err(error) => return validation_error("run", json, &error),
    };
    let kind = kind.unwrap_or_else(|| {
        plugin
            .manifest
            .capabilities
            .kinds
            .first()
            .cloned()
            .unwrap_or_else(|| "test".into())
    });
    let program = program.unwrap_or_else(|| {
        fixture
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("tsp-fixture")
            .to_owned()
    });
    let report = match run_fixture(
        &plugin,
        OptimizeRequest {
            kind,
            program,
            exit_code,
            content: input.clone(),
        },
    ) {
        Ok(report) => report,
        Err(error) => return validation_error("run", json, &error),
    };
    if json {
        print_json(&report);
    } else {
        println!(
            "{} {}: {:?}, {} to {} bytes, {:.2}% saved",
            report.plugin_id,
            report.version,
            report.action,
            report.input_bytes,
            report.output_bytes,
            report.savings_percent
        );
        print_diff(&input, report.output.as_bytes());
    }
    EXIT_OK
}

fn run_tests(args: &[OsString]) -> i32 {
    let json = args.iter().any(|value| value == "--json");
    let mut plugin_path = None;
    let mut fixtures = None;
    let mut index = 0;
    while index < args.len() {
        let value = &args[index];
        match value.to_string_lossy().as_ref() {
            "--json" => {}
            "--help" | "-h" => {
                print_test_usage();
                return EXIT_OK;
            }
            "--fixtures" => match option_value(args, &mut index) {
                Some(value) => fixtures = Some(PathBuf::from(value)),
                None => return missing_option("test", json, "--fixtures"),
            },
            option if option.starts_with('-') || plugin_path.is_some() => {
                return usage_error(
                    "test",
                    json,
                    "test accepts one plugin directory or plugin.json path",
                    "Run `tsp test --help` for command syntax.",
                );
            }
            _ => plugin_path = Some(PathBuf::from(value)),
        }
        index += 1;
    }
    let plugin_path = plugin_path.unwrap_or_else(|| PathBuf::from("."));
    let plugin = match load_and_resolve(&plugin_path) {
        Ok(plugin) => plugin,
        Err(error) => return validation_error("test", json, &error),
    };
    let fixtures = fixtures.unwrap_or_else(|| {
        plugin
            .manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("fixtures")
    });
    let report = match test_plugin(&plugin, &fixtures) {
        Ok(report) => report,
        Err(error) => return validation_error("test", json, &error),
    };
    if json {
        print_json(&report);
    } else {
        println!("Testing {} {}", report.plugin_id, report.version);
        for case in &report.cases {
            println!(
                "  {} {:<32} {}",
                if case.ok { "PASS" } else { "FAIL" },
                case.name,
                case.message
            );
        }
        println!("{} passed, {} failed", report.passed, report.failed);
    }
    if report.ok { EXIT_OK } else { EXIT_FAILURE }
}

fn run_new(args: &[OsString]) -> i32 {
    let json = args.iter().any(|value| value == "--json");
    let mut directory = None;
    let mut language = "rust".to_owned();
    let mut plugin_id = None;
    let mut display_name = None;
    let mut sdk_path = None;
    let mut index = 0;
    while index < args.len() {
        let value = &args[index];
        match value.to_string_lossy().as_ref() {
            "--json" => {}
            "--help" | "-h" => {
                print_new_usage();
                return EXIT_OK;
            }
            "--lang" => match option_value(args, &mut index) {
                Some(value) => language = value.to_string_lossy().into_owned(),
                None => return missing_option("new", json, "--lang"),
            },
            "--id" => match option_value(args, &mut index) {
                Some(value) => plugin_id = Some(value.to_string_lossy().into_owned()),
                None => return missing_option("new", json, "--id"),
            },
            "--name" => match option_value(args, &mut index) {
                Some(value) => display_name = Some(value.to_string_lossy().into_owned()),
                None => return missing_option("new", json, "--name"),
            },
            "--sdk-path" => match option_value(args, &mut index) {
                Some(value) => sdk_path = Some(PathBuf::from(value)),
                None => return missing_option("new", json, "--sdk-path"),
            },
            option if option.starts_with('-') || directory.is_some() => {
                return usage_error(
                    "new",
                    json,
                    "new accepts exactly one target directory",
                    "Run `tsp new --help` for command syntax.",
                );
            }
            _ => directory = Some(PathBuf::from(value)),
        }
        index += 1;
    }
    let Some(directory) = directory else {
        return usage_error(
            "new",
            json,
            "new requires a target directory",
            "Pass a new or empty directory for the plugin scaffold.",
        );
    };
    match scaffold_plugin(&NewOptions {
        directory,
        language,
        plugin_id,
        display_name,
        sdk_path,
    }) {
        Ok(report) => {
            if json {
                print_json(&report);
            } else {
                println!(
                    "Created {} ({}) in {}",
                    report.name, report.plugin_id, report.directory
                );
                for step in report.next_steps {
                    println!("  {step}");
                }
            }
            EXIT_OK
        }
        Err(error) => validation_error("new", json, &error),
    }
}

fn option_value<'a>(args: &'a [OsString], index: &mut usize) -> Option<&'a OsString> {
    *index += 1;
    args.get(*index)
        .filter(|value| !value.to_string_lossy().starts_with('-'))
}

fn option_value_allow_dash<'a>(args: &'a [OsString], index: &mut usize) -> Option<&'a OsString> {
    *index += 1;
    args.get(*index)
}

fn missing_option(command: &str, json: bool, option: &str) -> i32 {
    usage_error(
        command,
        json,
        &format!("{option} requires a value"),
        "Run the command with --help for syntax.",
    )
}

fn usage_error(command: &str, json: bool, message: &str, remediation: &'static str) -> i32 {
    print_error(
        command,
        json,
        "usage.arguments",
        message,
        remediation,
        EXIT_USAGE,
    )
}

fn validation_error(command: &str, json: bool, error: &ValidationError) -> i32 {
    print_error(
        command,
        json,
        error.code,
        &error.message,
        error.remediation,
        EXIT_FAILURE,
    )
}

fn print_error(
    command: &str,
    json: bool,
    code: &str,
    message: &str,
    remediation: &str,
    exit_code: i32,
) -> i32 {
    if json {
        print_json(&ErrorReport {
            ok: false,
            command,
            code,
            message,
            remediation,
        });
    } else {
        eprintln!("FAIL [{code}] {message}");
        eprintln!("Remediation: {remediation}");
    }
    exit_code
}

fn print_json<T: Serialize>(value: &T) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("serialize workbench report")
    );
}

fn print_diff(before: &[u8], after: &[u8]) {
    println!("--- before");
    println!("+++ after");
    if before == after {
        println!("  (no changes)");
        return;
    }
    println!("@@ complete output @@");
    for line in String::from_utf8_lossy(before).lines() {
        println!("-{}", safe_terminal_text(line));
    }
    for line in String::from_utf8_lossy(after).lines() {
        println!("+{}", safe_terminal_text(line));
    }
}

fn safe_terminal_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character == '\t' || !character.is_control() {
                character.to_string().chars().collect::<Vec<_>>()
            } else {
                character.escape_default().collect::<Vec<_>>()
            }
        })
        .collect()
}

fn print_usage() {
    println!(
        "TokenSaver Plugin Workbench\n\nUsage:\n  tsp new <directory> [--lang rust|go|python|typescript] [--id ID] [--name NAME] [--json]\n  tsp run <fixture> [--plugin DIR] [--kind KIND] [--program NAME] [--exit-code CODE] [--json]\n  tsp test [plugin-dir|plugin.json] [--fixtures DIR] [--json]\n  tsp bench [plugin-dir|plugin.json] [--fixtures DIR] [--iterations N] [--json]\n  tsp validate [plugin-dir|plugin.json] [--json]\n  tsp package [plugin-dir|plugin.json] [--output FILE.tsplug] [--json]\n  tsp catalog <package-directory> --output catalog.json [--json]\n  tsp help"
    );
}

fn print_validate_usage() {
    println!(
        "Usage: tsp validate [plugin-dir|plugin.json] [--json]\n\nValidates the manifest and runs the Level 1 TSPP process conformance suite."
    );
}

fn print_run_usage() {
    println!(
        "Usage: tsp run <fixture> [--plugin DIR] [--kind KIND] [--program NAME] [--exit-code CODE] [--json]\n\nRuns one recorded command output through a packaged plugin and prints a safe before/after diff."
    );
}

fn print_test_usage() {
    println!(
        "Usage: tsp test [plugin-dir|plugin.json] [--fixtures DIR] [--json]\n\nRuns every fixtures/*.case.json golden test in a fresh plugin process."
    );
}

fn print_bench_usage() {
    println!(
        "Usage: tsp bench [plugin-dir|plugin.json] [--fixtures DIR] [--iterations N] [--json]\n\nRuns the versioned golden corpus in fresh bounded processes and reports savings plus latency percentiles."
    );
}

fn print_package_usage() {
    println!(
        "Usage: tsp package [plugin-dir|plugin.json] [--output FILE.tsplug] [--json]\n\nRuns Level 1 validation and creates a deterministic single-platform package without installing or activating it."
    );
}

fn print_catalog_usage() {
    println!(
        "Usage: tsp catalog <package-directory> --output catalog.json [--json]\n\nVerifies native package reports and creates a deterministic digest catalog without installing or activating anything."
    );
}

fn print_new_usage() {
    println!(
        "Usage: tsp new <directory> [--lang rust|go|python|typescript] [--id ID] [--name NAME] [--sdk-path DIR] [--json]\n\nCreates a safe standalone-executable plugin scaffold without overwriting an existing project."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_commands_and_extra_paths_are_usage_errors() {
        assert_eq!(run_cli(["tsp", "unknown"]), EXIT_USAGE);
        assert_eq!(
            run_cli(["tsp", "validate", "one", "two", "--json"]),
            EXIT_USAGE
        );
        assert_eq!(run_cli(["tsp", "run"]), EXIT_USAGE);
        assert_eq!(run_cli(["tsp", "new"]), EXIT_USAGE);
        assert_eq!(
            run_cli(["tsp", "bench", "--iterations", "0", "--json"]),
            EXIT_USAGE
        );
        assert_eq!(
            run_cli(["tsp", "package", "one", "two", "--json"]),
            EXIT_USAGE
        );
        assert_eq!(run_cli(["tsp", "catalog", "--json"]), EXIT_USAGE);
    }

    #[test]
    fn help_is_successful_for_every_command() {
        for command in [
            "validate", "run", "test", "bench", "package", "catalog", "new",
        ] {
            assert_eq!(run_cli(["tsp", command, "--help"]), EXIT_OK);
        }
        assert_eq!(run_cli(["tsp", "help"]), EXIT_OK);
    }

    #[test]
    fn terminal_diff_escapes_control_characters() {
        assert_eq!(safe_terminal_text("ok\u{1b}[31m"), "ok\\u{1b}[31m");
    }

    #[test]
    fn signed_exit_codes_are_valid_option_values() {
        let args = [OsString::from("--exit-code"), OsString::from("-1")];
        let mut index = 0;
        assert_eq!(
            option_value_allow_dash(&args, &mut index),
            Some(&OsString::from("-1"))
        );
    }

    #[test]
    fn every_published_json_schema_is_unambiguous_and_parses() {
        for schema in [
            include_str!("../../../schemas/plugin-manifest.v1.json"),
            include_str!("../../../schemas/fixture-case.v1.json"),
            include_str!("../../../schemas/tokensaver-superec-plugin-profile.v1.json"),
            include_str!("../../../schemas/benchmark-report.v1.json"),
            include_str!("../../../schemas/run-report.v1.json"),
            include_str!("../../../schemas/test-report.v1.json"),
            include_str!("../../../schemas/validation-report.v1.json"),
            include_str!("../../../schemas/package-report.v1.json"),
            include_str!("../../../schemas/package-catalog.v1.json"),
            include_str!("../../../schemas/catalog-report.v1.json"),
            include_str!("../../../schemas/certification-report.v1.json"),
            include_str!("../../../schemas/certification-envelope.v1.json"),
            include_str!("../../../schemas/certification-trust-store.v1.json"),
            include_str!("../../../schemas/certification-revocations.v1.json"),
            include_str!("../../../schemas/certification-revocation-state.v1.json"),
            include_str!("../../../schemas/certification-stage-evidence.v1.json"),
            include_str!("../../../schemas/certification-artifact-signature-policy.v1.json"),
            include_str!("../../../schemas/certification-artifact-trust-store.v1.json"),
            include_str!("../../../schemas/certification-artifact-signature.v1.json"),
            include_str!("../../../schemas/certification-benchmark-policy.v1.json"),
            include_str!("../../../schemas/certification-fuzz-policy.v1.json"),
            include_str!("../../../schemas/certification-fuzz-corpus.v1.json"),
            include_str!("../../../schemas/certification-fuzz-report.v1.json"),
            include_str!("../../../schemas/certification-reproducible-build-policy.v1.json"),
            include_str!("../../../schemas/certification-reproducible-build-report.v1.json"),
            include_str!("../../../schemas/runtime-host-request.v1.json"),
            include_str!("../../../schemas/runtime-host-response.v1.json"),
            include_str!("../../../schemas/runtime-host-assets.v1.json"),
        ] {
            superec::validate_unambiguous_json(schema.as_bytes()).expect(
                "published JSON schema must not contain duplicate members or trailing JSON",
            );
            serde_json::from_str::<serde_json::Value>(schema).expect("published JSON schema");
        }
    }

    #[test]
    fn certification_levels_are_bounded_by_report_authority() {
        let package: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/package-report.v1.json"))
                .expect("package report schema");
        assert_eq!(
            package.pointer("/properties/certificationLevel/const"),
            Some(&serde_json::json!(1))
        );

        let catalog: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/package-catalog.v1.json"))
                .expect("package catalog schema");
        assert_eq!(
            catalog.pointer(
                "/properties/packages/additionalProperties/properties/certificationLevel/enum"
            ),
            Some(&serde_json::json!([1, 2, 3]))
        );
    }
}
