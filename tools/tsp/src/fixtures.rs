use crate::manifest::{ResolvedPlugin, ValidationError};
use crate::protocol::{OptimizeAction, OptimizeRequest, run_fixture_with_activation};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

const CASE_MAX_BYTES: u64 = 64 << 10;
pub(crate) const FIXTURE_MAX_BYTES: u64 = 16 << 20;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FixtureCase {
    pub(crate) schema_version: u32,
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) program: String,
    pub(crate) exit_code: i32,
    pub(crate) input: String,
    pub(crate) expected_action: OptimizeAction,
    #[serde(default)]
    pub(crate) expected_output: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureCaseReport {
    pub ok: bool,
    pub name: String,
    pub path: String,
    pub expected_action: OptimizeAction,
    pub actual_action: Option<OptimizeAction>,
    pub activation_attempt_id: String,
    pub message: String,
    pub duration_ms: u128,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestReport {
    pub schema_version: u32,
    pub ok: bool,
    pub plugin_id: String,
    pub version: String,
    pub platform: String,
    pub release_id: String,
    pub artifact_digest: String,
    pub fixture_directory: String,
    pub passed: usize,
    pub failed: usize,
    pub cases: Vec<FixtureCaseReport>,
    pub duration_ms: u128,
}

pub fn read_fixture_input(path: &Path) -> Result<Vec<u8>, ValidationError> {
    read_bounded_file(
        path,
        FIXTURE_MAX_BYTES,
        "fixture.read",
        "Use a regular UTF-8 fixture file no larger than 16 MiB.",
    )
}

pub fn test_plugin(
    plugin: &ResolvedPlugin,
    fixture_directory: &Path,
) -> Result<TestReport, ValidationError> {
    let started = Instant::now();
    let paths = fixture_case_paths(fixture_directory)?;

    let mut cases = Vec::with_capacity(paths.len());
    for path in paths {
        let case = load_case(&path)?;
        let case_started = Instant::now();
        let base = path.parent().unwrap_or(fixture_directory);
        let input_path = resolve_case_path(base, &case.input)?;
        let input = read_fixture_input(&input_path)?;
        let expected = match &case.expected_output {
            Some(relative) => {
                let path = resolve_case_path(base, relative)?;
                Some(read_bounded_file(
                    &path,
                    FIXTURE_MAX_BYTES,
                    "test.expected",
                    "Use a regular UTF-8 golden output no larger than 16 MiB.",
                )?)
            }
            None => None,
        };
        validate_case_expectation(&case, expected.as_deref())?;
        let request = OptimizeRequest {
            kind: case.kind.clone(),
            program: case.program.clone(),
            exit_code: case.exit_code,
            content: input.clone(),
        };
        crate::protocol::validate_fixture_request(plugin, &request)?;
        let activation_attempt_id = crate::identity::new_activation_attempt_id()?;
        let run = run_fixture_with_activation(plugin, request, activation_attempt_id.clone());
        let report = match run {
            Ok(run) => {
                let action_matches = run.action == case.expected_action;
                let output_matches = match (&case.expected_action, expected.as_deref()) {
                    (OptimizeAction::Optimize, Some(expected)) => run.output.as_bytes() == expected,
                    (OptimizeAction::Pass, None) => run.output.as_bytes() == input,
                    _ => false,
                };
                let ok = action_matches && output_matches;
                let message = if !action_matches {
                    format!(
                        "expected action {:?}, got {:?}",
                        case.expected_action, run.action
                    )
                } else if !output_matches {
                    "optimized output does not match the golden file byte-for-byte".into()
                } else {
                    format!(
                        "{:?}, {} bytes to {} bytes",
                        run.action, run.input_bytes, run.output_bytes
                    )
                };
                FixtureCaseReport {
                    ok,
                    name: case.name,
                    path: path.display().to_string(),
                    expected_action: case.expected_action,
                    actual_action: Some(run.action),
                    activation_attempt_id,
                    message,
                    duration_ms: case_started.elapsed().as_millis(),
                }
            }
            Err(error) => FixtureCaseReport {
                ok: false,
                name: case.name,
                path: path.display().to_string(),
                expected_action: case.expected_action,
                actual_action: None,
                activation_attempt_id,
                message: format!("[{}] {}", error.code, error.message),
                duration_ms: case_started.elapsed().as_millis(),
            },
        };
        cases.push(report);
    }
    let passed = cases.iter().filter(|case| case.ok).count();
    let failed = cases.len() - passed;
    Ok(TestReport {
        schema_version: 1,
        ok: failed == 0,
        plugin_id: plugin.manifest.id.clone(),
        version: plugin.manifest.version.clone(),
        platform: plugin.platform.clone(),
        release_id: plugin.release_id.clone(),
        artifact_digest: plugin.artifact_digest.clone(),
        fixture_directory: fixture_directory.display().to_string(),
        passed,
        failed,
        cases,
        duration_ms: started.elapsed().as_millis(),
    })
}

pub(crate) fn fixture_case_paths(
    fixture_directory: &Path,
) -> Result<Vec<PathBuf>, ValidationError> {
    let entries = fs::read_dir(fixture_directory).map_err(|error| {
        ValidationError::new(
            "test.fixtures",
            format!(
                "could not read fixture directory {}: {error}",
                fixture_directory.display()
            ),
            "Create a fixtures directory containing one or more *.case.json files.",
        )
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| {
                ValidationError::new(
                    "test.fixtures",
                    format!(
                        "could not enumerate fixture directory {}: {error}",
                        fixture_directory.display()
                    ),
                    "Check fixture directory permissions and retry.",
                )
            })?
            .path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".case.json"))
        {
            paths.push(path);
        }
    }
    paths.sort();
    if paths.is_empty() {
        return Err(ValidationError::new(
            "test.empty",
            format!(
                "{} contains no *.case.json files",
                fixture_directory.display()
            ),
            "Add at least one golden fixture case or pass --fixtures with the correct directory.",
        ));
    }

    Ok(paths)
}

pub(crate) fn load_case(path: &Path) -> Result<FixtureCase, ValidationError> {
    let bytes = read_bounded_file(
        path,
        CASE_MAX_BYTES,
        "test.case",
        "Use a regular *.case.json descriptor no larger than 64 KiB.",
    )?;
    let case: FixtureCase = serde_json::from_slice(&bytes).map_err(|error| {
        ValidationError::new(
            "test.caseJson",
            format!("could not parse {}: {error}", path.display()),
            "Fix the fixture descriptor fields and JSON types.",
        )
    })?;
    if case.schema_version != 1
        || case.name.is_empty()
        || case.name.len() > 128
        || case.program.is_empty()
        || case.input.is_empty()
    {
        return Err(ValidationError::new(
            "test.caseContract",
            format!(
                "{} has an invalid schemaVersion, name, program, or input",
                path.display()
            ),
            "Use schemaVersion 1, a short name, a program, and a relative input path.",
        ));
    }
    Ok(case)
}

pub(crate) fn validate_case_expectation(
    case: &FixtureCase,
    expected: Option<&[u8]>,
) -> Result<(), ValidationError> {
    if expected.is_some_and(|output| {
        output.is_empty() || output.contains(&0) || std::str::from_utf8(output).is_err()
    }) {
        return Err(ValidationError::new(
            "test.expectedText",
            format!("fixture {:?} has an unsafe golden output", case.name),
            "Use non-empty UTF-8 golden output without NUL bytes.",
        ));
    }
    match (&case.expected_action, expected) {
        (OptimizeAction::Pass, None) | (OptimizeAction::Optimize, Some(_)) => Ok(()),
        (OptimizeAction::Pass, Some(_)) => Err(ValidationError::new(
            "test.passOutput",
            format!(
                "fixture {:?} expects pass but also sets expectedOutput",
                case.name
            ),
            "Remove expectedOutput for pass fixtures.",
        )),
        (OptimizeAction::Optimize, None) => Err(ValidationError::new(
            "test.goldenMissing",
            format!(
                "fixture {:?} expects optimize but has no expectedOutput",
                case.name
            ),
            "Set expectedOutput to the relative path of the exact golden output.",
        )),
    }
}

pub(crate) fn resolve_case_path(base: &Path, relative: &str) -> Result<PathBuf, ValidationError> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ValidationError::new(
            "test.fixturePath",
            format!("fixture path must stay inside its directory: {relative:?}"),
            "Use a relative child path without parent-directory components.",
        ));
    }
    Ok(base.join(path))
}

pub(crate) fn read_bounded_file(
    path: &Path,
    limit: u64,
    code: &'static str,
    remediation: &'static str,
) -> Result<Vec<u8>, ValidationError> {
    let metadata = fs::metadata(path).map_err(|error| {
        ValidationError::new(
            code,
            format!("could not read {}: {error}", path.display()),
            remediation,
        )
    })?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(ValidationError::new(
            code,
            format!(
                "{} must be a regular file no larger than {limit} bytes",
                path.display()
            ),
            remediation,
        ));
    }
    fs::read(path).map_err(|error| {
        ValidationError::new(
            code,
            format!("could not read {}: {error}", path.display()),
            remediation,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_paths_cannot_escape_case_directory() {
        let base = Path::new("fixtures");
        assert_eq!(
            resolve_case_path(base, "nested/input.txt").unwrap(),
            base.join("nested/input.txt")
        );
        assert!(resolve_case_path(base, "../secret.txt").is_err());
    }

    #[test]
    fn golden_expectations_are_safe_and_action_specific() {
        let mut case = FixtureCase {
            schema_version: 1,
            name: "golden".into(),
            kind: "test".into(),
            program: "cargo".into(),
            exit_code: 0,
            input: "input.txt".into(),
            expected_action: OptimizeAction::Optimize,
            expected_output: Some("golden.txt".into()),
        };
        assert!(validate_case_expectation(&case, Some(b"safe")).is_ok());
        assert!(validate_case_expectation(&case, Some(b"bad\0output")).is_err());
        assert!(validate_case_expectation(&case, None).is_err());
        case.expected_action = OptimizeAction::Pass;
        assert!(validate_case_expectation(&case, None).is_ok());
        assert!(validate_case_expectation(&case, Some(b"unexpected")).is_err());
    }
}
