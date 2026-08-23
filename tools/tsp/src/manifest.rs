use serde::Deserialize;
#[cfg(test)]
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const MANIFEST_MAX_BYTES: u64 = 64 << 10;
const DEFAULT_BUDGET_MS: u32 = 250;
const MIN_BUDGET_MS: u32 = 50;
const MAX_BUDGET_MS: u32 = 1000;
const MAX_INPUT_BYTES: i64 = 16 << 20;
const MAX_PLUGIN_ID_BYTES: usize = 128;
const MAX_PLUGIN_ID_LABEL_BYTES: usize = 63;
const MAX_RUNTIME_ARGUMENTS: usize = 32;
const MAX_RUNTIME_ARGUMENT_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginManifest {
    pub api_version: i64,
    pub id: String,
    pub name: String,
    pub version: String,
    pub creator: PluginCreator,
    #[serde(default)]
    pub permissions: Vec<String>,
    pub runtime: PluginRuntime,
    #[serde(default)]
    pub capabilities: PluginCapabilities,
    #[serde(default)]
    pub limits: PluginLimits,
    #[serde(default)]
    pub integrity: Option<PluginIntegrity>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PluginCreator {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PluginRuntime {
    pub kind: String,
    pub entry: BTreeMap<String, String>,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginCapabilities {
    #[serde(default)]
    pub kinds: Vec<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub max_input_bytes: i64,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginLimits {
    #[serde(default)]
    pub time_budget_ms: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PluginIntegrity {
    pub algorithm: String,
    pub digests: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct ResolvedPlugin {
    pub manifest_path: PathBuf,
    pub manifest: PluginManifest,
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub platform: String,
    pub budget_ms: u32,
    pub artifact_digest: String,
    pub release_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationError {
    pub code: &'static str,
    pub message: String,
    pub remediation: &'static str,
}

impl ValidationError {
    /// Creates a bounded machine-readable validation failure for a host or SDK adapter.
    pub fn new(code: &'static str, message: impl Into<String>, remediation: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            remediation,
        }
    }
}

pub fn platform_key() -> String {
    let operating_system = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "x86" => "x86",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{operating_system}-{architecture}")
}

pub fn load_and_resolve(path: &Path) -> Result<ResolvedPlugin, ValidationError> {
    let manifest_path = if path.is_dir() {
        path.join("plugin.json")
    } else {
        path.to_path_buf()
    };
    let metadata = fs::metadata(&manifest_path).map_err(|error| {
        ValidationError::new(
            "manifest.read",
            format!("could not read {}: {error}", manifest_path.display()),
            "Pass a plugin directory or plugin.json path that exists.",
        )
    })?;
    if !metadata.is_file() || metadata.len() > MANIFEST_MAX_BYTES {
        return Err(ValidationError::new(
            "manifest.size",
            "plugin.json must be a regular file no larger than 64 KiB",
            "Reduce the manifest size and keep package data in separate files.",
        ));
    }
    let bytes = fs::read(&manifest_path).map_err(|error| {
        ValidationError::new(
            "manifest.read",
            format!("could not read {}: {error}", manifest_path.display()),
            "Check the manifest file permissions and retry.",
        )
    })?;
    let manifest: PluginManifest = serde_json::from_slice(&bytes).map_err(|error| {
        ValidationError::new(
            "manifest.json",
            format!("plugin.json is not a valid v1 manifest: {error}"),
            "Fix the reported JSON field or type and run validation again.",
        )
    })?;
    validate_manifest(&manifest)?;

    let platform = platform_key();
    let entry = manifest
        .runtime
        .entry
        .get(&platform)
        .filter(|entry| !entry.is_empty())
        .ok_or_else(|| {
            ValidationError::new(
                "runtime.platform",
                format!("runtime.entry has no executable for {platform}"),
                "Package an executable for this platform and add its runtime.entry key.",
            )
        })?;
    let entry_path = PathBuf::from(entry);
    let executable = if entry_path.is_absolute() {
        entry_path
    } else {
        manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(entry_path)
    };
    if !executable.is_file() {
        return Err(ValidationError::new(
            "runtime.executable",
            format!(
                "runtime entry is not an executable file: {}",
                executable.display()
            ),
            "Build and package the current platform executable at the manifest entry path.",
        ));
    }
    let executable = executable.canonicalize().map_err(|error| {
        ValidationError::new(
            "runtime.executable",
            format!(
                "could not resolve runtime executable {}: {error}",
                executable.display()
            ),
            "Use a local executable path that can be resolved before launch.",
        )
    })?;
    let artifact_digest = crate::identity::executable_digest(&executable)?;
    if let Some(integrity) = &manifest.integrity {
        if integrity.algorithm != "sha256" {
            return Err(ValidationError::new(
                "integrity.algorithm",
                "manifest integrity.algorithm must be sha256",
                "Use sha256 artifact digests produced by `tsp package`.",
            ));
        }
        let expected = integrity.digests.get(&platform).ok_or_else(|| {
            ValidationError::new(
                "integrity.platform",
                format!("manifest integrity has no digest for {platform}"),
                "Add the current platform digest or regenerate the package with `tsp package`.",
            )
        })?;
        if expected != &artifact_digest {
            return Err(ValidationError::new(
                "integrity.digest",
                format!(
                    "runtime digest mismatch for {platform}: expected {expected}, computed {artifact_digest}"
                ),
                "Restore the packaged executable or regenerate the package from trusted sources.",
            ));
        }
    }

    let budget_ms = effective_time_budget_ms(&manifest);
    let args = manifest.runtime.args.clone();
    let release_id =
        crate::identity::release_id(&manifest.id, &manifest.version, &platform, &artifact_digest);
    Ok(ResolvedPlugin {
        manifest_path,
        manifest,
        executable,
        args,
        platform,
        budget_ms,
        artifact_digest,
        release_id,
    })
}

pub(crate) fn effective_time_budget_ms(manifest: &PluginManifest) -> u32 {
    let requested_budget = manifest.limits.time_budget_ms;
    if requested_budget == 0 {
        DEFAULT_BUDGET_MS
    } else {
        requested_budget as u32
    }
}

pub fn validate_manifest(manifest: &PluginManifest) -> Result<(), ValidationError> {
    if manifest.api_version != 1 {
        return Err(ValidationError::new(
            "manifest.apiVersion",
            format!(
                "unsupported apiVersion {} (host speaks 1)",
                manifest.api_version
            ),
            "Set apiVersion to 1.",
        ));
    }
    if manifest.id.len() > MAX_PLUGIN_ID_BYTES || !valid_plugin_id(&manifest.id) {
        return Err(ValidationError::new(
            "manifest.id",
            "id must be reverse-DNS (for example com.example.my-plugin)",
            "Use at least three lowercase DNS labels with no leading or trailing hyphen.",
        ));
    }
    if manifest.name.is_empty() || manifest.name.len() > 64 {
        return Err(ValidationError::new(
            "manifest.name",
            "name is required (max 64 characters)",
            "Set a non-empty display name no longer than 64 UTF-8 bytes.",
        ));
    }
    if !valid_version(&manifest.version) {
        return Err(ValidationError::new(
            "manifest.version",
            "version must be semver (for example 1.0.0)",
            "Use major.minor.patch with an optional pre-release or build suffix.",
        ));
    }
    if manifest.creator.name.is_empty() {
        return Err(ValidationError::new(
            "manifest.creator.name",
            "creator.name is required",
            "Set creator.name to the person or organization publishing the plugin.",
        ));
    }
    if !manifest.permissions.is_empty() {
        return Err(ValidationError::new(
            "manifest.permissions",
            "permissions must be empty: the v1 host grants none",
            "Remove all permissions for a TSPP v1 optimizer plugin.",
        ));
    }
    if manifest.runtime.kind != "executable" {
        return Err(ValidationError::new(
            "manifest.runtime.kind",
            "runtime.kind must be executable",
            "Set runtime.kind to executable.",
        ));
    }
    if manifest.runtime.entry.is_empty() {
        return Err(ValidationError::new(
            "manifest.runtime.entry",
            "runtime.entry is required",
            "Add at least one platform-to-executable runtime entry.",
        ));
    }
    if manifest.runtime.args.len() > MAX_RUNTIME_ARGUMENTS
        || manifest
            .runtime
            .args
            .iter()
            .any(|argument| argument.len() > MAX_RUNTIME_ARGUMENT_BYTES || argument.contains('\0'))
    {
        return Err(ValidationError::new(
            "manifest.runtime.args",
            "runtime.args exceeds the TSPP v1 native runtime boundary",
            "Use at most 32 arguments, each at most 4096 UTF-8 bytes and without NUL.",
        ));
    }
    let mut seen_kinds = BTreeSet::new();
    for kind in &manifest.capabilities.kinds {
        if !matches!(kind.as_str(), "test" | "build" | "lint" | "status" | "log") {
            return Err(ValidationError::new(
                "manifest.capabilities.kinds",
                format!("capabilities.kinds contains unknown kind {kind:?}"),
                "Use only test, build, lint, status, and log.",
            ));
        }
        if !seen_kinds.insert(kind) {
            return Err(ValidationError::new(
                "manifest.capabilities.kinds",
                format!("capabilities.kinds contains duplicate kind {kind:?}"),
                "List each supported command-output kind once.",
            ));
        }
    }
    if !(0..=MAX_INPUT_BYTES).contains(&manifest.capabilities.max_input_bytes) {
        return Err(ValidationError::new(
            "manifest.capabilities.maxInputBytes",
            format!("capabilities.maxInputBytes must be 0 through {MAX_INPUT_BYTES}"),
            "Use 0 for the host default or declare a byte limit no larger than 16 MiB.",
        ));
    }
    let budget = manifest.limits.time_budget_ms;
    if budget != 0 && !(i64::from(MIN_BUDGET_MS)..=i64::from(MAX_BUDGET_MS)).contains(&budget) {
        return Err(ValidationError::new(
            "manifest.limits.timeBudgetMs",
            format!("limits.timeBudgetMs must be 0 or {MIN_BUDGET_MS} through {MAX_BUDGET_MS}"),
            "Use 0 for the 250 ms default or declare a budget from 50 through 1000 ms.",
        ));
    }
    if let Some(integrity) = &manifest.integrity {
        if integrity.algorithm != "sha256" {
            return Err(ValidationError::new(
                "integrity.algorithm",
                "manifest integrity.algorithm must be sha256",
                "Use sha256 artifact digests produced by `tsp package`.",
            ));
        }
        if integrity.digests.is_empty()
            || integrity
                .digests
                .iter()
                .any(|(platform, digest)| platform.is_empty() || !valid_digest(digest))
        {
            return Err(ValidationError::new(
                "integrity.digests",
                "manifest integrity.digests contains an invalid entry",
                "Use platform keys mapped to sha256: followed by 64 lowercase hexadecimal characters.",
            ));
        }
    }
    Ok(())
}

fn valid_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn valid_plugin_id(id: &str) -> bool {
    let labels: Vec<&str> = id.split('.').collect();
    labels.len() >= 3
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= MAX_PLUGIN_ID_LABEL_BYTES
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn valid_version(version: &str) -> bool {
    let suffix_at = version.find(['-', '+']);
    let (core, suffix) = match suffix_at {
        Some(index) => (&version[..index], Some(&version[index + 1..])),
        None => (version, None),
    };
    let mut numbers = core.split('.');
    let valid_core = (0..3).all(|_| {
        numbers
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) && numbers.next().is_none();
    valid_core
        && suffix.is_none_or(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::Value;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Deserialize)]
    struct Corpus {
        cases: Vec<CorpusCase>,
    }

    #[derive(Deserialize)]
    struct CorpusCase {
        name: String,
        valid: bool,
        manifest: Value,
    }

    #[test]
    fn shared_manifest_corpus_matches_workbench_rules() {
        let corpus: Corpus =
            serde_json::from_str(include_str!("../../../conformance/manifest-v1.cases.json"))
                .expect("parse manifest corpus");
        for case in corpus.cases {
            let result = serde_json::from_value::<PluginManifest>(case.manifest)
                .map_err(|error| error.to_string())
                .and_then(|manifest| validate_manifest(&manifest).map_err(|error| error.message));
            assert_eq!(
                result.is_ok(),
                case.valid,
                "manifest corpus case {} returned {result:?}",
                case.name
            );
        }
    }

    #[test]
    fn platform_key_uses_host_tokens() {
        let key = platform_key();
        let expected_os = if std::env::consts::OS == "macos" {
            "darwin"
        } else {
            std::env::consts::OS
        };
        assert!(key.starts_with(expected_os));
        assert!(!key.contains("x86_64"));
        assert!(!key.contains("aarch64"));
    }

    #[test]
    fn relative_plugin_directory_resolves_an_absolute_executable() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = TestDirectory(PathBuf::from("target").join(format!(
            "tokensaver-tsp-relative-plugin-{}-{unique}",
            std::process::id()
        )));
        fs::create_dir_all(&directory.0).expect("create relative plugin directory");
        let executable_name = if cfg!(windows) {
            "relative-plugin.exe"
        } else {
            "relative-plugin"
        };
        fs::copy(
            std::env::current_exe().expect("current test executable"),
            directory.0.join(executable_name),
        )
        .expect("copy relative plugin executable");
        let manifest = serde_json::json!({
            "apiVersion": 1,
            "id": "com.example.relative-plugin",
            "name": "Relative Plugin",
            "version": "0.1.0",
            "creator": { "name": "Test" },
            "runtime": {
                "kind": "executable",
                "entry": { platform_key(): executable_name }
            },
            "permissions": []
        });
        fs::write(
            directory.0.join("plugin.json"),
            serde_json::to_vec_pretty(&manifest).expect("serialize relative manifest"),
        )
        .expect("write relative manifest");

        let resolved = load_and_resolve(&directory.0).expect("resolve relative plugin");
        assert!(resolved.executable.is_absolute());
        assert!(resolved.executable.is_file());
    }

    #[test]
    fn packaged_manifest_digest_is_verified_before_execution() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = TestDirectory(std::env::temp_dir().join(format!(
            "tokensaver-tsp-integrity-{}-{unique}",
            std::process::id()
        )));
        fs::create_dir_all(&directory.0).expect("create test directory");
        let executable = directory.0.join(if cfg!(windows) {
            "plugin.exe"
        } else {
            "plugin"
        });
        fs::write(&executable, b"trusted executable").expect("write executable");
        let expected = format!("sha256:{:x}", Sha256::digest(b"trusted executable"));
        let platform = platform_key();
        let manifest = serde_json::json!({
            "apiVersion": 1,
            "id": "com.example.integrity",
            "name": "Integrity test",
            "version": "1.0.0",
            "creator": { "name": "Example" },
            "runtime": {
                "kind": "executable",
                "entry": { platform.clone(): executable.to_string_lossy() }
            },
            "integrity": {
                "algorithm": "sha256",
                "digests": { platform: expected }
            }
        });
        let manifest_path = directory.0.join("plugin.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write manifest");
        load_and_resolve(&manifest_path).expect("valid digest");

        fs::write(&executable, b"tampered executable").expect("tamper executable");
        let error = load_and_resolve(&manifest_path).expect_err("tampering must fail");
        assert_eq!(error.code, "integrity.digest");
    }
}
