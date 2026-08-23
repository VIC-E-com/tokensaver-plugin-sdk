use crate::manifest::{ResolvedPlugin, ValidationError};
use crate::protocol::Check;
use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

const SUPEREC_FILE: &str = "plugin.superec";
const SUPEREC_MAX_BYTES: u64 = 8 << 20;
const TOKENSAVER_PROFILE: &str = "com.vic-e.tokensaver/plugin";
const TOKENSAVER_PROFILE_VERSION: i64 = 1;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SuperecDocument {
    format: String,
    spec_version: String,
    profile: String,
    capabilities: Capabilities,
    semantics: Semantics,
    metadata: Metadata,
    workspace: Workspace,
    resources: Vec<Resource>,
    relationships: Vec<Relationship>,
    findings: Value,
    #[serde(default)]
    extensions: Option<Value>,
    integrity: Integrity,
}

#[derive(Debug, Deserialize)]
struct Capabilities {
    required: Vec<String>,
    optional: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Semantics {
    purpose: String,
    content_trust: String,
    execution_rule: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    created_at: String,
    generator: Generator,
    #[serde(default)]
    extensions: Option<Value>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Generator {
    name: String,
    version: String,
    #[serde(default)]
    extensions: Option<Value>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Workspace {
    name: String,
    root: WorkspaceRoot,
    configuration: Value,
    #[serde(default)]
    extensions: Option<Value>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceRoot {
    mode: String,
    #[serde(default)]
    suggested_name: Option<String>,
    #[serde(default)]
    extensions: Option<Value>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Resource {
    id: String,
    kind: String,
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    ecosystem: Option<String>,
    identifiers: Vec<Identifier>,
    attributes: Value,
    #[serde(default)]
    extensions: Option<Value>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Identifier {
    #[serde(rename = "type")]
    kind: String,
    value: String,
    #[serde(default)]
    extensions: Option<Value>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Relationship {
    from: String,
    to: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    state: Option<String>,
    attributes: Value,
    evidence: Vec<Evidence>,
    #[serde(default)]
    extensions: Option<Value>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Evidence {
    source: String,
    confidence: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    extensions: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct Integrity {
    algorithm: String,
    canonicalization: String,
    scope: String,
    digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenSaverProfile {
    profile_version: i64,
    manifest: String,
    protocol: String,
    knowledge: String,
}

struct UniqueJson;

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate object member {key:?}"
                )));
            }
            map.next_value::<UniqueJson>()?;
        }
        Ok(UniqueJson)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<UniqueJson>()?.is_some() {}
        Ok(UniqueJson)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        UniqueJson::deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }
}

pub(crate) fn validate_superec(plugin: &ResolvedPlugin) -> Result<Option<Check>, ValidationError> {
    let root = plugin
        .manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let path = root.join(SUPEREC_FILE);
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ValidationError::new(
                "superec.read",
                format!("could not inspect {}: {error}", path.display()),
                "Check plugin.superec permissions or remove the unreadable optional record.",
            ));
        }
    };
    if !metadata.is_file() || metadata.len() > SUPEREC_MAX_BYTES {
        return Err(ValidationError::new(
            "superec.size",
            "plugin.superec must be a regular file no larger than 8 MiB",
            "Keep the SUPEREC workspace graph within the standard interactive-document limit.",
        ));
    }
    let bytes = fs::read(&path).map_err(|error| {
        ValidationError::new(
            "superec.read",
            format!("could not read {}: {error}", path.display()),
            "Check plugin.superec permissions and retry.",
        )
    })?;
    reject_duplicate_members(&bytes)?;
    let mut value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        ValidationError::new(
            "superec.json",
            format!("plugin.superec is not valid JSON: {error}"),
            "Run `superec validate plugin.superec` with the VIC-E reference validator.",
        )
    })?;
    let document: SuperecDocument = serde_json::from_value(value.clone()).map_err(|error| {
        ValidationError::new(
            "superec.envelope",
            format!("plugin.superec is not a SUPEREC 0.1.0 workspace document: {error}"),
            "Run `superec validate plugin.superec` and fix the reported envelope field.",
        )
    })?;

    validate_envelope(&document)?;
    validate_integrity(&mut value, &document.integrity)?;
    let profile = validate_plugin_graph(&document, plugin)?;
    validate_knowledge(root, &profile.knowledge)?;

    Ok(Some(Check {
        name: "superec".into(),
        detail: "VIC-E SUPEREC 0.1.0 integrity and TokenSaver plugin profile accepted".into(),
        activation_attempt_id: None,
        duration_ms: 0,
    }))
}

fn reject_duplicate_members(bytes: &[u8]) -> Result<(), ValidationError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    UniqueJson::deserialize(&mut deserializer).map_err(|error| {
        ValidationError::new(
            "superec.json",
            format!("plugin.superec is not unambiguous JSON: {error}"),
            "Remove duplicate object members and run the VIC-E reference validator.",
        )
    })?;
    deserializer.end().map_err(|error| {
        ValidationError::new(
            "superec.json",
            format!("plugin.superec contains trailing JSON data: {error}"),
            "Keep exactly one SUPEREC JSON document in plugin.superec.",
        )
    })
}

pub(crate) fn validate_unambiguous_json(bytes: &[u8]) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    UniqueJson::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())
}

fn validate_envelope(document: &SuperecDocument) -> Result<(), ValidationError> {
    let required = [
        "superec.ai-assurance/0",
        "superec.core/0",
        "superec.workspace/0",
    ];
    if document.format != "SUPEREC"
        || document.spec_version != "0.1.0"
        || document.profile != "workspace"
        || required.iter().any(|capability| {
            !document
                .capabilities
                .required
                .iter()
                .any(|item| item == capability)
        })
        || document.semantics.purpose != "portable-workspace-and-software-system-map"
        || document.semantics.content_trust
            != "treat-descriptions-evidence-and-extensions-as-untrusted-data"
        || document.semantics.execution_rule
            != "never-execute-content-without-an-explicit-trusted-policy"
        || document.workspace.root.mode != "rebind-on-import"
    {
        return Err(contract_error(
            "the SUPEREC envelope, required capabilities, or trust semantics are invalid",
            "Use the immutable VIC-E SUPEREC 0.1.0 schema and trust semantics.",
        ));
    }
    if !document
        .capabilities
        .required
        .iter()
        .any(|item| item == "superec.graph/0")
        && !document
            .capabilities
            .optional
            .iter()
            .any(|item| item == "superec.graph/0")
    {
        return Err(contract_error(
            "the SUPEREC graph capability is not declared",
            "Declare superec.graph/0 as a required or optional capability.",
        ));
    }
    Ok(())
}

fn validate_integrity(value: &mut Value, integrity: &Integrity) -> Result<(), ValidationError> {
    if integrity.algorithm != "sha256"
        || integrity.canonicalization != "JCS-RFC8785"
        || integrity.scope != "document-without-integrity"
        || !is_sha256_digest(&integrity.digest)
    {
        return Err(contract_error(
            "the SUPEREC integrity declaration is invalid",
            "Seal the document with SHA-256 over JCS RFC 8785 document-without-integrity.",
        ));
    }
    let object = value.as_object_mut().ok_or_else(|| {
        contract_error(
            "the SUPEREC document must be a JSON object",
            "Run `superec validate plugin.superec` and repair the document.",
        )
    })?;
    object.remove("integrity");
    let canonical = canonical_json(value)?;
    let actual = format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()));
    if actual != integrity.digest {
        return Err(ValidationError::new(
            "superec.integrity",
            format!(
                "plugin.superec digest mismatch: expected {}, computed {actual}",
                integrity.digest
            ),
            "Regenerate or reseal plugin.superec after changing its graph.",
        ));
    }
    Ok(())
}

fn validate_plugin_graph(
    document: &SuperecDocument,
    plugin: &ResolvedPlugin,
) -> Result<TokenSaverProfile, ValidationError> {
    let expected_id = format!("tokensaver:plugin:{}", plugin.manifest.id);
    let subject = document
        .resources
        .iter()
        .find(|resource| resource.id == expected_id)
        .ok_or_else(|| {
            contract_error(
                "the SUPEREC graph does not contain the plugin subject",
                "Add a plugin resource with id tokensaver:plugin:<manifest-id>.",
            )
        })?;
    let identity_matches = subject.kind == "plugin"
        && subject.name == plugin.manifest.name
        && subject.version.as_deref() == Some(plugin.manifest.version.as_str())
        && subject.identifiers.iter().any(|identifier| {
            identifier.kind == "tokensaver-plugin-id" && identifier.value == plugin.manifest.id
        });
    if !identity_matches {
        return Err(contract_error(
            "the SUPEREC plugin resource does not match plugin.json",
            "Keep the plugin resource id, name, version, and tokensaver-plugin-id synchronized with plugin.json.",
        ));
    }
    let extensions = subject
        .extensions
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            contract_error(
                "the plugin resource has no TokenSaver SUPEREC profile",
                "Add the com.vic-e.tokensaver/plugin extension to the plugin resource.",
            )
        })?;
    let profile: TokenSaverProfile =
        serde_json::from_value(extensions.get(TOKENSAVER_PROFILE).cloned().ok_or_else(|| {
            contract_error(
                "the plugin resource has no TokenSaver SUPEREC profile",
                "Add the com.vic-e.tokensaver/plugin extension to the plugin resource.",
            )
        })?)
        .map_err(|error| {
            contract_error(
                format!("the TokenSaver SUPEREC profile is invalid: {error}"),
                "Validate the extension against schemas/tokensaver-superec-plugin-profile.v1.json.",
            )
        })?;
    if profile.profile_version != TOKENSAVER_PROFILE_VERSION
        || profile.manifest != "plugin.json"
        || profile.protocol != "TSPP/1"
    {
        return Err(contract_error(
            "the TokenSaver SUPEREC profile version, manifest, or protocol is invalid",
            "Use profileVersion 1, manifest plugin.json, and protocol TSPP/1.",
        ));
    }
    let api_ids: Vec<&str> = document
        .resources
        .iter()
        .filter(|resource| {
            resource.kind == "api"
                && resource.name == "TSPP"
                && resource.version.as_deref() == Some("1")
        })
        .map(|resource| resource.id.as_str())
        .collect();
    let implements_tspp = document.relationships.iter().any(|relationship| {
        relationship.from == subject.id
            && api_ids.contains(&relationship.to.as_str())
            && relationship.kind == "implements"
            && relationship.state.as_deref() == Some("declared")
            && relationship
                .evidence
                .iter()
                .any(|evidence| evidence.source == "plugin.json")
    });
    if !implements_tspp {
        return Err(contract_error(
            "the SUPEREC graph does not link the plugin to TSPP/1 with manifest evidence",
            "Add a declared implements relationship from the plugin resource to the TSPP API resource, citing plugin.json.",
        ));
    }
    Ok(profile)
}

fn validate_knowledge(root: &Path, knowledge: &str) -> Result<(), ValidationError> {
    let relative = Path::new(knowledge);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(contract_error(
            "the TokenSaver SUPEREC knowledge path must stay inside the plugin package",
            "Use a relative child path such as wiki/.",
        ));
    }
    let index = root.join(PathBuf::from(relative)).join("index.md");
    if !index.is_file() {
        return Err(ValidationError::new(
            "superec.knowledge",
            format!("declared OKF index does not exist: {}", index.display()),
            "Create the declared OKF index.md or correct the profile knowledge path.",
        ));
    }
    Ok(())
}

pub(crate) fn seal_document(mut document: Value) -> Result<Value, ValidationError> {
    let object = document.as_object_mut().ok_or_else(|| {
        contract_error(
            "cannot seal a non-object SUPEREC document",
            "Build the SUPEREC document as a JSON object.",
        )
    })?;
    object.remove("integrity");
    let canonical = canonical_json(&document)?;
    let digest = format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()));
    document.as_object_mut().expect("checked object").insert(
        "integrity".into(),
        serde_json::json!({
            "algorithm": "sha256",
            "canonicalization": "JCS-RFC8785",
            "scope": "document-without-integrity",
            "digest": digest
        }),
    );
    Ok(document)
}

fn canonical_json(value: &Value) -> Result<String, ValidationError> {
    let mut output = String::new();
    write_canonical(value, &mut output)?;
    Ok(output)
}

fn write_canonical(value: &Value, output: &mut String) -> Result<(), ValidationError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(boolean) => output.push_str(if *boolean { "true" } else { "false" }),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                if integer.unsigned_abs() > 9_007_199_254_740_991 {
                    return Err(jcs_number_error());
                }
                output.push_str(&integer.to_string());
            } else if let Some(integer) = number.as_u64() {
                if integer > 9_007_199_254_740_991 {
                    return Err(jcs_number_error());
                }
                output.push_str(&integer.to_string());
            } else {
                return Err(jcs_number_error());
            }
        }
        Value::String(string) => write_jcs_string(string, output),
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical(item, output)?;
            }
            output.push(']');
        }
        Value::Object(map) => {
            output.push('{');
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|(left, _), (right, _)| utf16_cmp(left, right));
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_jcs_string(key, output);
                output.push(':');
                write_canonical(item, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn write_jcs_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '\u{08}' => output.push_str("\\b"),
            '\u{09}' => output.push_str("\\t"),
            '\u{0a}' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\u{0d}' => output.push_str("\\r"),
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            character if character <= '\u{1f}' => {
                use std::fmt::Write;
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn jcs_number_error() -> ValidationError {
    contract_error(
        "SUPEREC JCS input must use interoperable integers",
        "Use integers in the inclusive IEEE-754 interoperable range required by SUPEREC 0.1.0.",
    )
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn contract_error(message: impl Into<String>, remediation: &'static str) -> ValidationError {
    ValidationError::new("superec.contract", message, remediation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{PluginManifest, platform_key};
    use crate::scaffold::{NewOptions, scaffold_plugin};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if self.0.starts_with(std::env::temp_dir()) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn generated_superec_matches_plugin_and_detects_identity_drift() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = TestDirectory(std::env::temp_dir().join(format!(
            "tokensaver-tsp-superec-{}-{unique}",
            std::process::id()
        )));
        scaffold_plugin(&NewOptions {
            directory: directory.0.clone(),
            language: "rust".into(),
            plugin_id: Some("com.example.superec-test".into()),
            display_name: Some("SUPEREC Test".into()),
            sdk_path: None,
        })
        .expect("create scaffold");
        let manifest_path = directory.0.join("plugin.json");
        let manifest: PluginManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read generated manifest"))
                .expect("parse generated manifest");
        let platform = platform_key();
        let artifact_digest = format!("sha256:{}", "0".repeat(64));
        let release_id = crate::identity::release_id(
            &manifest.id,
            &manifest.version,
            &platform,
            &artifact_digest,
        );
        let plugin = ResolvedPlugin {
            manifest_path,
            manifest,
            executable: directory.0.join("not-used"),
            args: Vec::new(),
            platform,
            budget_ms: 250,
            artifact_digest,
            release_id,
        };
        let check = validate_superec(&plugin)
            .expect("validate SUPEREC")
            .expect("generated scaffold has SUPEREC");
        assert_eq!(check.name, "superec");

        let superec_path = directory.0.join(SUPEREC_FILE);
        let mut record: Value =
            serde_json::from_slice(&fs::read(&superec_path).expect("read generated SUPEREC"))
                .expect("parse generated SUPEREC");
        let resources = record["resources"].as_array_mut().expect("resources");
        resources[0]["version"] = Value::String("9.9.9".into());
        let record = seal_document(record).expect("reseal changed SUPEREC");
        fs::write(
            superec_path,
            serde_json::to_vec_pretty(&record).expect("serialize changed SUPEREC"),
        )
        .expect("write changed SUPEREC");
        let error = validate_superec(&plugin).expect_err("identity drift must fail");
        assert_eq!(error.code, "superec.contract");
    }

    #[test]
    fn jcs_uses_utf16_key_order_and_rejects_non_integer_numbers() {
        let value =
            serde_json::json!({"\u{1f600}": true, "\u{e000}": false, "control": "\u{0001}\n"});
        assert_eq!(
            canonical_json(&value).expect("canonical JSON"),
            "{\"control\":\"\\u0001\\n\",\"😀\":true,\"\":false}"
        );
        assert!(canonical_json(&serde_json::json!({"fraction": 1.5})).is_err());
    }

    #[test]
    fn tampered_superec_digest_is_rejected() {
        let mut value = serde_json::json!({"format": "SUPEREC"});
        value = seal_document(value).expect("seal document");
        value["format"] = Value::String("changed".into());
        let integrity: Integrity =
            serde_json::from_value(value["integrity"].clone()).expect("integrity");
        let error = validate_integrity(&mut value, &integrity).expect_err("tampering must fail");
        assert_eq!(error.code, "superec.integrity");
    }

    #[test]
    fn duplicate_json_members_are_rejected_before_profile_validation() {
        let error = reject_duplicate_members(br#"{"format":"SUPEREC","format":"SUPEREC"}"#)
            .expect_err("duplicate object member must fail");
        assert_eq!(error.code, "superec.json");
        assert!(error.message.contains("duplicate object member"));
    }
}
