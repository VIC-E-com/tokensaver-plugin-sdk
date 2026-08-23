use crate::certification::CertificationLevel;
use crate::manifest::{ResolvedPlugin, ValidationError};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const FRAME_MAX_BYTES: usize = 24 << 20;
const READ_MAX_BYTES: usize = 64 << 20;
const HEADER_MAX_BYTES: usize = 8 << 10;
const MAX_HEADERS: usize = 32;
const MAX_FRAMES: usize = 32;
const SPAWN_GRACE_MS: u64 = 250;
// Self-extracting standalone runtimes may need to remove their private runtime
// directory after the language process handles shutdown. This grace applies
// only after the protocol exchange, not to initialize or optimize deadlines.
const EXIT_GRACE_MS: u64 = 2_000;
const INPUT_MAX_BYTES: usize = 16 << 20;

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub name: String,
    pub detail: String,
    #[serde(
        rename = "activationAttemptId",
        skip_serializing_if = "Option::is_none"
    )]
    pub activation_attempt_id: Option<String>,
    #[serde(rename = "durationMs")]
    pub duration_ms: u128,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationReport {
    pub schema_version: u32,
    pub ok: bool,
    pub certification_level: CertificationLevel,
    pub plugin_id: String,
    pub version: String,
    pub platform: String,
    pub release_id: String,
    pub artifact_digest: String,
    pub manifest_path: String,
    pub executable: String,
    pub checks: Vec<Check>,
    pub duration_ms: u128,
}

#[derive(Clone, Debug)]
pub struct OptimizeRequest {
    pub kind: String,
    pub program: String,
    pub exit_code: i32,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OptimizeAction {
    Pass,
    Optimize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunReport {
    pub schema_version: u32,
    pub ok: bool,
    pub plugin_id: String,
    pub version: String,
    pub platform: String,
    pub release_id: String,
    pub artifact_digest: String,
    pub activation_attempt_id: String,
    pub action: OptimizeAction,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub saved_bytes: usize,
    pub savings_percent: f64,
    pub output: String,
    pub duration_ms: u128,
}

#[derive(Clone, Copy)]
enum Scenario {
    Lifecycle,
    BeforeInitialize,
    MalformedBase64,
}

#[derive(Clone, Debug)]
struct ExchangeContract {
    plugin_id: String,
    version: String,
    kind: String,
    max_input_bytes: i64,
    budget_ms: u32,
}

pub fn validate_plugin(plugin: &ResolvedPlugin) -> Result<ValidationReport, ValidationError> {
    let started = Instant::now();
    let mut checks = vec![
        Check {
            name: "manifest".into(),
            detail: "host-equivalent v1 semantics accepted".into(),
            activation_attempt_id: None,
            duration_ms: 0,
        },
        Check {
            name: "runtime".into(),
            detail: format!(
                "{} exists for {}",
                plugin.executable.display(),
                plugin.platform
            ),
            activation_attempt_id: None,
            duration_ms: 0,
        },
    ];
    if let Some(check) = crate::superec::validate_superec(plugin)? {
        checks.push(check);
    }
    checks.push(run_scenario(plugin, Scenario::Lifecycle)?);
    checks.push(run_scenario(plugin, Scenario::BeforeInitialize)?);
    checks.push(run_scenario(plugin, Scenario::MalformedBase64)?);
    Ok(ValidationReport {
        schema_version: 1,
        ok: true,
        certification_level: CertificationLevel::Conformant,
        plugin_id: plugin.manifest.id.clone(),
        version: plugin.manifest.version.clone(),
        platform: plugin.platform.clone(),
        release_id: plugin.release_id.clone(),
        artifact_digest: plugin.artifact_digest.clone(),
        manifest_path: plugin.manifest_path.display().to_string(),
        executable: plugin.executable.display().to_string(),
        checks,
        duration_ms: started.elapsed().as_millis(),
    })
}

pub fn run_fixture(
    plugin: &ResolvedPlugin,
    request: OptimizeRequest,
) -> Result<RunReport, ValidationError> {
    validate_fixture_request(plugin, &request)?;
    let activation_attempt_id = crate::identity::new_activation_attempt_id()?;
    run_fixture_with_activation(plugin, request, activation_attempt_id)
}

pub(crate) fn run_fixture_with_activation(
    plugin: &ResolvedPlugin,
    request: OptimizeRequest,
    activation_attempt_id: String,
) -> Result<RunReport, ValidationError> {
    if !crate::identity::valid_activation_attempt_id(&activation_attempt_id) {
        return Err(ValidationError::new(
            "identity.activationAttemptId",
            "activation-attempt id is invalid",
            "Generate activation-attempt ids with the workbench identity module.",
        ));
    }
    validate_fixture_request(plugin, &request)?;
    let started = Instant::now();
    let mut command = plugin_command(plugin, false);
    let mut child = command.spawn().map_err(|error| {
        ValidationError::new(
            "protocol.spawn",
            format!("could not start {}: {error}", plugin.executable.display()),
            "Build a native executable for this platform and verify it starts directly.",
        )
    })?;
    let stdin = child.stdin.take().ok_or_else(|| {
        stop_child(&mut child);
        ValidationError::new(
            "protocol.stdin",
            "plugin process did not expose stdin",
            "Keep stdin available for framed TSPP requests.",
        )
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        stop_child(&mut child);
        ValidationError::new(
            "protocol.stdout",
            "plugin process did not expose stdout",
            "Reserve stdout for framed TSPP responses.",
        )
    })?;

    let plugin_id = plugin.manifest.id.clone();
    let version = plugin.manifest.version.clone();
    let budget_ms = plugin.budget_ms;
    let raw = request.content.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let result = exchange_fixture(stdin, stdout, &plugin_id, &version, budget_ms, &request);
        let _ = sender.send(result);
    });
    let deadline = Duration::from_millis(u64::from(budget_ms) + SPAWN_GRACE_MS);
    let result = match receiver.recv_timeout(deadline) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            stop_child(&mut child);
            let _ = worker.join();
            return Err(ValidationError::new(
                "protocol.timeout",
                format!(
                    "plugin exceeded the {} ms host deadline",
                    deadline.as_millis()
                ),
                "Return initialize and optimize responses within limits.timeBudgetMs.",
            ));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            stop_child(&mut child);
            let _ = worker.join();
            return Err(ValidationError::new(
                "protocol.worker",
                "the protocol workbench worker stopped unexpectedly",
                "Check the plugin process for an early crash or invalid frame.",
            ));
        }
    };
    let (action, optimized) = match result {
        Ok(result) => result,
        Err(error) => {
            stop_child(&mut child);
            let _ = worker.join();
            return Err(error);
        }
    };
    let status = wait_for_exit(&mut child, Duration::from_millis(EXIT_GRACE_MS))?;
    let _ = worker.join();
    if !status.success() {
        return Err(ValidationError::new(
            "protocol.exit",
            format!("plugin exited with {status} after shutdown"),
            "Handle shutdown and exit successfully without writing non-protocol data to stdout.",
        ));
    }

    let output = optimized.unwrap_or_else(|| raw.clone());
    let saved_bytes = raw.len().saturating_sub(output.len());
    let savings_percent = if raw.is_empty() {
        0.0
    } else {
        saved_bytes as f64 * 100.0 / raw.len() as f64
    };
    Ok(RunReport {
        schema_version: 1,
        ok: true,
        plugin_id: plugin.manifest.id.clone(),
        version: plugin.manifest.version.clone(),
        platform: plugin.platform.clone(),
        release_id: plugin.release_id.clone(),
        artifact_digest: plugin.artifact_digest.clone(),
        activation_attempt_id,
        action,
        input_bytes: raw.len(),
        output_bytes: output.len(),
        saved_bytes,
        savings_percent,
        output: String::from_utf8(output).expect("fixture output was validated as UTF-8"),
        duration_ms: started.elapsed().as_millis(),
    })
}

pub(crate) fn validate_fixture_request(
    plugin: &ResolvedPlugin,
    request: &OptimizeRequest,
) -> Result<(), ValidationError> {
    if request.content.len() > INPUT_MAX_BYTES {
        return Err(ValidationError::new(
            "fixture.size",
            "fixture input exceeds the 16 MiB TSPP v1 limit",
            "Reduce the recorded command output to 16 MiB or less.",
        ));
    }
    if request.content.contains(&0) || std::str::from_utf8(&request.content).is_err() {
        return Err(ValidationError::new(
            "fixture.text",
            "fixture input must be UTF-8 text without NUL bytes",
            "Use a recorded text command output rather than binary data.",
        ));
    }
    let declared_limit = plugin.manifest.capabilities.max_input_bytes;
    if declared_limit > 0 && request.content.len() as i64 > declared_limit {
        return Err(ValidationError::new(
            "fixture.pluginLimit",
            format!(
                "fixture is {} bytes but the plugin declares maxInputBytes {declared_limit}",
                request.content.len()
            ),
            "Use a smaller fixture or raise capabilities.maxInputBytes.",
        ));
    }
    if !matches!(
        request.kind.as_str(),
        "test" | "build" | "lint" | "status" | "log"
    ) {
        return Err(ValidationError::new(
            "fixture.kind",
            format!("unknown command-output kind {:?}", request.kind),
            "Use test, build, lint, status, or log.",
        ));
    }
    let kinds = &plugin.manifest.capabilities.kinds;
    if !kinds.is_empty() && !kinds.contains(&request.kind) {
        return Err(ValidationError::new(
            "fixture.capability",
            format!("plugin does not declare the {:?} capability", request.kind),
            "Choose a declared capability or add it to capabilities.kinds.",
        ));
    }
    Ok(())
}

fn plugin_command(plugin: &ResolvedPlugin, discard_stderr: bool) -> Command {
    let mut command = Command::new(&plugin.executable);
    command
        .args(&plugin.args)
        .current_dir(
            plugin
                .executable
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
        )
        .env_clear()
        .env("TOKENSAVER_PLUGIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(if discard_stderr {
            Stdio::null()
        } else {
            Stdio::inherit()
        });
    // Keep the environment credential-free while retaining operating-system paths
    // required by native loaders and self-extracting standalone executables.
    for key in ["SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR"] {
        if let Some(value) = std::env::var_os(key).filter(|value| !value.is_empty()) {
            command.env(key, value);
        }
    }
    command
}

fn run_scenario(plugin: &ResolvedPlugin, scenario: Scenario) -> Result<Check, ValidationError> {
    let started = Instant::now();
    let activation_attempt_id = crate::identity::new_activation_attempt_id()?;
    let mut command = plugin_command(plugin, true);
    let mut child = command.spawn().map_err(|error| {
        ValidationError::new(
            "protocol.spawn",
            format!("could not start {}: {error}", plugin.executable.display()),
            "Build a native executable for this platform and verify it starts directly.",
        )
    })?;
    let stdin = child.stdin.take().ok_or_else(|| {
        stop_child(&mut child);
        ValidationError::new(
            "protocol.stdin",
            "plugin process did not expose stdin",
            "Keep stdin available for framed TSPP requests.",
        )
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        stop_child(&mut child);
        ValidationError::new(
            "protocol.stdout",
            "plugin process did not expose stdout",
            "Reserve stdout for framed TSPP responses.",
        )
    })?;

    let contract = ExchangeContract {
        plugin_id: plugin.manifest.id.clone(),
        version: plugin.manifest.version.clone(),
        kind: plugin
            .manifest
            .capabilities
            .kinds
            .first()
            .cloned()
            .unwrap_or_else(|| "test".into()),
        max_input_bytes: plugin.manifest.capabilities.max_input_bytes,
        budget_ms: plugin.budget_ms,
    };
    let budget_ms = contract.budget_ms;
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let result = exchange(stdin, stdout, scenario, &contract);
        let _ = sender.send(result);
    });

    let deadline = Duration::from_millis(u64::from(budget_ms) + SPAWN_GRACE_MS);
    let result = match receiver.recv_timeout(deadline) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            stop_child(&mut child);
            let _ = worker.join();
            return Err(ValidationError::new(
                "protocol.timeout",
                format!(
                    "plugin exceeded the {} ms host deadline",
                    deadline.as_millis()
                ),
                "Return initialize and optimize responses within limits.timeBudgetMs.",
            ));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            stop_child(&mut child);
            let _ = worker.join();
            return Err(ValidationError::new(
                "protocol.worker",
                "the protocol validation worker stopped unexpectedly",
                "Check the plugin process for an early crash or invalid frame.",
            ));
        }
    };

    if let Err(error) = result {
        stop_child(&mut child);
        let _ = worker.join();
        return Err(error);
    }
    let status = wait_for_exit(&mut child, Duration::from_millis(EXIT_GRACE_MS))?;
    let _ = worker.join();
    if !status.success() {
        return Err(ValidationError::new(
            "protocol.exit",
            format!("plugin exited with {status} after shutdown"),
            "Handle shutdown and exit successfully without writing non-protocol data to stdout.",
        ));
    }

    let (name, detail) = match scenario {
        Scenario::Lifecycle => (
            "lifecycle",
            "initialize identity, safe optimize response, shutdown, and exit verified",
        ),
        Scenario::BeforeInitialize => (
            "pre-initialize",
            "optimize before initialize rejected with JSON-RPC error -32002",
        ),
        Scenario::MalformedBase64 => (
            "malformed-input",
            "invalid base64 rejected with JSON-RPC error -32602",
        ),
    };
    Ok(Check {
        name: name.into(),
        detail: detail.into(),
        activation_attempt_id: Some(activation_attempt_id),
        duration_ms: started.elapsed().as_millis(),
    })
}

fn exchange(
    mut stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
    scenario: Scenario,
    contract: &ExchangeContract,
) -> Result<(), ValidationError> {
    let limited = stdout.take(READ_MAX_BYTES as u64);
    let mut reader = BufReader::new(limited);
    let result = match scenario {
        Scenario::Lifecycle => {
            initialize(
                &mut stdin,
                &mut reader,
                &contract.plugin_id,
                &contract.version,
                contract.budget_ms,
            )?;
            validate_normal_optimize(
                &mut stdin,
                &mut reader,
                &contract.kind,
                contract.max_input_bytes,
                contract.budget_ms,
            )
        }
        Scenario::BeforeInitialize => {
            write_frame(
                &mut stdin,
                &json!({
                    "jsonrpc": "2.0", "id": 2, "method": "optimize", "params": {}
                }),
            )?;
            expect_error(&mut reader, 2, -32002, "protocol.preInitialize")
        }
        Scenario::MalformedBase64 => {
            initialize(
                &mut stdin,
                &mut reader,
                &contract.plugin_id,
                &contract.version,
                contract.budget_ms,
            )?;
            write_frame(
                &mut stdin,
                &json!({
                    "jsonrpc": "2.0", "id": 2, "method": "optimize",
                    "params": {
                        "kind": &contract.kind, "program": "tsp-fixture", "exitCode": 1,
                        "encoding": "base64", "content": "%%%", "budgetMs": contract.budget_ms
                    }
                }),
            )?;
            expect_error(&mut reader, 2, -32602, "protocol.malformedBase64")
        }
    };
    let _ = write_frame(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "method": "shutdown" }),
    );
    result
}

fn exchange_fixture(
    mut stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
    plugin_id: &str,
    version: &str,
    budget_ms: u32,
    request: &OptimizeRequest,
) -> Result<(OptimizeAction, Option<Vec<u8>>), ValidationError> {
    let limited = stdout.take(READ_MAX_BYTES as u64);
    let mut reader = BufReader::new(limited);
    let result = (|| {
        initialize(&mut stdin, &mut reader, plugin_id, version, budget_ms)?;
        write_frame(
            &mut stdin,
            &json!({
                "jsonrpc": "2.0", "id": 2, "method": "optimize",
                "params": {
                    "kind": &request.kind,
                    "program": program_basename(&request.program),
                    "exitCode": request.exit_code,
                    "encoding": "base64",
                    "content": BASE64.encode(&request.content),
                    "budgetMs": budget_ms
                }
            }),
        )?;
        let response = read_response(&mut reader, 2)?;
        parse_optimize_response(&response, &request.content)
    })();
    let _ = write_frame(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "method": "shutdown" }),
    );
    result
}

fn program_basename(program: &str) -> String {
    std::path::Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("tsp-fixture")
        .to_owned()
}

fn initialize<W: Write, R: BufRead>(
    writer: &mut W,
    reader: &mut R,
    expected_id: &str,
    expected_version: &str,
    budget_ms: u32,
) -> Result<(), ValidationError> {
    write_frame(
        writer,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "apiVersion": 1, "host": "tsp", "budgetMs": budget_ms }
        }),
    )?;
    let response = read_response(reader, 1)?;
    if response.get("error").is_some_and(|value| !value.is_null()) {
        return Err(ValidationError::new(
            "protocol.initialize",
            format!("plugin rejected initialize: {response}"),
            "Accept the TSPP v1 initialize request and return apiVersion, pluginId, and version.",
        ));
    }
    let result = response.get("result").unwrap_or(&Value::Null);
    if result.get("apiVersion") != Some(&json!(1))
        || result.get("pluginId").and_then(Value::as_str) != Some(expected_id)
        || result.get("version").and_then(Value::as_str) != Some(expected_version)
    {
        return Err(ValidationError::new(
            "protocol.identity",
            format!("initialize identity does not match plugin.json: {result}"),
            "Compile the manifest id and version into the plugin initialize response.",
        ));
    }
    Ok(())
}

fn validate_normal_optimize<W: Write, R: BufRead>(
    writer: &mut W,
    reader: &mut R,
    kind: &str,
    max_input_bytes: i64,
    budget_ms: u32,
) -> Result<(), ValidationError> {
    let raw = conformance_fixture(max_input_bytes);
    write_frame(
        writer,
        &json!({
            "jsonrpc": "2.0", "id": 2, "method": "optimize",
            "params": {
                "kind": kind, "program": "tsp-fixture", "exitCode": 1,
                "encoding": "base64", "content": BASE64.encode(&raw), "budgetMs": budget_ms
            }
        }),
    )?;
    let response = read_response(reader, 2)?;
    parse_optimize_response(&response, &raw).map(|_| ())
}

fn parse_optimize_response(
    response: &Value,
    raw: &[u8],
) -> Result<(OptimizeAction, Option<Vec<u8>>), ValidationError> {
    if response.get("error").is_some_and(|value| !value.is_null()) {
        return Err(ValidationError::new(
            "protocol.optimize",
            format!("plugin rejected a valid optimize request: {response}"),
            "Accept valid base64 UTF-8 command output after initialize.",
        ));
    }
    let result = response.get("result").unwrap_or(&Value::Null);
    match result.get("action").and_then(Value::as_str) {
        Some("pass") => Ok((OptimizeAction::Pass, None)),
        Some("optimize") => {
            let encoded = result
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ValidationError::new(
                        "safety.content",
                        "optimize response has no base64 content",
                        "Return content when action is optimize, or return action pass.",
                    )
                })?;
            let content = BASE64.decode(encoded).map_err(|_| {
                ValidationError::new(
                    "safety.base64",
                    "optimized content is not valid base64",
                    "Encode optimized UTF-8 bytes with standard base64.",
                )
            })?;
            if content.is_empty() || content.contains(&0) || std::str::from_utf8(&content).is_err()
            {
                return Err(ValidationError::new(
                    "safety.text",
                    "optimized content must be non-empty UTF-8 without NUL bytes",
                    "Return safe text or action pass when no safe optimization is available.",
                ));
            }
            if content.len().saturating_mul(100) >= raw.len().saturating_mul(80) {
                return Err(ValidationError::new(
                    "safety.reduction",
                    format!(
                        "optimized content is {} bytes from {} bytes; at least 20% reduction is required",
                        content.len(),
                        raw.len()
                    ),
                    "Return action pass unless the proposal is at least 20% smaller.",
                ));
            }
            Ok((OptimizeAction::Optimize, Some(content)))
        }
        other => Err(ValidationError::new(
            "protocol.action",
            format!("unknown optimize action: {other:?}"),
            "Return action pass or action optimize.",
        )),
    }
}

fn expect_error<R: BufRead>(
    reader: &mut R,
    id: i64,
    expected_code: i64,
    rule: &'static str,
) -> Result<(), ValidationError> {
    let response = read_response(reader, id)?;
    let code = response
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_i64);
    if code != Some(expected_code) {
        return Err(ValidationError::new(
            rule,
            format!("expected JSON-RPC error {expected_code}, got {response}"),
            "Use the public SDK protocol loop or implement the documented TSPP error contract.",
        ));
    }
    Ok(())
}

fn read_response<R: BufRead>(reader: &mut R, id: i64) -> Result<Value, ValidationError> {
    for _ in 0..MAX_FRAMES {
        let frame = read_frame(reader)?;
        let value: Value = serde_json::from_slice(&frame).map_err(|error| {
            ValidationError::new(
                "protocol.json",
                format!("plugin response is not valid JSON: {error}"),
                "Write only framed JSON-RPC 2.0 messages to stdout.",
            )
        })?;
        if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(ValidationError::new(
                "protocol.jsonrpc",
                format!("plugin response is not JSON-RPC 2.0: {value}"),
                "Set jsonrpc to 2.0 on every response.",
            ));
        }
        if value.get("id").and_then(Value::as_i64) == Some(id) {
            return Ok(value);
        }
    }
    Err(ValidationError::new(
        "protocol.frameBudget",
        "plugin did not return the requested response within 32 frames",
        "Return the matching response without unbounded notifications.",
    ))
}

fn write_frame<W: Write>(writer: &mut W, value: &Value) -> Result<(), ValidationError> {
    let payload = serde_json::to_vec(value).map_err(|error| {
        ValidationError::new(
            "workbench.json",
            format!("could not serialize validation request: {error}"),
            "Report this TokenSaver SDK defect.",
        )
    })?;
    write!(writer, "Content-Length: {}\r\n\r\n", payload.len())
        .and_then(|_| writer.write_all(&payload))
        .and_then(|_| writer.flush())
        .map_err(|error| {
            ValidationError::new(
                "protocol.write",
                format!("could not write a TSPP request: {error}"),
                "Keep the plugin alive and reading stdin until shutdown.",
            )
        })
}

fn read_frame<R: BufRead>(reader: &mut R) -> Result<Vec<u8>, ValidationError> {
    let mut content_length = None;
    let mut header_bytes = 0usize;
    for header_count in 0..=MAX_HEADERS {
        let mut line = Vec::new();
        let read = reader
            .read_until(b'\n', &mut line)
            .map_err(frame_read_error)?;
        if read == 0 {
            return Err(frame_read_error("plugin closed stdout before responding"));
        }
        header_bytes = header_bytes.saturating_add(read);
        if header_bytes > HEADER_MAX_BYTES {
            return Err(frame_read_error("frame headers exceed 8 KiB"));
        }
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        if line.is_empty() {
            if let Some(length) = content_length {
                let mut frame = vec![0; length];
                reader.read_exact(&mut frame).map_err(frame_read_error)?;
                return Ok(frame);
            }
            continue;
        }
        let separator = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| frame_read_error("malformed frame header"))?;
        let name = std::str::from_utf8(&line[..separator])
            .map_err(|_| frame_read_error("frame header name is not UTF-8"))?
            .trim();
        if name.eq_ignore_ascii_case("Content-Length") {
            let value = std::str::from_utf8(&line[separator + 1..])
                .map_err(|_| frame_read_error("Content-Length is not UTF-8"))?
                .trim();
            let length = value
                .parse::<usize>()
                .map_err(|_| frame_read_error("Content-Length is not a number"))?;
            if length == 0 || length > FRAME_MAX_BYTES {
                return Err(frame_read_error(
                    "Content-Length is outside the frame limit",
                ));
            }
            content_length = Some(length);
        }
        if header_count == MAX_HEADERS {
            return Err(frame_read_error("too many frame headers"));
        }
    }
    Err(frame_read_error("frame has no Content-Length"))
}

fn frame_read_error(error: impl std::fmt::Display) -> ValidationError {
    ValidationError::new(
        "protocol.frame",
        format!("could not read a bounded TSPP frame: {error}"),
        "Use Content-Length framing and reserve stdout for TSPP messages.",
    )
}

fn conformance_fixture(max_input_bytes: i64) -> Vec<u8> {
    let mut fixture = (0..140)
        .map(|index| {
            if index == 80 {
                format!("line {index}: ERROR conformance failure {}", "x".repeat(72))
            } else {
                format!("line {index}: conformance output {}", "x".repeat(72))
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    if max_input_bytes > 0 {
        fixture.truncate(fixture.len().min(max_input_bytes as usize));
    }
    fixture
}

fn wait_for_exit(
    child: &mut Child,
    grace: Duration,
) -> Result<std::process::ExitStatus, ValidationError> {
    let deadline = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                stop_child(child);
                return Err(ValidationError::new(
                    "protocol.shutdown",
                    "plugin did not exit within 250 ms after shutdown",
                    "Handle the shutdown notification and exit promptly.",
                ));
            }
            Err(error) => {
                stop_child(child);
                return Err(ValidationError::new(
                    "protocol.wait",
                    format!("could not wait for the plugin process: {error}"),
                    "Ensure the plugin process can be supervised by its parent.",
                ));
            }
        }
    }
}

fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn response(value: Value) -> BufReader<Cursor<Vec<u8>>> {
        let mut frame = Vec::new();
        write_frame(&mut frame, &value).expect("frame response");
        BufReader::new(Cursor::new(frame))
    }

    #[test]
    fn frame_reader_rejects_invalid_lengths() {
        for input in [
            "Content-Length: 0\r\n\r\n".to_string(),
            format!("Content-Length: {}\r\n\r\n", FRAME_MAX_BYTES + 1),
            "Broken\r\n\r\n".to_string(),
        ] {
            assert!(read_frame(&mut BufReader::new(Cursor::new(input))).is_err());
        }
    }

    #[test]
    fn conformance_fixture_exercises_host_eligible_output() {
        let fixture = conformance_fixture(0);
        assert!(fixture.len() > 4096);
        assert!(
            std::str::from_utf8(&fixture)
                .expect("UTF-8")
                .contains("ERROR")
        );
        assert_eq!(conformance_fixture(128).len(), 128);
    }

    #[test]
    fn optimize_response_safety_matches_host_acceptance_rules() {
        let mut writer = Vec::new();
        let mut pass = response(json!({
            "jsonrpc": "2.0", "id": 2, "result": { "action": "pass" }
        }));
        validate_normal_optimize(&mut writer, &mut pass, "test", 0, 250)
            .expect("pass is conformant");

        let mut unsafe_output = response(json!({
            "jsonrpc": "2.0", "id": 2,
            "result": { "action": "optimize", "content": BASE64.encode([0]) }
        }));
        let error = validate_normal_optimize(&mut Vec::new(), &mut unsafe_output, "test", 0, 250)
            .expect_err("NUL output must fail");
        assert_eq!(error.code, "safety.text");

        let raw = conformance_fixture(0);
        let insufficient = &raw[..raw.len() * 9 / 10];
        let mut insufficient_output = response(json!({
            "jsonrpc": "2.0", "id": 2,
            "result": { "action": "optimize", "content": BASE64.encode(insufficient) }
        }));
        let error =
            validate_normal_optimize(&mut Vec::new(), &mut insufficient_output, "test", 0, 250)
                .expect_err("insufficient reduction must fail");
        assert_eq!(error.code, "safety.reduction");

        let mut unknown_action = response(json!({
            "jsonrpc": "2.0", "id": 2, "result": { "action": "replace" }
        }));
        let error = validate_normal_optimize(&mut Vec::new(), &mut unknown_action, "test", 0, 250)
            .expect_err("unknown action must fail");
        assert_eq!(error.code, "protocol.action");
    }
}
