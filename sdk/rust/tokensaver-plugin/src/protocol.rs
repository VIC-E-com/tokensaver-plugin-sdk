use crate::model::{Action, MAX_CONTENT_BYTES, Optimizer, Request};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::error::Error;
use std::fmt;
use std::io::{self, BufRead, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};

const API_VERSION: u32 = 1;
const MAX_FRAME_BYTES: usize = 24 << 20;
const MAX_HEADER_BYTES: usize = 8 << 10;
const MAX_HEADERS: usize = 32;

#[derive(Debug)]
pub enum ProtocolError {
    Io(io::Error),
    MalformedHeader,
    MissingContentLength,
    InvalidContentLength,
    TooManyHeaders,
    HeaderTooLarge,
    InvalidJson(serde_json::Error),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "protocol I/O failed: {error}"),
            Self::MalformedHeader => formatter.write_str("malformed TSPP frame header"),
            Self::MissingContentLength => formatter.write_str("TSPP frame has no Content-Length"),
            Self::InvalidContentLength => formatter.write_str("invalid TSPP Content-Length"),
            Self::TooManyHeaders => formatter.write_str("too many TSPP frame headers"),
            Self::HeaderTooLarge => formatter.write_str("TSPP frame headers exceed the size limit"),
            Self::InvalidJson(error) => write!(formatter, "invalid TSPP JSON: {error}"),
        }
    }
}

impl Error for ProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidJson(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ProtocolError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for ProtocolError {
    fn from(error: serde_json::Error) -> Self {
        Self::InvalidJson(error)
    }
}

#[derive(Deserialize)]
struct RpcRequest {
    #[serde(default)]
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InitializeParams {
    api_version: u32,
    #[allow(dead_code)]
    host: String,
    #[allow(dead_code)]
    budget_ms: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OptimizeParams {
    kind: String,
    program: String,
    exit_code: i32,
    encoding: String,
    content: String,
    budget_ms: u32,
}

/// Serves TSPP v1 on caller-provided streams. This is public so workbenches
/// and plugin tests can exercise exactly the runtime used by `run`.
pub fn serve<O: Optimizer, R: BufRead, W: Write>(
    optimizer: &O,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), ProtocolError> {
    let mut initialized = false;
    while let Some(frame) = read_frame(reader)? {
        let request: RpcRequest = serde_json::from_slice(&frame)?;
        if request.jsonrpc != "2.0" {
            write_error(writer, request.id, -32600, "jsonrpc must be 2.0")?;
            continue;
        }
        match request.method.as_str() {
            "initialize" => {
                let params: InitializeParams = match serde_json::from_value(request.params) {
                    Ok(params) => params,
                    Err(_) => {
                        write_error(writer, request.id, -32602, "invalid initialize params")?;
                        continue;
                    }
                };
                if params.api_version != API_VERSION {
                    write_error(writer, request.id, -32602, "unsupported apiVersion")?;
                    continue;
                }
                initialized = true;
                write_result(
                    writer,
                    request.id,
                    json!({
                        "apiVersion": API_VERSION,
                        "pluginId": O::PLUGIN_ID,
                        "version": O::VERSION,
                    }),
                )?;
            }
            "optimize" => {
                if !initialized {
                    write_error(writer, request.id, -32002, "plugin is not initialized")?;
                    continue;
                }
                let params: OptimizeParams = match serde_json::from_value(request.params) {
                    Ok(params) => params,
                    Err(_) => {
                        write_error(writer, request.id, -32602, "invalid optimize params")?;
                        continue;
                    }
                };
                let decoded = match decode_request(params) {
                    Ok(request) => request,
                    Err(message) => {
                        write_error(writer, request.id, -32602, message)?;
                        continue;
                    }
                };
                let action = catch_unwind(AssertUnwindSafe(|| optimizer.optimize(decoded)));
                match action {
                    Ok(Action::Pass) => {
                        write_result(writer, request.id, json!({ "action": "pass" }))?;
                    }
                    Ok(Action::Optimize(content)) => {
                        // Action fields are public for ergonomic matching, so enforce
                        // constructor invariants again at the protocol boundary.
                        if content.is_empty()
                            || content.as_bytes().contains(&0)
                            || content.len() > MAX_CONTENT_BYTES
                        {
                            write_error(writer, request.id, -32603, "unsafe optimized content")?;
                            continue;
                        }
                        write_result(
                            writer,
                            request.id,
                            json!({
                                "action": "optimize",
                                "content": BASE64.encode(content.as_bytes()),
                            }),
                        )?;
                    }
                    Err(_) => {
                        write_error(writer, request.id, -32603, "optimizer panicked")?;
                    }
                }
            }
            "shutdown" => break,
            _ => write_error(writer, request.id, -32601, "method not found")?,
        }
    }
    Ok(())
}

fn decode_request(params: OptimizeParams) -> Result<Request, &'static str> {
    if params.encoding != "base64" {
        return Err("encoding must be base64");
    }
    let content = BASE64
        .decode(params.content)
        .map_err(|_| "content is not valid base64")?;
    if content.len() > MAX_CONTENT_BYTES {
        return Err("decoded content exceeds 16 MiB");
    }
    if content.contains(&0) {
        return Err("decoded content contains NUL bytes");
    }
    let text = String::from_utf8(content).map_err(|_| "decoded content is not UTF-8")?;
    Ok(Request::new(
        params.kind,
        params.program,
        params.exit_code,
        text,
        params.budget_ms,
    ))
}

fn write_result<W: Write>(
    writer: &mut W,
    id: Option<Value>,
    result: Value,
) -> Result<(), ProtocolError> {
    write_frame(
        writer,
        &RpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        },
    )
}

fn write_error<W: Write>(
    writer: &mut W,
    id: Option<Value>,
    code: i32,
    message: impl Into<String>,
) -> Result<(), ProtocolError> {
    write_frame(
        writer,
        &RpcResponse {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
        },
    )
}

fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<(), ProtocolError> {
    let payload = serde_json::to_vec(value)?;
    write!(writer, "Content-Length: {}\r\n\r\n", payload.len())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

fn read_frame<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut content_length = None;
    let mut header_bytes = 0usize;
    for header_count in 0..=MAX_HEADERS {
        let mut line = Vec::new();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            return if header_count == 0 {
                Ok(None)
            } else {
                Err(ProtocolError::MissingContentLength)
            };
        }
        header_bytes = header_bytes.saturating_add(read);
        if header_bytes > MAX_HEADER_BYTES {
            return Err(ProtocolError::HeaderTooLarge);
        }
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        if line.is_empty() {
            if let Some(length) = content_length {
                let mut frame = vec![0; length];
                reader.read_exact(&mut frame)?;
                return Ok(Some(frame));
            }
            continue;
        }
        let separator = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(ProtocolError::MalformedHeader)?;
        let name = std::str::from_utf8(&line[..separator])
            .map_err(|_| ProtocolError::MalformedHeader)?
            .trim();
        if name.eq_ignore_ascii_case("Content-Length") {
            let value = std::str::from_utf8(&line[separator + 1..])
                .map_err(|_| ProtocolError::InvalidContentLength)?
                .trim();
            let length = value
                .parse::<usize>()
                .map_err(|_| ProtocolError::InvalidContentLength)?;
            if length == 0 || length > MAX_FRAME_BYTES {
                return Err(ProtocolError::InvalidContentLength);
            }
            content_length = Some(length);
        }
    }
    Err(ProtocolError::TooManyHeaders)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    struct Echo;

    impl Optimizer for Echo {
        const PLUGIN_ID: &'static str = "com.tokensaver.echo-test";
        const VERSION: &'static str = "1.2.3";

        fn optimize(&self, request: Request) -> Action {
            if request.kind() == "test" {
                Action::optimized(format!("{}:{}", request.program(), request.text()))
                    .expect("test action")
            } else {
                Action::Pass
            }
        }
    }

    struct Panics;

    impl Optimizer for Panics {
        const PLUGIN_ID: &'static str = "com.tokensaver.panic-test";
        const VERSION: &'static str = "1.0.0";

        fn optimize(&self, _request: Request) -> Action {
            panic!("intentional test panic")
        }
    }

    fn framed(value: Value) -> Vec<u8> {
        let payload = serde_json::to_vec(&value).expect("serialize frame");
        let mut frame = format!("Content-Length: {}\r\n\r\n", payload.len()).into_bytes();
        frame.extend(payload);
        frame
    }

    fn request_stream(kind: &str, content: &[u8]) -> Vec<u8> {
        let mut input = framed(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "apiVersion": 1, "host": "tokensaver", "budgetMs": 250 }
        }));
        input.extend(framed(json!({
            "jsonrpc": "2.0", "id": 2, "method": "optimize",
            "params": {
                "kind": kind, "program": "go", "exitCode": 1,
                "encoding": "base64", "content": BASE64.encode(content), "budgetMs": 250
            }
        })));
        input.extend(framed(json!({ "jsonrpc": "2.0", "method": "shutdown" })));
        input
    }

    fn response_values(output: Vec<u8>) -> Vec<Value> {
        let mut reader = BufReader::new(Cursor::new(output));
        let mut values = Vec::new();
        while let Some(frame) = read_frame(&mut reader).expect("read response") {
            values.push(serde_json::from_slice(&frame).expect("response JSON"));
        }
        values
    }

    #[test]
    fn exact_host_lifecycle_returns_handshake_and_optimization() {
        let mut reader = BufReader::new(Cursor::new(request_stream("test", b"raw output")));
        let mut output = Vec::new();
        serve(&Echo, &mut reader, &mut output).expect("serve lifecycle");

        let responses = response_values(output);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[0]["result"]["apiVersion"], 1);
        assert_eq!(responses[0]["result"]["pluginId"], Echo::PLUGIN_ID);
        assert_eq!(responses[0]["result"]["version"], Echo::VERSION);
        assert_eq!(responses[1]["id"], 2);
        assert_eq!(responses[1]["result"]["action"], "optimize");
        let encoded = responses[1]["result"]["content"].as_str().expect("content");
        assert_eq!(BASE64.decode(encoded).expect("base64"), b"go:raw output");
    }

    #[test]
    fn pass_response_has_no_content() {
        let mut reader = BufReader::new(Cursor::new(request_stream("log", b"raw")));
        let mut output = Vec::new();
        serve(&Echo, &mut reader, &mut output).expect("serve lifecycle");
        let responses = response_values(output);
        assert_eq!(responses[1]["result"], json!({ "action": "pass" }));
    }

    #[test]
    fn invalid_base64_is_a_bounded_rpc_error() {
        let mut input = framed(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "apiVersion": 1, "host": "tokensaver", "budgetMs": 250 }
        }));
        input.extend(framed(json!({
            "jsonrpc": "2.0", "id": 2, "method": "optimize",
            "params": {
                "kind": "test", "program": "go", "exitCode": 0,
                "encoding": "base64", "content": "%%%", "budgetMs": 250
            }
        })));
        let mut reader = BufReader::new(Cursor::new(input));
        let mut output = Vec::new();
        serve(&Echo, &mut reader, &mut output).expect("serve invalid request");
        let responses = response_values(output);
        assert_eq!(responses[1]["error"]["code"], -32602);
    }

    #[test]
    fn optimizer_panics_are_isolated_as_rpc_errors() {
        let mut reader = BufReader::new(Cursor::new(request_stream("test", b"raw")));
        let mut output = Vec::new();
        serve(&Panics, &mut reader, &mut output).expect("serve panicking optimizer");
        let responses = response_values(output);
        assert_eq!(responses[1]["error"]["code"], -32603);
        assert_eq!(responses[1]["error"]["message"], "optimizer panicked");
    }

    #[test]
    fn optimize_before_initialize_is_rejected() {
        let input = framed(json!({
            "jsonrpc": "2.0", "id": 7, "method": "optimize", "params": {}
        }));
        let mut reader = BufReader::new(Cursor::new(input));
        let mut output = Vec::new();
        serve(&Echo, &mut reader, &mut output).expect("serve request");
        let responses = response_values(output);
        assert_eq!(responses[0]["error"]["code"], -32002);
    }

    #[test]
    fn v1_accepts_additive_request_fields_but_rejects_another_major() {
        let mut input = framed(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "apiVersion": 1,
                "host": "tokensaver",
                "budgetMs": 250,
                "extensions": { "com.example.trace": true }
            }
        }));
        input.extend(framed(json!({
            "jsonrpc": "2.0", "id": 2, "method": "optimize",
            "params": {
                "kind": "test",
                "program": "cargo",
                "exitCode": 0,
                "encoding": "base64",
                "content": BASE64.encode(b"raw"),
                "budgetMs": 250,
                "extensions": { "com.example.fixture": "value" }
            }
        })));
        input.extend(framed(json!({ "jsonrpc": "2.0", "method": "shutdown" })));
        let mut output = Vec::new();
        serve(&Echo, &mut BufReader::new(Cursor::new(input)), &mut output)
            .expect("serve requests with additive v1 fields");
        let responses = response_values(output);
        assert_eq!(responses[0]["result"]["apiVersion"], 1);
        assert_eq!(responses[1]["result"]["action"], "optimize");

        let incompatible = framed(json!({
            "jsonrpc": "2.0", "id": 3, "method": "initialize",
            "params": { "apiVersion": 2, "host": "tokensaver", "budgetMs": 250 }
        }));
        let mut output = Vec::new();
        serve(
            &Echo,
            &mut BufReader::new(Cursor::new(incompatible)),
            &mut output,
        )
        .expect("return a bounded incompatible-version error");
        let responses = response_values(output);
        assert_eq!(responses[0]["error"]["code"], -32602);
        assert_eq!(responses[0]["error"]["message"], "unsupported apiVersion");
    }

    #[test]
    fn frame_reader_rejects_oversize_and_malformed_headers() {
        let oversize = format!("Content-Length: {}\r\n\r\n", MAX_FRAME_BYTES + 1);
        assert!(matches!(
            read_frame(&mut BufReader::new(Cursor::new(oversize))),
            Err(ProtocolError::InvalidContentLength)
        ));
        assert!(matches!(
            read_frame(&mut BufReader::new(Cursor::new(b"broken\r\n\r\n"))),
            Err(ProtocolError::MalformedHeader)
        ));
    }
}
