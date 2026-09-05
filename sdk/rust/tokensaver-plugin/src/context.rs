//! TSPP v2 context-service plumbing. No filesystem, process, or network authority.
//! Host-owned capabilities and native confinement remain outside this module.
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, Read, Write},
    panic::{AssertUnwindSafe, catch_unwind},
};
pub const API_VERSION: u32 = 2;
pub const PROFILE: &str = "context-service.v1";
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub trait ContextService {
    const PLUGIN_ID: &'static str;
    const VERSION: &'static str;
    /// Implement only supported context.* methods. Errors are bounded symbols.
    fn call(&self, method: &str, params: Value) -> Result<Value, ContextError>;
}
#[derive(Debug)]
pub enum ContextError {
    InvalidParams,
    MethodNotFound,
    Unavailable,
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid context-service frame")
}
fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut length = None;
    let mut total = 0;
    for i in 0..32 {
        let mut line = Vec::new();
        let n = reader.take(8193).read_until(b'\n', &mut line)?;
        if n == 0 {
            return if i == 0 { Ok(None) } else { Err(invalid()) };
        }
        total += n;
        if total > 8192 || !line.ends_with(b"\n") {
            return Err(invalid());
        }
        if line == b"\r\n" || line == b"\n" {
            let n = length.ok_or_else(invalid)?;
            let mut body = vec![0; n];
            reader.read_exact(&mut body)?;
            return Ok(Some(body));
        }
        let text = std::str::from_utf8(&line).map_err(|_| invalid())?;
        let (name, value) = text.trim().split_once(':').ok_or_else(invalid)?;
        if name.eq_ignore_ascii_case("Content-Length") {
            if length.is_some() {
                return Err(invalid());
            }
            let n: usize = value.trim().parse().map_err(|_| invalid())?;
            if n == 0 || n > MAX_FRAME_BYTES {
                return Err(invalid());
            }
            length = Some(n);
        }
    }
    Err(invalid())
}
fn write_frame(writer: &mut impl Write, value: &Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(invalid());
    }
    write!(writer, "Content-Length: {}\r\n\r\n", bytes.len())?;
    writer.write_all(&bytes)?;
    writer.flush()
}
/// Bounded synchronous lifecycle. The caller must impose an OS execution deadline.
pub fn serve<S: ContextService>(
    service: &S,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> io::Result<()> {
    let mut initialized = false;
    while let Some(bytes) = read_frame(reader)? {
        let request: Value = crate::context_json::from_slice(&bytes)?;
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request["method"].as_str().unwrap_or("");
        if request["jsonrpc"] != "2.0"
            || !(id.is_null() || id.is_string() || id.is_i64() || id.is_u64())
        {
            return Err(invalid());
        }
        if method == "shutdown" {
            return Ok(());
        }
        if id.is_null() {
            continue;
        }
        let response = if method == "initialize" {
            if request["params"]["apiVersion"] != API_VERSION
                || request["params"]["profile"] != PROFILE
                || initialized
            {
                Err((-32602, "unsupported context-service initialization"))
            } else {
                initialized = true;
                Ok(
                    json!({"apiVersion":API_VERSION,"profile":PROFILE,"pluginId":S::PLUGIN_ID,"version":S::VERSION}),
                )
            }
        } else if !initialized {
            Err((-32002, "initialize first"))
        } else if !method.starts_with("context.") {
            Err((-32601, "unknown method"))
        } else {
            match catch_unwind(AssertUnwindSafe(|| {
                service.call(method, request["params"].clone())
            })) {
                Ok(Ok(value)) => Ok(value),
                Ok(Err(ContextError::InvalidParams)) => Err((-32602, "invalid params")),
                Ok(Err(ContextError::MethodNotFound)) => Err((-32601, "unknown method")),
                _ => Err((-32603, "context service unavailable")),
            }
        };
        let mut response = match response {
            Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
            Err((code, message)) => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
            }
        };
        if serde_json::to_vec(&response)?.len() > MAX_FRAME_BYTES {
            response = json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"response exceeds limit"}});
        }
        write_frame(writer, &response)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    struct Echo;
    impl ContextService for Echo {
        const PLUGIN_ID: &'static str = "com.example.context";
        const VERSION: &'static str = "1.0.0";
        fn call(&self, method: &str, params: Value) -> Result<Value, ContextError> {
            if method == "context.panic" {
                panic!("fixture");
            }
            Ok(params)
        }
    }
    fn exchange(requests: &[Value]) -> Vec<Value> {
        let mut input = Vec::new();
        for r in requests {
            write_frame(&mut input, r).unwrap();
        }
        let mut output = Vec::new();
        serve(&Echo, &mut Cursor::new(input), &mut output).unwrap();
        let mut cursor = Cursor::new(output);
        let mut values = Vec::new();
        while let Some(bytes) = read_frame(&mut cursor).unwrap() {
            values.push(serde_json::from_slice(&bytes).unwrap());
        }
        values
    }
    fn hello() -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"apiVersion":2,"profile":PROFILE}})
    }
    #[test]
    fn negotiates_v2_and_refuses_v1_optimizer() {
        let v = exchange(&[hello(), json!({"jsonrpc":"2.0","id":2,"method":"optimize"})]);
        assert_eq!(v[0]["result"]["profile"], PROFILE);
        assert_eq!(v[1]["error"]["code"], -32601);
        let mut h = hello();
        h["params"]["apiVersion"] = json!(1);
        assert_eq!(exchange(&[h])[0]["error"]["code"], -32602);
    }
    #[test]
    fn panic_isolated_and_next_call_works() {
        let v = exchange(&[
            hello(),
            json!({"jsonrpc":"2.0","id":2,"method":"context.panic"}),
            json!({"jsonrpc":"2.0","id":3,"method":"context.echo","params":{"ok":true}}),
        ]);
        assert_eq!(v[1]["error"]["code"], -32603);
        assert_eq!(v[2]["result"]["ok"], true);
    }
    #[test]
    fn headers_are_bounded_and_duplicates_rejected() {
        for bytes in [
            b"Content-Length: 2\nContent-Length: 2\n\n{}".to_vec(),
            vec![b'x'; 9000],
            b"Content-Length: 1048577\n\n".to_vec(),
        ] {
            assert!(read_frame(&mut Cursor::new(bytes)).is_err());
        }
    }
}
