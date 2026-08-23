//! Rust SDK for TokenSaver Plugin Protocol (TSPP) v1 optimizers.
//!
//! The SDK deliberately contains protocol plumbing only. Optimization logic
//! belongs to each plugin and is never part of this crate.

mod model;
mod protocol;

pub use model::{Action, ActionError, Optimizer, Request};
pub use protocol::{ProtocolError, serve};

use std::io::{self, BufReader};

/// Runs an optimizer over stdin/stdout until the TokenSaver host sends the
/// TSPP `shutdown` notification or closes stdin.
///
/// Protocol failures are emitted as one structured JSON record on stderr.
/// stdout remains reserved exclusively for framed TSPP messages.
pub fn run<O: Optimizer>(optimizer: O) {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    if let Err(error) = serve(&optimizer, &mut reader, &mut writer) {
        let record = serde_json::json!({
            "level": "error",
            "source": "tokensaver-plugin-sdk",
            "message": error.to_string(),
        });
        eprintln!("{record}");
    }
}
