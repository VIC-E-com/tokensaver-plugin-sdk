use std::io::{Read, Write};

const FILESYSTEM_PROBE_PREFIX: &[u8] = b"TS_FS|";
const MAXIMUM_FILESYSTEM_PROBE_PATH_BYTES: usize = 4096;

fn main() {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .expect("fixture stdin");
    if let Some(encoded_path) = input.strip_prefix(FILESYSTEM_PROBE_PREFIX) {
        filesystem_probe(encoded_path);
    } else if input == b"TS_ARGS" {
        let marker = std::env::var("TOKENSAVER_PLUGIN").unwrap_or_default();
        std::io::stdout()
            .write_all(
                format!(
                    "{marker}\n{}",
                    std::env::args().skip(1).collect::<Vec<_>>().join("\n")
                )
                .as_bytes(),
            )
            .expect("fixture arguments");
    } else {
        std::io::stdout().write_all(&input).expect("fixture stdout");
    }
}

fn filesystem_probe(encoded_path: &[u8]) {
    if encoded_path.is_empty() || encoded_path.len() > MAXIMUM_FILESYSTEM_PROBE_PATH_BYTES {
        std::io::stdout()
            .write_all(b"INVALID")
            .expect("fixture probe result");
        return;
    }
    let Ok(path) = std::str::from_utf8(encoded_path) else {
        std::io::stdout()
            .write_all(b"INVALID")
            .expect("fixture probe result");
        return;
    };
    let result = match std::fs::File::open(path) {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => b"DENIED".as_slice(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => b"NOT_FOUND".as_slice(),
        Err(_) => b"ERROR".as_slice(),
        Ok(_) => b"READABLE".as_slice(),
    };
    std::io::stdout()
        .write_all(result)
        .expect("fixture probe result");
}
