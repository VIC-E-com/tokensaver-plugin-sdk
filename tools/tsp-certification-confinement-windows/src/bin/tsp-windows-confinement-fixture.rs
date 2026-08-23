#[cfg(target_os = "windows")]
fn main() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::process::Command;

    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).expect("stdin");
    let text = String::from_utf8_lossy(&input);
    if text == "TS_ARGS" {
        let arguments = std::env::args().skip(1).collect::<Vec<_>>().join("\n");
        std::io::stdout()
            .write_all(arguments.as_bytes())
            .expect("argument output");
        return;
    }
    let success = if text == "TS_WORK" {
        std::fs::write("fixture-evidence", b"evidence").is_ok()
    } else if let Some(path) = text.strip_prefix("TS_FS|") {
        std::fs::read(path).is_err()
    } else if let Some(port) = text.strip_prefix("TS_NETWORK|") {
        port.parse::<u16>().ok().is_some_and(|port| {
            TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                std::time::Duration::from_millis(250),
            )
            .is_err()
        })
    } else if text == "TS_PROCESS" {
        Command::new("cmd.exe")
            .args(["/d", "/c", "exit", "0"])
            .status()
            .is_err()
    } else if text == "TS_THREAD" {
        matches!(std::thread::spawn(|| 42).join(), Ok(42))
    } else if text == "TS_ENV" {
        std::env::var_os("SYSTEMROOT").is_some()
            && std::env::var_os("SYSTEMDRIVE").is_some()
            && std::env::var_os("LOCALAPPDATA").and_then(|path| std::fs::canonicalize(path).ok())
                == std::env::current_dir()
                    .ok()
                    .and_then(|path| std::fs::canonicalize(path).ok())
            && std::env::var_os("API_KEY").is_none()
            && std::env::var_os("USERPROFILE").is_none()
    } else if text == "TS_OVERFLOW" {
        std::io::stdout().write_all(&vec![b'x'; 64 * 1024]).is_ok()
    } else if text == "TS_STDERR" {
        std::io::stderr().write_all(&vec![b'e'; 64 * 1024]).is_ok()
    } else if text == "TS_HANG" {
        loop {
            std::thread::park_timeout(std::time::Duration::from_secs(60));
        }
    } else if text == "TS_CRASH" {
        std::process::abort()
    } else if text == "TS_MEMORY" {
        let mut allocations = Vec::new();
        loop {
            allocations.push(vec![0x5au8; 4 << 20]);
            std::hint::black_box(&allocations);
        }
    } else {
        std::io::stdout().write_all(&input).expect("stdout");
        return;
    };
    if matches!(text.as_ref(), "TS_OVERFLOW" | "TS_STDERR") {
        return;
    }
    print_result(success);
}

#[cfg(target_os = "windows")]
fn print_result(success: bool) {
    use std::io::Write;
    let output = if success {
        b"ok".as_slice()
    } else {
        b"failed".as_slice()
    };
    std::io::stdout().write_all(output).expect("stdout");
    if !success {
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {}
