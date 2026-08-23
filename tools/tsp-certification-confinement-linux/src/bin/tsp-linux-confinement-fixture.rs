#[cfg(target_os = "linux")]
fn main() {
    use std::io::{Read, Write};
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .expect("fixture stdin");
    match input.as_slice() {
        b"TS_HANG" => loop {
            std::thread::park_timeout(std::time::Duration::from_secs(1));
        },
        b"TS_OVERFLOW" => {
            let bytes = vec![b'x'; 1024 * 1024];
            std::io::stdout()
                .write_all(&bytes)
                .expect("fixture overflow");
        }
        b"TS_STDERR" => {
            let bytes = vec![b'e'; 1024 * 1024];
            std::io::stderr().write_all(&bytes).expect("fixture stderr");
        }
        b"TS_MEMORY" => {
            let mut bytes = vec![0u8; 256 * 1024 * 1024];
            for page in bytes.chunks_mut(4096) {
                page[0] = 1;
            }
            std::hint::black_box(bytes);
        }
        b"TS_CRASH" => std::process::abort(),
        b"TS_FS" => {
            let denied = std::fs::read("/etc/passwd").is_err();
            print_result(denied);
        }
        b"TS_WORK" => {
            let allowed = std::fs::write("/work/fixture-evidence", b"evidence").is_ok();
            print_result(allowed);
        }
        b"TS_NETWORK" => {
            let denied = std::net::TcpStream::connect("127.0.0.1:9").is_err();
            print_result(denied);
        }
        b"TS_FORK" => {
            // SAFETY: this fixture probes whether seccomp rejects the syscall before any child exists.
            let denied = unsafe { libc::syscall(libc::SYS_fork) } == -1;
            print_result(denied);
        }
        b"TS_THREAD" => {
            let allowed = matches!(std::thread::spawn(|| 7u8).join(), Ok(7));
            print_result(allowed);
        }
        b"TS_ARGS" => std::io::stdout()
            .write_all(
                std::env::args()
                    .skip(1)
                    .collect::<Vec<_>>()
                    .join("\n")
                    .as_bytes(),
            )
            .expect("fixture arguments"),
        _ => std::io::stdout().write_all(&input).expect("fixture echo"),
    }
}

#[cfg(target_os = "linux")]
fn print_result(success: bool) {
    use std::io::Write;
    std::io::stdout()
        .write_all(if success { b"ok" } else { b"unsafe" })
        .expect("fixture result");
}

#[cfg(not(target_os = "linux"))]
fn main() {}
