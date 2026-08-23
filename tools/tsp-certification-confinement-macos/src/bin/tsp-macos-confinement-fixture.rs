#[cfg(target_os = "macos")]
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
            std::io::stdout()
                .write_all(&vec![b'x'; 1024 * 1024])
                .expect("fixture overflow");
        }
        b"TS_STDERR" => {
            std::io::stderr()
                .write_all(&vec![b'e'; 1024 * 1024])
                .expect("fixture stderr");
        }
        b"TS_MEMORY" => {
            let mut bytes = vec![0u8; 256 * 1024 * 1024];
            for page in bytes.chunks_mut(4096) {
                page[0] = 1;
            }
            std::hint::black_box(bytes);
        }
        b"TS_CRASH" => std::process::abort(),
        b"TS_FS" => print_result(
            std::env::args_os()
                .nth(1)
                .is_some_and(|path| std::fs::read(path).is_err()),
        ),
        b"TS_WORK" => print_result(std::fs::write("fixture-evidence", b"evidence").is_ok()),
        b"TS_NETWORK" => {
            print_result(std::net::TcpStream::connect("127.0.0.1:9").is_err());
        }
        b"TS_FORK" => {
            let denied = unsafe { libc::fork() } == -1;
            print_result(denied);
        }
        b"TS_THREAD" => {
            print_result(matches!(std::thread::spawn(|| 7u8).join(), Ok(7)));
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

#[cfg(target_os = "macos")]
fn print_result(success: bool) {
    use std::io::Write;
    std::io::stdout()
        .write_all(if success { b"ok" } else { b"unsafe" })
        .expect("fixture result");
}

#[cfg(not(target_os = "macos"))]
fn main() {}
