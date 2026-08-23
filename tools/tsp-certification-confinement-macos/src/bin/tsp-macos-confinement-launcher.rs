#[cfg(target_os = "macos")]
fn main() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() < 5 || arguments[1] != "--memory-bytes" || arguments[3] != "--" {
        fail(117, b"arguments\n");
    }
    let Some(memory) = arguments[2]
        .to_str()
        .and_then(|value| value.parse::<libc::rlim_t>().ok())
        .filter(|value| *value > 0)
    else {
        fail(118, b"memory\n");
    };
    for (resource, value, code, stage) in [
        (libc::RLIMIT_DATA, memory, 119, b"rlimit_data\n".as_slice()),
        (libc::RLIMIT_NPROC, 1, 120, b"rlimit_nproc\n".as_slice()),
        (libc::RLIMIT_NOFILE, 32, 121, b"rlimit_nofile\n".as_slice()),
        (libc::RLIMIT_CORE, 0, 122, b"rlimit_core\n".as_slice()),
    ] {
        if set_limit(resource, value).is_err() {
            fail(code, stage);
        }
    }
    let Ok(executable) = CString::new(arguments[4].as_os_str().as_bytes()) else {
        fail(123, b"executable\n");
    };
    let Ok(argument_values) = arguments[4..]
        .iter()
        .map(|value| CString::new(value.as_os_str().as_bytes()))
        .collect::<Result<Vec<_>, _>>()
    else {
        fail(124, b"argument_value\n");
    };
    let mut argument_pointers = argument_values
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    argument_pointers.push(std::ptr::null());
    let environment = std::env::vars_os()
        .filter_map(|(name, value)| {
            let mut bytes = name.as_os_str().as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_os_str().as_bytes());
            CString::new(bytes).ok()
        })
        .collect::<Vec<_>>();
    let mut environment_pointers = environment
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    environment_pointers.push(std::ptr::null());
    let descriptor_limit = unsafe { libc::getdtablesize() }.max(3);
    for descriptor in 3..descriptor_limit {
        unsafe {
            libc::close(descriptor);
        }
    }
    unsafe {
        libc::execve(
            executable.as_ptr(),
            argument_pointers.as_ptr(),
            environment_pointers.as_ptr(),
        );
    }
    fail(125, b"execve\n");
}

#[cfg(target_os = "macos")]
fn fail(code: i32, stage: &'static [u8]) -> ! {
    #[cfg(debug_assertions)]
    unsafe {
        libc::write(libc::STDERR_FILENO, stage.as_ptr().cast(), stage.len());
    }
    std::process::exit(code);
}

#[cfg(target_os = "macos")]
fn set_limit(resource: libc::c_int, value: libc::rlim_t) -> Result<(), ()> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    if unsafe { libc::setrlimit(resource, &limit) } == 0 {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {}
