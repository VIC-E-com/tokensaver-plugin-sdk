#[cfg(target_os = "macos")]
fn main() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() < 5 || arguments[1] != "--memory-bytes" || arguments[3] != "--" {
        std::process::exit(127);
    }
    let Some(memory) = arguments[2]
        .to_str()
        .and_then(|value| value.parse::<libc::rlim_t>().ok())
        .filter(|value| *value > 0)
    else {
        std::process::exit(127);
    };
    if set_limit(libc::RLIMIT_AS, memory).is_err()
        || set_limit(libc::RLIMIT_DATA, memory).is_err()
        || set_limit(libc::RLIMIT_NPROC, 1).is_err()
        || set_limit(libc::RLIMIT_NOFILE, 32).is_err()
        || set_limit(libc::RLIMIT_CORE, 0).is_err()
    {
        std::process::exit(127);
    }
    let Ok(executable) = CString::new(arguments[4].as_os_str().as_bytes()) else {
        std::process::exit(127);
    };
    let Ok(argument_values) = arguments[4..]
        .iter()
        .map(|value| CString::new(value.as_os_str().as_bytes()))
        .collect::<Result<Vec<_>, _>>()
    else {
        std::process::exit(127);
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
    std::process::exit(127);
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
