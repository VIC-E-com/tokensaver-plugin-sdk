use super::LinuxKernelError;

const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_CHAR: u64 = 1 << 6;
const MAKE_DIR: u64 = 1 << 7;
const MAKE_REG: u64 = 1 << 8;
const MAKE_SOCK: u64 = 1 << 9;
const MAKE_FIFO: u64 = 1 << 10;
const MAKE_BLOCK: u64 = 1 << 11;
const MAKE_SYM: u64 = 1 << 12;
const REFER: u64 = 1 << 13;
const TRUNCATE: u64 = 1 << 14;
const HANDLED: u64 = EXECUTE
    | WRITE_FILE
    | READ_FILE
    | READ_DIR
    | REMOVE_DIR
    | REMOVE_FILE
    | MAKE_CHAR
    | MAKE_DIR
    | MAKE_REG
    | MAKE_SOCK
    | MAKE_FIFO
    | MAKE_BLOCK
    | MAKE_SYM
    | REFER
    | TRUNCATE;
const READ_EXECUTE: u64 = EXECUTE | READ_FILE | READ_DIR;
const READ_ONLY: u64 = READ_FILE | READ_DIR;
const WORK: u64 = HANDLED & !EXECUTE;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: libc::c_int,
    reserved: u32,
}

pub(super) fn apply() -> Result<(), LinuxKernelError> {
    let ruleset = RulesetAttr {
        handled_access_fs: HANDLED,
    };
    // SAFETY: ruleset points to the complete ABI v1 filesystem attribute.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &ruleset as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    } as libc::c_int;
    if descriptor < 0 {
        return Err(LinuxKernelError);
    }
    let result = add_path(descriptor, c"/plugin", READ_EXECUTE)
        .and_then(|()| add_path(descriptor, c"/lib", READ_EXECUTE))
        .and_then(|()| add_path(descriptor, c"/lib64", READ_EXECUTE))
        .and_then(|()| add_path(descriptor, c"/usr/lib", READ_EXECUTE))
        .and_then(|()| add_path(descriptor, c"/proc", READ_ONLY))
        .and_then(|()| add_path(descriptor, c"/work", WORK))
        .and_then(|()| {
            // SAFETY: no_new_privs permanently tightens this child before restriction.
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                return Err(LinuxKernelError);
            }
            // SAFETY: descriptor is a live ruleset and flags are zero for ABI v1.
            if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, descriptor, 0u32) } != 0 {
                return Err(LinuxKernelError);
            }
            Ok(())
        });
    // SAFETY: descriptor is owned by this function and closed exactly once.
    let closed = unsafe { libc::close(descriptor) };
    if result.is_err() || closed != 0 {
        Err(LinuxKernelError)
    } else {
        Ok(())
    }
}

fn add_path(
    ruleset: libc::c_int,
    path: &std::ffi::CStr,
    access: u64,
) -> Result<(), LinuxKernelError> {
    // SAFETY: path is NUL terminated and O_PATH obtains a rule anchor without content access.
    let parent = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if parent < 0 {
        return Err(LinuxKernelError);
    }
    let rule = PathBeneathAttr {
        allowed_access: access,
        parent_fd: parent,
        reserved: 0,
    };
    // SAFETY: descriptor and parent are live, and rule has the kernel ABI layout.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset,
            LANDLOCK_RULE_PATH_BENEATH,
            &rule as *const PathBeneathAttr,
            0u32,
        )
    };
    // SAFETY: parent is owned by this function and closed exactly once.
    let closed = unsafe { libc::close(parent) };
    if result != 0 || closed != 0 {
        Err(LinuxKernelError)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_can_write_but_not_execute_and_runtime_is_read_only() {
        assert_eq!(WORK & EXECUTE, 0);
        assert_ne!(WORK & WRITE_FILE, 0);
        assert_ne!(WORK & TRUNCATE, 0);
        assert_eq!(READ_EXECUTE & WRITE_FILE, 0);
        assert_ne!(READ_EXECUTE & EXECUTE, 0);
        assert_eq!(READ_ONLY & EXECUTE, 0);
        assert_eq!(HANDLED & !((1 << 15) - 1), 0);
    }
}
