use super::{
    LinuxConfinementConfig, LinuxConfinementKernel, LinuxKernelExecution, LinuxKernelObservation,
};
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::mem::zeroed;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::ptr::null;

mod child;
mod io;
mod landlock;
mod seccomp;

const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
const SECCOMP_GET_ACTION_AVAIL: libc::c_uint = 2;
const SECCOMP_RET_KILL_PROCESS: libc::c_uint = 0x8000_0000;

#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxKernel;

#[derive(Clone, Copy, Debug)]
pub struct LinuxKernelError;

impl LinuxConfinementKernel for LinuxKernel {
    type Error = LinuxKernelError;

    fn preflight(&self, config: &LinuxConfinementConfig) -> Result<(), Self::Error> {
        verify_namespace_surface()?;
        verify_landlock()?;
        verify_seccomp()?;
        verify_pidfd()?;
        verify_cgroup_v2(config.cgroup_parent())?;
        verify_private_directory(config.sandbox_root())?;
        verify_private_directory(config.writable_directory())
    }

    fn execute(
        &self,
        request: LinuxKernelExecution<'_>,
    ) -> Result<LinuxKernelObservation, Self::Error> {
        let cgroup = CgroupLeaf::create(
            request.cgroup_parent,
            request.attempt_id,
            request.maximum_memory_bytes,
        )?;
        let child = child::spawn(request, cgroup.descriptor())?;
        io::run(child, cgroup, request)
    }
}

fn verify_namespace_surface() -> Result<(), LinuxKernelError> {
    for namespace in ["user", "mnt", "net", "pid"] {
        if !std::path::Path::new("/proc/self/ns")
            .join(namespace)
            .exists()
        {
            return Err(LinuxKernelError);
        }
    }
    if fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .ok()
        .is_some_and(|value| value.trim() == "0")
    {
        return Err(LinuxKernelError);
    }
    // A deliberately invalid size cannot create a process. EINVAL proves clone3 is present.
    // SAFETY: the null pointer is paired with a zero size as a non-mutating availability probe.
    let result = unsafe { libc::syscall(libc::SYS_clone3, null::<libc::c_void>(), 0usize) };
    if result != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
        return Err(LinuxKernelError);
    }
    Ok(())
}

fn verify_landlock() -> Result<(), LinuxKernelError> {
    // SAFETY: Landlock's VERSION query requires a null attribute and zero size.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 3 {
        return Err(LinuxKernelError);
    }
    Ok(())
}

fn verify_seccomp() -> Result<(), LinuxKernelError> {
    let action = SECCOMP_RET_KILL_PROCESS;
    // SAFETY: action is a valid readable u32 for the availability query.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_ACTION_AVAIL,
            0u32,
            &action as *const libc::c_uint,
        )
    };
    if result != 0 {
        return Err(LinuxKernelError);
    }
    Ok(())
}

fn verify_pidfd() -> Result<(), LinuxKernelError> {
    // SAFETY: getpid has no preconditions and pidfd_open is called for this process.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0u32) };
    if descriptor < 0 {
        return Err(LinuxKernelError);
    }
    // SAFETY: descriptor was returned by pidfd_open and is closed exactly once.
    if unsafe { libc::close(descriptor as libc::c_int) } != 0 {
        return Err(LinuxKernelError);
    }
    Ok(())
}

fn verify_cgroup_v2(parent: &std::path::Path) -> Result<(), LinuxKernelError> {
    let path = CString::new(parent.as_os_str().as_bytes()).map_err(|_| LinuxKernelError)?;
    let mut stats: libc::statfs = unsafe { zeroed() };
    // SAFETY: path is NUL terminated and stats is a valid output buffer.
    if unsafe { libc::statfs(path.as_ptr(), &mut stats) } != 0
        || stats.f_type as libc::c_long != CGROUP2_SUPER_MAGIC
    {
        return Err(LinuxKernelError);
    }
    let controllers =
        fs::read_to_string(parent.join("cgroup.controllers")).map_err(|_| LinuxKernelError)?;
    let subtree =
        fs::read_to_string(parent.join("cgroup.subtree_control")).map_err(|_| LinuxKernelError)?;
    if !["memory", "pids"].iter().all(|required| {
        controllers
            .split_ascii_whitespace()
            .any(|value| value == *required)
            && subtree
                .split_ascii_whitespace()
                .any(|value| value == *required)
    }) || !parent.join("cgroup.procs").is_file()
        || !parent.join("cgroup.subtree_control").is_file()
        || !parent.join("cgroup.kill").is_file()
        || !parent.join("memory.events").is_file()
        || !parent.join("memory.peak").is_file()
    {
        return Err(LinuxKernelError);
    }
    // SAFETY: path is NUL terminated; W_OK|X_OK is a read-only permission probe.
    if unsafe { libc::access(path.as_ptr(), libc::W_OK | libc::X_OK) } != 0 {
        return Err(LinuxKernelError);
    }
    Ok(())
}

struct CgroupLeaf {
    path: std::path::PathBuf,
    descriptor: OwnedFd,
    cleaned: bool,
}

impl CgroupLeaf {
    fn create(
        parent: &std::path::Path,
        attempt_id: &str,
        memory_bytes: u64,
    ) -> Result<Self, LinuxKernelError> {
        if memory_bytes == 0
            || !((attempt_id.len() == 70 && attempt_id.starts_with("tsfa1_"))
                || (attempt_id.len() == 37 && attempt_id.starts_with("tsa1_")))
            || !attempt_id
                .bytes()
                .skip(if attempt_id.starts_with("tsfa1_") {
                    6
                } else {
                    5
                })
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(LinuxKernelError);
        }
        let path = parent.join(attempt_id);
        fs::create_dir(&path).map_err(|_| LinuxKernelError)?;
        let raw = open_directory(&path);
        if raw < 0 {
            let _ = fs::remove_dir(&path);
            return Err(LinuxKernelError);
        }
        // SAFETY: open_directory returned a new owned descriptor.
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut leaf = Self {
            path,
            descriptor,
            cleaned: false,
        };
        let configured = leaf
            .write("memory.max", &memory_bytes.to_string())
            .and_then(|()| leaf.write("memory.swap.max", "0"))
            .and_then(|()| leaf.write("memory.oom.group", "1"))
            .and_then(|()| leaf.write("pids.max", "64"));
        if configured.is_err() {
            leaf.cleanup_best_effort();
            return Err(LinuxKernelError);
        }
        Ok(leaf)
    }

    fn descriptor(&self) -> libc::c_int {
        self.descriptor.as_raw_fd()
    }

    fn write(&self, name: &str, value: &str) -> Result<(), LinuxKernelError> {
        let path = self.path.join(name);
        let metadata = fs::symlink_metadata(&path).map_err(|_| LinuxKernelError)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(LinuxKernelError);
        }
        let mut file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|_| LinuxKernelError)?;
        file.write_all(value.as_bytes())
            .map_err(|_| LinuxKernelError)?;
        file.flush().map_err(|_| LinuxKernelError)
    }

    fn kill(&self) -> Result<(), LinuxKernelError> {
        self.write("cgroup.kill", "1")
    }

    fn populated(&self) -> Result<bool, LinuxKernelError> {
        parse_keyed_u64(
            &fs::read_to_string(self.path.join("cgroup.events")).map_err(|_| LinuxKernelError)?,
            "populated",
        )
        .map(|value| value != 0)
    }

    fn peak_memory_bytes(&self) -> Result<u64, LinuxKernelError> {
        parse_single_u64(
            &fs::read_to_string(self.path.join("memory.peak")).map_err(|_| LinuxKernelError)?,
        )
    }

    fn memory_limit_hit(&self) -> Result<bool, LinuxKernelError> {
        let events =
            fs::read_to_string(self.path.join("memory.events")).map_err(|_| LinuxKernelError)?;
        Ok(parse_keyed_u64(&events, "oom")? != 0 || parse_keyed_u64(&events, "oom_kill")? != 0)
    }

    fn finish(mut self) -> Result<(u64, bool), LinuxKernelError> {
        if self.populated()? {
            return Err(LinuxKernelError);
        }
        let result = (self.peak_memory_bytes()?, self.memory_limit_hit()?);
        fs::remove_dir(&self.path).map_err(|_| LinuxKernelError)?;
        self.cleaned = true;
        Ok(result)
    }

    fn wait_empty(&self, deadline: std::time::Instant) -> Result<(), LinuxKernelError> {
        while self.populated()? {
            if std::time::Instant::now() >= deadline {
                return Err(LinuxKernelError);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        Ok(())
    }

    fn cleanup_best_effort(&mut self) {
        let _ = self.kill();
        if self.populated().ok() == Some(false) && fs::remove_dir(&self.path).is_ok() {
            self.cleaned = true;
        }
    }
}

impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        if !self.cleaned {
            self.cleanup_best_effort();
        }
    }
}

fn open_directory(path: &std::path::Path) -> libc::c_int {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return -1;
    };
    // SAFETY: path is NUL terminated and flags request a read-only directory descriptor.
    unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    }
}

fn parse_single_u64(value: &str) -> Result<u64, LinuxKernelError> {
    let value = value.trim();
    if value.is_empty() || value.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(LinuxKernelError);
    }
    value.parse().map_err(|_| LinuxKernelError)
}

fn parse_keyed_u64(document: &str, key: &str) -> Result<u64, LinuxKernelError> {
    let mut result = None;
    for line in document.lines() {
        let mut fields = line.split_ascii_whitespace();
        let name = fields.next().ok_or(LinuxKernelError)?;
        let value = fields.next().ok_or(LinuxKernelError)?;
        if fields.next().is_some() || name.is_empty() {
            return Err(LinuxKernelError);
        }
        if name == key {
            if result.is_some() {
                return Err(LinuxKernelError);
            }
            result = Some(parse_single_u64(value)?);
        }
    }
    result.ok_or(LinuxKernelError)
}

fn verify_private_directory(root: &std::path::Path) -> Result<(), LinuxKernelError> {
    let metadata = fs::symlink_metadata(root).map_err(|_| LinuxKernelError)?;
    // The host owns both private directories and grants no group/other access.
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(LinuxKernelError);
    }
    let path = CString::new(root.as_os_str().as_bytes()).map_err(|_| LinuxKernelError)?;
    // SAFETY: path is NUL terminated; W_OK|X_OK is a non-mutating permission check.
    if unsafe { libc::access(path.as_ptr(), libc::W_OK | libc::X_OK) } != 0 {
        return Err(LinuxKernelError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_numbers_and_keyed_documents_are_strict() {
        assert_eq!(parse_single_u64("0\n").expect("zero"), 0);
        assert_eq!(
            parse_single_u64("18446744073709551615").expect("max"),
            u64::MAX
        );
        for invalid in ["", "-1", "+1", "1 2", "18446744073709551616"] {
            assert!(parse_single_u64(invalid).is_err(), "{invalid}");
        }

        let document = "low 2\nhigh 7\nmax 11\n";
        assert_eq!(parse_keyed_u64(document, "high").expect("high"), 7);
        for invalid in ["high\n", "high 1 extra\n", "high 1\nhigh 2\n", "other 1\n"] {
            assert!(parse_keyed_u64(invalid, "high").is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn private_directory_must_be_writable_and_not_a_symlink() {
        let root = std::env::temp_dir().join(format!(
            "tokensaver-linux-root-check-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("root");
        let mut permissions = fs::metadata(&root).expect("metadata").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o700);
        fs::set_permissions(&root, permissions).expect("private mode");
        verify_private_directory(&root).expect("private root");
        fs::write(root.join("unexpected"), b"data").expect("entry");
        verify_private_directory(&root).expect("nonempty concurrent root");
        fs::remove_dir_all(root).expect("cleanup");
    }
}
