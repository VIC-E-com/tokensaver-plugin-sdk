use super::{LinuxKernelError, landlock, seccomp};
use crate::linux_driver::LinuxKernelExecution;
use std::ffi::{CStr, CString};
use std::fs;
use std::mem::size_of;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

const CLONE_INTO_CGROUP: u64 = 0x0000_0002_0000_0000;
const CLOSE_RANGE_UNSHARE: libc::c_uint = 1 << 1;
const CHILD_SETUP_EXIT: libc::c_int = 127;

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

pub(super) struct ChildProcess {
    pub pid: libc::pid_t,
    pub pidfd: OwnedFd,
    pub stdin: OwnedFd,
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
    pub status: OwnedFd,
    pub root: PathBuf,
}

struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
}

struct PreparedChild {
    root: CString,
    executable_source: CString,
    writable_source: CString,
    library_mounts: Vec<(CString, CString)>,
    root_plugin_directory: CString,
    root_plugin: CString,
    root_work: CString,
    root_proc: CString,
    root_lib: CString,
    root_lib64: CString,
    root_usr: CString,
    root_usr_lib: CString,
    _environment: Vec<CString>,
    environment_pointers: Vec<*const libc::c_char>,
    _arguments: Vec<CString>,
    argument_pointers: Vec<*const libc::c_char>,
    stdin_read: libc::c_int,
    stdout_write: libc::c_int,
    stderr_write: libc::c_int,
    sync_read: libc::c_int,
    status_write: libc::c_int,
}

pub(super) fn spawn(
    request: LinuxKernelExecution<'_>,
    cgroup: libc::c_int,
) -> Result<ChildProcess, LinuxKernelError> {
    let root = request.sandbox_root.join(request.attempt_id);
    fs::create_dir(&root).map_err(|_| LinuxKernelError)?;
    let mut root_cleanup = RootCleanup {
        path: &root,
        armed: true,
    };
    let stdin = pipe()?;
    let stdout = pipe()?;
    let stderr = pipe()?;
    let sync = pipe()?;
    let status = pipe()?;
    set_nonblocking(stdin.write.as_raw_fd())?;
    set_nonblocking(stdout.read.as_raw_fd())?;
    set_nonblocking(stderr.read.as_raw_fd())?;
    set_nonblocking(status.read.as_raw_fd())?;

    let prepared = PreparedChild::new(
        &root,
        request,
        stdin.read.as_raw_fd(),
        stdout.write.as_raw_fd(),
        stderr.write.as_raw_fd(),
        sync.read.as_raw_fd(),
        status.write.as_raw_fd(),
    )?;
    let mut pidfd = -1i32;
    let mut arguments = CloneArgs {
        flags: (libc::CLONE_NEWUSER
            | libc::CLONE_NEWNS
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWPID
            | libc::CLONE_PIDFD) as u64
            | CLONE_INTO_CGROUP,
        pidfd: (&mut pidfd as *mut libc::c_int) as u64,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cgroup as u64,
        ..CloneArgs::default()
    };
    // SAFETY: clone3 receives the complete initialized v0 structure. The child calls only the
    // raw no-allocation transition and always terminates with execve or _exit.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &mut arguments as *mut CloneArgs,
            size_of::<CloneArgs>(),
        )
    };
    if pid < 0 {
        let _ = fs::remove_dir(&root);
        return Err(LinuxKernelError);
    }
    if pid == 0 {
        // SAFETY: this is the isolated clone3 child and the method never returns.
        unsafe { prepared.run() }
    }
    let pid = libc::pid_t::try_from(pid).map_err(|_| LinuxKernelError)?;
    if pidfd < 0 {
        terminate_and_reap(pid, None);
        return Err(LinuxKernelError);
    }
    // SAFETY: clone3 returned a new owned pidfd through the supplied pointer.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    drop(stdin.read);
    drop(stdout.write);
    drop(stderr.write);
    drop(sync.read);
    drop(status.write);
    if configure_identity_maps(pid).is_err() {
        terminate_and_reap(pid, Some(pidfd.as_raw_fd()));
        let _ = fs::remove_dir(&root);
        return Err(LinuxKernelError);
    }
    if write_all(sync.write.as_raw_fd(), b"1").is_err() {
        terminate_and_reap(pid, Some(pidfd.as_raw_fd()));
        let _ = fs::remove_dir(&root);
        return Err(LinuxKernelError);
    }
    drop(sync.write);
    root_cleanup.armed = false;
    drop(root_cleanup);
    Ok(ChildProcess {
        pid,
        pidfd,
        stdin: stdin.write,
        stdout: stdout.read,
        stderr: stderr.read,
        status: status.read,
        root,
    })
}

struct RootCleanup<'a> {
    path: &'a Path,
    armed: bool,
}

impl Drop for RootCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir(self.path);
        }
    }
}

impl PreparedChild {
    fn new(
        root: &Path,
        request: LinuxKernelExecution<'_>,
        stdin_read: libc::c_int,
        stdout_write: libc::c_int,
        stderr_write: libc::c_int,
        sync_read: libc::c_int,
        status_write: libc::c_int,
    ) -> Result<Self, LinuxKernelError> {
        let mut environment = Vec::new();
        for (name, value) in request.environment {
            environment
                .push(CString::new(format!("{name}={value}")).map_err(|_| LinuxKernelError)?);
        }
        environment.push(CString::new("TOKENSAVER_PLUGIN=1").map_err(|_| LinuxKernelError)?);
        environment.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let mut environment_pointers: Vec<_> =
            environment.iter().map(|value| value.as_ptr()).collect();
        environment_pointers.push(null());
        let mut arguments = vec![CString::new("/plugin/plugin").map_err(|_| LinuxKernelError)?];
        for argument in request.arguments {
            arguments.push(CString::new(argument.as_bytes()).map_err(|_| LinuxKernelError)?);
        }
        let mut argument_pointers: Vec<_> = arguments.iter().map(|value| value.as_ptr()).collect();
        argument_pointers.push(null());
        let root = path_cstring(root)?;
        let library_mounts = [
            ("/lib", c"lib"),
            ("/lib64", c"lib64"),
            ("/usr/lib", c"usr/lib"),
        ]
        .into_iter()
        .filter(|(source, _)| Path::new(source).is_dir())
        .map(|(source, relative)| {
            Ok((
                CString::new(source).map_err(|_| LinuxKernelError)?,
                joined_path(&root, relative).map_err(|_| LinuxKernelError)?,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            root_plugin_directory: joined_path(&root, c"plugin").map_err(|_| LinuxKernelError)?,
            root_plugin: joined_path(&root, c"plugin/plugin").map_err(|_| LinuxKernelError)?,
            root_work: joined_path(&root, c"work").map_err(|_| LinuxKernelError)?,
            root_proc: joined_path(&root, c"proc").map_err(|_| LinuxKernelError)?,
            root_lib: joined_path(&root, c"lib").map_err(|_| LinuxKernelError)?,
            root_lib64: joined_path(&root, c"lib64").map_err(|_| LinuxKernelError)?,
            root_usr: joined_path(&root, c"usr").map_err(|_| LinuxKernelError)?,
            root_usr_lib: joined_path(&root, c"usr/lib").map_err(|_| LinuxKernelError)?,
            root,
            executable_source: path_cstring(request.executable)?,
            writable_source: path_cstring(request.writable_directory)?,
            library_mounts,
            _environment: environment,
            environment_pointers,
            _arguments: arguments,
            argument_pointers,
            stdin_read,
            stdout_write,
            stderr_write,
            sync_read,
            status_write,
        })
    }

    unsafe fn run(&self) -> ! {
        if raw_read_one(self.sync_read).is_err() {
            child_fail(self.status_write, 10);
        }
        if unsafe { libc::dup2(self.stdin_read, libc::STDIN_FILENO) } < 0
            || unsafe { libc::dup2(self.stdout_write, libc::STDOUT_FILENO) } < 0
            || unsafe { libc::dup2(self.stderr_write, libc::STDERR_FILENO) } < 0
        {
            child_fail(self.status_write, 11);
        }
        if close_untrusted_descriptors(self.status_write).is_err() {
            child_fail(self.status_write, 12);
        }
        if configure_user_identity().is_err() {
            child_fail(self.status_write, 13);
        }
        if configure_mounts(self).is_err() {
            child_fail(self.status_write, 14);
        }
        if landlock::apply().is_err() {
            child_fail(self.status_write, 15);
        }
        if seccomp::apply().is_err() {
            child_fail(self.status_write, 16);
        }
        let executable = c"/plugin/plugin";
        // SAFETY: argv and environment are NUL-terminated arrays backed by live C strings.
        unsafe {
            libc::execve(
                executable.as_ptr(),
                self.argument_pointers.as_ptr(),
                self.environment_pointers.as_ptr(),
            );
        }
        child_fail(self.status_write, 17)
    }
}

fn configure_mounts(plan: &PreparedChild) -> Result<(), ()> {
    if unsafe {
        libc::mount(
            null(),
            c"/".as_ptr(),
            null(),
            libc::MS_REC | libc::MS_PRIVATE,
            null(),
        )
    } != 0
        || unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                plan.root.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                c"mode=0755,size=67108864".as_ptr().cast(),
            )
        } != 0
    {
        return Err(());
    }
    for target in [
        &plan.root_plugin_directory,
        &plan.root_work,
        &plan.root_proc,
        &plan.root_lib,
        &plan.root_lib64,
        &plan.root_usr,
    ] {
        if unsafe { libc::mkdir(target.as_ptr(), 0o755) } != 0 {
            return Err(());
        }
    }
    if unsafe { libc::mkdir(plan.root_usr_lib.as_ptr(), 0o755) } != 0 {
        return Err(());
    }
    let file = unsafe {
        libc::open(
            plan.root_plugin.as_ptr(),
            libc::O_CREAT | libc::O_RDONLY | libc::O_CLOEXEC,
            0o500,
        )
    };
    if file < 0 {
        return Err(());
    }
    unsafe { libc::close(file) };
    bind_mount(&plan.executable_source, &plan.root_plugin, true, false)?;
    bind_mount(&plan.writable_source, &plan.root_work, false, false)?;
    for (source, target) in &plan.library_mounts {
        bind_mount(source, target, true, false)?;
    }
    if unsafe {
        libc::mount(
            c"proc".as_ptr(),
            plan.root_proc.as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            null(),
        )
    } != 0
        || unsafe { libc::chroot(plan.root.as_ptr()) } != 0
        || unsafe { libc::chdir(c"/work".as_ptr()) } != 0
    {
        return Err(());
    }
    Ok(())
}

fn bind_mount(source: &CStr, target: &CStr, readonly: bool, noexec: bool) -> Result<(), ()> {
    // SAFETY: source and target are valid NUL-terminated paths in the private mount namespace.
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            null(),
            libc::MS_BIND | libc::MS_REC,
            null(),
        )
    } != 0
    {
        return Err(());
    }
    let mut flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV;
    if readonly {
        flags |= libc::MS_RDONLY;
    }
    if noexec {
        flags |= libc::MS_NOEXEC;
    }
    if unsafe { libc::mount(null(), target.as_ptr(), null(), flags, null()) } != 0 {
        return Err(());
    }
    Ok(())
}

fn configure_identity_maps(pid: libc::pid_t) -> Result<(), LinuxKernelError> {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    fs::write(format!("/proc/{pid}/setgroups"), "deny").map_err(|_| LinuxKernelError)?;
    fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1\n"))
        .map_err(|_| LinuxKernelError)?;
    fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1\n")).map_err(|_| LinuxKernelError)
}

fn configure_user_identity() -> Result<(), ()> {
    if unsafe { libc::setresgid(0, 0, 0) } != 0 || unsafe { libc::setresuid(0, 0, 0) } != 0 {
        Err(())
    } else {
        Ok(())
    }
}

fn close_untrusted_descriptors(status: libc::c_int) -> Result<(), ()> {
    if status < 3 {
        return Err(());
    }
    // SAFETY: the ranges exclude the sole status descriptor retained until exec.
    let lower = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            (status - 1) as u32,
            CLOSE_RANGE_UNSHARE,
        )
    };
    let upper =
        unsafe { libc::syscall(libc::SYS_close_range, (status + 1) as u32, u32::MAX, 0u32) };
    if lower != 0 || upper != 0 {
        return Err(());
    }
    // SAFETY: status is live and must close automatically on successful exec.
    if unsafe { libc::fcntl(status, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(());
    }
    Ok(())
}

fn joined_path(root: &CStr, relative: &CStr) -> Result<CString, ()> {
    let mut bytes = root.to_bytes().to_vec();
    bytes.push(b'/');
    bytes.extend_from_slice(relative.to_bytes());
    CString::new(bytes).map_err(|_| ())
}

fn pipe() -> Result<Pipe, LinuxKernelError> {
    let mut descriptors = [-1; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(LinuxKernelError);
    }
    Ok(Pipe {
        read: unsafe { OwnedFd::from_raw_fd(descriptors[0]) },
        write: unsafe { OwnedFd::from_raw_fd(descriptors[1]) },
    })
}

fn set_nonblocking(fd: libc::c_int) -> Result<(), LinuxKernelError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        Err(LinuxKernelError)
    } else {
        Ok(())
    }
}

fn path_cstring(path: &Path) -> Result<CString, LinuxKernelError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| LinuxKernelError)
}

fn write_all(fd: libc::c_int, mut bytes: &[u8]) -> Result<(), LinuxKernelError> {
    while !bytes.is_empty() {
        let count = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if count <= 0 {
            return Err(LinuxKernelError);
        }
        bytes = &bytes[count as usize..];
    }
    Ok(())
}

fn raw_read_one(fd: libc::c_int) -> Result<(), ()> {
    let mut byte = 0u8;
    if unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) } == 1 && byte == b'1' {
        Ok(())
    } else {
        Err(())
    }
}

fn child_fail(status: libc::c_int, code: u8) -> ! {
    unsafe {
        libc::write(status, (&code as *const u8).cast(), 1);
        libc::_exit(CHILD_SETUP_EXIT)
    }
}

fn terminate_and_reap(pid: libc::pid_t, pidfd: Option<libc::c_int>) {
    unsafe {
        if let Some(pidfd) = pidfd {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                libc::SIGKILL,
                null::<libc::siginfo_t>(),
                0u32,
            );
        } else {
            libc::kill(pid, libc::SIGKILL);
        }
        libc::waitpid(pid, null_mut(), 0);
    }
}

use std::os::fd::AsRawFd;
