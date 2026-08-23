use super::{
    MacosConfinementConfig, MacosConfinementKernel, MacosKernelExecution, MacosKernelObservation,
};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokensaver_certification_confinement::NativeTermination;

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const REAP_GRACE: Duration = Duration::from_secs(2);
const MINIMUM_MEMORY_MARGIN: u64 = 4 << 20;
const MAXIMUM_MEMORY_MARGIN: u64 = 32 << 20;

#[derive(Clone, Copy, Debug, Default)]
pub struct MacosKernel;

#[derive(Clone, Copy, Debug)]
pub struct MacosKernelError;

impl MacosConfinementKernel for MacosKernel {
    type Error = MacosKernelError;

    fn preflight(&self, config: &MacosConfinementConfig) -> Result<(), Self::Error> {
        verify_immutable_executable(std::path::Path::new(SANDBOX_EXEC), true)?;
        verify_immutable_executable(config.executable(), false)?;
        verify_immutable_executable(config.launcher(), false)?;
        verify_private_directory(config.writable_directory())
    }

    fn execute(
        &self,
        request: MacosKernelExecution<'_>,
    ) -> Result<MacosKernelObservation, Self::Error> {
        if request.maximum_memory_bytes == 0
            || request.maximum_stdout_bytes == 0
            || request.maximum_stderr_bytes == 0
            || request.deadline.is_zero()
        {
            return Err(MacosKernelError);
        }
        let mut command = Command::new(SANDBOX_EXEC);
        command
            .arg("-p")
            .arg(request.sandbox_profile)
            .arg(request.launcher)
            .arg("--memory-bytes")
            .arg(request.maximum_memory_bytes.to_string())
            .arg("--")
            .arg(request.executable)
            .args(request.arguments)
            .env_clear()
            .envs(request.environment.iter().cloned())
            .current_dir(request.writable_directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command.spawn().map_err(|_| MacosKernelError)?;
        let pid = libc::pid_t::try_from(child.id()).map_err(|_| MacosKernelError)?;
        let mut cleanup = ProcessCleanup { pid, reaped: false };
        let stdin = child.stdin.take().ok_or(MacosKernelError)?;
        let stdout = child.stdout.take().ok_or(MacosKernelError)?;
        let stderr = child.stderr.take().ok_or(MacosKernelError)?;
        let result = run_process(
            pid,
            &mut cleanup,
            stdin,
            stdout,
            stderr,
            request.input,
            request.maximum_memory_bytes,
            request.maximum_stdout_bytes,
            request.maximum_stderr_bytes,
            request.deadline,
        );
        drop(child);
        result
    }
}

struct Capture<R> {
    stream: R,
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
    closed: bool,
}

impl<R: Read + AsRawFd> Capture<R> {
    fn new(stream: R, limit: usize) -> Result<Self, MacosKernelError> {
        set_nonblocking(stream.as_raw_fd())?;
        Ok(Self {
            stream,
            bytes: Vec::with_capacity(limit.min(64 * 1024)),
            limit,
            exceeded: false,
            closed: false,
        })
    }

    fn drain(&mut self) -> Result<(), MacosKernelError> {
        if self.closed || self.exceeded {
            return Ok(());
        }
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    self.closed = true;
                    return Ok(());
                }
                Ok(count) => {
                    let remaining = self.limit.saturating_sub(self.bytes.len());
                    let retained = remaining.min(count);
                    self.bytes.extend_from_slice(&buffer[..retained]);
                    if retained != count || self.bytes.len() == self.limit {
                        let mut probe = [0u8; 1];
                        match self.stream.read(&mut probe) {
                            Ok(0) => self.closed = true,
                            Ok(_) => self.exceeded = true,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                            Err(_) => return Err(MacosKernelError),
                        }
                    }
                    if self.exceeded {
                        return Ok(());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(MacosKernelError),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_process(
    pid: libc::pid_t,
    cleanup: &mut ProcessCleanup,
    stdin: std::process::ChildStdin,
    stdout: impl Read + AsRawFd,
    stderr: impl Read + AsRawFd,
    input: &[u8],
    memory_limit: u64,
    stdout_limit: usize,
    stderr_limit: usize,
    deadline: Duration,
) -> Result<MacosKernelObservation, MacosKernelError> {
    set_nonblocking(stdin.as_raw_fd())?;
    let mut stdin = Some(stdin);
    let mut stdout = Capture::new(stdout, stdout_limit)?;
    let mut stderr = Capture::new(stderr, stderr_limit)?;
    let started = Instant::now();
    let mut input_offset = 0usize;
    let mut killed_for_deadline = false;
    let mut killed_for_memory = false;
    let mut killed_for_stream = false;
    let mut sampled_peak_memory = 0u64;
    let memory_threshold = memory_kill_threshold(memory_limit);
    let mut status = 0;
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };

    loop {
        stdout.drain()?;
        stderr.drain()?;
        if let Some(stream) = stdin.as_mut() {
            write_input(stream, input, &mut input_offset)?;
            if input_offset == input.len() {
                stdin.take();
            }
        }
        if let Some(memory) = resident_memory_bytes(pid)? {
            sampled_peak_memory = sampled_peak_memory.max(memory);
            if memory >= memory_threshold
                && !killed_for_memory
                && !killed_for_stream
                && !killed_for_deadline
            {
                kill_group(pid)?;
                killed_for_memory = true;
            }
        }
        if (stdout.exceeded || stderr.exceeded)
            && !killed_for_stream
            && !killed_for_memory
            && !killed_for_deadline
        {
            kill_group(pid)?;
            killed_for_stream = true;
        }
        if started.elapsed() >= deadline
            && !killed_for_deadline
            && !killed_for_stream
            && !killed_for_memory
        {
            kill_group(pid)?;
            killed_for_deadline = true;
        }
        let waited = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, &mut usage) };
        if waited == pid {
            cleanup.reaped = true;
            break;
        }
        if waited < 0 {
            kill_group_best_effort(pid);
            reap_best_effort(pid);
            return Err(MacosKernelError);
        }
        poll_streams(
            stdin.as_ref().map(AsRawFd::as_raw_fd),
            stdout.stream.as_raw_fd(),
            stderr.stream.as_raw_fd(),
        )?;
    }

    drop(stdin);
    let drain_deadline = Instant::now() + REAP_GRACE;
    while !stdout.closed || !stderr.closed {
        stdout.drain()?;
        stderr.drain()?;
        if stdout.exceeded {
            stdout.closed = true;
        }
        if stderr.exceeded {
            stderr.closed = true;
        }
        if (!stdout.closed || !stderr.closed) && Instant::now() >= drain_deadline {
            return Err(MacosKernelError);
        }
        if !stdout.closed || !stderr.closed {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    verify_group_empty(pid)?;
    let wait_peak_memory = u64::try_from(usage.ru_maxrss).map_err(|_| MacosKernelError)?;
    let peak_memory_bytes = sampled_peak_memory.max(wait_peak_memory);
    let termination = if killed_for_memory {
        NativeTermination::MemoryLimitKilled
    } else if killed_for_deadline {
        NativeTermination::DeadlineKilled
    } else if libc::WIFEXITED(status) {
        NativeTermination::Exited(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        NativeTermination::Signaled(libc::WTERMSIG(status) as u32)
    } else {
        return Err(MacosKernelError);
    };
    Ok(MacosKernelObservation {
        termination,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        duration_milliseconds: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        peak_memory_bytes,
        stdout_limit_exceeded: stdout.exceeded,
        stderr_limit_exceeded: stderr.exceeded,
        process_reaped: true,
    })
}

fn memory_kill_threshold(limit: u64) -> u64 {
    let margin = (limit / 8).clamp(MINIMUM_MEMORY_MARGIN, MAXIMUM_MEMORY_MARGIN);
    limit.saturating_sub(margin).max(1)
}

fn resident_memory_bytes(pid: libc::pid_t) -> Result<Option<u64>, MacosKernelError> {
    let mut usage: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::proc_pid_rusage(
            pid,
            libc::RUSAGE_INFO_V2,
            (&mut usage as *mut libc::rusage_info_v2).cast(),
        )
    };
    if result == 0 {
        Ok(Some(usage.ri_phys_footprint.max(usage.ri_resident_size)))
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(None)
    } else {
        Err(MacosKernelError)
    }
}

fn write_input(
    stdin: &mut (impl Write + AsRawFd),
    input: &[u8],
    offset: &mut usize,
) -> Result<(), MacosKernelError> {
    if *offset == input.len() {
        return Ok(());
    }
    match stdin.write(&input[*offset..]) {
        Ok(0) => Err(MacosKernelError),
        Ok(count) => {
            *offset = offset.checked_add(count).ok_or(MacosKernelError)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Err(MacosKernelError),
        Err(_) => Err(MacosKernelError),
    }
}

fn poll_streams(
    stdin: Option<RawFd>,
    stdout: RawFd,
    stderr: RawFd,
) -> Result<(), MacosKernelError> {
    let mut descriptors = [
        libc::pollfd {
            fd: stdout,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stderr,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stdin.unwrap_or(-1),
            events: libc::POLLOUT,
            revents: 0,
        },
    ];
    let count = if stdin.is_some() { 3 } else { 2 };
    let timeout = i32::try_from(POLL_INTERVAL.as_millis()).unwrap_or(5);
    let result = unsafe { libc::poll(descriptors.as_mut_ptr(), count, timeout) };
    if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
        Err(MacosKernelError)
    } else {
        Ok(())
    }
}

fn set_nonblocking(descriptor: RawFd) -> Result<(), MacosKernelError> {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        Err(MacosKernelError)
    } else {
        Ok(())
    }
}

fn kill_group(pid: libc::pid_t) -> Result<(), MacosKernelError> {
    let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(MacosKernelError)
    }
}

fn kill_group_best_effort(pid: libc::pid_t) {
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
}

fn reap_best_effort(pid: libc::pid_t) {
    let mut status = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
}

fn verify_group_empty(pid: libc::pid_t) -> Result<(), MacosKernelError> {
    if unsafe { libc::kill(-pid, 0) } == -1
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    {
        Ok(())
    } else {
        kill_group_best_effort(pid);
        Err(MacosKernelError)
    }
}

fn verify_immutable_executable(
    path: &std::path::Path,
    require_root: bool,
) -> Result<(), MacosKernelError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| MacosKernelError)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.mode() & 0o022 != 0
        || (require_root && metadata.uid() != 0)
    {
        return Err(MacosKernelError);
    }
    Ok(())
}

fn verify_private_directory(path: &std::path::Path) -> Result<(), MacosKernelError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| MacosKernelError)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(MacosKernelError);
    }
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| MacosKernelError)?;
    if unsafe { libc::access(path.as_ptr(), libc::W_OK | libc::X_OK) } == 0 {
        Ok(())
    } else {
        Err(MacosKernelError)
    }
}

struct ProcessCleanup {
    pid: libc::pid_t,
    reaped: bool,
}

impl Drop for ProcessCleanup {
    fn drop(&mut self) {
        if !self.reaped {
            kill_group_best_effort(self.pid);
            reap_best_effort(self.pid);
        }
    }
}
