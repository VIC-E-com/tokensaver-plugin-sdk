use super::{CgroupLeaf, LinuxKernelError, child::ChildProcess, debug_stage};
use crate::linux_driver::{LinuxKernelExecution, LinuxKernelObservation};
use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr::null;
use std::time::{Duration, Instant};
use tokensaver_certification_confinement::NativeTermination;

const CHUNK: usize = 16 * 1024;
const REAP_GRACE: Duration = Duration::from_secs(5);

pub(super) fn run(
    child: ChildProcess,
    cgroup: CgroupLeaf,
    request: LinuxKernelExecution<'_>,
) -> Result<LinuxKernelObservation, LinuxKernelError> {
    let ChildProcess {
        pid,
        pidfd,
        stdin: child_stdin,
        stdout: child_stdout,
        stderr: child_stderr,
        status: child_status,
        root,
    } = child;
    let mut cleanup = ProcessCleanup {
        pid,
        pidfd: pidfd.as_raw_fd(),
        cgroup: &cgroup,
        root: &root,
        armed: true,
        reaped: false,
    };
    let started = Instant::now();
    let mut stdin = Some(child_stdin);
    let mut input_offset = 0usize;
    let mut stdout = Capture::new(child_stdout, request.maximum_stdout_bytes);
    let mut stderr = Capture::new(child_stderr, request.maximum_stderr_bytes);
    let mut status = Some(child_status);
    let mut setup_failure = None;
    let mut exited = false;
    let mut killed_for_deadline = false;
    let mut killed_for_stream = false;
    let mut kill_started = None;

    while !exited {
        if input_offset == request.input.len() {
            stdin.take();
        }
        stdout.drain()?;
        stderr.drain()?;
        read_setup_status(&mut status, &mut setup_failure)?;
        if setup_failure.is_some() && kill_started.is_none() {
            kill_complete(pidfd.as_raw_fd(), &cgroup)?;
            kill_started.get_or_insert_with(Instant::now);
        }
        if (stdout.exceeded || stderr.exceeded) && !killed_for_stream {
            kill_complete(pidfd.as_raw_fd(), &cgroup)?;
            killed_for_stream = true;
            kill_started.get_or_insert_with(Instant::now);
        }
        if started.elapsed() >= request.deadline
            && kill_started.is_none()
            && !killed_for_deadline
            && !killed_for_stream
        {
            kill_complete(pidfd.as_raw_fd(), &cgroup)?;
            killed_for_deadline = true;
            kill_started.get_or_insert_with(Instant::now);
        }
        if kill_started.is_some_and(|value: Instant| value.elapsed() > REAP_GRACE) {
            return Err(LinuxKernelError);
        }
        if let Some(descriptor) = &stdin {
            write_input(descriptor, request.input, &mut input_offset)?;
        }
        exited = pidfd_exited(pidfd.as_raw_fd())?;
        if !exited {
            poll_once(
                pidfd.as_raw_fd(),
                stdout.descriptor.as_raw_fd(),
                stderr.descriptor.as_raw_fd(),
                stdin.as_ref(),
                status.as_ref(),
                started,
                request.deadline,
            )?;
        }
    }

    let wait_status = reap(pid)?;
    cleanup.reaped = true;
    if stdout.exceeded {
        stdout.closed = true;
    }
    if stderr.exceeded {
        stderr.closed = true;
    }
    let drain_deadline = Instant::now() + REAP_GRACE;
    while !stdout.closed || !stderr.closed || status.is_some() {
        stdout.drain()?;
        stderr.drain()?;
        read_setup_status(&mut status, &mut setup_failure)?;
        if Instant::now() >= drain_deadline {
            return Err(LinuxKernelError);
        }
        if !stdout.closed || !stderr.closed || status.is_some() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    cgroup.wait_empty(Instant::now() + REAP_GRACE)?;
    std::fs::remove_dir(&root).map_err(|_| LinuxKernelError)?;
    cleanup.disarm();
    drop(cleanup);
    let (peak_memory_bytes, memory_limit_hit) = cgroup.finish()?;
    if let Some(code) = setup_failure {
        debug_stage("child_setup", Some(i32::from(code)));
        return Err(LinuxKernelError);
    }
    let termination = if memory_limit_hit {
        NativeTermination::MemoryLimitKilled
    } else if killed_for_deadline {
        NativeTermination::DeadlineKilled
    } else if libc::WIFEXITED(wait_status) {
        NativeTermination::Exited(libc::WEXITSTATUS(wait_status))
    } else if libc::WIFSIGNALED(wait_status) {
        NativeTermination::Signaled(libc::WTERMSIG(wait_status) as u32)
    } else {
        return Err(LinuxKernelError);
    };
    Ok(LinuxKernelObservation {
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

struct ProcessCleanup<'a> {
    pid: libc::pid_t,
    pidfd: libc::c_int,
    cgroup: &'a CgroupLeaf,
    root: &'a std::path::Path,
    armed: bool,
    reaped: bool,
}

impl ProcessCleanup<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cgroup.kill();
            // SAFETY: pidfd identifies this attempt's child; ESRCH is already terminated.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd,
                    libc::SIGKILL,
                    null::<libc::siginfo_t>(),
                    0u32,
                );
                if !self.reaped {
                    libc::waitpid(self.pid, std::ptr::null_mut(), 0);
                }
            }
            let _ = std::fs::remove_dir(self.root);
        }
    }
}

struct Capture {
    descriptor: OwnedFd,
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
    closed: bool,
}

impl Capture {
    fn new(descriptor: OwnedFd, limit: usize) -> Self {
        Self {
            descriptor,
            bytes: Vec::with_capacity(limit.min(CHUNK)),
            limit,
            exceeded: false,
            closed: false,
        }
    }

    fn drain(&mut self) -> Result<(), LinuxKernelError> {
        if self.closed {
            return Ok(());
        }
        let mut buffer = [0u8; CHUNK];
        loop {
            // SAFETY: descriptor is live and buffer is writable for CHUNK bytes.
            let count = unsafe {
                libc::read(
                    self.descriptor.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if count == 0 {
                self.closed = true;
                return Ok(());
            }
            if count < 0 {
                let error = std::io::Error::last_os_error().raw_os_error();
                if error == Some(libc::EAGAIN) || error == Some(libc::EWOULDBLOCK) {
                    return Ok(());
                }
                if error == Some(libc::EINTR) {
                    continue;
                }
                return Err(LinuxKernelError);
            }
            let count = count as usize;
            let retained = count.min(self.limit.saturating_sub(self.bytes.len()));
            self.bytes.extend_from_slice(&buffer[..retained]);
            if retained < count {
                self.exceeded = true;
                return Ok(());
            }
        }
    }
}

fn write_input(
    descriptor: &OwnedFd,
    input: &[u8],
    offset: &mut usize,
) -> Result<(), LinuxKernelError> {
    if *offset >= input.len() {
        return Ok(());
    }
    // SAFETY: descriptor is live and the remaining input slice is readable.
    let count = unsafe {
        libc::write(
            descriptor.as_raw_fd(),
            input[*offset..].as_ptr().cast(),
            input.len() - *offset,
        )
    };
    if count < 0 {
        let error = std::io::Error::last_os_error().raw_os_error();
        if error == Some(libc::EAGAIN)
            || error == Some(libc::EWOULDBLOCK)
            || error == Some(libc::EINTR)
        {
            return Ok(());
        }
        if error == Some(libc::EPIPE) {
            *offset = input.len();
            return Ok(());
        }
        return Err(LinuxKernelError);
    }
    if count == 0 {
        return Err(LinuxKernelError);
    }
    *offset = offset.checked_add(count as usize).ok_or(LinuxKernelError)?;
    Ok(())
}

fn read_setup_status(
    status: &mut Option<OwnedFd>,
    failed: &mut Option<u8>,
) -> Result<(), LinuxKernelError> {
    let Some(descriptor) = status else {
        return Ok(());
    };
    let mut byte = 0u8;
    // SAFETY: descriptor is live and byte is writable.
    let count = unsafe { libc::read(descriptor.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) };
    if count == 0 {
        status.take();
        return Ok(());
    }
    if count == 1 {
        *failed = Some(byte);
        return Ok(());
    }
    let error = std::io::Error::last_os_error().raw_os_error();
    if error == Some(libc::EAGAIN) || error == Some(libc::EWOULDBLOCK) || error == Some(libc::EINTR)
    {
        Ok(())
    } else {
        Err(LinuxKernelError)
    }
}

fn pidfd_exited(pidfd: libc::c_int) -> Result<bool, LinuxKernelError> {
    let mut poll = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll points to one initialized descriptor record.
    let result = unsafe { libc::poll(&mut poll, 1, 0) };
    if result < 0 {
        return Err(LinuxKernelError);
    }
    Ok(result == 1 && poll.revents & libc::POLLIN != 0)
}

fn poll_once(
    pidfd: libc::c_int,
    stdout: libc::c_int,
    stderr: libc::c_int,
    stdin: Option<&OwnedFd>,
    status: Option<&OwnedFd>,
    started: Instant,
    deadline: Duration,
) -> Result<(), LinuxKernelError> {
    let mut descriptors = [
        libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
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
            fd: -1,
            events: 0,
            revents: 0,
        },
        libc::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        },
    ];
    let mut count = 3usize;
    if let Some(fd) = stdin {
        descriptors[count] = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        count += 1;
    }
    if let Some(fd) = status {
        descriptors[count] = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        count += 1;
    }
    let remaining = deadline
        .saturating_sub(started.elapsed())
        .min(Duration::from_millis(10));
    let timeout = i32::try_from(remaining.as_millis()).unwrap_or(10).max(1);
    // SAFETY: descriptors is a live contiguous initialized pollfd array.
    if unsafe { libc::poll(descriptors.as_mut_ptr(), count as libc::nfds_t, timeout) } < 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
    {
        return Err(LinuxKernelError);
    }
    Ok(())
}

fn kill_complete(pidfd: libc::c_int, cgroup: &CgroupLeaf) -> Result<(), LinuxKernelError> {
    cgroup.kill()?;
    // SAFETY: pidfd belongs to the child and siginfo is intentionally null.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            libc::SIGKILL,
            null::<libc::siginfo_t>(),
            0u32,
        )
    };
    if result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(LinuxKernelError)
    }
}

fn reap(pid: libc::pid_t) -> Result<libc::c_int, LinuxKernelError> {
    let mut status = 0;
    // SAFETY: pid is the unreaped direct clone3 child and status is writable.
    if unsafe { libc::waitpid(pid, &mut status, 0) } == pid {
        Ok(status)
    } else {
        Err(LinuxKernelError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    #[test]
    fn capture_retains_exact_bound_and_reports_overflow() {
        let (read, write) = pipe_nonblocking();
        let bytes = vec![b'x'; 2048];
        // SAFETY: write is live and bytes is readable.
        assert_eq!(
            unsafe { libc::write(write.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) },
            bytes.len() as isize
        );
        let mut capture = Capture::new(read, 1024);
        capture.drain().expect("drain");
        assert!(capture.exceeded);
        assert_eq!(capture.bytes, vec![b'x'; 1024]);
    }

    #[test]
    fn setup_status_distinguishes_failure_and_exec_close() {
        let (read, write) = pipe_nonblocking();
        let mut status = Some(read);
        let mut failed = None;
        // SAFETY: write is live and code is readable.
        let code = 7u8;
        assert_eq!(
            unsafe { libc::write(write.as_raw_fd(), (&code as *const u8).cast(), 1) },
            1
        );
        read_setup_status(&mut status, &mut failed).expect("status failure");
        assert_eq!(failed, Some(code));
        drop(write);
        read_setup_status(&mut status, &mut failed).expect("status eof");
        assert!(status.is_none());
    }

    fn pipe_nonblocking() -> (OwnedFd, OwnedFd) {
        let mut descriptors = [-1; 2];
        // SAFETY: descriptors is a writable pair and flags are valid.
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        // SAFETY: pipe2 returned two new owned descriptors.
        unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        }
    }
}
