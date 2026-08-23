use super::{WindowsConfinementKernel, WindowsKernelExecution, WindowsKernelObservation};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_APPCONTAINER_REQUIRED, ERROR_BAD_ENVIRONMENT,
    ERROR_BAD_EXE_FORMAT, ERROR_BAD_LENGTH, ERROR_BAD_PATHNAME, ERROR_BROKEN_PIPE,
    ERROR_BUFFER_OVERFLOW, ERROR_CALL_NOT_IMPLEMENTED, ERROR_COMMITMENT_LIMIT,
    ERROR_CURRENT_DIRECTORY, ERROR_DIRECTORY, ERROR_DLL_INIT_FAILED, ERROR_DLL_NOT_FOUND,
    ERROR_ELEVATION_REQUIRED, ERROR_ENVVAR_NOT_FOUND, ERROR_EXE_MACHINE_TYPE_MISMATCH,
    ERROR_EXE_MARKED_INVALID, ERROR_FILE_NOT_FOUND, ERROR_FILENAME_EXCED_RANGE,
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_ACCESS, ERROR_INVALID_DATA,
    ERROR_INVALID_EXE_SIGNATURE, ERROR_INVALID_FUNCTION, ERROR_INVALID_HANDLE,
    ERROR_INVALID_MODULETYPE, ERROR_INVALID_NAME, ERROR_INVALID_PARAMETER,
    ERROR_INVALID_SECURITY_DESCR, ERROR_INVALID_SID, ERROR_MOD_NOT_FOUND,
    ERROR_NESTING_NOT_ALLOWED, ERROR_NO_DATA, ERROR_NO_SYSTEM_RESOURCES, ERROR_NO_TOKEN,
    ERROR_NOT_APPCONTAINER, ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_SUPPORTED,
    ERROR_NOT_SUPPORTED_IN_APPCONTAINER, ERROR_OUTOFMEMORY, ERROR_PATH_NOT_FOUND,
    ERROR_PRIVILEGE_NOT_HELD, ERROR_PROC_NOT_FOUND, ERROR_SUCCESS, GetLastError, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::NetworkManagement::WindowsFirewall::NetworkIsolationGetAppContainerConfig;
use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows_sys::Win32::Security::{
    EqualSid, FreeSid, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2, JobObjectAssociateCompletionPortInformation,
    JobObjectBasicAccountingInformation, JobObjectBasicUIRestrictions,
    JobObjectExtendedLimitInformation, JobObjectLimitViolationInformation2,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
use windows_sys::Win32::System::SystemServices::JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
    InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};

const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const IO_CHUNK_BYTES: usize = 16 * 1024;
const REAP_TIMEOUT: Duration = Duration::from_secs(5);
const TERMINATION_EXIT_CODE: u32 = 0x5453_5043;
const MAX_LOOPBACK_EXEMPTIONS: u32 = 65_536;
const JOB_COMPLETION_KEY: usize = 1;
// `windows-sys` currently defines JOB_OBJECT_UILIMIT_ALL as 0x1ff. The 0x100 IME bit is
// rejected with ERROR_INVALID_PARAMETER on older supported Windows kernels. Spell out the
// complete, stable 0xff control set so the signed policy is exact and cross-version deterministic.
const STABLE_JOB_UI_RESTRICTIONS: u32 = JOB_OBJECT_UILIMIT_HANDLES
    | JOB_OBJECT_UILIMIT_READCLIPBOARD
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    | JOB_OBJECT_UILIMIT_GLOBALATOMS
    | JOB_OBJECT_UILIMIT_DESKTOP
    | JOB_OBJECT_UILIMIT_EXITWINDOWS;

#[derive(Clone, Copy, Debug, Default)]
pub struct Win32Kernel;

/// Bounded failure stages for trusted native-proof diagnostics.
///
/// These values deliberately contain no Win32 error code, path, handle, environment value,
/// or plugin-controlled data. The product driver still maps every value to its generic
/// `LaunchFailure` boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win32KernelStage {
    AppContainerIdentity,
    LoopbackPolicy,
    JobCreation,
    JobLimits,
    JobUiRestrictions,
    JobUiRestrictionsAccessDenied,
    JobUiRestrictionsInvalid,
    JobUiRestrictionsUnsupported,
    PipeCreation,
    AttributeList,
    Environment,
    ProcessCreation,
    ProcessCreationAccessDenied,
    ProcessCreationBadImage,
    ProcessCreationDependency,
    ProcessCreationElevationRequired,
    ProcessCreationEnvironmentMalformed,
    ProcessCreationEnvironmentMissing,
    ProcessCreationInvocation,
    ProcessCreationInvalid,
    ProcessCreationNotFound,
    ProcessCreationResources,
    ProcessCreationSecurityContext,
    ProcessCreationUnsupported,
    ProcessCreationWithoutStatus,
    ProcessCreationSystem1To31,
    ProcessCreationSystem32To63,
    ProcessCreationSystem64To127,
    ProcessCreationSystem128To255,
    ProcessCreationLoaderClass,
    ProcessCreationSecurityOrRuntimeClass,
    ProcessCreationPackageClass,
    ProcessCreationOtherClass,
    JobAssignment,
    ThreadResume,
    InputWriter,
    StreamCapture,
    ProcessWait,
    Termination,
    Reap,
    ExitStatus,
    JobAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win32KernelError {
    stage: Win32KernelStage,
}

impl Win32KernelError {
    const fn new(stage: Win32KernelStage) -> Self {
        Self { stage }
    }

    pub const fn stage(self) -> Win32KernelStage {
        self.stage
    }
}

impl WindowsConfinementKernel for Win32Kernel {
    type Error = Win32KernelError;

    fn preflight(&self, app_container_name: &str) -> Result<(), Self::Error> {
        let sid = AppContainerSid::derive(app_container_name)
            .map_err(|_| Win32KernelError::new(Win32KernelStage::AppContainerIdentity))?;
        verify_not_loopback_exempt(sid.as_ptr())
    }

    fn execute(
        &self,
        execution: WindowsKernelExecution<'_>,
    ) -> Result<WindowsKernelObservation, Self::Error> {
        // Re-derive and re-check immediately before launch to close the preflight/launch gap.
        let sid = AppContainerSid::derive(execution.app_container_name)
            .map_err(|_| Win32KernelError::new(Win32KernelStage::AppContainerIdentity))?;
        verify_not_loopback_exempt(sid.as_ptr())?;
        execute_confined(execution, sid.as_ptr())
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE, stage: Win32KernelStage) -> Result<Self, Win32KernelError> {
        if handle.is_null() {
            Err(Win32KernelError::new(stage))
        } else {
            Ok(Self(handle))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }

    fn into_raw(mut self) -> HANDLE {
        let handle = self.0;
        self.0 = null_mut();
        handle
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this instance uniquely owns a valid Win32 handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct AppContainerSid(PSID);

impl AppContainerSid {
    fn derive(name: &str) -> Result<Self, Win32KernelError> {
        let name = wide_null(name);
        let mut sid = null_mut();
        // SAFETY: name is NUL terminated and sid is a valid out pointer.
        let status = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if status < 0 || sid.is_null() {
            return Err(Win32KernelError::new(
                Win32KernelStage::AppContainerIdentity,
            ));
        }
        Ok(Self(sid))
    }

    fn as_ptr(&self) -> PSID {
        self.0
    }
}

impl Drop for AppContainerSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the SID was allocated by DeriveAppContainerSidFromAppContainerName.
            unsafe {
                FreeSid(self.0);
            }
        }
    }
}

struct LoopbackList(*mut SID_AND_ATTRIBUTES);

impl Drop for LoopbackList {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: NetworkIsolationGetAppContainerConfig returns COM task memory.
            unsafe {
                CoTaskMemFree(self.0.cast());
            }
        }
    }
}

fn verify_not_loopback_exempt(sid: PSID) -> Result<(), Win32KernelError> {
    let mut count = 0u32;
    let mut entries = null_mut();
    // SAFETY: both arguments are valid out pointers.
    let status = unsafe { NetworkIsolationGetAppContainerConfig(&mut count, &mut entries) };
    if status != 0 || count > MAX_LOOPBACK_EXEMPTIONS || (count != 0 && entries.is_null()) {
        if !entries.is_null() {
            let _guard = LoopbackList(entries);
        }
        return Err(Win32KernelError::new(Win32KernelStage::LoopbackPolicy));
    }
    let list = LoopbackList(entries);
    if count == 0 {
        return Ok(());
    }
    // SAFETY: the API returned count initialized entries and the count is bounded above.
    let entries = unsafe { std::slice::from_raw_parts(list.0, count as usize) };
    if entries.iter().any(|entry| {
        !entry.Sid.is_null() && {
            // SAFETY: both arguments are SIDs returned by Windows security APIs.
            unsafe { EqualSid(sid, entry.Sid) != 0 }
        }
    }) {
        return Err(Win32KernelError::new(Win32KernelStage::LoopbackPolicy));
    }
    Ok(())
}

struct AttributeList {
    storage: Vec<usize>,
}

impl AttributeList {
    fn new(attribute_count: u32) -> Result<Self, Win32KernelError> {
        let mut bytes = 0usize;
        // SAFETY: a null first argument is the documented size query.
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), attribute_count, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(Win32KernelError::new(Win32KernelStage::AttributeList));
        }
        let units = bytes
            .checked_add(size_of::<usize>() - 1)
            .ok_or_else(|| Win32KernelError::new(Win32KernelStage::AttributeList))?
            / size_of::<usize>();
        let mut storage = vec![0usize; units];
        // SAFETY: storage is aligned and large enough for the size returned by Windows.
        let ok = unsafe {
            InitializeProcThreadAttributeList(
                storage.as_mut_ptr().cast(),
                attribute_count,
                0,
                &mut bytes,
            )
        };
        if ok == 0 {
            return Err(Win32KernelError::new(Win32KernelStage::AttributeList));
        }
        Ok(Self { storage })
    }

    fn as_ptr(&mut self) -> *mut c_void {
        self.storage.as_mut_ptr().cast()
    }

    fn update(
        &mut self,
        attribute: usize,
        value: *const c_void,
        bytes: usize,
    ) -> Result<(), Win32KernelError> {
        // SAFETY: this list was initialized and value remains alive through CreateProcessW.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                attribute,
                value,
                bytes,
                null_mut(),
                null(),
            )
        };
        if ok == 0 {
            Err(Win32KernelError::new(Win32KernelStage::AttributeList))
        } else {
            Ok(())
        }
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if !self.storage.is_empty() {
            // SAFETY: the list was successfully initialized and is deleted exactly once.
            unsafe {
                DeleteProcThreadAttributeList(self.storage.as_mut_ptr().cast());
            }
        }
    }
}

struct Pipe {
    parent: OwnedHandle,
    child: OwnedHandle,
}

fn stdin_pipe() -> Result<Pipe, Win32KernelError> {
    let (read, write) = create_inherited_pipe()?;
    clear_inherit(write.raw())?;
    Ok(Pipe {
        parent: write,
        child: read,
    })
}

fn output_pipe() -> Result<Pipe, Win32KernelError> {
    let (read, write) = create_inherited_pipe()?;
    clear_inherit(read.raw())?;
    Ok(Pipe {
        parent: read,
        child: write,
    })
}

fn create_inherited_pipe() -> Result<(OwnedHandle, OwnedHandle), Win32KernelError> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| Win32KernelError::new(Win32KernelStage::PipeCreation))?,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut read = null_mut();
    let mut write = null_mut();
    // SAFETY: out pointers and the security attributes are valid.
    let ok = unsafe { CreatePipe(&mut read, &mut write, &attributes, PIPE_BUFFER_BYTES) };
    if ok == 0 {
        return Err(Win32KernelError::new(Win32KernelStage::PipeCreation));
    }
    let read = OwnedHandle::new(read, Win32KernelStage::PipeCreation)?;
    let write = OwnedHandle::new(write, Win32KernelStage::PipeCreation)?;
    Ok((read, write))
}

fn clear_inherit(handle: HANDLE) -> Result<(), Win32KernelError> {
    // SAFETY: handle is a live pipe handle.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        Err(Win32KernelError::new(Win32KernelStage::PipeCreation))
    } else {
        Ok(())
    }
}

fn execute_confined(
    execution: WindowsKernelExecution<'_>,
    app_container_sid: PSID,
) -> Result<WindowsKernelObservation, Win32KernelError> {
    let started = Instant::now();
    let (job, completion_port) = create_job(execution.maximum_memory_bytes)?;
    let stdin = stdin_pipe()?;
    let stdout = output_pipe()?;
    let stderr = output_pipe()?;

    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: app_container_sid,
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let inherited_handles = [stdin.child.raw(), stdout.child.raw(), stderr.child.raw()];
    let mut attributes = AttributeList::new(2)?;
    attributes.update(
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
        (&capabilities as *const SECURITY_CAPABILITIES).cast(),
        size_of::<SECURITY_CAPABILITIES>(),
    )?;
    attributes.update(
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
        inherited_handles.as_ptr().cast(),
        size_of_val(&inherited_handles),
    )?;

    let executable = wide_path_null(execution.executable_path);
    let current_directory = wide_path_null(execution.working_directory);
    let mut command_line = quoted_command_line(execution.executable_path, execution.arguments)?;
    let environment = environment_block(execution.environment)?;
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>())
        .map_err(|_| Win32KernelError::new(Win32KernelStage::ProcessCreation))?;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin.child.raw();
    startup.StartupInfo.hStdOutput = stdout.child.raw();
    startup.StartupInfo.hStdError = stderr.child.raw();
    startup.lpAttributeList = attributes.as_ptr();
    let mut process: PROCESS_INFORMATION = unsafe { zeroed() };
    let creation_flags = CREATE_SUSPENDED
        | CREATE_NO_WINDOW
        | CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT;
    // SAFETY: all pointers remain alive for the call and only the three listed handles inherit.
    let created = unsafe {
        CreateProcessW(
            executable.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            creation_flags,
            environment.as_ptr().cast(),
            current_directory.as_ptr(),
            &startup.StartupInfo,
            &mut process,
        )
    };
    if created == 0 || process.hProcess.is_null() || process.hThread.is_null() {
        // SAFETY: this is read immediately after the failed Win32 call on the same thread.
        let stage = match unsafe { GetLastError() } {
            ERROR_SUCCESS => Win32KernelStage::ProcessCreationWithoutStatus,
            ERROR_ACCESS_DENIED => Win32KernelStage::ProcessCreationAccessDenied,
            ERROR_BAD_EXE_FORMAT
            | ERROR_EXE_MARKED_INVALID
            | ERROR_INVALID_EXE_SIGNATURE
            | ERROR_INVALID_MODULETYPE => Win32KernelStage::ProcessCreationBadImage,
            ERROR_DLL_INIT_FAILED
            | ERROR_DLL_NOT_FOUND
            | ERROR_MOD_NOT_FOUND
            | ERROR_PROC_NOT_FOUND => Win32KernelStage::ProcessCreationDependency,
            ERROR_ELEVATION_REQUIRED => Win32KernelStage::ProcessCreationElevationRequired,
            ERROR_BAD_ENVIRONMENT => Win32KernelStage::ProcessCreationEnvironmentMalformed,
            ERROR_ENVVAR_NOT_FOUND => Win32KernelStage::ProcessCreationEnvironmentMissing,
            ERROR_BAD_LENGTH
            | ERROR_BAD_PATHNAME
            | ERROR_BUFFER_OVERFLOW
            | ERROR_FILENAME_EXCED_RANGE
            | ERROR_INSUFFICIENT_BUFFER
            | ERROR_INVALID_ACCESS
            | ERROR_INVALID_DATA
            | ERROR_INVALID_HANDLE
            | ERROR_INVALID_NAME => Win32KernelStage::ProcessCreationInvocation,
            ERROR_EXE_MACHINE_TYPE_MISMATCH | ERROR_INVALID_PARAMETER => {
                Win32KernelStage::ProcessCreationInvalid
            }
            ERROR_CURRENT_DIRECTORY
            | ERROR_DIRECTORY
            | ERROR_FILE_NOT_FOUND
            | ERROR_PATH_NOT_FOUND => Win32KernelStage::ProcessCreationNotFound,
            ERROR_COMMITMENT_LIMIT
            | ERROR_NOT_ENOUGH_MEMORY
            | ERROR_NO_SYSTEM_RESOURCES
            | ERROR_OUTOFMEMORY => Win32KernelStage::ProcessCreationResources,
            ERROR_APPCONTAINER_REQUIRED
            | ERROR_INVALID_SECURITY_DESCR
            | ERROR_INVALID_SID
            | ERROR_NOT_APPCONTAINER
            | ERROR_NO_TOKEN
            | ERROR_PRIVILEGE_NOT_HELD => Win32KernelStage::ProcessCreationSecurityContext,
            ERROR_CALL_NOT_IMPLEMENTED
            | ERROR_INVALID_FUNCTION
            | ERROR_NESTING_NOT_ALLOWED
            | ERROR_NOT_SUPPORTED
            | ERROR_NOT_SUPPORTED_IN_APPCONTAINER => Win32KernelStage::ProcessCreationUnsupported,
            1..=31 => Win32KernelStage::ProcessCreationSystem1To31,
            32..=63 => Win32KernelStage::ProcessCreationSystem32To63,
            64..=127 => Win32KernelStage::ProcessCreationSystem64To127,
            128..=255 => Win32KernelStage::ProcessCreationSystem128To255,
            256..=1023 => Win32KernelStage::ProcessCreationLoaderClass,
            1024..=4095 => Win32KernelStage::ProcessCreationSecurityOrRuntimeClass,
            4096..=16_383 => Win32KernelStage::ProcessCreationPackageClass,
            _ => Win32KernelStage::ProcessCreationOtherClass,
        };
        return Err(Win32KernelError::new(stage));
    }
    let process_handle = OwnedHandle::new(process.hProcess, Win32KernelStage::ProcessCreation)?;
    let thread_handle = OwnedHandle::new(process.hThread, Win32KernelStage::ProcessCreation)?;
    drop(stdin.child);
    drop(stdout.child);
    drop(stderr.child);

    // SAFETY: the process is still suspended and both handles are valid.
    if unsafe { AssignProcessToJobObject(job.raw(), process_handle.raw()) } == 0 {
        terminate_unassigned_and_reap(process_handle.raw())?;
        return Err(Win32KernelError::new(Win32KernelStage::JobAssignment));
    }
    // SAFETY: this is the initial suspended thread and it has not been resumed before.
    if unsafe { ResumeThread(thread_handle.raw()) } == u32::MAX {
        terminate_job_and_reap(job.raw(), process_handle.raw())?;
        return Err(Win32KernelError::new(Win32KernelStage::ThreadResume));
    }
    drop(thread_handle);

    let writer = match spawn_stdin_writer(stdin.parent, execution.input.to_vec()) {
        Ok(writer) => StdinWriter(Some(writer)),
        Err(error) => {
            terminate_job_and_reap(job.raw(), process_handle.raw())?;
            return Err(error);
        }
    };
    // Declared after the writer so errors kill the process before joining its writer.
    let mut cleanup = AssignedProcessCleanup::new(job.raw(), process_handle.raw());
    let mut stdout_capture = StreamCapture::new(stdout.parent, execution.maximum_stdout_bytes);
    let mut stderr_capture = StreamCapture::new(stderr.parent, execution.maximum_stderr_bytes);
    let mut deadline_killed = false;
    let mut memory_limit_killed = false;
    let mut limit_killed = false;
    let mut termination_started = None;
    loop {
        stdout_capture.drain_available()?;
        stderr_capture.drain_available()?;
        if drain_job_notifications(completion_port.raw())?
            && !memory_limit_killed
            && !deadline_killed
            && !limit_killed
        {
            terminate_job(job.raw())?;
            memory_limit_killed = true;
            termination_started = Some(Instant::now());
        }
        if (stdout_capture.exceeded || stderr_capture.exceeded) && !limit_killed {
            terminate_job(job.raw())?;
            limit_killed = true;
            termination_started = Some(Instant::now());
        }
        // SAFETY: process_handle remains live for the complete loop.
        match unsafe { WaitForSingleObject(process_handle.raw(), 0) } {
            WAIT_OBJECT_0 => {
                break;
            }
            WAIT_TIMEOUT => {}
            WAIT_FAILED => {
                return Err(Win32KernelError::new(Win32KernelStage::ProcessWait));
            }
            _ => return Err(Win32KernelError::new(Win32KernelStage::ProcessWait)),
        }
        if started.elapsed() >= execution.deadline && !deadline_killed && !limit_killed {
            terminate_job(job.raw())?;
            deadline_killed = true;
            termination_started = Some(Instant::now());
        }
        if termination_started.is_some_and(|value: Instant| value.elapsed() > REAP_TIMEOUT) {
            return Err(Win32KernelError::new(Win32KernelStage::Reap));
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    if writer.join()?.is_err() && !deadline_killed && !limit_killed {
        return Err(Win32KernelError::new(Win32KernelStage::InputWriter));
    }
    drain_after_exit(&mut stdout_capture, &mut stderr_capture)?;
    memory_limit_killed |= drain_job_notifications(completion_port.raw())?;

    let mut exit_code = 0u32;
    // SAFETY: the process is signaled and the out pointer is valid.
    if unsafe { GetExitCodeProcess(process_handle.raw(), &mut exit_code) } == 0 {
        return Err(Win32KernelError::new(Win32KernelStage::ExitStatus));
    }
    let (peak_memory_bytes, process_reaped, memory_limit_violated) = job_observation(job.raw())?;
    memory_limit_killed |= memory_limit_violated;
    if !process_reaped {
        return Err(Win32KernelError::new(Win32KernelStage::Reap));
    }
    cleanup.disarm();
    let termination = if deadline_killed {
        tokensaver_certification_confinement::NativeTermination::DeadlineKilled
    } else if memory_limit_killed {
        tokensaver_certification_confinement::NativeTermination::MemoryLimitKilled
    } else if exit_code & 0x8000_0000 != 0 {
        tokensaver_certification_confinement::NativeTermination::Exception(exit_code)
    } else {
        tokensaver_certification_confinement::NativeTermination::Exited(exit_code as i32)
    };
    Ok(WindowsKernelObservation {
        termination,
        stdout: stdout_capture.bytes,
        stderr: stderr_capture.bytes,
        duration_milliseconds: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        peak_memory_bytes,
        stdout_limit_exceeded: stdout_capture.exceeded,
        stderr_limit_exceeded: stderr_capture.exceeded,
        process_reaped,
    })
}

struct AssignedProcessCleanup {
    job: HANDLE,
    process: HANDLE,
    armed: bool,
}

impl AssignedProcessCleanup {
    fn new(job: HANDLE, process: HANDLE) -> Self {
        Self {
            job,
            process,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for AssignedProcessCleanup {
    fn drop(&mut self) {
        if self.armed {
            if terminate_job(self.job).is_err() {
                // SAFETY: this is the root process in the owned one-process job.
                unsafe {
                    TerminateProcess(self.process, TERMINATION_EXIT_CODE);
                }
            }
            let _ = wait_reaped(self.process);
        }
    }
}

fn create_job(maximum_memory_bytes: u64) -> Result<(OwnedHandle, OwnedHandle), Win32KernelError> {
    let memory = usize::try_from(maximum_memory_bytes)
        .map_err(|_| Win32KernelError::new(Win32KernelStage::JobLimits))?;
    // SAFETY: null attributes and name request a private default-security job object.
    let job = OwnedHandle::new(
        unsafe { CreateJobObjectW(null(), null()) },
        Win32KernelStage::JobCreation,
    )?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.ProcessMemoryLimit = memory;
    // SAFETY: job and the fixed-size information buffer are valid.
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .map_err(|_| Win32KernelError::new(Win32KernelStage::JobLimits))?,
        )
    } == 0
    {
        return Err(Win32KernelError::new(Win32KernelStage::JobLimits));
    }
    let restrictions = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: STABLE_JOB_UI_RESTRICTIONS,
    };
    // SAFETY: job and the fixed-size information buffer are valid.
    let ui_restricted = unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectBasicUIRestrictions,
            (&restrictions as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
            u32::try_from(size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>())
                .map_err(|_| Win32KernelError::new(Win32KernelStage::JobUiRestrictions))?,
        )
    };
    if ui_restricted == 0 {
        // SAFETY: this is read immediately after the failed Win32 call on the same thread.
        let stage = match unsafe { GetLastError() } {
            ERROR_ACCESS_DENIED => Win32KernelStage::JobUiRestrictionsAccessDenied,
            ERROR_INVALID_PARAMETER => Win32KernelStage::JobUiRestrictionsInvalid,
            ERROR_NOT_SUPPORTED => Win32KernelStage::JobUiRestrictionsUnsupported,
            _ => Win32KernelStage::JobUiRestrictions,
        };
        return Err(Win32KernelError::new(stage));
    }
    // SAFETY: INVALID_HANDLE_VALUE requests a new private completion port.
    let completion_port = OwnedHandle::new(
        unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 1) },
        Win32KernelStage::JobCreation,
    )?;
    let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
        CompletionKey: JOB_COMPLETION_KEY as *mut c_void,
        CompletionPort: completion_port.raw(),
    };
    // SAFETY: the job, completion port, and fixed-size association are valid and live.
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectAssociateCompletionPortInformation,
            (&association as *const JOBOBJECT_ASSOCIATE_COMPLETION_PORT).cast(),
            u32::try_from(size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>())
                .map_err(|_| Win32KernelError::new(Win32KernelStage::JobCreation))?,
        )
    } == 0
    {
        return Err(Win32KernelError::new(Win32KernelStage::JobCreation));
    }
    Ok((job, completion_port))
}

fn terminate_job(job: HANDLE) -> Result<(), Win32KernelError> {
    // SAFETY: job is live and owned by this execution.
    if unsafe { TerminateJobObject(job, TERMINATION_EXIT_CODE) } == 0 {
        Err(Win32KernelError::new(Win32KernelStage::Termination))
    } else {
        Ok(())
    }
}

fn terminate_job_and_reap(job: HANDLE, process: HANDLE) -> Result<(), Win32KernelError> {
    terminate_job(job)?;
    wait_reaped(process)
}

fn terminate_unassigned_and_reap(process: HANDLE) -> Result<(), Win32KernelError> {
    // SAFETY: process is live, suspended, and not assigned to the configured job.
    if unsafe { TerminateProcess(process, TERMINATION_EXIT_CODE) } == 0 {
        return Err(Win32KernelError::new(Win32KernelStage::Termination));
    }
    wait_reaped(process)
}

fn wait_reaped(process: HANDLE) -> Result<(), Win32KernelError> {
    let timeout = u32::try_from(REAP_TIMEOUT.as_millis())
        .map_err(|_| Win32KernelError::new(Win32KernelStage::Reap))?;
    // SAFETY: process is a live process handle.
    if unsafe { WaitForSingleObject(process, timeout) } == WAIT_OBJECT_0 {
        Ok(())
    } else {
        Err(Win32KernelError::new(Win32KernelStage::Reap))
    }
}

fn job_observation(job: HANDLE) -> Result<(u64, bool, bool), Win32KernelError> {
    let deadline = Instant::now() + REAP_TIMEOUT;
    let mut peak_memory_bytes = 0u64;
    loop {
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        // SAFETY: job and the fixed-size output buffer are valid.
        if unsafe {
            QueryInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .map_err(|_| Win32KernelError::new(Win32KernelStage::JobAccounting))?,
                null_mut(),
            )
        } == 0
        {
            return Err(Win32KernelError::new(Win32KernelStage::JobAccounting));
        }
        peak_memory_bytes =
            peak_memory_bytes.max(u64::try_from(limits.PeakProcessMemoryUsed).unwrap_or(u64::MAX));
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
        // SAFETY: job and the fixed-size output buffer are valid.
        if unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                u32::try_from(size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>())
                    .map_err(|_| Win32KernelError::new(Win32KernelStage::JobAccounting))?,
                null_mut(),
            )
        } == 0
        {
            return Err(Win32KernelError::new(Win32KernelStage::JobAccounting));
        }
        if accounting.ActiveProcesses == 0 {
            return Ok((peak_memory_bytes, true, memory_limit_violated(job)?));
        }
        if Instant::now() >= deadline {
            return Ok((peak_memory_bytes, false, false));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn memory_limit_violated(job: HANDLE) -> Result<bool, Win32KernelError> {
    let mut violation: JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2 = unsafe { zeroed() };
    // SAFETY: job and the fixed-size output buffer are valid.
    if unsafe {
        QueryInformationJobObject(
            job,
            JobObjectLimitViolationInformation2,
            (&mut violation as *mut JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2).cast(),
            u32::try_from(size_of::<JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2>())
                .map_err(|_| Win32KernelError::new(Win32KernelStage::JobAccounting))?,
            null_mut(),
        )
    } == 0
    {
        return Err(Win32KernelError::new(Win32KernelStage::JobAccounting));
    }
    Ok(violation.ViolationLimitFlags & JOB_OBJECT_LIMIT_PROCESS_MEMORY != 0)
}

fn drain_job_notifications(completion_port: HANDLE) -> Result<bool, Win32KernelError> {
    let mut memory_limit = false;
    loop {
        let mut message = 0u32;
        let mut completion_key = 0usize;
        let mut overlapped = null_mut();
        // SAFETY: the completion port is live and all output pointers are valid.
        let received = unsafe {
            GetQueuedCompletionStatus(
                completion_port,
                &mut message,
                &mut completion_key,
                &mut overlapped,
                0,
            )
        };
        if received == 0 {
            // SAFETY: this is read immediately after the failed Win32 call on the same thread.
            if unsafe { GetLastError() } == WAIT_TIMEOUT {
                return Ok(memory_limit);
            }
            return Err(Win32KernelError::new(Win32KernelStage::JobAccounting));
        }
        if completion_key != JOB_COMPLETION_KEY {
            return Err(Win32KernelError::new(Win32KernelStage::JobAccounting));
        }
        if message == JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT {
            memory_limit = true;
        }
    }
}

fn spawn_stdin_writer(
    handle: OwnedHandle,
    input: Vec<u8>,
) -> Result<std::thread::JoinHandle<Result<(), ()>>, Win32KernelError> {
    let raw = handle.into_raw() as usize;
    std::thread::Builder::new()
        .name("tsp-certification-stdin".into())
        .spawn(move || {
            let handle = OwnedHandle(raw as HANDLE);
            let mut offset = 0usize;
            while offset < input.len() {
                let chunk = (input.len() - offset).min(u32::MAX as usize);
                let mut written = 0u32;
                // SAFETY: handle is live and the selected input slice is valid for this call.
                let ok = unsafe {
                    WriteFile(
                        handle.raw(),
                        input[offset..].as_ptr(),
                        u32::try_from(chunk).map_err(|_| ())?,
                        &mut written,
                        null_mut(),
                    )
                };
                if ok == 0 || written == 0 {
                    return Err(());
                }
                offset = offset.checked_add(written as usize).ok_or(())?;
            }
            Ok(())
        })
        .map_err(|_| Win32KernelError::new(Win32KernelStage::InputWriter))
}

struct StdinWriter(Option<std::thread::JoinHandle<Result<(), ()>>>);

impl StdinWriter {
    fn join(mut self) -> Result<Result<(), ()>, Win32KernelError> {
        self.0
            .take()
            .ok_or_else(|| Win32KernelError::new(Win32KernelStage::InputWriter))?
            .join()
            .map_err(|_| Win32KernelError::new(Win32KernelStage::InputWriter))
    }
}

impl Drop for StdinWriter {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let _ = handle.join();
        }
    }
}

struct StreamCapture {
    handle: OwnedHandle,
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
    closed: bool,
}

impl StreamCapture {
    fn new(handle: OwnedHandle, limit: usize) -> Self {
        Self {
            handle,
            bytes: Vec::with_capacity(limit.min(IO_CHUNK_BYTES)),
            limit,
            exceeded: false,
            closed: false,
        }
    }

    fn drain_available(&mut self) -> Result<(), Win32KernelError> {
        if self.closed {
            return Ok(());
        }
        loop {
            let mut available = 0u32;
            // SAFETY: handle is a live parent-side anonymous pipe handle.
            let ok = unsafe {
                PeekNamedPipe(
                    self.handle.raw(),
                    null_mut(),
                    0,
                    null_mut(),
                    &mut available,
                    null_mut(),
                )
            };
            if ok == 0 {
                let code = std::io::Error::last_os_error().raw_os_error();
                if matches!(code, Some(value) if value == ERROR_BROKEN_PIPE as i32 || value == ERROR_NO_DATA as i32)
                {
                    self.closed = true;
                    return Ok(());
                }
                return Err(Win32KernelError::new(Win32KernelStage::StreamCapture));
            }
            if available == 0 {
                return Ok(());
            }
            let read_size = (available as usize).min(IO_CHUNK_BYTES);
            let mut buffer = [0u8; IO_CHUNK_BYTES];
            let mut read = 0u32;
            // SAFETY: availability was checked and buffer is valid for read_size bytes.
            let ok = unsafe {
                ReadFile(
                    self.handle.raw(),
                    buffer.as_mut_ptr(),
                    u32::try_from(read_size)
                        .map_err(|_| Win32KernelError::new(Win32KernelStage::StreamCapture))?,
                    &mut read,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(Win32KernelError::new(Win32KernelStage::StreamCapture));
            }
            if read == 0 {
                return Ok(());
            }
            let read = read as usize;
            let remaining = self.limit.saturating_sub(self.bytes.len());
            let retained = read.min(remaining);
            self.bytes.extend_from_slice(&buffer[..retained]);
            if retained < read {
                self.exceeded = true;
            }
        }
    }
}

fn drain_after_exit(
    stdout: &mut StreamCapture,
    stderr: &mut StreamCapture,
) -> Result<(), Win32KernelError> {
    let deadline = Instant::now() + REAP_TIMEOUT;
    while !stdout.closed || !stderr.closed {
        stdout.drain_available()?;
        stderr.drain_available()?;
        if Instant::now() >= deadline {
            return Err(Win32KernelError::new(Win32KernelStage::StreamCapture));
        }
        if !stdout.closed || !stderr.closed {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(())
}

fn environment_block(environment: &[(String, String)]) -> Result<Vec<u16>, Win32KernelError> {
    let mut values = environment.to_vec();
    values.push(("TOKENSAVER_PLUGIN".into(), "1".into()));
    values.sort_by(|left, right| left.0.cmp(&right.0));
    let mut block = Vec::new();
    for (name, value) in values {
        if name.contains('\0') || name.contains('=') || value.contains('\0') {
            return Err(Win32KernelError::new(Win32KernelStage::Environment));
        }
        block.extend(name.encode_utf16());
        block.push('=' as u16);
        block.extend(value.encode_utf16());
        block.push(0);
    }
    block.push(0);
    if block.len() > super::MAX_ENVIRONMENT_UTF16_UNITS {
        return Err(Win32KernelError::new(Win32KernelStage::Environment));
    }
    Ok(block)
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_path_null(value: &std::path::Path) -> Vec<u16> {
    value
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn quoted_command_line(
    executable: &std::path::Path,
    arguments: &[String],
) -> Result<Vec<u16>, Win32KernelError> {
    let mut value = Vec::new();
    append_windows_argument(&mut value, executable.as_os_str().encode_wide())?;
    for argument in arguments {
        value.push(' ' as u16);
        append_windows_argument(&mut value, argument.encode_utf16())?;
    }
    if value.len() >= 32_767 {
        return Err(Win32KernelError::new(Win32KernelStage::ProcessCreation));
    }
    value.push(0);
    Ok(value)
}

// CreateProcessW receives one mutable command line. This implements the
// CommandLineToArgvW quoting contract exactly, including backslashes before a
// quote and trailing backslashes inside the surrounding quotes.
fn append_windows_argument(
    output: &mut Vec<u16>,
    argument: impl Iterator<Item = u16>,
) -> Result<(), Win32KernelError> {
    output.push('"' as u16);
    let mut backslashes = 0usize;
    for unit in argument {
        if unit == 0 {
            return Err(Win32KernelError::new(Win32KernelStage::ProcessCreation));
        }
        if unit == '\\' as u16 {
            backslashes += 1;
            continue;
        }
        if unit == '"' as u16 {
            output.extend(std::iter::repeat_n('\\' as u16, backslashes * 2 + 1));
        } else {
            output.extend(std::iter::repeat_n('\\' as u16, backslashes));
        }
        backslashes = 0;
        output.push(unit);
    }
    output.extend(std::iter::repeat_n('\\' as u16, backslashes * 2));
    output.push('"' as u16);
    Ok(())
}
