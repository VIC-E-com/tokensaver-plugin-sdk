#[cfg(target_os = "linux")]
mod selected {
    use crate::{NativeResult, ValidatedRequest, duration, runtime_engine};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use tokensaver_certification_confinement_linux::{
        LinuxConfinementConfig, LinuxConfinementKernel, LinuxKernel, LinuxKernelExecution,
    };

    pub fn platform_key() -> &'static str {
        if cfg!(target_arch = "x86_64") {
            "linux-x64"
        } else if cfg!(target_arch = "aarch64") {
            "linux-arm64"
        } else {
            "unsupported"
        }
    }

    pub fn execute(request: &ValidatedRequest) -> Result<NativeResult, &'static str> {
        if !request.executable.starts_with(&request.release) {
            return Err("confinement_identity");
        }
        let sandbox_root = required_path("TOKENSAVER_PLUGIN_SANDBOX_ROOT")?;
        let cgroup_parent = required_path("TOKENSAVER_PLUGIN_CGROUP_PARENT")?;
        let config = LinuxConfinementConfig::new(
            &request.executable,
            &sandbox_root,
            &request.work,
            &cgroup_parent,
            BTreeMap::from([
                ("HOME".into(), "/nonexistent".into()),
                ("TMPDIR".into(), "/work".into()),
            ]),
            runtime_engine(),
        )
        .map_err(|_| "confinement_config")?;
        let kernel = LinuxKernel;
        kernel
            .preflight(&config)
            .map_err(|_| "confinement_preflight")?;
        let observed = kernel
            .execute(LinuxKernelExecution {
                attempt_id: &request.request.attempt_id,
                executable: config.executable(),
                sandbox_root: config.sandbox_root(),
                writable_directory: config.writable_directory(),
                cgroup_parent: config.cgroup_parent(),
                environment: config.environment(),
                arguments: &request.request.arguments,
                input: &request.input,
                maximum_memory_bytes: request.request.maximum_memory_bytes,
                maximum_stdout_bytes: request.request.maximum_stdout_bytes,
                maximum_stderr_bytes: request.request.maximum_stderr_bytes,
                deadline: duration(request),
            })
            .map_err(|_| "confinement_execute")?;
        Ok(NativeResult {
            backend_id: "com.tokensaver.native-runtime.linux",
            policy_digest: config.policy_digest().into(),
            termination: observed.termination,
            stdout: observed.stdout,
            stderr: observed.stderr,
            duration_milliseconds: observed.duration_milliseconds,
            peak_memory_bytes: observed.peak_memory_bytes,
            stdout_limit_exceeded: observed.stdout_limit_exceeded,
            stderr_limit_exceeded: observed.stderr_limit_exceeded,
            process_reaped: observed.process_reaped,
        })
    }

    pub fn deprovision(_: &ValidatedRequest) -> Result<(), &'static str> {
        Ok(())
    }

    fn required_path(name: &str) -> Result<PathBuf, &'static str> {
        let value = std::env::var_os(name).ok_or("confinement_resource")?;
        let path = std::fs::canonicalize(value).map_err(|_| "confinement_resource")?;
        if !path.is_absolute() || !path.is_dir() {
            return Err("confinement_resource");
        }
        Ok(path)
    }
}

#[cfg(target_os = "macos")]
mod selected {
    use crate::{NativeResult, ValidatedRequest, duration, runtime_engine};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use tokensaver_certification_confinement_macos::{
        MacosConfinementConfig, MacosConfinementKernel, MacosKernel, MacosKernelExecution,
    };

    pub fn platform_key() -> &'static str {
        if cfg!(target_arch = "x86_64") {
            "darwin-x64"
        } else if cfg!(target_arch = "aarch64") {
            "darwin-arm64"
        } else {
            "unsupported"
        }
    }

    pub fn execute(request: &ValidatedRequest) -> Result<NativeResult, &'static str> {
        if !request.executable.starts_with(&request.release) {
            return Err("confinement_identity");
        }
        let launcher = required_file("TOKENSAVER_PLUGIN_LIMIT_LAUNCHER")?;
        let config = MacosConfinementConfig::new(
            &request.executable,
            &launcher,
            &request.work,
            BTreeMap::from([
                ("HOME".into(), "/nonexistent".into()),
                ("LC_ALL".into(), "C".into()),
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("TMPDIR".into(), request.work.to_string_lossy().into_owned()),
                ("TOKENSAVER_PLUGIN".into(), "1".into()),
            ]),
            runtime_engine(),
        )
        .map_err(|_| "confinement_config")?;
        let kernel = MacosKernel;
        kernel
            .preflight(&config)
            .map_err(|_| "confinement_preflight")?;
        let observed = kernel
            .execute(MacosKernelExecution {
                attempt_id: &request.request.attempt_id,
                executable: config.executable(),
                launcher: config.launcher(),
                writable_directory: config.writable_directory(),
                sandbox_profile: config.sandbox_profile(),
                environment: config.environment(),
                arguments: &request.request.arguments,
                input: &request.input,
                maximum_memory_bytes: request.request.maximum_memory_bytes,
                maximum_stdout_bytes: request.request.maximum_stdout_bytes,
                maximum_stderr_bytes: request.request.maximum_stderr_bytes,
                deadline: duration(request),
            })
            .map_err(|_| "confinement_execute")?;
        Ok(NativeResult {
            backend_id: "com.tokensaver.native-runtime.macos",
            policy_digest: config.policy_digest().into(),
            termination: observed.termination,
            stdout: observed.stdout,
            stderr: observed.stderr,
            duration_milliseconds: observed.duration_milliseconds,
            peak_memory_bytes: observed.peak_memory_bytes,
            stdout_limit_exceeded: observed.stdout_limit_exceeded,
            stderr_limit_exceeded: observed.stderr_limit_exceeded,
            process_reaped: observed.process_reaped,
        })
    }

    pub fn deprovision(_: &ValidatedRequest) -> Result<(), &'static str> {
        Ok(())
    }

    fn required_file(name: &str) -> Result<PathBuf, &'static str> {
        let value = std::env::var_os(name).ok_or("confinement_resource")?;
        let path = std::fs::canonicalize(value).map_err(|_| "confinement_resource")?;
        if !path.is_absolute() || !path.is_file() {
            return Err("confinement_resource");
        }
        Ok(path)
    }
}

#[cfg(windows)]
mod selected {
    use crate::{NativeResult, ValidatedRequest, duration, runtime_engine};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::process::Command;
    use tokensaver_certification_confinement_windows::{
        Win32Kernel, WindowsConfinementConfig, WindowsConfinementKernel, WindowsKernelExecution,
    };
    use windows_sys::Win32::Foundation::{LocalFree, S_OK};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::Isolation::CreateAppContainerProfile;
    use windows_sys::Win32::Security::{FreeSid, PSID};

    pub fn platform_key() -> &'static str {
        if cfg!(target_arch = "x86_64") {
            "windows-x64"
        } else if cfg!(target_arch = "aarch64") {
            "windows-arm64"
        } else {
            "unsupported"
        }
    }

    pub fn execute(request: &ValidatedRequest) -> Result<NativeResult, &'static str> {
        let profile_name = profile_name(&request.request.plugin_id);
        let sid = ensure_profile(&profile_name).map_err(|_| "confinement_profile")?;
        grant(&request.release, &sid, "(OI)(CI)RX").map_err(|_| "confinement_acl")?;
        grant(&request.work, &sid, "(OI)(CI)M").map_err(|_| "confinement_acl")?;
        let system_root = std::env::var("SYSTEMROOT").map_err(|_| "confinement_environment")?;
        let system_drive = std::env::var("SYSTEMDRIVE").map_err(|_| "confinement_environment")?;
        let config = WindowsConfinementConfig::new(
            &request.executable,
            &request.work,
            profile_name,
            BTreeMap::from([
                (
                    "LOCALAPPDATA".into(),
                    request.work.to_string_lossy().into_owned(),
                ),
                ("SYSTEMDRIVE".into(), system_drive),
                ("SYSTEMROOT".into(), system_root),
                ("TEMP".into(), request.work.to_string_lossy().into_owned()),
                ("TMP".into(), request.work.to_string_lossy().into_owned()),
            ]),
            runtime_engine(),
        )
        .map_err(|_| "confinement_config")?;
        let kernel = Win32Kernel;
        kernel
            .preflight(config.app_container_name())
            .map_err(|_| "confinement_preflight")?;
        let observed = kernel
            .execute(WindowsKernelExecution {
                executable_path: config.executable_path(),
                working_directory: config.working_directory(),
                app_container_name: config.app_container_name(),
                environment: config.environment(),
                arguments: &request.request.arguments,
                input: &request.input,
                maximum_memory_bytes: request.request.maximum_memory_bytes,
                maximum_stdout_bytes: request.request.maximum_stdout_bytes,
                maximum_stderr_bytes: request.request.maximum_stderr_bytes,
                deadline: duration(request),
            })
            .map_err(|_| "confinement_execute")?;
        Ok(NativeResult {
            backend_id: "com.tokensaver.native-runtime.windows",
            policy_digest: config.policy_digest().into(),
            termination: observed.termination,
            stdout: observed.stdout,
            stderr: observed.stderr,
            duration_milliseconds: observed.duration_milliseconds,
            peak_memory_bytes: observed.peak_memory_bytes,
            stdout_limit_exceeded: observed.stdout_limit_exceeded,
            stderr_limit_exceeded: observed.stderr_limit_exceeded,
            process_reaped: observed.process_reaped,
        })
    }

    pub fn deprovision(request: &ValidatedRequest) -> Result<(), &'static str> {
        use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;
        let name = wide(&profile_name(&request.request.plugin_id));
        // SAFETY: name is a live NUL-terminated UTF-16 string.
        let result = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
        const HRESULT_FILE_NOT_FOUND: i32 = 0x8007_0002u32 as i32;
        if result == S_OK || result == HRESULT_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err("confinement_deprovision")
        }
    }

    fn profile_name(plugin_id: &str) -> String {
        let digest = format!("{:x}", Sha256::digest(plugin_id.as_bytes()));
        format!("com.tokensaver.plugin.{}", &digest[..32])
    }

    fn ensure_profile(name: &str) -> Result<String, ()> {
        let name_wide = wide(name);
        let display = wide("TokenSaver plugin");
        let description = wide("Capability-free TokenSaver plugin runtime");
        let mut sid: PSID = std::ptr::null_mut();
        // SAFETY: all strings are NUL-terminated and sid is a valid output pointer.
        let result = unsafe {
            CreateAppContainerProfile(
                name_wide.as_ptr(),
                display.as_ptr(),
                description.as_ptr(),
                std::ptr::null(),
                0,
                &mut sid,
            )
        };
        if result == S_OK {
            let value = sid_string(sid)?;
            // SAFETY: CreateAppContainerProfile returned this SID allocation.
            unsafe { FreeSid(sid) };
            return Ok(value);
        }
        const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00b7u32 as i32;
        if result != HRESULT_ALREADY_EXISTS {
            eprintln!("runtime host: AppContainer profile creation failed ({result:#x})");
            return Err(());
        }
        derive_sid(name)
    }

    fn derive_sid(name: &str) -> Result<String, ()> {
        use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
        let name = wide(name);
        let mut sid: PSID = std::ptr::null_mut();
        // SAFETY: name is NUL-terminated and sid is a valid output pointer.
        let result = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if result < 0 || sid.is_null() {
            return Err(());
        }
        let value = sid_string(sid)?;
        // SAFETY: DeriveAppContainerSidFromAppContainerName returned this SID allocation.
        unsafe { FreeSid(sid) };
        Ok(value)
    }

    fn sid_string(sid: PSID) -> Result<String, ()> {
        let mut value = std::ptr::null_mut();
        // SAFETY: sid is valid and value is a valid output pointer.
        if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 || value.is_null() {
            return Err(());
        }
        let mut length = 0usize;
        // SAFETY: the API returned a NUL-terminated UTF-16 allocation.
        unsafe {
            while *value.add(length) != 0 {
                length += 1;
            }
        }
        // SAFETY: the allocation contains length initialized UTF-16 code units.
        let result = String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
            .map_err(|_| ());
        // SAFETY: ConvertSidToStringSidW allocates through LocalAlloc.
        unsafe { LocalFree(value.cast::<c_void>()) };
        result
    }

    fn grant(path: &Path, sid: &str, rights: &str) -> Result<(), ()> {
        let system_root = std::env::var_os("SYSTEMROOT").ok_or(())?;
        let icacls = Path::new(&system_root).join("System32").join("icacls.exe");
        if !icacls.is_file() {
            return Err(());
        }
        let trustee = format!("*{sid}:{rights}");
        let status = Command::new(icacls)
            .arg(path)
            .args(["/grant:r", &trustee])
            .env_clear()
            .env("SYSTEMROOT", system_root)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|_| ())?;
        if status.success() { Ok(()) } else { Err(()) }
    }

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod selected {
    use crate::{NativeResult, ValidatedRequest};

    pub fn platform_key() -> &'static str {
        "unsupported"
    }

    pub fn execute(_: &ValidatedRequest) -> Result<NativeResult, &'static str> {
        Err("confinement_unsupported")
    }

    pub fn deprovision(_: &ValidatedRequest) -> Result<(), &'static str> {
        Err("confinement_unsupported")
    }
}

pub use selected::{deprovision, execute, platform_key};
