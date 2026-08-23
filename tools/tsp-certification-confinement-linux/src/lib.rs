//! Trusted Linux namespace, seccomp, Landlock, and cgroup v2 protocol-fuzz confinement.
//!
//! The public driver is available only on Linux. Native calls remain isolated in the Linux-only
//! implementation and every failure is converted to one bounded error without a fallback.

#![cfg_attr(not(target_os = "linux"), forbid(unsafe_code))]

#[cfg(target_os = "linux")]
mod linux_driver;

#[cfg(target_os = "linux")]
pub use linux_driver::*;

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxDriverUnavailable;
