//! Trusted Windows AppContainer and Job Object driver for protocol-fuzz certification.
//!
//! The public driver is available only on Windows. Native calls are isolated in `win32` and every
//! failure is converted to one bounded error without an unsandboxed fallback.

#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod windows_driver;

#[cfg(windows)]
pub use windows_driver::*;

#[cfg(not(windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsDriverUnavailable;
