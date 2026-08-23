//! Trusted macOS sandbox, process-group, and resource-limit protocol-fuzz confinement.
//!
//! The safe adapter is portable for deterministic tests. The production kernel is exported only
//! on macOS. Native failures collapse to one bounded error and never retry without confinement.
#![cfg_attr(not(target_os = "macos"), forbid(unsafe_code))]

mod macos_driver;

pub use macos_driver::*;
