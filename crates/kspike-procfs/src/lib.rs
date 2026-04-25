//! procfs / sysfs taps for KSpike.
//!
//! Three taps in this crate:
//!   • `TcpTap`     — /proc/net/tcp{,6} state-change observer
//!   • `ModulesTap` — /proc/modules + /sys/module/<m>/refcnt integrity
//!   • Generic helpers used by both.

pub mod tcp;
pub mod modules;
pub mod parse;

pub use tcp::TcpTap;
pub use modules::ModulesTap;
