//! Generic tap abstraction — a stream of raw observations from the kernel.

use kspike_core::Signal;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TapError {
    #[error("tap is not supported on this platform")]
    Unsupported,
    #[error("privilege required: {0}")]
    Privilege(&'static str),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapStatus {
    Idle,
    Active,
    Degraded,
    Offline,
}

pub trait KernelTap: Send + Sync {
    fn name(&self) -> &'static str;
    fn status(&self) -> TapStatus;
    /// Non-blocking poll. Returns zero or more signals. Must never block.
    fn poll(&mut self) -> Result<Vec<Signal>, TapError>;
}
