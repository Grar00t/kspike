//! KSpike stock modules — defenders, detectors, strikers.

pub mod engine;
pub mod detectors;
pub mod defenders;
#[cfg(feature = "strikers")]
pub mod strikers;
#[cfg(feature = "msf_mirror")]
pub mod msf_mirror;

pub use engine::{Engine, EngineConfig, EngineStats};
