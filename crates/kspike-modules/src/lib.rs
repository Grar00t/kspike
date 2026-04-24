//! KSpike stock modules — defenders, detectors, strikers.

pub mod engine;
pub mod detectors;
pub mod defenders;
#[cfg(feature = "strikers")]
pub mod strikers;

pub use engine::{Engine, EngineConfig, EngineStats};
