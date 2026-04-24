use thiserror::Error;

pub type Result<T> = std::result::Result<T, KSpikeError>;

#[derive(Error, Debug)]
pub enum KSpikeError {
    #[error("module '{0}' not found")]
    ModuleNotFound(String),

    #[error("module '{name}' rejected signal: {reason}")]
    ModuleRejected { name: String, reason: String },

    #[error("judge denied authorization: {0}")]
    JudgeDenied(String),

    #[error("ROE violation: {0}")]
    RoeViolation(String),

    #[error("evidence ledger error: {0}")]
    Evidence(String),

    #[error("kernel interface error: {0}")]
    Kernel(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
