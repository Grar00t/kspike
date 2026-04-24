//! KSpike Judge — the Casper-backed Rules of Engagement evaluator.
//!
//! The Judge decides whether a module's requested action is *authorized*.
//! For defensive verdicts the bar is low (risk_level ≤ threshold).
//! For offensive (Striker) verdicts the Judge enforces four conditions drawn
//! from the Casper Charter, mirroring both classical Islamic jurisprudence
//! on defensive warfare (رد العدوان بالمثل) and modern active-defense law:
//!
//!   (1) CERTAINTY   — attack is in progress, evidenced, not merely suspected.
//!   (2) EXHAUSTION  — defenders have been tried or are too slow.
//!   (3) LEGITIMACY  — target is the attacker, not bystanders.
//!   (4) PROPORTION  — force is commensurate with the threat.
//!
//! The Judge is *pluggable*. The default Judge runs a deterministic rules
//! engine (`StaticJudge`). A `CasperJudge` delegates final adjudication to
//! the Casper Engine for contextual reasoning. Both write every ruling to
//! the evidence ledger. There are no silent denials and no silent approvals.

pub mod roe;
pub mod judge;

pub use judge::{Judge, JudgeRuling, RulingContext, StaticJudge, ManualJudge, KhzJudge};
pub use roe::{Roe, StrikeConditions, RoeConfig};
