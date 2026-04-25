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
//!
//! ## Multi-Layer Architecture
//!
//! The judge system now supports a 5-layer pipeline:
//!
//!   1. **rule_parser**: Operator-editable rules (NRULE format)
//!   2. **constraint_solver**: Linear constraint feasibility check
//!   3. **hybrid_reasoner**: Knowledge-base query resolution
//!   4. **khz_judge**: KHZ-Q balance (Φ threshold)
//!   5. **proof_generator**: Cryptographic audit trail (SHA-256)

pub mod roe;
pub mod judge;
pub mod rule_parser;
pub mod constraint_solver;
pub mod hybrid_reasoner;
pub mod proof_generator;
pub mod multi_layer_judge;

pub use judge::{Judge, JudgeRuling, RulingContext, StaticJudge, ManualJudge, KhzJudge};
pub use roe::{Roe, StrikeConditions, RoeConfig};
pub use rule_parser::{RuleParser, Rule, RulePattern, RuleDecision, RuleContext};
pub use constraint_solver::{ConstraintSolver, ConstraintContext, ConstraintSystem};
pub use hybrid_reasoner::{HybridReasoner, KnowledgeBase, QueryResult};
pub use proof_generator::{ProofGenerator, ProofRecord, AuditTrail};
pub use multi_layer_judge::{MultiLayerJudge, MultiLayerEvaluation};
