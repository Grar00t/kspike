//! KHZ_Q — Khawarizmi-Fitrah Quantum Balancer
//! ==========================================
//!
//! A symbolic decision-scoring engine derived from 115 evolving protocol
//! revisions authored by Sulaiman Al-Shammari (DRAGON403). The raw
//! protocol stream lives in `docs/khz/khz_protocols.ndjson`. This crate
//! distills the stable core and exposes it to the KSpike Judge.
//!
//! Core equation (V2.1 → V41, stable):
//!
//!   Φ = Σᵢ [ Reduction(ΔHarm_i)
//!         ⊕ Balancing(ΔNecessity_j)
//!         ⊗ Superposition( ⋃ Wisdom_k ∪ ⋃ Science_m ∪ Quantum_n ) ]
//!
//! Necessity rule:   IF ΣΔHarm=0 ∧ ΣΔNecessity>0  →  FULL_ASSISTANCE
//! Error loop:       IF NEW_EVIDENCE  →  RECALCULATE ∧ ADMIT_ERROR ∧ UPDATE_Φ
//! Khawarizmi:       AlJabr(restore_missing) ⊕ AlMuqabala(balance_opposites)
//!
//! The ten canonical rules (V3.0 onward):
//!   1. REDUCTION        — remove contradictory terms from the Fitrah base
//!   2. BALANCING        — equalise Harm vs Necessity across equality
//!   3. RESTORATION      — restore missing values from historical wisdom
//!   4. SUPERPOSITION    — hold all ethical states until collapse
//!   5. ENTANGLEMENT     — link every decision to full Fitrah context
//!   6. DYNAMIC NECESSITY— ΔNecessity = f(suffering, long-term good)
//!   7. Q-OPTIMIZATION   — minimise decision-space energy
//!   8. ADMIT ERROR      — on contradiction, collapse to new truth, log it
//!   9. FITRAH ANCHOR    — every rule traces to pure Fitrah
//!  10. LOOP FOREVER     — repeat on every new input until convergence
//!
//! This crate implements all ten as pure Rust functions with no hidden state
//! and no silent failures. Every balance produces a `Ruling` that records the
//! rationale so it can be sealed into the evidence ledger.

pub mod operator;
pub mod balancer;
pub mod protocol;
pub mod fitrah;

pub use balancer::{KhzBalancer, Ruling};
pub use operator::{Delta, HarmVector, NecessityVector, Phi};
pub use protocol::{ProtocolStream, ProtocolRecord};
pub use fitrah::{FitrahAnchor, WisdomSource};

/// KHZ_Q distilled stable version.
pub const KHZ_STABLE: &str = "KHZ_Q_V41_DISTILLED";
