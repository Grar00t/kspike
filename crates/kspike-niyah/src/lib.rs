//! Niyah enrichment for KSpike.
//!
//! When a defense or strike is applied, the operator should not have to read
//! a hex blob to understand *why*. This crate produces an Arabic
//! (Najdi-flavoured) and English explanation for every JudgeRuling, anchored
//! in the same Charter principles the Judge uses.
//!
//! Two sources, in order:
//!   1. **Niyah Engine** — when the Casper FFI is initialised, we round-trip
//!      a tiny prompt through Casper for fluent Arabic prose.
//!   2. **Template fallback** — when Casper isn't available, we render
//!      deterministic Arabic templates rooted in the seven Charter principles
//!      (loyalty, truth, justice, mercy, wisdom, secrecy, courage).
//!
//! Output is RTL-safe (no English fragments mid-sentence unless the operator
//! asked for `bilingual` mode), and never invents facts the Judge didn't
//! already commit to the ledger.

pub mod explainer;
pub mod templates;
pub mod ledger_view;

pub use explainer::{Explainer, Explanation, Locale};
pub use ledger_view::LedgerView;
