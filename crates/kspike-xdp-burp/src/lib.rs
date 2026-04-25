//! KSpike XDP-Burp — kernel-native transparent MITM.
//!
//! Architecture
//! ------------
//!
//! ```text
//!                 NIC
//!                  │
//!      ┌───────────▼────────────┐      ← wire-speed, kernel-space
//!      │  XDP program (eBPF)    │
//!      │  • parse L2/L3/L4      │
//!      │  • detect: jndi, sgn,  │
//!      │    meterpreter, psexec │
//!      │  • RingBuf   ──────────┼─┐    ← hot path (threats → Engine)
//!      │  • PerfEvent ──────────┼─┼─┐  ← cold path (flow telemetry)
//!      │  • XDP_REDIRECT ───────┼─┼─┼──► honeypot interface
//!      └────────────────────────┘ │ │
//!                                 │ │
//!    ┌────────────────────────────▼─▼─────────────┐  ← user-space
//!    │  kspike-xdp-burp (this crate, tokio)        │
//!    │  • XdpBurpTap    : KernelTap impl           │
//!    │  • signal reader → Engine.ingest()          │
//!    │  • debug reader  → tracing logs             │
//!    └──────────────────────────────────┬──────────┘
//!                                       ▼
//!                                ┌──────────────┐
//!                                │  KSpike      │
//!                                │  Engine      │
//!                                │  (judge-     │
//!                                │   gated)     │
//!                                └──────────────┘
//! ```
//!
//! Two build modes:
//!   - default   : loader compiles; attach is stubbed (`Unsupported`).
//!                 A pcap-replay harness lets you exercise the full pipeline.
//!   - `aya_runtime` feature: links aya, loads the eBPF .o, attaches to an
//!                 interface via XDP. Requires CAP_BPF / root.

pub mod tap;
pub mod replay;
pub mod sinkhole;
#[cfg(feature = "aya_runtime")]
pub mod runtime;

pub use tap::{XdpBurpTap, XdpBurpConfig, AttachMode, SinkholeIface};
pub use replay::PcapReplay;
pub use sinkhole::{SinkholeManager, SinkholePlan};
