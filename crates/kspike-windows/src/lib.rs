//! KSpike Windows-side bridge.
//!
//! Provides two scaffolds:
//!
//!   • `WfpMirror` — mirrors XDP semantics on Windows via Windows Filtering
//!     Platform (WFP) callouts. The actual driver lives outside this crate
//!     (signed `.sys`); this Rust side only orchestrates and ingests.
//!
//!   • `EtwProvider` — registers an ETW provider so any process on Windows
//!     can emit kspike-shaped signals that the daemon picks up over the
//!     same UNIX-socket IPC (via a Windows Service on the WSL2 bridge).
//!
//! Why a single crate? Because the Linux daemon needs to *understand*
//! Windows-shaped signals even when KSpike isn't running on Windows —
//! Sulaiman's environment is Snapdragon X Elite + WSL2-Kali, so the engine
//! sees both halves.

pub mod wfp;
pub mod etw;
pub mod ingest;

pub use wfp::{WfpMirror, WfpFlow, WfpAction, WfpDirection, WfpLayer};
pub use etw::{EtwProvider, EtwLevel};
pub use ingest::wsl_bridge_signal;
