//! eBPF LSM hooks for KSpike.
//!
//! Linux 5.7+ exposes BPF LSM — small eBPF programs attach at LSM hook
//! points (file_open, bprm_check_security, capable, …). We use them to
//! detect:
//!   • `bprm_check_security` opening on a setuid binary the operator did
//!     not allow-list  →  privilege-escalation suspect.
//!   • `file_open` on a path inside the canary set  →  credential dump
//!     suspect (real LSM event, not an inferred one).
//!   • `capable(CAP_SYS_MODULE)` from a process not in the allow-list  →
//!     rootkit installation attempt.
//!
//! This crate only contains the user-space scaffolding. The actual eBPF
//! program lives under `bpf/` and is compiled with the bpfel target
//! (same recipe as kspike-xdp-burp).

pub mod tap;
pub mod event;

pub use tap::LsmTap;
pub use event::LsmEvent;
