//! KSpike kernel surface
//! =====================
//!
//! The substrate every built-in module runs on. This is NOT a plugin layer —
//! these taps live *inside* the engine and are compiled in. Each tap exposes
//! a typed stream of raw observations (`KernelTap::poll`) that the engine
//! turns into `Signal`s without any cross-process boundary.
//!
//! Taps provided:
//!   - `proc_net_tcp`   : /proc/net/tcp{,6} connection states
//!   - `proc_modules`   : /proc/modules + /sys/module/*/refcnt integrity watch
//!   - `proc_self_maps` : map-based shellcode RWX region scanner
//!   - `auth_log`       : /var/log/auth.log streaming tail
//!   - `packet_tap`     : raw AF_PACKET (feature = "nf") or pcap-replay for tests
//!   - `canary_memory`  : plants fake credentials into reserved pages
//!
//! On non-Linux hosts the Linux-specific taps return `Unsupported` but compile
//! cleanly so the rest of the engine is portable.

pub mod tap;
pub mod packet;
pub mod canary;
pub mod inspect;

pub use tap::{KernelTap, TapError, TapStatus};
pub use packet::{PacketView, PacketTap, Protocol, FlowKey};
pub use canary::{MemoryCanary, CanaryToken};
pub use inspect::{bytes_contain, hex_signature_match, utf16_contains};
