//! kspike-daemon — long-running engine process.
//!
//! Exposes a **shared `Arc<Engine>`** so multiple taps (XDP, procfs, nflog,
//! Casper FFI, honeypot) can feed signals concurrently, and a **UNIX-socket
//! control plane** so the TUI, systemd, and operator scripts can issue
//! commands without re-initialising state every call.
//!
//! Protocol (newline-delimited JSON over /run/kspike.sock):
//!
//!   client ─▶ { "op": "status" }
//!   server ◀─ { "ok": true, "stats": { "signals": 42, ... } }
//!
//!   client ─▶ { "op": "ingest", "signal": <Signal> }
//!   server ◀─ { "ok": true, "outcomes": [...] }
//!
//!   client ─▶ { "op": "list_modules" }
//!   server ◀─ { "ok": true, "modules": ["detector.ssh_bruteforce", ...] }
//!
//!   client ─▶ { "op": "shutdown" }
//!   server ◀─ { "ok": true }

pub mod server;
pub mod client;
pub mod wire;
pub mod build;

pub use server::Daemon;
pub use client::Client;
pub use wire::{Request, Response};
pub use build::{build_engine, EngineBuild};
