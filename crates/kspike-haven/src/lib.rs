//! HAVEN OS integration.
//!
//! KSpike on HAVEN is not a daemon you install — it's a first-class boot
//! service, started before the network is up, with a strict contract:
//!
//!   1. **Boot order**: kspike-haven runs after `phalanx-init` and before
//!      `network-online.target`. By the time any external packet reaches
//!      a userland process, the XDP program is loaded and the engine is
//!      listening.
//!
//!   2. **Phalanx Protocol**: when a strike is authorised, KSpike publishes
//!      the SIGNED evidence record to the Phalanx bus so other HAVEN
//!      services (firewall, DNS, IDS) can react in lock-step.
//!
//!   3. **Niyah-as-Judge**: on HAVEN, `CasperJudge` is wired to the
//!      built-in Niyah Engine — no FFI dlopen, no model_path; the engine
//!      ships with the OS image.
//!
//! This crate exposes the boot manifest format, the Phalanx publish/subscribe
//! contract, and the bootstrap entrypoint that HAVEN init calls.

pub mod manifest;
pub mod phalanx;
pub mod boot;

pub use manifest::{BootManifest, ServiceMode, NetworkPosture};
pub use phalanx::{PhalanxBus, PhalanxMessage};
pub use boot::bootstrap;
