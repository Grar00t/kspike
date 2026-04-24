//! Honeypot profiles for the sinkhole striker.
//!
//! A `HoneypotProfile` describes:
//!   • what the honey should *look* like (banner, hostname, OS)
//!   • how long to keep the attacker engaged
//!   • what actions to simulate (command output, filesystem layout)
//!   • what data is *never* returned (the Charter binds the honey too:
//!     it must not lie about anything that could cause legal harm to a
//!     bystander whose identity happens to match one of our pretexts).

pub mod profile;
pub mod responder;
pub mod builtins;

pub use profile::{HoneypotProfile, OsFamily, RetentionPolicy};
pub use responder::{Responder, Canned};
pub use builtins::{meterpreter_win10_x64, ssh_ubuntu_2004, smb_win7};
