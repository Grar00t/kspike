//! Sinkhole orchestration — translates a striker authorisation into:
//!   1. a veth pair `kspike-honey0 <-> kspike-honey1`
//!   2. honeypot listener on `kspike-honey1`
//!   3. SINKHOLE_MAP entry pointing the attacker's dst_ip at honey0 ifindex
//!
//! When `aya_runtime` is off, `apply` returns a plan instead of executing,
//! so unit tests + dry-runs can verify the orchestration logic.

use kspike_honeypot::HoneypotProfile;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkholePlan {
    pub target_ipv4: Ipv4Addr,
    pub honey_iface_pair: (String, String),
    pub honey_listen_addr: String,
    pub profile_name: String,
    pub commands: Vec<String>,
    pub map_install: (u32, String),  // (dst_ipv4_be, "ifindex_of_honey0")
}

pub struct SinkholeManager {
    pub iface_pair_prefix: String,
}

impl Default for SinkholeManager {
    fn default() -> Self { Self { iface_pair_prefix: "kspike-honey".into() } }
}

impl SinkholeManager {
    /// Produce a plan. With aya_runtime, the caller executes it.
    pub fn plan(&self, target: Ipv4Addr, profile: &HoneypotProfile, ifindex_placeholder: &str) -> SinkholePlan {
        let pair = (
            format!("{}0", self.iface_pair_prefix),
            format!("{}1", self.iface_pair_prefix),
        );
        let listen_port = profile.open_ports.first().copied().unwrap_or(4444);
        let listen_addr = format!("169.254.42.1:{listen_port}");
        let cmds = vec![
            format!("ip link add {} type veth peer name {}", pair.0, pair.1),
            format!("ip link set {} up", pair.0),
            format!("ip link set {} up", pair.1),
            format!("ip addr add 169.254.42.1/30 dev {}", pair.1),
            format!("ip addr add 169.254.42.2/30 dev {}", pair.0),
            format!("# launch honeypot listener on {} with profile {}",
                    listen_addr, profile.name),
        ];
        let dst_be = u32::from_be_bytes(target.octets());
        SinkholePlan {
            target_ipv4: target,
            honey_iface_pair: pair,
            honey_listen_addr: listen_addr,
            profile_name: profile.name.clone(),
            commands: cmds,
            map_install: (dst_be, ifindex_placeholder.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kspike_honeypot::builtins::meterpreter_win10_x64;

    #[test]
    fn plan_is_well_formed() {
        let mgr = SinkholeManager::default();
        let p = mgr.plan(Ipv4Addr::new(198, 51, 100, 99),
                         &meterpreter_win10_x64(),
                         "<ifindex>");
        assert_eq!(p.honey_iface_pair.0, "kspike-honey0");
        assert!(p.commands.iter().any(|c| c.contains("veth")));
    }
}
