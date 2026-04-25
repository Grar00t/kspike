//! WFP-mirror — Windows-side equivalent of XDP-Burp.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WfpFlow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub direction: WfpDirection,
    pub layer: WfpLayer,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WfpDirection { Inbound, Outbound }

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WfpLayer {
    AleAuthRecvAcceptV4,
    AleAuthRecvAcceptV6,
    AleAuthConnectV4,
    AleAuthConnectV6,
    StreamV4,
    StreamV6,
    DatagramDataV4,
    DatagramDataV6,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WfpAction {
    Permit,
    Block,
    Inspect,    // pass payload up to user-space for deeper analysis
    Redirect,   // sinkhole, similar to XDP_REDIRECT
}

pub struct WfpMirror {
    pub provider_name: String,
    pub callout_name: String,
}

impl Default for WfpMirror {
    fn default() -> Self {
        Self {
            provider_name: "{KSPIKE-WFP-PROVIDER-1}".into(),
            callout_name: "kspike_callout_v1".into(),
        }
    }
}

impl WfpMirror {
    /// Decide an action for a flow. Pure logic — the actual callout
    /// invocation lives in the `.sys` driver; this is the policy brain
    /// the driver consults via shared memory.
    pub fn decide(&self, flow: &WfpFlow) -> WfpAction {
        // Conservative defaults: never block well-known clean ports.
        match flow.dst_port {
            22 | 80 | 443 | 53 => WfpAction::Permit,
            445 if matches!(flow.direction, WfpDirection::Inbound) => WfpAction::Inspect,
            _ => WfpAction::Permit,
        }
    }
}
