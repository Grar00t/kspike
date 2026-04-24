//! Packet view — enough structure for L4 signatures without a full parser.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol { Tcp, Udp, Icmp, Other }

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
    pub proto: Protocol,
}

#[derive(Debug, Clone)]
pub struct PacketView<'a> {
    pub flow: FlowKey,
    pub payload: &'a [u8],
    pub len: usize,
    pub captured_at: chrono::DateTime<chrono::Utc>,
}

impl<'a> PacketView<'a> {
    pub fn new(flow: FlowKey, payload: &'a [u8]) -> Self {
        Self { len: payload.len(), flow, payload, captured_at: chrono::Utc::now() }
    }
}

/// A packet tap. On Linux with `nf` feature, backed by nfqueue/AF_PACKET.
/// By default, provides a programmable test harness (`feed`) used by unit tests
/// and replay tools — the production integration lives behind cfg.
pub struct PacketTap {
    queue: Vec<OwnedPacket>,
}

#[derive(Debug, Clone)]
pub struct OwnedPacket {
    pub flow: FlowKey,
    pub payload: Vec<u8>,
    pub captured_at: chrono::DateTime<chrono::Utc>,
}

impl PacketTap {
    pub fn new() -> Self { Self { queue: Vec::new() } }

    /// Inject a packet — used by tests and by higher-level taps that
    /// receive frames out-of-band.
    pub fn feed(&mut self, flow: FlowKey, payload: Vec<u8>) {
        self.queue.push(OwnedPacket { flow, payload, captured_at: chrono::Utc::now() });
    }

    pub fn drain(&mut self) -> Vec<OwnedPacket> { std::mem::take(&mut self.queue) }
    pub fn len(&self)   -> usize { self.queue.len() }
    pub fn is_empty(&self) -> bool { self.queue.is_empty() }
}

impl Default for PacketTap { fn default() -> Self { Self::new() } }
