//! Live kernel attach path. Compiled only with `--features aya_runtime`.
//!
//! Responsibilities:
//!   1. Load the compiled BPF object (path provided by KSPIKE_BPF env var
//!      or `--bpf <path>`).
//!   2. Locate the `burp_kernel` XDP program, attach to the configured
//!      interface in the requested mode (skb / driver / offload).
//!   3. Spawn two reader tasks:
//!       - RingBuf `EVENTS`     → decode XdpSignalEvent → tap.sink()
//!       - PerfEvent `DEBUG`    → decode XdpDebugEvent  → tracing::debug
//!   4. Manage `SINKHOLE_MAP` from user-space: when the engine authorises
//!      `striker.net.meterpreter_sinkhole`, install (dst_ipv4, ifindex).

#![cfg(feature = "aya_runtime")]

use crate::tap::{XdpBurpTap, AttachMode};
use anyhow::{Context, Result};
use aya::{
    maps::{HashMap as BpfHashMap, perf::AsyncPerfEventArray, RingBuf},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use kspike_kernel::xdp_event::{decode_signal, decode_debug};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

pub struct Runtime {
    pub ebpf: Arc<Mutex<Ebpf>>,
    pub readers: Vec<JoinHandle<()>>,
}

pub async fn attach(tap: &mut XdpBurpTap, bpf_obj_path: &Path) -> Result<Runtime> {
    let cfg = tap.config().clone();
    info!("loading BPF object: {}", bpf_obj_path.display());
    let mut ebpf = Ebpf::load_file(bpf_obj_path)
        .with_context(|| format!("Ebpf::load_file({})", bpf_obj_path.display()))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("aya_log init: {e} (kernel logs from BPF won't surface)");
    }

    let prog: &mut Xdp = ebpf.program_mut("burp_kernel")
        .ok_or_else(|| anyhow::anyhow!("XDP program 'burp_kernel' not in BPF object"))?
        .try_into()?;
    prog.load()?;

    let flags = match cfg.mode {
        AttachMode::Skb     => XdpFlags::SKB_MODE,
        AttachMode::Driver  => XdpFlags::DRV_MODE,
        AttachMode::Offload => XdpFlags::HW_MODE,
    };
    prog.attach(&cfg.interface, flags)
        .with_context(|| format!("attach XDP to {}", cfg.interface))?;
    info!("XDP attached to {} mode={:?}", cfg.interface, cfg.mode);

    let ebpf = Arc::new(Mutex::new(ebpf));
    let mut readers = Vec::new();

    // ─── RingBuf reader: typed threats → tap.sink() ────────────────────────
    {
        let ebpf = ebpf.clone();
        let sink = tap.sink();
        readers.push(tokio::spawn(async move {
            let mut guard = ebpf.lock().await;
            let map = match guard.take_map("EVENTS") {
                Some(m) => m,
                None => { warn!("EVENTS map missing"); return; }
            };
            drop(guard);
            let mut rb = match RingBuf::try_from(map) {
                Ok(r) => r, Err(e) => { warn!("RingBuf wrap: {e}"); return; }
            };
            let fd = rb.as_raw_fd();
            let afd = match tokio::io::unix::AsyncFd::new(fd) {
                Ok(a) => a, Err(e) => { warn!("AsyncFd: {e}"); return; }
            };
            loop {
                let mut g = match afd.readable().await {
                    Ok(g) => g, Err(e) => { warn!("readable: {e}"); break; }
                };
                while let Some(item) = rb.next() {
                    if let Some(ev) = decode_signal(&item) {
                        sink.lock().unwrap().push_back(ev);
                    }
                }
                g.clear_ready();
            }
        }));
    }

    // ─── PerfEventArray reader: telemetry → tracing::debug ─────────────────
    {
        let ebpf = ebpf.clone();
        readers.push(tokio::spawn(async move {
            let mut guard = ebpf.lock().await;
            let map = match guard.take_map("DEBUG") {
                Some(m) => m, None => { return; }
            };
            drop(guard);
            let mut perf = match AsyncPerfEventArray::try_from(map) {
                Ok(p) => p, Err(e) => { warn!("perf wrap: {e}"); return; }
            };
            for cpu_id in match aya::util::online_cpus() {
                Ok(v) => v, Err(e) => { warn!("online_cpus: {e:?}"); return; }
            } {
                let mut buf = match perf.open(cpu_id, None) {
                    Ok(b) => b, Err(e) => { warn!("perf.open cpu{cpu_id}: {e}"); continue; }
                };
                tokio::spawn(async move {
                    use bytes::BytesMut;
                    let mut bufs = vec![BytesMut::with_capacity(1024); 16];
                    loop {
                        match buf.read_events(&mut bufs).await {
                            Ok(events) => {
                                for b in bufs.iter().take(events.read) {
                                    if let Some(ev) = decode_debug(b) {
                                        debug!(target: "xdp.debug",
                                            "af={} type={} pkt_len={} {}:{}->{}:{}",
                                            ev.af, ev.event_type, ev.pkt_len,
                                            ipv4_str(&ev.src_ip[..4]), ev.src_port,
                                            ipv4_str(&ev.dst_ip[..4]), ev.dst_port);
                                    }
                                }
                            }
                            Err(e) => { warn!("perf read: {e}"); break; }
                        }
                    }
                });
            }
        }));
    }

    tap.mark_active();
    Ok(Runtime { ebpf, readers })
}

fn ipv4_str(o: &[u8]) -> String {
    if o.len() < 4 { return "?".into(); }
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

/// User-space helper: install a sinkhole (dst_ipv4 → ifindex) into the BPF
/// SINKHOLE_MAP. Called by the engine when a striker is authorised.
pub async fn sinkhole_install(rt: &Runtime, dst_ipv4_be: u32, ifindex: u32) -> Result<()> {
    let mut guard = rt.ebpf.lock().await;
    let map = guard.map_mut("SINKHOLE_MAP")
        .ok_or_else(|| anyhow::anyhow!("SINKHOLE_MAP missing"))?;
    let mut hm: BpfHashMap<_, u32, u32> = BpfHashMap::try_from(map)?;
    hm.insert(dst_ipv4_be, ifindex, 0)?;
    info!("SINKHOLE installed dst={dst_ipv4_be:#x} → if{ifindex}");
    Ok(())
}

pub async fn sinkhole_remove(rt: &Runtime, dst_ipv4_be: u32) -> Result<()> {
    let mut guard = rt.ebpf.lock().await;
    let map = guard.map_mut("SINKHOLE_MAP")
        .ok_or_else(|| anyhow::anyhow!("SINKHOLE_MAP missing"))?;
    let mut hm: BpfHashMap<_, u32, u32> = BpfHashMap::try_from(map)?;
    hm.remove(&dst_ipv4_be)?;
    info!("SINKHOLE removed dst={dst_ipv4_be:#x}");
    Ok(())
}
