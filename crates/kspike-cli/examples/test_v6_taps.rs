// Standalone test that exercises the v0.6 taps in this very sandbox.
use kspike_kernel::KernelTap;
use kspike_procfs::{TcpTap, ModulesTap};
use kspike_auth_log::AuthLogTap;
use kspike_ebpf_lsm::{LsmTap, LsmEvent};

fn main() {
    println!("── procfs.tcp tap ──");
    let mut tcp = TcpTap::new();
    let s1 = tcp.poll().unwrap();
    println!("  first poll: {} signals", s1.len());
    if let Some(s) = s1.first() {
        println!("  sample: kind={} actor={:?} target={:?}", s.kind, s.actor, s.target);
    }

    println!("\n── procfs.modules tap ──");
    let mut m = ModulesTap::new();
    let s = m.poll().unwrap();
    println!("  first poll: {} signals", s.len());

    println!("\n── auth-log tap (synthetic) ──");
    let tmp = std::env::temp_dir().join("kspike-auth-test.log");
    std::fs::write(&tmp, b"").unwrap();
    let mut tap = AuthLogTap::new(&tmp);
    // append a burst
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(&tmp).unwrap();
    for _ in 0..12 {
        writeln!(f, "Apr 24 22:11:00 host sshd[1234]: Failed password for invalid user admin from 198.51.100.99 port 33222 ssh2").unwrap();
    }
    drop(f);
    let s = tap.poll().unwrap();
    println!("  signals: {}", s.len());
    for sig in &s {
        println!("    • {} from {:?} (conf={:.2})", sig.kind, sig.actor, sig.raw_confidence);
    }

    println!("\n── ebpf-lsm tap (synthetic) ──");
    let mut lsm = LsmTap::new();
    let mut comm = [0u8; 16]; comm[..4].copy_from_slice(b"bash");
    let mut path = [0u8; 256];
    let p = b"/etc/shadow";
    path[..p.len()].copy_from_slice(p);
    lsm.inject(LsmEvent {
        hook: 1, _pad0: [0;3], pid: 4242, uid: 1000, gid: 1000, cap: 0,
        comm, path, ts_ns: 999,
    });
    let s = lsm.poll().unwrap();
    for sig in &s {
        println!("    • {} actor={:?} target={:?}", sig.kind, sig.actor, sig.target);
    }
}
