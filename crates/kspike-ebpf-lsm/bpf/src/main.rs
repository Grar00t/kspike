//! KSpike LSM program — three hooks, single RingBuf.
//!
//! Build (host with kernel headers + nightly + bpfel):
//!     cd crates/kspike-ebpf-lsm/bpf
//!     cargo +nightly build --release \
//!         --target bpfel-unknown-none -Z build-std=core
//!
//! Attach: requires CAP_BPF + a kernel built with CONFIG_BPF_LSM=y and
//! `bpf` enabled in `/sys/kernel/security/lsm`.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns},
    macros::{lsm, map},
    maps::RingBuf,
    programs::LsmContext,
};

const HOOK_FILE_OPEN: u8     = 1;
const HOOK_BPRM_CHECK: u8    = 2;
const HOOK_CAP_SYS_MODULE: u8 = 3;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LsmEvent {
    pub hook: u8,
    pub _pad0: [u8; 3],
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cap: u32,
    pub comm: [u8; 16],
    pub path: [u8; 256],
    pub ts_ns: u64,
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[lsm(hook = "file_open")]
pub fn lsm_file_open(_ctx: LsmContext) -> i32 {
    emit(HOOK_FILE_OPEN, 0);
    0
}

#[lsm(hook = "bprm_check_security")]
pub fn lsm_bprm_check(_ctx: LsmContext) -> i32 {
    emit(HOOK_BPRM_CHECK, 0);
    0
}

#[lsm(hook = "capable")]
pub fn lsm_capable(_ctx: LsmContext) -> i32 {
    // CAP_SYS_MODULE = 16. The full ctx parsing is omitted here for brevity;
    // a production version reads the cap argument from the LSM ctx.
    emit(HOOK_CAP_SYS_MODULE, 16);
    0
}

#[inline(always)]
fn emit(hook: u8, cap: u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;
    let mut comm_buf = [0u8; 16];
    if let Ok(c) = bpf_get_current_comm() {
        let n = if c.len() < 16 { c.len() } else { 16 };
        let mut i = 0;
        while i < n { comm_buf[i] = c[i]; i += 1; }
    }
    let ev = LsmEvent {
        hook, _pad0: [0; 3], pid, uid, gid, cap,
        comm: comm_buf, path: [0; 256],
        ts_ns: unsafe { bpf_ktime_get_ns() },
    };
    if let Some(mut buf) = EVENTS.reserve::<LsmEvent>(0) {
        unsafe { core::ptr::write_unaligned(buf.as_mut_ptr(), ev) };
        buf.submit(0);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
