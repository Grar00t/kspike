//! Shared LSM event schema (mirrored bit-by-bit by `bpf/src/main.rs`).

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LsmEvent {
    pub hook: u8,           // 1=file_open  2=bprm_check  3=capable_cap_sys_module
    pub _pad0: [u8; 3],
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cap: u32,           // when hook==3
    pub comm: [u8; 16],
    pub path: [u8; 256],
    pub ts_ns: u64,
}
