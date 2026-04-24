# Building & Loading the XDP eBPF Program

> Full recipe for turning `crates/kspike-xdp-burp/bpf/` into a loadable BPF
> object and attaching it to a live interface.

## Prerequisites (one-time)

```bash
# Linux kernel ≥ 5.15 with BTF enabled (check: zcat /proc/config.gz | grep BTF)
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) libelf-dev pkg-config

# Nightly Rust + BPF target
rustup toolchain install nightly
rustup component add --toolchain nightly rust-src rustfmt clippy
rustup target  add --toolchain nightly bpfel-unknown-none bpfeb-unknown-none

# bpf-linker (REQUIRED — aya uses it as the BPF link step)
cargo install bpf-linker --locked
```

## Build the BPF object

```bash
cd crates/kspike-xdp-burp/bpf
cargo +nightly build --release \
    --target bpfel-unknown-none \
    -Z build-std=core
```

Result:

```
crates/kspike-xdp-burp/bpf/target/bpfel-unknown-none/release/kspike-xdp-burp-ebpf
```

Verify the ELF:

```bash
file target/bpfel-unknown-none/release/kspike-xdp-burp-ebpf
# → ELF 64-bit LSB relocatable, eBPF, ...

llvm-objdump --section-headers \
    target/bpfel-unknown-none/release/kspike-xdp-burp-ebpf | head -30
# → look for: .text, xdp, maps, license (must be GPL-compatible or kernel rejects).
```

## Attach (privileged)

Build the user-space loader with the `aya_runtime` feature enabled:

```bash
cargo build --release -p kspike-xdp-burp --features aya_runtime
```

Grant capabilities (no full root needed):

```bash
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+eip \
    ./target/release/kspike-xdp-burp
```

Run:

```bash
./target/release/kspike-xdp-burp --interface eth0 --mode skb
# modes:  skb (generic) | driver (native) | offload (NIC hw)
```

## Detach

Clean detach:

```bash
sudo ip link set dev eth0 xdpgeneric off
sudo ip link set dev eth0 xdpdrv     off
sudo ip link set dev eth0 xdpoffload off
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Permission denied` on load | Missing CAP_BPF | `setcap` as above |
| `Invalid argument` from verifier | Stack frame > 512 B, unbounded loop | Shrink payload buffer, add explicit bound |
| `BTF not found` | Kernel built without CONFIG_DEBUG_INFO_BTF | Use `--btf-from-file /sys/kernel/btf/vmlinux` |
| NIC drops traffic | XDP driver mode incompatible | Fall back to `--mode skb` |
| Secure Boot rejects load | Kernel enforces module signing | MOK-sign the object, or temp-disable SB |

## Where the pieces live

- eBPF source .......... `crates/kspike-xdp-burp/bpf/src/main.rs`
- Shared event schema .. `crates/kspike-kernel/src/xdp_event.rs`
- User-space tap ....... `crates/kspike-xdp-burp/src/tap.rs`
- Loader binary ........ `crates/kspike-xdp-burp/src/main.rs`
- Attach scaffold ...... `attach_xdp()` behind `cfg(feature = "aya_runtime")`
