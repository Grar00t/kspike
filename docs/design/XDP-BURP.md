# XDP-Burp — Kernel-Native Transparent MITM

> **"لو Burp Suite صار kernel-native، يصير سلاحاً شاملاً. في KSpike يصير درعاً شاملاً."**

## 1. What it is

A kernel-space transparent interceptor that sits at the earliest point in the
Linux receive path (XDP / eXpress Data Path). It inspects every incoming
packet at wire speed, matches a small set of high-confidence threat
signatures, and either:

- `XDP_PASS` — forward normally (default),
- `XDP_DROP` — drop the packet in-kernel (wire-speed defense),
- `XDP_REDIRECT` — steer the flow into a honeypot interface
  (authorised by `striker.net.meterpreter_sinkhole`).

Every decision emits a `Signal` to user-space via RingBuf, which the engine
then feeds through the Judge, seals in the evidence ledger, and may amplify
with additional defenders.

## 2. Why kernel-native

| | user-space Burp | KSpike XDP-Burp |
|---|---|---|
| Speed | good | wire-speed (no syscall path) |
| Visibility | only what's routed through it | every packet on the NIC |
| Stealth | visible process | kernel program |
| Scope | manual pentest | automated defense/response |
| CPU cost | high (context switches) | near-zero |

## 3. Architecture

```
               NIC
                │
   ┌────────────▼──────────────┐
   │  XDP program (eBPF)       │  kernel
   │  • L2/L3/L4 parse         │
   │  • detect: jndi, sgn,     │
   │    meterpreter, psexec    │
   │  • RingBuf   EVENTS ──────┼──┐
   │  • PerfArr   DEBUG  ──────┼──┼─┐
   │  • bpf_redirect ──────────┼──┼─┼─► sinkhole veth → honeypot
   └───────────────────────────┘  │ │
                                  │ │
   ┌──────────────────────────────▼─▼────┐
   │ kspike-xdp-burp (tokio + aya)        │  user-space
   │ • XdpBurpTap : KernelTap impl        │
   │ • RingBuf reader → engine.ingest     │
   │ • PerfArray reader → tracing logs    │
   └─────────────────────────────┬────────┘
                                 ▼
                          KSpike Engine
                          (judge-gated)
```

## 4. Layout

```
crates/kspike-xdp-burp/
├── Cargo.toml                 user-space crate (lib + bin)
├── src/
│   ├── lib.rs                 public API
│   ├── tap.rs                 XdpBurpTap (KernelTap impl)
│   ├── replay.rs              pcap-replay harness (no CAP_BPF needed)
│   └── main.rs                kspike-xdp-burp binary
└── bpf/                       separate crate, different target
    ├── Cargo.toml
    ├── rust-toolchain.toml    nightly + bpfel target
    ├── .cargo/config.toml     target = bpfel-unknown-none, -Zbuild-std
    └── src/main.rs            XDP program
```

The **shared event schema** lives in `kspike-kernel/src/xdp_event.rs` and is
duplicated with bit-identical `#[repr(C)]` layout inside the eBPF crate (eBPF
is no_std and can't depend on a std-feature-bearing crate). A test in the
user-space crate verifies the sizes match.

## 5. Building

### User-space side (works anywhere)

```bash
cargo build --release -p kspike-xdp-burp
./target/release/kspike-xdp-burp     # runs the pcap-replay pipeline
```

This mode injects three synthetic attacks (Log4Shell, Meterpreter,
EternalBlue) through the `XdpBurpTap` so the full detect→judge→defend path
runs end-to-end without needing a kernel.

### eBPF side (requires a Linux host with CAP_BPF)

Prereqs:

```bash
# 1. rust nightly + bpfel target
rustup toolchain install nightly
rustup component add --toolchain nightly rust-src
rustup target add --toolchain nightly bpfel-unknown-none

# 2. clang + libbpf headers
sudo apt install clang libbpf-dev linux-headers-$(uname -r)

# 3. aya tooling (optional but recommended)
cargo install bpf-linker
```

Build the BPF object:

```bash
cd crates/kspike-xdp-burp/bpf
cargo +nightly build --release \
    --target bpfel-unknown-none \
    -Z build-std=core
```

The result is `target/bpfel-unknown-none/release/kspike-xdp-burp-ebpf`.

### Attaching (privileged)

Load it with the `aya_runtime` feature on the user-space side:

```bash
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin=eip \
    ./target/release/kspike-xdp-burp

./target/release/kspike-xdp-burp --interface eth0
```

## 6. Secure Boot / module signing

Modern distros with Secure Boot enabled may refuse to load unsigned eBPF
programs. Options:

- Sign the BPF object with a MOK key enrolled via `mokutil`.
- Disable Secure Boot in firmware (not recommended on production hosts).
- Use the **SKB mode** (`XDP_FLAGS_SKB_MODE`) which has softer signing
  requirements in some distributions.

## 7. Operational safety

- **Start in REPLAY mode** (no `aya_runtime` feature). Watch ledger output.
- **Then SKB attach** on a lab host. Watch for kernel warnings.
- **Then NATIVE driver attach** on production. Monitor `dmesg` for verifier
  rejections.

A buggy XDP program can degrade NIC performance to zero or, in extreme
cases, wedge the driver. Always have out-of-band console access to the host
when attaching to production NICs for the first time.

## 8. Sinkhole wiring (for `meterpreter_sinkhole` striker)

When the judge authorises a sinkhole strike on IP `X`:

1. User-space creates a veth pair (`kspike-honey0 ↔ kspike-honey1`) if not
   already present, with one end attached to the honeypot profile.
2. `ip link set kspike-honey0 up`, note its ifindex.
3. User-space writes `(X, ifindex)` into the `SINKHOLE_MAP` BPF map.
4. The XDP program picks that up on the next packet and calls
   `bpf_redirect(ifindex, 0)` → the attacker's traffic flows into the honey.
5. Striker's `apply` returns success; the ledger records authz + the map entry.

Revoke by deleting the map key.

## 9. Limitations (v0.3)

- First 64 bytes of each TCP payload only. Deeper inspection needs per-CPU
  scratch buffers (planned).
- No TCP reassembly inside eBPF — pathological fragmentation will evade us.
- HTTPS cannot be decrypted inside XDP without kernel TLS + a distributed
  CA. We rely on **behavioural** signatures (timing, size mod 16, flow
  direction ratios) for encrypted flows; see
  `detector.net.meterpreter_beacon`.
- No IPv6 extension-header walking; flags if the Ethernet-direct IPv6 header
  is TCP, otherwise passes.
- `bpf_redirect` path is scaffolded — real implementation requires the
  user-space side to also load an `xdp_devmap` if going to a different NIC.

## 10. Judge integration

The XDP program only **detects** and, at most, **drops**. It never fires
strikers autonomously — redirection is consulted from a map the Judge owns.
The chain of control remains:

```
XDP (detect) → RingBuf → user-space → Engine → Judge (ROE + KHZ) → (re)install SINKHOLE_MAP entry
```

No silent offensive action ever originates in the kernel.
