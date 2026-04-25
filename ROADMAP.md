# KSpike Roadmap

## v0.1 — Foundation ✓
- kspike-core (Module trait, Signal, EventBus, Evidence, Humility)
- kspike-khz (Al-Jabr/Al-Muqabala, Φ balancer, 115-version archive)
- kspike-judge (StaticJudge, KhzJudge, ManualJudge, 4-condition ROE)
- kspike-modules v0.1 (ssh + kernel + fs defenders, 2 strikers)
- kspike-cli
- Casper-Sovereign-1.0 license

## v0.2 — MSF-Mirror ✓
- kspike-kernel substrate (packet view, inspect helpers, canary registry)
- 9 MSF-mirror modules (EternalBlue, PSExec, Log4Shell, Shikata,
  Meterpreter ×2, Kerberoast, CredDumpCanary, CanaryToken)
- Engine Ignore-bypass fix

## v0.3 — XDP-Burp ✓
- kspike-xdp-burp: user-space tokio loader + eBPF XDP program
- Shared XdpSignalEvent/XdpDebugEvent schema (IPv4 + IPv6)
- RingBuf + PerfEventArray + SINKHOLE_MAP
- FNV-1a no-alloc hash, ktime timestamps
- msf_mirror modules wired to XDP fast-path kinds

## v0.4 — Daemon + TUI + Casper + Honeypot + K-Forge ✓ (this release)

**Shared-state engine (kspike-daemon)**
- UNIX-socket IPC (newline JSON)
- Operations: status, ingest, list_modules, plant_canary, ledger_tail, shutdown
- systemd unit (dist/systemd/kspike.service) with full hardening
- Shared Arc<Engine>, Arc<MemoryCanary> — no more state loss between calls

**Interactive console (kspike-tui)**
- msfconsole-style REPL: help, status, modules, tail, plant, ingest, shutdown
- Connects to kspiked over UNIX socket
- Zero extra deps (no rustyline)

**Honeypot profiles (kspike-honeypot)**
- HoneypotProfile schema + RetentionPolicy
- Canned responder
- Built-ins: meterpreter_win10_x64, ssh_ubuntu_2004, smb_win7
- forbidden_leaks list — honeys are Charter-bound too

**Casper FFI bridge (kspike-casper-ffi)**
- CasperJudge: wraps any Judge; Casper can only tighten
- Runtime dlopen of libcasper.so (feature `link_casper`)
- Stub mode when Casper is absent — compiles anywhere

**P2P gossip skeleton (kspike-kforge)**
- Wire frames: Advert, FetchReq, Segment
- PeerList bookkeeping
- Verify-then-merge path into /var/lib/kspike/peers/<signer_fpr>.jsonl

**Docs**
- docs/ops/BUILDING-BPF.md — full bpf-linker + CAP_BPF recipe

## v0.5 — Live Kernel Attach ✓
- `aya_runtime` feature wired: `Ebpf::load_file` + XDP attach (skb/drv/offload)
- RingBuf reader (AsyncFd) → `XdpBurpTap.sink()` → Engine
- PerfEventArray reader (per-CPU) → tracing::debug
- `SinkholeManager` produces a deterministic plan (veth pair + listen + map
  install) consumed by the runtime when a striker is authorised
- `sinkhole_install/remove` operate on the live BPF SINKHOLE_MAP

## v0.6 — Kernel Observability ✓
- kspike-procfs:
  * `TcpTap` — /proc/net/tcp{,6} parser, IPv4+IPv6, LISTEN/ESTABLISHED diff
  * `ModulesTap` — new modules / hidden LKM / refcnt anomaly detection
- kspike-auth-log:
  * `AuthLogTap` — streaming tail with sliding-window burst aggregation
  * Recognises sshd, sudo, PAM events; emits ssh.auth.fail.burst
- kspike-ebpf-lsm:
  * User-space `LsmTap` + shared `LsmEvent` schema
  * eBPF program (bpf/) with file_open / bprm_check_security / capable hooks
  * Tested in replay mode

## Casper Integration ✓
- `kspike-casper-ffi/include/casper_ffi.h` — stable ABI v1.0 (4 symbols)
- Same header committed to `Grar00t/Casper_Engine/include/casper_ffi.h`
- KSpike's CasperJudge can dlopen libcasper.so under `--features link_casper`

## v0.7 — Arabic NLP Enrichment ✓
- `kspike-niyah` crate — Explainer + templates + LedgerView
- Arabic (Najdi-flavoured) + English + Bilingual locales
- Charter-anchored prose; never invents facts the Judge didn't commit
- Falls back deterministically when Casper FFI is absent

## v0.8 — K-Forge Production ✓
- `discovery.rs` — file-backed peers + mDNS-ready API
- `keylog.rs` — append-only signed key log; `is_attested_by` gate
- `backpressure.rs` — per-peer token bucket (live-tested)

## v0.9 — Windows/WSL2 Bridge ✓
- `kspike-windows` crate (cross-compiles on any host)
- `WfpMirror` + WFP layer/direction/action types
- `EtwProvider` formatter for Gratech-KSpike events
- `wsl_bridge_signal` — turns Windows-side payloads into kspike Signals

## v1.0 — HAVEN OS Integration ✓
- `kspike-haven` crate — BootManifest, Phalanx bus, bootstrap()
- `dist/haven/manifest.toml` — operator-facing config schema
- `dist/haven/kspike-haven.service` — boot order before network-online
- Phalanx topics: ioc.add, strike.authorised, evidence.sealed, roe.amendment
- ServiceMode: Audit | Defensive | DefensiveWithStrike
- NetworkPosture: DenyByDefault | DefenseInDepth | Federation

## CI ✓
- `.github/workflows/ci.yml` — minimal-permissions build + test + clippy
- `.github/workflows/ebpf.yml` — nightly + bpfel target (advisory)
- `.github/dependabot.yml` — weekly cargo + monthly actions

---

# Future

## v1.1 — Hardware-Backed Signing
- TPM 2.0 / fTPM-sealed signing keys for the evidence ledger
- Signed-boot attestation for the entire KSpike stack

## v1.2 — Federated Threat Intel
- Peer-to-peer IOC exchange across opt-in HAVEN nodes
- Reputation system rooted in the K-Forge key log

## v2.0 — KSpike for Embedded
- ARM Cortex-M / RISC-V build profile
- Stripped-down engine for IoT defense
