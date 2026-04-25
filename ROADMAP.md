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

## v0.7 — Arabic NLP Enrichment
- Integrate kspike-casper-ffi with Niyah Engine prompts
- Arabic ROE explanations in ledger
- Natural-language signal provenance for non-technical operators

## v0.8 — K-Forge Production
- mDNS peer discovery
- Gossip throttling + back-pressure
- Cross-peer canary sharing (with consent)
- Community IOC feed format

## v0.9 — Windows/WSL2 Bridge
- Windows kernel driver that mirrors XDP semantics via WFP
- ETW providers for Windows-side signals
- PS-remoting over the kspiked IPC

## v1.0 — HAVEN OS Integration
- Boots as a first-class service on khawrizm-os
- Phalanx Protocol integration
- Niyah Engine as the default `CasperJudge` backend
