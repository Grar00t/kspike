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

## v0.5 — Live Kernel Attach (next)
- Fully wire `aya_runtime` feature:
  * Load compiled BPF object
  * Attach to interface (skb/driver/offload modes)
  * RingBuf → mpsc::Sender → Engine
  * PerfEventArray → tracing::debug
- bpf_redirect implementation + SINKHOLE_MAP management from user-space
- XDP sinkhole integration with kspike-honeypot veth pair setup

## v0.6 — Kernel Observability
- kspike-procfs: /proc/net/tcp{,6} + /proc/modules integrity tap
- kspike-auth-log: streaming tail of /var/log/auth.log
- kspike-ebpf-lsm: LSM hooks for syscall anomaly detection

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
