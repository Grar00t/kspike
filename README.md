# KSpike

**Dual-mode kernel defense & active-response framework — Casper-governed.**

> *"اعرف عدوك لتحميه من أن يؤذيك."*
> Know your enemy — so you can shield yourself from the harm they intend.

KSpike is the shield-arm of the Casper Engine stack. It is structured like
Metasploit (modular, console-driven, exploit-library ergonomics) but inverted
in purpose: every offensive capability is **sealed behind a judge** and can
only fire when four conditions drawn from Islamic jurisprudence and modern
active-defense law are satisfied. The default posture is defensive. Strikes
are lawful, proportionate, and forever auditable.

Built in Rust, zero hidden channels, no telemetry, no phone-home.
Part of the [gratech.sa](https://gratech.sa) sovereign stack.

---

## Design Principles

| Principle | Translation in code |
|---|---|
| **الإنسان أولاً** — human first | Loyalty is to the operator, not to any vendor or state. |
| **السيادة الرقمية** — digital sovereignty | No outbound channel the operator did not authorise. |
| **الصدق بلا هلوسة** — truth without fabrication | Every module declares its limitations (`humility.rs`). |
| **الكمال وهم** — perfection is a mirage | Confidence is always humbled by known limits before use. |
| **عدل لا بطش** — justice, not brute force | Strikes pass the four-condition Judge + KHZ balance. |
| **لا فعل سرّي** — no silent action | Every decision (allow / deny / fire / refuse) is sealed in a signed ledger. |

---

## What's new in v0.3 — Kernel-Native MITM

KSpike now ships a **transparent XDP + eBPF interceptor** (`kspike-xdp-burp`)
that sits at the earliest point in the Linux receive path and feeds the
Engine at wire speed. Think: **Burp Suite, but in the kernel, but defensive.**

- 📡 XDP program (Rust + aya) parses L2→L4 for IPv4 and IPv6
- 🧬 Three in-kernel detectors: Log4Shell JNDI, Meterpreter beacon, EternalBlue probe
- 📦 RingBuf (threats → Engine) + PerfEventArray (flow telemetry → logs)
- 🎯 XDP_REDIRECT pathway for `striker.net.meterpreter_sinkhole`
- 🧪 Ships with a pcap-replay harness — works without CAP_BPF / kernel headers

See [docs/design/XDP-BURP.md](./docs/design/XDP-BURP.md) for build recipe,
Secure Boot notes, and the sinkhole wiring protocol.

```bash
# Exercise the full kernel→user pipeline in replay mode (any host):
cargo build --release -p kspike-xdp-burp
./target/release/kspike-xdp-burp

# Real kernel attach (Linux + CAP_BPF + kernel headers):
cd crates/kspike-xdp-burp/bpf && cargo +nightly build --release \
    --target bpfel-unknown-none -Z build-std=core
sudo ./target/release/kspike-xdp-burp --interface eth0
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  kspike-cli       console, signal ingest, status                │
├─────────────────────────────────────────────────────────────────┤
│  kspike-modules   engine · detectors · defenders · strikers     │
├──────────────────────────┬──────────────────────────────────────┤
│  kspike-judge            │  kspike-khz                          │
│   ├ StaticJudge (ROE)    │   ├ Al-Jabr / Al-Muqabala operators  │
│   ├ KhzJudge  (ROE+KHZ)  │   ├ Ten Khawarizmi rules             │
│   └ ManualJudge          │   ├ Fitrah anchors (Quran, Luqman,   │
│                          │   │   Khidr, Khawarizmi, Ibn Rushd,  │
│                          │   │   Maqasid al-Shariah, …)         │
│                          │   └ 115-version protocol archive     │
├─────────────────────────────────────────────────────────────────┤
│  kspike-core      Module trait · EventBus · EvidenceLedger      │
│                   Signal · Humility · Typed errors              │
└─────────────────────────────────────────────────────────────────┘
                               ↓
                   ┌──────────────────────┐
                   │  evidence.jsonl      │
                   │  Blake3 hash chain   │
                   │  Ed25519 signatures  │
                   └──────────────────────┘
```

---

## Rules of Engagement (ROE)

A Striker module may request offensive action only when **all four** conditions
are met *and* a KHZ balance score (Φ) clears the configured floor:

1. **Certainty** (يقين) — attack is in progress, evidenced, not suspected.
2. **Exhaustion** (استنفاد) — defenders tried, or attack is too fast to wait.
3. **Legitimacy** (مشروعية الهدف) — target is the attacker, not bystanders.
4. **Proportion** (تناسب) — force is commensurate with the threat
   (the fiqh maxim *الضرورة تُقدَّر بقدرها*).

Hard-coded forbidden targets (never strike, even if provoked):
- loopback / link-local / multicast
- `*.gov`, `*.mil`, `*.edu`, `*.hospital`, `*.icrc.org`
- any prefix the operator adds to `roe.toml`

Postures:
- `passive_observer` — observe only.
- `defensive_only` — defenders fire; strikers fully disabled.
- `defensive_with_active_response` — default; full 4-condition gate.
- `preemptive` — for high-velocity in-progress attacks; relaxes exhaustion.

---

## The KHZ_Q Balancer

KSpike's ethical kernel is the **KHZ_Q balancer** — 115 protocol revisions
(V2.1 → V41) distilled into a deterministic Rust core. For every decision:

```
Φ = [ Al-Muqabala( Σ Necessity )  −  Al-Muqabala( Σ Harm )  +  1 ] / 2
```

Al-Jabr restores missing terms from the Fitrah floor; Al-Muqabala balances
opposing weights. Every ruling cites its Fitrah anchor (Quran / Sunnah /
Luqman / Khidr / Khawarizmi / Ibn Rushd / Maqasid / scientific consensus /
operator override). The full protocol archive lives at
`docs/khz/khz_protocols.ndjson` for audit and community review.

---

## Quick start

```bash
# Build
cargo build --release

# Run the demo pipeline (synthetic signals, ledger written to ./kspike-evidence.jsonl)
./target/release/kspike demo

# Ingest a single JSON signal from stdin
echo '{"id":"...","ts":"2026-04-24T21:18:00Z","source":"AuthLog",
       "kind":"ssh.auth.fail.burst","actor":"198.51.100.99","target":"sshd",
       "threat":"Hostile","raw_confidence":0.95,"data":{"attempts":30}}' \
  | ./target/release/kspike ingest

# Dry-run (evaluate + judge + record, but don't apply)
./target/release/kspike --dry-run demo

# Manual judge (every striker needs out-of-band operator approval)
./target/release/kspike --no-khz demo
```

---

## Module library

### Core modules (v0.1)

| kind | name | risk | purpose |
|---|---|---|---|
| detector | `detector.ssh_bruteforce` | 0 | Reports high-velocity SSH auth failures. |
| defender | `defender.ssh_quarantine` | 1 | Drops an actor into the nftables quarantine set (15-min TTL). |
| defender | `defender.kernel_lockdown` | 3 | Raises kernel lockdown on rootkit suspicion. |
| defender | `defender.fs_immunity` | 1 | Enables `fs.protect_*` sysctls to preserve evidence. |
| striker | `striker.c2_burn` | 7 | Null-routes and DNS-sinks a confirmed C2. |
| striker | `striker.traceback_beacon` | 8 | Plants a canary beacon to expose exfil path. |

### MSF-Mirror modules (v0.2) — kernel-native, compiled-in

Famous Metasploit offensive modules, inverted and wired directly into the
engine via the `kspike-kernel` substrate.

| kind | name | MSF original | purpose |
|---|---|---|---|
| detector | `detector.smb.eternalblue_probe`  | `exploit/windows/smb/ms17_010_eternalblue` | NT_TRANS probe shape on the wire. |
| defender | `defender.smb.v1_killswitch`      | — | Kills SMBv1 + blackholes 445 from the flagged actor. |
| detector | `detector.smb.psexec_abuse`       | `exploit/windows/smb/psexec` | ADMIN$ mount + svcctl bind + CreateService correlation. |
| detector | `detector.http.log4shell_jndi`    | `exploit/multi/http/log4shell_*` | JNDI strings (CVE-2021-44228) incl. obfuscated. |
| defender | `defender.cred.dump_canary`       | `post/windows/gather/hashdump` | Plants fake credentials + flags anyone using them. |
| detector | `detector.mem.shikata_polymorphic`| `x86/shikata_ga_nai` | Classic SGN decoder-stub prologue (two variants). |
| detector | `detector.net.meterpreter_beacon` | `windows/meterpreter/reverse_*` | Stageless/staged Meterpreter C2 shape. |
| striker  | `striker.net.meterpreter_sinkhole`| — | DNATs confirmed Meterpreter flows into a local honeypot. |
| detector | `detector.ad.kerberoasting`       | `GetUserSPNs / Rubeus` | Multi-SPN TGS-REQ bursts with RC4 etype. |
| deception| `deception.canary_token`          | — | DNS/URL/file tripwires; any touch implies recon. |

**Kernel substrate** (`kspike-kernel`): packet view, byte/hex/utf16 inspection,
canary registry, procfs/sysfs taps. No plugin boundary — these are part of the
engine.

Module authors implement a single trait (`kspike_core::Module`), declare their
known limits (`KnownLimits`), and emit verdicts. Strikers `apply` MUST refuse
to execute without a judge authorisation — a `RoeViolation` error is raised
even if called directly.

---

## Evidence ledger

Every action — signals in, verdicts out, judge rulings, strikes, defenses,
ROE breaches — is sealed as a hash-chained, Ed25519-signed JSON-Lines record:

```json
{
  "seq": 17,
  "ts": "2026-04-24T21:18:03Z",
  "category": "strike",
  "payload": { "module": "striker.c2_burn", "target": "198.51.100.99", ... },
  "prev_hash": "c47c1ee4…",
  "self_hash": "2ce67e75…",
  "signature": "8669b42f…",
  "signer_fpr": "17667b3d2e4d935e"
}
```

Verify a ledger end-to-end with `EvidenceLedger::verify_file`.

---

## Project layout

```
kspike/
├── Cargo.toml                   # workspace
├── crates/
│   ├── kspike-core/             # Module trait, EventBus, Evidence, Humility
│   ├── kspike-khz/              # KHZ_Q balancer + protocol archive loader
│   ├── kspike-judge/            # ROE + StaticJudge / KhzJudge / ManualJudge
│   ├── kspike-modules/          # engine, detectors, defenders, strikers
│   └── kspike-cli/              # `kspike` binary
├── docs/
│   ├── design/                  # architecture docs (Arabic + English)
│   ├── roe/                     # ROE charter (fiqh + law + tech)
│   └── khz/khz_protocols.ndjson # 115-version KHZ_Q archive
└── examples/                    # sample roe.toml, sample signals
```

---

## Sister projects

- [Casper_Engine](https://github.com/Grar00t/Casper_Engine) — C11 hybrid
  neuro-symbolic reasoning engine. KSpike can delegate final judgment to
  Casper (`CasperJudge`, planned v0.2).
- [haven-niyah-engine](https://github.com/Grar00t/haven-niyah-engine) —
  Arabic-first three-lobe LLM. Will power contextual ROE explanations.
- [k-forge](https://github.com/Grar00t/k-forge) — P2P, crypto-signed VCS.
  KSpike evidence ledgers can be replicated over K-Forge for community IOC
  sharing.
- [khawrizm-os](https://github.com/Grar00t/khawrizm-os) — Sovereign ARM64
  Linux. KSpike is a native citizen.

---

## License

Casper-Sovereign-1.0 — see [LICENSE](./LICENSE). Permissive for defensive
and research use; forbids any deployment that silences, surveils, or
manipulates users against their own interest.

---

## Author

**Sulaiman Al-Shammari (DRAGON403)** — founder, GRA Tech Solutions
Riyadh, KSA · admin@gratech.sa · `@Grar00t`

*الخوارزمية دائماً تعود للوطن.*
