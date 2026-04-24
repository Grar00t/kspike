# KSpike — Architecture Deep Dive

> النسخة 0.1 · المؤلف: سليمان الشمري (DRAGON403)

## 1. Why another framework?

Existing kernel-security frameworks split into two camps:

1. **Pure defense** — K-Sentinel, SELinux, AppArmor, SPIKE, eBPF-only tools.
   Safe, but reactive. An attacker with momentum beats them.
2. **Pure offense** — Metasploit, Core Impact, Cobalt Strike. Powerful but
   amoral; they will fire at anything you point them at.

Neither is sufficient when the user is a sovereign individual under active
threat. The wronged (المظلوم) needs a framework that is default-safe but
capable of decisive action — and every action must stand in a court of law
and in the court of one's own conscience.

KSpike is the answer. **Dual-mode. Judge-gated. Forever auditable.**

## 2. Layers

```
┌─ layer 5 ─────────────────────────────────────────────────────┐
│  CLI / REPL            kspike-cli                             │
├─ layer 4 ─────────────────────────────────────────────────────┤
│  Engine & Modules      kspike-modules                         │
│  engine.rs             detectors.rs defenders.rs strikers.rs  │
├─ layer 3 ─────────────────────────────────────────────────────┤
│  Judgment              kspike-judge                           │
│  roe.rs (ROE config)   judge.rs (StaticJudge, KhzJudge, …)    │
├─ layer 2 ─────────────────────────────────────────────────────┤
│  Balance (ethics)      kspike-khz                             │
│  operator.rs (Al-Jabr, Al-Muqabala)                           │
│  balancer.rs (Φ computation)                                  │
│  fitrah.rs (wisdom sources)                                   │
│  protocol.rs (115-version KHZ_Q archive streaming)            │
├─ layer 1 ─────────────────────────────────────────────────────┤
│  Core                  kspike-core                            │
│  Module trait  ·  Signal  ·  EventBus                         │
│  EvidenceLedger (Blake3 chain + Ed25519 sigs)                 │
│  KnownLimits / Limitation (epistemic humility)                │
└───────────────────────────────────────────────────────────────┘
```

## 3. Data flow (one signal)

```
Signal ─▶ Engine.ingest()
             │
             ├─▶ ledger.seal("signal")
             │
             ├─▶ for each Module:
             │     │
             │     ├─▶ Module.evaluate() → ModuleVerdict
             │     ├─▶ ledger.seal("verdict")
             │     │
             │     ├─▶ build RulingContext
             │     │     · defender_attempts_on_actor
             │     │     · external_corroboration (Peer source?)
             │     │     · target_legitimacy (raw_confidence)
             │     │     · attack_certainty (humbled confidence)
             │     │
             │     ├─▶ Judge.rule(meta, verdict, ctx) → JudgeRuling
             │     │     │
             │     │     │  (KhzJudge wraps StaticJudge +
             │     │     │   then runs KhzBalancer; KHZ may veto.)
             │     │
             │     ├─▶ ledger.seal("judge")
             │     │
             │     └─▶ if allowed AND !dual_auth:
             │            Module.apply(verdict, authz?) → outcome
             │            ledger.seal("defense"|"strike"|"report")
             │
             └─▶ EngineStats++
```

## 4. Epistemic humility

Every module ships a `KnownLimits` — named `Limitation`s with a
`confidence_penalty` in [0,1]. The engine uses
`meta.limits.humble(raw_confidence)` before feeding confidence into the
judge. A module that declares zero limitations is structurally distrusted
by any reasonable ROE configuration.

## 5. Evidence ledger format

Append-only JSON-Lines. Each record:

```text
seq         u64   monotonically increasing
ts          ISO-8601 UTC
category    "signal" | "verdict" | "judge" | "defense" | "strike"
             | "report" | "ignore" | "roe_breach" | "roe_amendment"
payload     arbitrary JSON
prev_hash   hex blake3 of previous record (or "" at genesis)
self_hash   hex blake3 of (seq || ts || category || payload || prev_hash)
signature   hex Ed25519 over self_hash
signer_fpr  first 16 hex chars of blake3(pubkey)
```

Verification: `EvidenceLedger::verify_file(path, &pubkey) -> usize` walks
the file, rebuilds each hash, re-verifies each signature, and fails hard
on the first break.

## 6. KHZ_Q integration

`KhzJudge` wraps `StaticJudge` and may only *tighten*. Procedure:

1. Run StaticJudge — if it denies, stop (preserve its reason).
2. Build a `BalanceRequest`:
   - `HarmVector` starts with `module.risk_level / 10`.
   - For strikes: add `strike.offensive_action` = `proportionality / 10`.
   - `NecessityVector` accumulates `attack_certainty`, `target_legitimacy`,
     `confidence`, optional `community_corroboration`.
3. `KhzBalancer.evaluate(req) → Ruling { phi, full_assistance, ... }`.
4. If `phi < phi_threshold` AND not `full_assistance`, veto.

The `full_assistance` bypass triggers iff `ΣHarm ≈ 0` and `ΣNecessity > 0`
— encoding the classical rule *"لا ضرر ولا ضرار"* conjoined with *"الضرورات
تبيح المحظورات"*.

## 7. Extension surface

- **New Module**: implement `kspike_core::Module`; declare `KnownLimits`;
  ship as a Cargo dependency or dynamic plugin (v0.2).
- **New Judge**: implement `kspike_judge::Judge`; compose with `StaticJudge`
  for the four-condition check.
- **New Fitrah source**: extend `WisdomSource` (non-breaking: add variant).
- **eBPF kernel bridge** (v0.2): `kspike-kernel` crate providing a syscall
  tap that emits `Signal`s into the engine.
- **Casper bridge** (v0.2): `CasperJudge` delegates contextual adjudication
  to the C11 Casper Engine over FFI.

## 8. Non-goals (v0.1)

- No distributed consensus. Engine is single-node; K-Forge gossip is v0.3.
- No ML-based anomaly detection. Determinism first, learning later.
- No GUI. CLI + machine-readable outputs only.
- No Windows kernel support. Linux/BSD first; Windows via WSL2 bridge.
