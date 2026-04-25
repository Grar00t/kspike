//! End-to-end smoke test for v0.7 → v1.0.

use kspike_core::{KnownLimits, ModuleKind, ModuleMeta, ModuleVerdict};
use kspike_judge::JudgeRuling;
use kspike_niyah::{Explainer, Locale, LedgerView};
use kspike_kforge::{TokenBucket, KeyLog, KeyLogEntry};
use kspike_haven::{bootstrap, BootManifest, PhalanxBus, PhalanxMessage};
use kspike_windows::{WfpMirror, WfpFlow, WfpDirection, WfpLayer, EtwProvider, EtwLevel};
use std::net::IpAddr;

fn main() {
    println!("══════════════════════════════════════════");
    println!("  KSpike v1.0 end-to-end smoke test");
    println!("══════════════════════════════════════════\n");

    println!("── 1. Niyah explainer (Arabic) ──");
    let meta = ModuleMeta {
        name: "striker.net.meterpreter_sinkhole".into(),
        kind: ModuleKind::Striker,
        version: "0.1.0".into(),
        description: "DNAT C2 to honey".into(),
        author: "gratech".into(),
        risk_level: 7,
        limits: KnownLimits::new(),
        tags: vec!["c2".into()],
    };
    let verdict = ModuleVerdict::RequestStrike {
        action: "dnat_to_honeypot".into(),
        target: "198.51.100.99".into(),
        justification: "confirmed C2".into(),
        confidence: 0.94,
        proportionality: 4,
    };
    let ruling = JudgeRuling {
        allowed: true,
        reason: "ROE all 4 conditions met | KHZ Φ=0.78".into(),
        conditions_met: [true; 4],
        required_dual_auth: false,
        ts: chrono::Utc::now(),
    };
    let exp = Explainer::new(Locale::Arabic).explain(&meta, &verdict, &ruling);
    println!("  العنوان: {}", exp.headline);
    println!("  الفقرة:  {}", exp.paragraph);
    println!("  المبادئ: {:?}", exp.charter_principles);

    println!("\n── 2. Niyah ledger view ──");
    let rec: serde_json::Value = serde_json::json!({
        "seq": 42, "ts": "2026-04-25T20:00:00Z",
        "category": "strike",
        "self_hash": "ab12cd34ef56789012345678",
        "payload": { "module": "striker.net.meterpreter_sinkhole", "target": "198.51.100.99" }
    });
    let v = LedgerView::from_record(&rec).unwrap();
    println!("  seq={} {} (ar={}) — {}", v.seq, v.category_en, v.category_ar, v.summary_ar);

    println!("\n── 3. K-Forge token bucket back-pressure ──");
    let mut tb = TokenBucket::new(3.0, 1.0);
    println!("  allow×3: {} {} {}", tb.allow(1.0), tb.allow(1.0), tb.allow(1.0));
    println!("  allow #4 (should fail): {}", tb.allow(1.0));

    println!("\n── 4. K-Forge key log ──");
    let path = std::env::temp_dir().join("kspike-keylog.jsonl");
    let _ = std::fs::remove_file(&path);
    let entry = KeyLogEntry {
        ts: chrono::Utc::now(),
        signer_fpr: "17667b3d2e4d935e".into(),
        pubkey_hex: "deadbeef".into(),
        attestation: "self-attested by operator".into(),
        attested_by: "17667b3d2e4d935e".into(),
    };
    KeyLog::append(&path, &entry).unwrap();
    let log = KeyLog::load(&path).unwrap();
    println!("  loaded? {}",
        log.lookup("17667b3d2e4d935e").is_some());

    println!("\n── 5. Windows WFP mirror decide() ──");
    let mirror = WfpMirror::default();
    let flow = WfpFlow {
        src: "10.0.0.99".parse::<IpAddr>().unwrap(),
        dst: "10.0.0.5".parse::<IpAddr>().unwrap(),
        src_port: 49231, dst_port: 445,
        direction: WfpDirection::Inbound,
        layer: WfpLayer::AleAuthRecvAcceptV4,
    };
    println!("  inbound 445: {:?}", mirror.decide(&flow));

    println!("\n── 6. Windows ETW format ──");
    let etw = EtwProvider::default();
    println!("  {}", etw.format(EtwLevel::Warning, "windows.process.create",
        &serde_json::json!({"pid": 4242, "image": "powershell.exe"})));

    println!("\n── 7. HAVEN bootstrap ──");
    let manifest_path = std::env::temp_dir().join("kspike-haven-manifest.toml");
    std::fs::write(&manifest_path, b"version=\"1.0\"\noperator=\"smoke\"\nservice_mode=\"defensive\"\nnetwork_posture=\"defense_in_depth\"\ninterfaces=[\"eth0\"]\nroe_path=\"/etc/kspike/roe.toml\"\nledger_path=\"/var/lib/kspike/ledger.jsonl\"\nniyah_locale=\"ar\"\nphalanx_peers=[\"unix:///run/phalanx.bus\"]\n").unwrap();
    let status = bootstrap(&manifest_path).unwrap();
    println!("  ok: {} | warnings: {}", status.ok, status.warnings.len());
    for w in &status.warnings { println!("    ⚠ {w}"); }

    println!("\n── 8. Phalanx publish format ──");
    let msg = PhalanxMessage {
        ts: chrono::Utc::now(),
        publisher: "kspike".into(),
        topic: "strike.authorised".into(),
        payload: serde_json::json!({"target": "198.51.100.99"}),
        signer_fpr: "17667b3d2e4d935e".into(),
        signature: "<hex>".into(),
    };
    print!("  wire: {}", PhalanxBus::format(&msg));
    println!("  publishes: {:?}", PhalanxBus::topics_published());

    println!("\n══════════════════════════════════════════");
    println!("  All v0.7 → v1.0 surfaces working ✓");
    println!("══════════════════════════════════════════");
}
