//! KSpike CLI console — msfconsole-spirit, Casper-governed.

use clap::{Parser, Subcommand};
use kspike_core::{BANNER, Signal, SignalSource, ThreatLevel};
use kspike_judge::{StaticJudge, KhzJudge};
use kspike_judge::roe::Roe;
use kspike_modules::engine::{Engine, EngineConfig};
use kspike_modules::defenders::{SshQuarantineDefender, KernelLockdownDefender, FilesystemImmunityDefender};
use kspike_modules::detectors::SshBruteforceDetector;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "kspike", version, about = "KSpike dual-mode kernel defense console")]
struct Cli {
    /// Path to roe.toml (optional — uses defaults when absent).
    #[arg(long)]
    roe: Option<std::path::PathBuf>,

    /// Path to evidence ledger (jsonl).
    #[arg(long, default_value = "./kspike-evidence.jsonl")]
    ledger: std::path::PathBuf,

    /// Dry-run — modules report but never apply actions.
    #[arg(long)]
    dry_run: bool,

    /// Use KHZ-backed judge instead of plain StaticJudge.
    #[arg(long, default_value_t = true)]
    khz: bool,

    /// Minimum KHZ Φ score (0..1) required to authorise.
    #[arg(long, default_value_t = 0.50)]
    phi: f32,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the engine and run a synthetic demo signal pipeline.
    Demo,
    /// Load modules and ingest a single JSON signal from stdin, exit.
    Ingest,
    /// Print framework status and loaded config.
    Status,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()
            .add_directive("info".parse().unwrap()))
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();
    println!("{BANNER}");

    let roe = match &cli.roe {
        Some(p) => Roe::load(p)?,
        None => Roe::default_roe(),
    };
    let static_judge = StaticJudge::new(roe);

    let judge: Arc<dyn kspike_judge::Judge> = if cli.khz {
        Arc::new(KhzJudge::new(static_judge, cli.phi))
    } else {
        Arc::new(static_judge)
    };

    let cfg = EngineConfig { ledger_path: Some(cli.ledger.clone()), dry_run: cli.dry_run };
    let engine = Engine::new(cfg, judge);

    // Register modules.
    engine.register(Arc::new(SshBruteforceDetector::default()))?;
    engine.register(Arc::new(SshQuarantineDefender::default()))?;
    engine.register(Arc::new(KernelLockdownDefender::default()))?;
    engine.register(Arc::new(FilesystemImmunityDefender::default()))?;
    #[cfg(feature = "strikers")]
    {
        engine.register(Arc::new(kspike_modules::strikers::C2BurnStriker::default()))?;
        engine.register(Arc::new(kspike_modules::strikers::TracebackBeaconStriker::default()))?;
    }

    // MSF-mirror modules — kernel-native, built-in.
    use kspike_modules::msf_mirror as msf;
    use kspike_kernel::canary::MemoryCanary;
    let canary_reg = Arc::new(MemoryCanary::new());
    engine.register(Arc::new(msf::EternalBlueProbeDetector::default()))?;
    engine.register(Arc::new(msf::SmbV1Killswitch::default()))?;
    engine.register(Arc::new(msf::PsExecAbuseDetector::default()))?;
    engine.register(Arc::new(msf::Log4ShellJndiDetector::default()))?;
    engine.register(Arc::new(msf::CredDumpCanaryDefender::new(canary_reg.clone())))?;
    engine.register(Arc::new(msf::ShikataPolymorphicDetector::default()))?;
    engine.register(Arc::new(msf::MeterpreterBeaconDetector::default()))?;
    engine.register(Arc::new(msf::KerberoastDetector::default()))?;
    engine.register(Arc::new(msf::CanaryTokenDeception::new(canary_reg.clone())))?;
    #[cfg(feature = "strikers")]
    engine.register(Arc::new(msf::MeterpreterSinkholeStriker::default()))?;

    match cli.cmd {
        Cmd::Demo     => demo(&engine),
        Cmd::Ingest   => ingest_stdin(&engine),
        Cmd::Status   => {
            let s = engine.stats();
            println!("stats: {s:?}");
            Ok(())
        }
    }
}

fn demo(engine: &Engine) -> anyhow::Result<()> {
    println!("▶ demo: injecting synthetic signals");

    let s1 = Signal::new(SignalSource::AuthLog, "ssh.auth.fail.burst")
        .actor("203.0.113.42")
        .target("sshd")
        .threat(ThreatLevel::Suspicious)
        .confidence(0.93)
        .with("attempts", serde_json::json!(17));
    engine.ingest(s1)?;

    let s2 = Signal::new(SignalSource::Kernel, "kernel.rootkit.suspect.lkm_hidden")
        .target("kernel:/proc/modules")
        .threat(ThreatLevel::Hostile)
        .confidence(0.81);
    engine.ingest(s2)?;

    let s3 = Signal::new(SignalSource::Network, "c2.confirmed.beacon")
        .actor("evil.example.net")
        .target("198.51.100.99")
        .threat(ThreatLevel::Catastrophic)
        .confidence(0.95);
    engine.ingest(s3)?;

    let s = engine.stats();
    println!("▶ stats: signals={} defenses={} strikes={} denials={} reports={}",
        s.signals, s.defenses, s.strikes, s.denials, s.reports);
    Ok(())
}

fn ingest_stdin(engine: &Engine) -> anyhow::Result<()> {
    let mut buf = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
    let sig: Signal = serde_json::from_str(&buf)?;
    let outs = engine.ingest(sig)?;
    println!("{}", serde_json::to_string_pretty(&outs)?);
    Ok(())
}
