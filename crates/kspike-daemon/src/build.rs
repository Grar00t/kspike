//! Engine construction — shared by daemon + TUI + one-shot CLI.

use anyhow::Result;
use kspike_core::Module;
use kspike_judge::{Judge, KhzJudge, StaticJudge, roe::Roe};
use kspike_kernel::canary::MemoryCanary;
use kspike_modules::defenders::{FilesystemImmunityDefender, KernelLockdownDefender, SshQuarantineDefender};
use kspike_modules::detectors::SshBruteforceDetector;
use kspike_modules::engine::{Engine, EngineConfig};
use kspike_modules::msf_mirror as msf;
use std::sync::Arc;

pub struct EngineBuild {
    pub engine: Arc<Engine>,
    pub canary: Arc<MemoryCanary>,
    pub module_names: Vec<String>,
}

pub fn build_engine(ledger_path: Option<std::path::PathBuf>, phi: f32, dry_run: bool) -> Result<EngineBuild> {
    let roe          = Roe::default_roe();
    let static_judge = StaticJudge::new(roe);
    let judge: Arc<dyn Judge> = Arc::new(KhzJudge::new(static_judge, phi));

    let engine = Arc::new(Engine::new(
        EngineConfig { ledger_path, dry_run },
        judge,
    ));

    let canary = Arc::new(MemoryCanary::new());
    let mods: Vec<Arc<dyn Module>> = vec![
        Arc::new(SshBruteforceDetector::default()),
        Arc::new(SshQuarantineDefender::default()),
        Arc::new(KernelLockdownDefender::default()),
        Arc::new(FilesystemImmunityDefender::default()),
        Arc::new(msf::EternalBlueProbeDetector::default()),
        Arc::new(msf::SmbV1Killswitch::default()),
        Arc::new(msf::PsExecAbuseDetector::default()),
        Arc::new(msf::Log4ShellJndiDetector::default()),
        Arc::new(msf::ShikataPolymorphicDetector::default()),
        Arc::new(msf::MeterpreterBeaconDetector::default()),
        Arc::new(msf::KerberoastDetector::default()),
        Arc::new(msf::CredDumpCanaryDefender::new(canary.clone())),
        Arc::new(msf::CanaryTokenDeception::new(canary.clone())),
    ];
    let mut names = Vec::with_capacity(mods.len());
    for m in mods {
        names.push(m.meta().name.clone());
        engine.register(m)?;
    }
    Ok(EngineBuild { engine, canary, module_names: names })
}
