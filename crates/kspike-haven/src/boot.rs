//! Bootstrap entrypoint called by HAVEN init.

use crate::manifest::BootManifest;
use anyhow::Result;
use std::path::Path;

/// Load the manifest, validate sanity, and emit a JSON status line that
/// HAVEN's init system reads to decide whether to continue boot.
///
/// This is intentionally tiny: the actual engine startup happens in
/// kspiked, which HAVEN execs with the path returned here.
pub fn bootstrap(manifest_path: &Path) -> Result<BootStatus> {
    let manifest = if manifest_path.exists() {
        let txt = std::fs::read_to_string(manifest_path)?;
        toml::from_str::<BootManifest>(&txt)?
    } else {
        BootManifest::default()
    };

    // Validation pass.
    let mut warnings = Vec::new();
    if manifest.interfaces.is_empty() {
        warnings.push("no network interfaces declared — XDP will not attach".into());
    }
    if !Path::new(&manifest.roe_path).exists() {
        warnings.push(format!("ROE file missing: {}", manifest.roe_path));
    }

    Ok(BootStatus { manifest, warnings, ok: true })
}

#[derive(Debug, serde::Serialize)]
pub struct BootStatus {
    pub manifest: BootManifest,
    pub warnings: Vec<String>,
    pub ok: bool,
}
