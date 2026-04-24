//! UNIX-socket server — accepts `Request`, returns `Response`.

use crate::build::{build_engine, EngineBuild};
use crate::wire::{Request, Response};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{Mutex, Notify};
use tracing::{info, warn};

pub struct Daemon {
    pub build: EngineBuild,
    pub sock_path: PathBuf,
    shutdown: Arc<Notify>,
}

impl Daemon {
    pub fn new(sock_path: PathBuf, ledger: Option<PathBuf>, phi: f32, dry_run: bool) -> Result<Self> {
        let build = build_engine(ledger, phi, dry_run)?;
        Ok(Self { build, sock_path, shutdown: Arc::new(Notify::new()) })
    }

    pub fn shutdown_handle(&self) -> Arc<Notify> { self.shutdown.clone() }

    pub async fn serve(self) -> Result<()> {
        let _ = std::fs::remove_file(&self.sock_path);
        if let Some(parent) = self.sock_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let listener = UnixListener::bind(&self.sock_path)
            .with_context(|| format!("bind {}", self.sock_path.display()))?;
        // tighten perms — user-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.sock_path, std::fs::Permissions::from_mode(0o600));
        }
        info!("kspiked listening on {}", self.sock_path.display());

        let engine   = self.build.engine.clone();
        let mods     = Arc::new(self.build.module_names.clone());
        let canary   = self.build.canary.clone();
        let shutdown = self.shutdown.clone();
        let ledger_path = Arc::new(Mutex::new(None::<PathBuf>));

        loop {
            tokio::select! {
                _ = shutdown.notified() => { info!("daemon shutting down"); break; }
                accept = listener.accept() => {
                    let (stream, _addr) = match accept {
                        Ok(v) => v,
                        Err(e) => { warn!("accept: {e}"); continue; }
                    };
                    let engine = engine.clone();
                    let mods   = mods.clone();
                    let canary = canary.clone();
                    let shutdown = shutdown.clone();
                    let ledger_path = ledger_path.clone();
                    tokio::spawn(async move {
                        let (rd, mut wr) = stream.into_split();
                        let mut lines = BufReader::new(rd).lines();
                        while let Ok(Some(line)) = lines.next_line().await {
                            let resp = match serde_json::from_str::<Request>(&line) {
                                Err(e) => Response::err(format!("bad request: {e}")),
                                Ok(req) => handle(req, &engine, &mods, &canary, &ledger_path, &shutdown).await,
                            };
                            let mut s = match serde_json::to_string(&resp) {
                                Ok(s) => s, Err(e) => format!("{{\"ok\":false,\"error\":\"{e}\"}}"),
                            };
                            s.push('\n');
                            if wr.write_all(s.as_bytes()).await.is_err() { break; }
                        }
                    });
                }
            }
        }
        let _ = std::fs::remove_file(&self.sock_path);
        Ok(())
    }
}

async fn handle(
    req: Request,
    engine: &Arc<kspike_modules::Engine>,
    mods: &Arc<Vec<String>>,
    canary: &Arc<kspike_kernel::MemoryCanary>,
    _ledger_path: &Arc<Mutex<Option<PathBuf>>>,
    shutdown: &Arc<Notify>,
) -> Response {
    match req {
        Request::Status => {
            let stats = engine.stats();
            let mut r = Response::ok_empty();
            r.stats = Some(stats);
            r
        }
        Request::Ingest { signal } => {
            match engine.ingest(signal) {
                Ok(outs) => { let mut r = Response::ok_empty(); r.outcomes = outs; r }
                Err(e)   => Response::err(e.to_string()),
            }
        }
        Request::ListModules => {
            let mut r = Response::ok_empty();
            r.modules = mods.as_ref().clone();
            r
        }
        Request::PlantCanary { placement, needle_hex } => {
            let Some(bytes) = hex_decode(&needle_hex) else {
                return Response::err("needle_hex is not valid hex");
            };
            let id = canary.plant(kspike_kernel::canary::CanaryToken::new(placement, bytes));
            let mut r = Response::ok_empty(); r.canary_id = Some(id); r
        }
        Request::LedgerTail { n } => {
            let p = match std::env::var("KSPIKE_LEDGER") {
                Ok(p) => PathBuf::from(p),
                Err(_) => PathBuf::from("/var/lib/kspike/ledger.jsonl"),
            };
            match read_tail(&p, n) {
                Ok(v) => { let mut r = Response::ok_empty(); r.ledger = v; r }
                Err(e) => Response::err(e.to_string()),
            }
        }
        Request::Shutdown => {
            shutdown.notify_one();
            Response::ok_empty()
        }
    }
}

fn read_tail(p: &Path, n: usize) -> std::io::Result<Vec<serde_json::Value>> {
    let s = match std::fs::read_to_string(p) {
        Ok(s) => s, Err(_) => return Ok(vec![]),
    };
    Ok(s.lines().rev().take(n)
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect::<Vec<_>>().into_iter().rev().collect())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(s.len()/2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let h = hv(b[i])?; let l = hv(b[i+1])?;
        out.push((h<<4)|l);
    }
    Some(out)
}
fn hv(c: u8) -> Option<u8> { match c {
    b'0'..=b'9'=>Some(c-b'0'), b'a'..=b'f'=>Some(c-b'a'+10),
    b'A'..=b'F'=>Some(c-b'A'+10), _=>None,
}}
