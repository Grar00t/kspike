//! kspike-tui — interactive REPL. Minimal on purpose (no extra deps).
//!
//! Grammar:
//!
//!   help                            — show commands
//!   status                          — engine stats
//!   modules                         — list registered modules
//!   tail <N>                        — last N ledger records
//!   plant <placement> <hex-needle>  — register a canary
//!   ingest <JSON>                   — ingest a Signal (inline JSON)
//!   shutdown                        — stop the daemon
//!   quit | exit                     — leave the TUI

use anyhow::Result;
use clap::Parser;
use kspike_daemon::wire::{Request, Response};
use kspike_daemon::Client;
use std::io::Write;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Parser)]
#[command(name = "kspike-tui", version, about = "KSpike interactive console")]
struct Cli {
    #[arg(long, default_value = "/run/kspike.sock")]
    socket: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!();
    println!("  ╦╔═╔═╗┌─┐┬┬┌─┌─┐    kspike> interactive console");
    println!("  ╠╩╗╚═╗├─┘│├┴┐├┤     connected to {}", cli.socket.display());
    println!("  ╩ ╩╚═╝┴  ┴┴ ┴└─┘    type 'help' for commands\n");

    let mut client = match Client::connect(&cli.socket).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ cannot reach kspiked ({e})");
            eprintln!("  try:  cargo run --release -p kspike-daemon -- --socket {}", cli.socket.display());
            return Ok(());
        }
    };

    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    loop {
        print!("kspike> ");
        std::io::stdout().flush().ok();
        let Ok(Some(line)) = lines.next_line().await else { break; };
        let line = line.trim();
        if line.is_empty() { continue; }

        let (cmd, rest) = split_once_ws(line);
        match cmd {
            "quit" | "exit" | "q" => break,
            "help" | "?"          => print_help(),

            "status" => {
                let r = client.call(Request::Status).await?;
                print_response(&r);
            }
            "modules" => {
                let r = client.call(Request::ListModules).await?;
                if let Some(err) = &r.error { println!("✗ {err}"); }
                else { for m in &r.modules { println!("  • {m}"); } }
            }
            "tail" => {
                let n: usize = rest.trim().parse().unwrap_or(10);
                let r = client.call(Request::LedgerTail { n }).await?;
                if let Some(err) = &r.error { println!("✗ {err}"); }
                else {
                    for rec in &r.ledger {
                        let seq = rec.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
                        let cat = rec.get("category").and_then(|v| v.as_str()).unwrap_or("?");
                        let ts  = rec.get("ts").and_then(|v| v.as_str()).unwrap_or("?");
                        println!("  seq={seq:4} {cat:10} {ts}");
                    }
                }
            }
            "plant" => {
                let (placement, needle) = split_once_ws(rest);
                if placement.is_empty() || needle.is_empty() {
                    println!("usage: plant <placement> <hex-needle>"); continue;
                }
                let r = client.call(Request::PlantCanary {
                    placement: placement.into(),
                    needle_hex: needle.into(),
                }).await?;
                if let Some(id) = r.canary_id { println!("✓ canary {id}"); }
                else if let Some(e) = r.error { println!("✗ {e}"); }
            }
            "ingest" => {
                let sig: kspike_core::Signal = match serde_json::from_str(rest) {
                    Ok(v) => v, Err(e) => { println!("✗ bad JSON: {e}"); continue; }
                };
                let r = client.call(Request::Ingest { signal: sig }).await?;
                println!("{}", serde_json::to_string_pretty(&r)?);
            }
            "shutdown" => {
                let _ = client.call(Request::Shutdown).await?;
                println!("✓ shutdown requested"); break;
            }
            _ => println!("? unknown command: '{cmd}' — try 'help'"),
        }
    }
    Ok(())
}

fn split_once_ws(s: &str) -> (&str, &str) {
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], s[i..].trim_start()),
        None => (s, ""),
    }
}

fn print_help() {
    println!(r#"
  kspike> commands:

    status                          engine stats (signals/defenses/strikes/…)
    modules                         list registered modules
    tail <N>                        last N ledger records
    plant <placement> <hex-needle>  register a canary token
    ingest <JSON>                   ingest an ad-hoc Signal
    shutdown                        stop kspiked
    help | ?                        this screen
    quit | exit | q                 leave the TUI
"#);
}

fn print_response(r: &Response) {
    if let Some(e) = &r.error { println!("✗ {e}"); return; }
    if let Some(s) = &r.stats {
        println!("  signals   : {}", s.signals);
        println!("  defenses  : {}", s.defenses);
        println!("  strikes   : {}", s.strikes);
        println!("  denials   : {}", s.denials);
        println!("  reports   : {}", s.reports);
    } else {
        println!("  ok");
    }
}
