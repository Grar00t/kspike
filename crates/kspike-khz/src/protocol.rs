//! Streaming loader for the raw KHZ_Q protocol archive.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// One parsed protocol revision from the archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolRecord {
    pub protocol: Option<String>,
    pub raw: serde_json::Value,
}

/// Lazy iterator over the archive.
pub struct ProtocolStream {
    reader: std::io::BufReader<std::fs::File>,
}

impl ProtocolStream {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let f = std::fs::File::open(path)?;
        Ok(Self { reader: std::io::BufReader::new(f) })
    }
}

impl Iterator for ProtocolStream {
    type Item = anyhow::Result<ProtocolRecord>;
    fn next(&mut self) -> Option<Self::Item> {
        use std::io::BufRead;
        let mut line = String::new();
        loop {
            line.clear();
            match self.reader.read_line(&mut line) {
                Ok(0) => return None,
                Ok(_) => {
                    let t = line.trim();
                    if t.is_empty() { continue; }
                    let raw: serde_json::Value = match serde_json::from_str(t) {
                        Ok(v) => v,
                        Err(e) => return Some(Err(e.into())),
                    };
                    let protocol = raw.get("PROTOCOL").and_then(|v| v.as_str()).map(String::from);
                    return Some(Ok(ProtocolRecord { protocol, raw }));
                }
                Err(e) => return Some(Err(e.into())),
            }
        }
    }
}
