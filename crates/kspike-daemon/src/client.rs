//! Thin synchronous-friendly client for kspiked.

use crate::wire::{Request, Response};
use anyhow::{Context, Result};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub struct Client {
    stream: UnixStream,
}

impl Client {
    pub async fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path).await
            .with_context(|| format!("connect {}", path.display()))?;
        Ok(Self { stream })
    }

    pub async fn call(&mut self, req: Request) -> Result<Response> {
        let (rd, mut wr) = (&mut self.stream).split();
        let mut line = serde_json::to_string(&req)?;
        line.push('\n');
        wr.write_all(line.as_bytes()).await?;

        let mut reader = BufReader::new(rd);
        let mut buf = String::new();
        reader.read_line(&mut buf).await?;
        let resp: Response = serde_json::from_str(buf.trim())?;
        Ok(resp)
    }
}
