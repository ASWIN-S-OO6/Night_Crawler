use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

/// Async TCP connect scan with bounded concurrency and live progress reporting.
/// Returns the list of open TCP ports.
pub async fn scan_tcp(
    ip: IpAddr,
    ports: &[u16],
    concurrency: usize,
    timeout_ms: u64,
    progress: Option<Arc<AtomicU64>>,
) -> Result<Vec<u16>> {
    let total = ports.len() as u64;
    let ip = Arc::new(ip);
    let mut open: Vec<u16> = Vec::new();

    let results = stream::iter(ports.iter().cloned())
        .map(|port| {
            let ip = ip.clone();
            let progress = progress.clone();
            async move {
                let open = probe_port(&ip, port, timeout_ms).await;
                if let Some(p) = &progress {
                    p.fetch_add(1, Ordering::Relaxed);
                }
                (port, open)
            }
        })
        .buffer_unordered(concurrency);

    tokio::pin!(results);
    while let Some((port, is_open)) = results.next().await {
        let _ = total;
        if is_open {
            open.push(port);
        }
    }
    open.sort_unstable();
    Ok(open)
}

async fn probe_port(ip: &IpAddr, port: u16, timeout_ms: u64) -> bool {
    match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect((*ip, port)),
    )
    .await
    {
        Ok(Ok(_)) => true,
        _ => false,
    }
}
