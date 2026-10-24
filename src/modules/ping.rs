use anyhow::Result;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;

/// TTL from the last system ICMP ping (used for OS fingerprinting).
pub static LAST_TTL: AtomicU32 = AtomicU32::new(0);

pub fn last_ttl() -> Option<u32> {
    let v = LAST_TTL.load(Ordering::Relaxed);
    if v > 0 { Some(v) } else { None }
}

/// Liveness probe: system ICMP ping first, fallback to TCP connect ping.
/// Returns (alive, rtt_ms, method).
pub async fn check_alive(target: &str, tcp_ports: &[u16]) -> Result<(bool, Option<f64>, String)> {
    // NOTE: TTL is captured separately via `ping_ttl` for OS fingerprinting.
    // 1. Try system ping (ICMP) — most accurate when available.
    if let Some((ok, rtt)) = icmp_ping(target).await {
        return Ok((ok, rtt, "icmp".into()));
    }
    // 2. TCP ping fallback
    for port in tcp_ports {
        if let Ok(_s) = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect((target, *port))).await {
            return Ok((true, None, format!("tcp:{}", port)));
        }
    }
    Ok((false, None, "none".into()))
}

async fn icmp_ping(target: &str) -> Option<(bool, Option<f64>)> {
    let bin = if cfg!(target_os = "windows") {
        "ping"
    } else {
        "ping"
    };
    let out = tokio::process::Command::new(bin)
        .args(if cfg!(target_os = "windows") {
            vec!["-n", "1", "-w", "2000", target]
        } else {
            vec!["-c", "1", "-W", "2", target]
        })
        .output()
        .await
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let success = out.status.success()
        || stdout.contains("1 received")
        || stdout.contains("1 packets received")
        || stdout.contains("bytes from");
    let rtt = extract_rtt(&stdout);
    LAST_TTL.store(extract_ttl(&stdout), Ordering::Relaxed);
    Some((success, rtt))
}

fn extract_ttl(out: &str) -> u32 {
    // e.g. "ttl=51" / "ttl 128"
    let re = regex::Regex::new(r"ttl[=\s]+(\d+)").ok();
    re.and_then(|r| r.captures(out))
        .and_then(|c| c[1].parse().ok())
        .unwrap_or(0)
}

fn extract_rtt(out: &str) -> Option<f64> {
    // linux: time=23.4 ms   windows: time<1ms / time=1ms
    let re = regex::Regex::new(r"time[=<]\s*([\d.]+)\s*ms").ok()?;
    re.captures(out)
        .and_then(|c| c[1].parse::<f64>().ok())
}
