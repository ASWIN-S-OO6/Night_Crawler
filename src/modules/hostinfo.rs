//! Host identification & enrichment: OS fingerprinting from ICMP TTL,
//! traceroute path, and geo/ASN lookup — the details that fill the
//! "Target / Host" section of the report.

use crate::types::{GeoInfo, TargetInfo, TraceHop};
use anyhow::Result;
use std::time::Duration;

/// Fingerprint the OS from the ICMP TTL (classic nmap-style heuristic).
pub fn os_from_ttl(ttl: u32) -> &'static str {
    match ttl {
        0..=32 => "likely Cisco/OSI switch or embedded (very low TTL)",
        33..=64 => "Linux/Unix (TTL ~64)",
        65..=128 => "Windows (TTL ~128)",
        _ => "Solaris/AIX/older Cisco (TTL ~255)",
    }
}

/// Run traceroute (system binary if present) and parse the hops.
pub async fn traceroute(ip: &str) -> Vec<TraceHop> {
    let out = tokio::process::Command::new("sh")
        .args(["-c", &format!("command -v traceroute >/dev/null 2>&1 && traceroute -n -w 1 -q 1 -m 12 {}", ip)])
        .output()
        .await;
    let stdout = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return Vec::new(),
    };
    let mut hops = Vec::new();
    for line in stdout.lines().skip(1) {
        // " 2  10.0.0.1  1.234 ms"
        let l = line.trim_start();
        let mut it = l.split_whitespace();
        let ttl: u8 = match it.next().unwrap_or("").parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ip_part = it.next().unwrap_or("").to_string();
        if ip_part == "*" || !ip_part.contains('.') {
            continue;
        }
        let rtt: f64 = it
            .next()
            .unwrap_or("")
            .trim_end_matches("ms")
            .parse()
            .unwrap_or(0.0);
        hops.push(TraceHop {
            ttl,
            ip: ip_part.clone(),
            host: String::new(),
            rtt_ms: rtt,
        });
    }
    hops
}

/// Geo/ASN/ISP lookup via the free ip-api.com endpoint.
pub async fn geo_lookup(ip: &str) -> Option<GeoInfo> {
    let url = format!("http://ip-api.com/json/{}?fields=status,country,regionName,city,isp,org,as,query", ip);
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .build()
        .ok()?
        .get(&url)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: serde_json::Value = resp.json().await.ok()?;
    if v.get("status").and_then(|s| s.as_str()) != Some("success") {
        return None;
    }
    let g = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());
    Some(GeoInfo {
        query: g("query").unwrap_or_default(),
        country: g("country"),
        region: g("regionName"),
        city: g("city"),
        isp: g("isp"),
        org: g("org"),
        asn: g("as"),
    })
}

/// Fill the enriched-host fields on TargetInfo (OS, traceroute, geo, ports).
pub async fn enrich_target(target: &mut TargetInfo, open_ports: &[u16], ping_ttl: Option<u32>) -> Result<()> {
    // OS fingerprint from TTL
    if let Some(ttl) = ping_ttl {
        target.ttl_guess_os = Some(os_from_ttl(ttl).to_string());
        target.ttl_value = Some(ttl);
    }
    target.open_ports = open_ports.to_vec();

    if let Some(ip) = target.ip {
        // traceroute path (skip for localhost — meaningless)
        if !ip.is_loopback() {
            target.traceroute = traceroute(&ip.to_string()).await;
        }
        // geo / ASN (skip private ranges — no public data)
        let is_private = match ip {
            std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        };
        if !ip.is_loopback() && !is_private {
            target.geo = geo_lookup(&ip.to_string()).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_os_mapping() {
        assert!(os_from_ttl(64).contains("Linux"));
        assert!(os_from_ttl(128).contains("Windows"));
        assert!(os_from_ttl(255).contains("Solaris"));
    }

    #[test]
    fn geo_json_parsed() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"status":"success","country":"United States","regionName":"NJ",
                "city":"Absecon","isp":"Linode LLC","org":"Akamai","as":"AS63949","query":"45.33.32.156"}"#,
        )
        .unwrap();
        let g = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());
        assert_eq!(g("country").as_deref(), Some("United States"));
        assert!(g("as").unwrap().starts_with("AS"));
    }
}
