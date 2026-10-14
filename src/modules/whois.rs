use crate::types::WhoisResults;
use anyhow::Result;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;

/// Query a whois server for a given object.
async fn whois_query(server: &str, query: &str) -> Result<String> {
    let addr = if server.contains(':') {
        server.to_string()
    } else {
        format!("{}:43", server)
    };
    let stream = TcpStream::connect(&addr).await?;
    let (mut rx, mut tx) = stream.into_split();
    tx.write_all(format!("{}\r\n", query).as_bytes()).await?;

    // read until the server closes or we hit a cap
    let mut buf: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(remaining, rx.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 256 * 1024 {
                    break;
                }
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn extract_field(raw: &str, keys: &[&str]) -> Option<String> {
    for line in raw.lines() {
        let lower = line.to_ascii_lowercase();
        for key in keys {
            if let Some(rest) = lower.strip_prefix(&format!("{}:", key.to_ascii_lowercase())) {
                let orig = &line[line.len() - rest.trim_start().len()..];
                let v = orig.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn find_referral(raw: &str) -> Option<String> {
    // e.g. "whois:            whois.verisign-grs.com"
    for line in raw.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("whois:") {
            let v = rest.trim();
            if v.contains('.') && !v.contains(' ') && v.len() < 60 {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// WHOIS for a domain, following referrals (up to 3 hops).
pub async fn whois_domain(domain: &str) -> Result<WhoisResults> {
    let mut server = "whois.iana.org".to_string();
    let current = domain.to_string();
    let mut raw = String::new();
    let mut used = String::new();

    for _ in 0..3 {
        let resp = whois_query(&server, &current).await?;
        raw.push_str(&format!("--- via {} ---\n", server));
        raw.push_str(&resp);
        used = server.clone();
        match find_referral(&resp) {
            Some(next) if next != server => {
                server = next;
                continue;
            }
            _ => break,
        }
    }

    let registrar = extract_field(&raw, &["registrar", "sponsoring registrar"]);
    let created = extract_field(&raw, &["creation date", "created", "created-on", "registered on", "registration time"]);
    let expires = extract_field(&raw, &["registry expiry date", "expiration date", "expires", "expiry date"]);
    let org = extract_field(&raw, &["registrant organization", "org", "organization", "org-name"]);
    let abuse_email = extract_field(&raw, &["registrar abuse contact email", "abuse-mailbox", "abuse email"]);

    Ok(WhoisResults {
        server: used,
        registrar,
        created,
        expires,
        org,
        abuse_email,
        raw: raw.trim().to_string(),
    })
}

/// WHOIS for an IP, following IANA -> RIR -> NIR referrals.
pub async fn whois_ip(ip: &str) -> Result<WhoisResults> {
    let mut server = "whois.iana.org".to_string();
    let mut raw = String::new();
    let mut used = server.clone();

    for _ in 0..4 {
        let resp = whois_query(&server, ip).await?;
        raw.push_str(&format!("--- via {} ---\n", server));
        raw.push_str(&resp);
        used = server.clone();
        if let Some(next) = find_referral(&resp) {
            if next != server {
                server = next;
                continue;
            }
        }
        break;
    }

    let org = extract_field(&raw, &["org-name", "orgname", "netname", "owner", "descr"]);
    let created = extract_field(&raw, &["created", "regdate", "registration date"]);
    let abuse_email = extract_field(&raw, &["abuse-mailbox", "abuse mailbox", "orgabuse-email"]);

    Ok(WhoisResults {
        server: used,
        registrar: None,
        created,
        expires: None,
        org,
        abuse_email,
        raw: raw.trim().to_string(),
    })
}

// Helper to silence unused import warnings in some builds
#[allow(dead_code)]
async fn _ping(rx: &mut OwnedReadHalf) {
    let _ = rx;
}
