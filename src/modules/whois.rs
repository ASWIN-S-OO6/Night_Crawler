use crate::types::WhoisResults;
use anyhow::Result;
use serde::{Deserialize, Serialize};
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

/// WHOIS for a domain, trying RDAP first then legacy WHOIS with referrals.
pub async fn whois_domain(domain: &str) -> Result<WhoisResults> {
    let client = reqwest::Client::builder()
        .user_agent("NightCrawler/0.1 (recon agent)")
        .timeout(Duration::from_secs(15))
        .build()?;

    // Try RDAP first (modern, structured, faster)
    if let Ok(rdap_result) = rdap_domain(&client, domain).await {
        return Ok(rdap_result);
    }

    // Fallback to legacy WHOIS with referrals
    legacy_whois_domain(domain).await
}

/// Legacy WHOIS for a domain, following referrals (up to 3 hops).
async fn legacy_whois_domain(domain: &str) -> Result<WhoisResults> {
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
    let registrant_name = extract_field(&raw, &["registrant name", "registrant"]);
    let registrant_email = extract_field(&raw, &["registrant email", "registrant email address"]);

    // Extract nameservers from raw WHOIS
    let mut name_servers = Vec::new();
    for line in raw.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("name server:") || lower.starts_with("nserver:") {
            if let Some(ns) = line.split(':').nth(1) {
                let ns = ns.trim().trim_end_matches('.');
                if !ns.is_empty() && ns.contains('.') {
                    name_servers.push(ns.to_string());
                }
            }
        }
    }
    name_servers.dedup();

    Ok(WhoisResults {
        server: used,
        registrar,
        created,
        expires,
        org,
        abuse_email,
        raw: raw.trim().to_string(),
        registrant_name,
        registrant_email,
        name_servers,
        dnssec: None,
    })
}

/// WHOIS for an IP, trying RDAP first then legacy WHOIS with IANA -> RIR -> NIR referrals.
pub async fn whois_ip(ip: &str) -> Result<WhoisResults> {
    let client = reqwest::Client::builder()
        .user_agent("NightCrawler/0.1 (recon agent)")
        .timeout(Duration::from_secs(15))
        .build()?;

    // Try RDAP first
    if let Ok(rdap_result) = rdap_ip(&client, ip).await {
        return Ok(rdap_result);
    }

    // Fallback to legacy WHOIS
    legacy_whois_ip(ip).await
}

/// Legacy WHOIS for an IP, following IANA -> RIR -> NIR referrals.
async fn legacy_whois_ip(ip: &str) -> Result<WhoisResults> {
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
        registrant_name: None,
        registrant_email: None,
        name_servers: Vec::new(),
        dnssec: None,
    })
}

// Helper to silence unused import warnings in some builds
#[allow(dead_code)]
async fn _ping(rx: &mut OwnedReadHalf) {
    let _ = rx;
}

/// RDAP (Registration Data Access Protocol) response structures
#[derive(Debug, Deserialize, Serialize)]
struct RdapResponse {
    objectClassName: Option<String>,
    handle: Option<String>,
    ldhName: Option<String>,
    unicodeName: Option<String>,
    nameservers: Option<Vec<RdapNameserver>>,
    secureDNS: Option<RdapSecureDns>,
    entities: Option<Vec<RdapEntity>>,
    status: Option<Vec<String>>,
    remarks: Option<Vec<RdapRemark>>,
    links: Option<Vec<RdapLink>>,
    events: Option<Vec<RdapEvent>>,
    network: Option<RdapNetwork>,
    startAddress: Option<String>,
    endAddress: Option<String>,
    ipVersion: Option<String>,
    cidr0Cidrs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RdapNameserver {
    ldhName: Option<String>,
    unicodeName: Option<String>,
    ipAddresses: Option<RdapIpAddresses>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RdapIpAddresses {
    v4: Option<Vec<String>>,
    v6: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RdapSecureDns {
    zoneSigned: Option<bool>,
    delegationSigned: Option<bool>,
    maxSigLife: Option<i64>,
    dsData: Option<Vec<RdapDsData>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RdapDsData {
    keyTag: Option<i64>,
    algorithm: Option<i64>,
    digest: Option<String>,
    digestType: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RdapEntity {
    objectClassName: Option<String>,
    handle: Option<String>,
    vcardArray: Option<Vec<serde_json::Value>>,
    roles: Option<Vec<String>>,
    remarks: Option<Vec<RdapRemark>>,
    links: Option<Vec<RdapLink>>,
    events: Option<Vec<RdapEvent>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RdapRemark {
    description: Option<Vec<String>>,
    title: Option<String>,
    type_: Option<String>,
    #[serde(rename = "type")]
    type_field: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RdapLink {
    value: Option<String>,
    rel: Option<String>,
    href: Option<String>,
    type_: Option<String>,
    #[serde(rename = "type")]
    type_field: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RdapEvent {
    eventAction: Option<String>,
    eventDate: Option<String>,
    eventActor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RdapNetwork {
    objectClassName: Option<String>,
    handle: Option<String>,
    startAddress: Option<String>,
    endAddress: Option<String>,
    ipVersion: Option<String>,
    name: Option<String>,
    parentHandle: Option<String>,
    cidr0Cidrs: Option<Vec<String>>,
    status: Option<Vec<String>>,
    entities: Option<Vec<RdapEntity>>,
    remarks: Option<Vec<RdapRemark>>,
    links: Option<Vec<RdapLink>>,
    events: Option<Vec<RdapEvent>>,
}

/// Query RDAP for a domain (modern replacement for WHOIS)
async fn rdap_domain(client: &reqwest::Client, domain: &str) -> Result<WhoisResults> {
    let url = format!("https://rdap.org/domain/{}", domain);
    let resp = client.get(&url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!("RDAP HTTP {}", status));
    }
    let rdap: RdapResponse = resp.json().await?;

    let mut registrar = None;
    let mut created = None;
    let mut expires = None;
    let mut org = None;
    let mut registrant_name = None;
    let mut registrant_email = None;
    let mut name_servers = Vec::new();
    let mut dnssec = None;

    // Extract registrar from entities with role "registrar"
    if let Some(entities) = &rdap.entities {
        for entity in entities {
            if entity.roles.as_ref().map(|r| r.contains(&"registrar".to_string())).unwrap_or(false) {
                if let Some(vcard) = &entity.vcardArray {
                    if vcard.len() > 1 {
                        if let Some(arr) = vcard[1].as_array() {
                            for item in arr {
                                if let Some(field) = item.as_array() {
                                    if field.len() >= 4 {
                                        if field[0].as_str() == Some("fn") {
                                            registrar = Some(field[3].as_str().unwrap_or("").to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Extract creation/expiration from events
    if let Some(events) = &rdap.events {
        for event in events {
            match event.eventAction.as_deref() {
                Some("registration") => created = event.eventDate.clone(),
                Some("expiration") => expires = event.eventDate.clone(),
                _ => {}
            }
        }
    }

    // Extract nameservers
    if let Some(ns) = &rdap.nameservers {
        for n in ns {
            if let Some(name) = n.ldhName.as_deref().or(n.unicodeName.as_deref()) {
                name_servers.push(name.to_string());
            }
        }
    }

    // Extract DNSSEC status
    if let Some(dns) = &rdap.secureDNS {
        dnssec = Some(format!("zone_signed: {}, delegation_signed: {}", 
            dns.zoneSigned.unwrap_or(false), 
            dns.delegationSigned.unwrap_or(false)));
    }

    // Extract registrant info from entities with role "registrant"
    if let Some(entities) = &rdap.entities {
        for entity in entities {
            if entity.roles.as_ref().map(|r| r.contains(&"registrant".to_string())).unwrap_or(false) {
                if let Some(vcard) = &entity.vcardArray {
                    if vcard.len() > 1 {
                        if let Some(arr) = vcard[1].as_array() {
                            for item in arr {
                                if let Some(field) = item.as_array() {
                                    if field.len() >= 4 {
                                        match field[0].as_str() {
                                            Some("fn") => registrant_name = Some(field[3].as_str().unwrap_or("").to_string()),
                                            Some("email") => registrant_email = Some(field[3].as_str().unwrap_or("").to_string()),
                                            Some("org") => org = Some(field[3].as_str().unwrap_or("").to_string()),
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let raw = serde_json::to_string_pretty(&rdap).unwrap_or_default();

    Ok(WhoisResults {
        server: "rdap.org".to_string(),
        registrar,
        created,
        expires,
        org,
        abuse_email: None,
        raw,
        registrant_name,
        registrant_email,
        name_servers,
        dnssec,
    })
}

/// Query RDAP for an IP address
async fn rdap_ip(client: &reqwest::Client, ip: &str) -> Result<WhoisResults> {
    let url = format!("https://rdap.org/ip/{}", ip);
    let resp = client.get(&url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!("RDAP HTTP {}", status));
    }
    let rdap: RdapResponse = resp.json().await?;

    let mut org = None;
    let mut created = None;
    let mut abuse_email = None;
    let mut name_servers = Vec::new();

    if let Some(events) = &rdap.events {
        for event in events {
            if event.eventAction.as_deref() == Some("registration") {
                created = event.eventDate.clone();
            }
        }
    }

    if let Some(entities) = &rdap.entities {
        for entity in entities {
            if entity.roles.as_ref().map(|r| r.contains(&"registrant".to_string())).unwrap_or(false)
                || entity.roles.as_ref().map(|r| r.contains(&"abuse".to_string())).unwrap_or(false) {
                if let Some(vcard) = &entity.vcardArray {
                    if vcard.len() > 1 {
                        if let Some(arr) = vcard[1].as_array() {
                            for item in arr {
                                if let Some(field) = item.as_array() {
                                    if field.len() >= 4 {
                                        match field[0].as_str() {
                                            Some("fn") => org = Some(field[3].as_str().unwrap_or("").to_string()),
                                            Some("email") => abuse_email = Some(field[3].as_str().unwrap_or("").to_string()),
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(network) = &rdap.network {
        if let Some(events) = &network.events {
            for event in events {
                if event.eventAction.as_deref() == Some("registration") && created.is_none() {
                    created = event.eventDate.clone();
                }
            }
        }
        if let Some(entities) = &network.entities {
            for entity in entities {
                if entity.roles.as_ref().map(|r| r.contains(&"abuse".to_string())).unwrap_or(false) {
                    if let Some(vcard) = &entity.vcardArray {
                        if vcard.len() > 1 {
                            if let Some(arr) = vcard[1].as_array() {
                                for item in arr {
                                    if let Some(field) = item.as_array() {
                                        if field.len() >= 4 && field[0].as_str() == Some("email") {
                                            abuse_email = Some(field[3].as_str().unwrap_or("").to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let raw = serde_json::to_string_pretty(&rdap).unwrap_or_default();

    Ok(WhoisResults {
        server: "rdap.org".to_string(),
        registrar: None,
        created,
        expires: None,
        org,
        abuse_email,
        raw,
        registrant_name: None,
        registrant_email: None,
        name_servers,
        dnssec: None,
    })
}
