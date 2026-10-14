use crate::types::NbnsResults;
use anyhow::{anyhow, Result};
use rand::Rng;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

/// First-level NetBIOS name encoding (RFC 1001): each nibble -> 'A'+nibble.
fn encode_nbns_name(name: &str) -> Vec<u8> {
    let mut nb = [0u8; 16];
    let bytes = name.as_bytes();
    nb[0] = b'*';
    // "*" + 15 nulls for node status
    let mut out = vec![32u8]; // length byte: 32 encoded bytes follow
    for &b in nb.iter() {
        out.push(0x41 + (b >> 4));
        out.push(0x41 + (b & 0x0f));
    }
    out.push(0x00); // scope
    let _ = bytes;
    out
}

fn suffix_to_service(suffix: u8) -> &'static str {
    match suffix {
        0x00 => "Workstation Service",
        0x01 => "Messenger Service",
        0x03 => "Messenger / Client Service",
        0x06 => "RAS Server Service",
        0x1C => "Domain Controllers",
        0x1B => "Domain Master Browser (likely PDC)",
        0x1D => "Master Browser",
        0x1E => "Browser Service Elections",
        0x20 => "File Server (SMB)",
        0x21 => "RAS Client Service",
        0xBE => "Network Monitor Agent",
        0xBF => "Network Monitor Application",
        _ => "Unknown service",
    }
}

fn build_nbstat_query() -> Vec<u8> {
    let id: u16 = rand::thread_rng().gen();
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x00]); // flags: recursion not needed
    q.extend_from_slice(&[0x00, 0x01]); // QD
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    q.extend_from_slice(&encode_nbns_name("*"));
    q.extend_from_slice(&0x21u16.to_be_bytes()); // NBSTAT
    q.extend_from_slice(&0x01u16.to_be_bytes()); // IN
    q
}

fn skip_encoded_name(buf: &[u8], mut p: usize) -> Result<usize> {
    if p >= buf.len() {
        return Err(anyhow!("nbns overrun"));
    }
    if buf[p] == 0xc0 {
        return Ok(p + 2);
    }
    let len = buf[p] as usize;
    p += 1 + len;
    // scope labels
    while p < buf.len() {
        let l = buf[p] as usize;
        p += 1;
        if l == 0 {
            break;
        }
        p += l;
    }
    Ok(p)
}

fn parse_nbstat(buf: &[u8]) -> Result<NbnsResults> {
    if buf.len() < 12 {
        return Err(anyhow!("short nbns response"));
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        return Err(anyhow!("not a response"));
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(anyhow!("nbns rcode {}", rcode));
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut p = 12usize;
    for _ in 0..qd {
        p = skip_encoded_name(buf, p)?;
        p += 4; // type + class
    }
    if an == 0 {
        return Err(anyhow!("no answers"));
    }
    for _ in 0..an {
        p = skip_encoded_name(buf, p)?;
        p += 2; // type (0x21)
        p += 2; // class
        p += 4; // ttl
        if p + 2 > buf.len() {
            return Err(anyhow!("nbns overrun"));
        }
        let rdlen = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
        p += 2;
        let rdata = &buf[p..(p + rdlen).min(buf.len())];
        // NBSTAT: [num_names][name(16) flags(2)]* mac(6) stats(18+)
        if rdata.is_empty() {
            return Err(anyhow!("empty nbstat rdata"));
        }
        let num = rdata[0] as usize;
        let mut names: Vec<(String, String)> = Vec::new();
        let mut group: Vec<String> = Vec::new();
        let mut off = 1usize;
        for _ in 0..num {
            if off + 18 > rdata.len() {
                break;
            }
            let name_bytes = &rdata[off..off + 16];
            let nb_flags = u16::from_be_bytes([rdata[off + 16], rdata[off + 17]]);
            off += 18;
            let name: String = String::from_utf8_lossy(&name_bytes[..15])
                .trim_end()
                .to_string();
            let suffix = name_bytes[15];
            let svc = suffix_to_service(suffix);
            let tag = if nb_flags & 0x8000 != 0 {
                "UNIQUE"
            } else {
                "GROUP"
            };
            let entry = (name.clone(), format!("{} {} [0x{:02X}]", svc, tag, suffix));
            if nb_flags & 0x8000 == 0 {
                group.push(name);
            }
            names.push(entry);
        }
        let mac = if off + 6 <= rdata.len() {
            format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                rdata[off], rdata[off + 1], rdata[off + 2], rdata[off + 3], rdata[off + 4], rdata[off + 5]
            )
        } else {
            "unknown".into()
        };
        return Ok(NbnsResults { names, mac_address: mac, group });
    }
    Err(anyhow!("no answer parsed"))
}

/// Query NBSTAT (node status) on UDP/137 (or custom port). Err when unreachable.
pub async fn nbns_query(ip: IpAddr, port: u16) -> Result<NbnsResults> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let target = SocketAddr::new(ip, port);
    let q = build_nbstat_query();
    for _ in 0..2 {
        sock.send_to(&q, target).await?;
        let mut buf = vec![0u8; 2048];
        match tokio::time::timeout(Duration::from_millis(2000), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                if let Ok(res) = parse_nbstat(&buf[..n]) {
                    return Ok(res);
                }
            }
            _ => continue,
        }
    }
    Err(anyhow!("no nbns response from {}:{}", ip, port))
}
