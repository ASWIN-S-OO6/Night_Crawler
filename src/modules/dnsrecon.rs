use crate::types::{DnsRecord, DnsResults};
use crate::util::strip_domain;
use anyhow::{anyhow, Context, Result};
use hickory_proto::rr::{RData, RecordType};
use hickory_resolver::TokioAsyncResolver;
use rand::Rng;
use std::net::{IpAddr, SocketAddr, TcpStream as StdTcpStream};
use std::time::Duration;

pub fn make_resolver() -> Result<TokioAsyncResolver> {
    TokioAsyncResolver::tokio_from_system_conf().context("failed to init system DNS resolver")
}

pub fn rdata_to_string(r: &RData) -> String {
    match r {
        RData::A(a) => a.0.to_string(),
        RData::AAAA(aaaa) => aaaa.0.to_string(),
        RData::CNAME(c) => strip_domain(&c.0.to_string()),
        RData::NS(ns) => strip_domain(&ns.0.to_string()),
        RData::MX(mx) => format!("{} {}", mx.preference(), strip_domain(&mx.exchange().to_string())),
        RData::TXT(txt) => txt.to_string().trim_matches('"').to_string(),
        RData::SOA(soa) => format!(
            "{} {} serial:{}",
            strip_domain(&soa.mname().to_string()),
            strip_domain(&soa.rname().to_string()),
            soa.serial()
        ),
        RData::PTR(p) => strip_domain(&p.0.to_string()),
        RData::SRV(s) => format!(
            "{}:{} prio:{} weight:{}",
            strip_domain(&s.target().to_string()),
            s.port(),
            s.priority(),
            s.weight()
        ),
        RData::CAA(caa) => caa.to_string(),
        other => format!("{:?}", other),
    }
}

fn rdata_type_name(data: &RData) -> &'static str {
    match data {
        RData::A(_) => "A",
        RData::AAAA(_) => "AAAA",
        RData::CNAME(_) => "CNAME",
        RData::NS(_) => "NS",
        RData::MX(_) => "MX",
        RData::TXT(_) => "TXT",
        RData::SOA(_) => "SOA",
        RData::PTR(_) => "PTR",
        RData::SRV(_) => "SRV",
        RData::CAA(_) => "CAA",
        _ => "OTHER",
    }
}

/// Query a broad set of record types for a domain.
pub async fn query_records(resolver: &TokioAsyncResolver, domain: &str) -> Vec<DnsRecord> {
    let types = [
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::TXT,
        RecordType::SOA,
        RecordType::SRV,
        RecordType::CAA,
    ];
    let mut out: Vec<DnsRecord> = Vec::new();
    for rt in types {
        if let Ok(lookup) = resolver.lookup(domain.to_string(), rt).await {
            for rec in lookup.records() {
                if let Some(data) = rec.data() {
                    out.push(DnsRecord {
                        rtype: rdata_type_name(data).to_string(),
                        name: strip_domain(&rec.name().to_string()),
                        value: rdata_to_string(data),
                        ttl: Some(rec.ttl() as u64),
                    });
                }
            }
        }
    }
    out
}

pub async fn resolve_a(resolver: &TokioAsyncResolver, host: &str) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    for rt in [RecordType::A, RecordType::AAAA] {
        if let Ok(lookup) = resolver.lookup(host.to_string(), rt).await {
            for rec in lookup.records() {
                if let Some(data) = rec.data() {
                    match data {
                        RData::A(a) => ips.push(IpAddr::V4(a.0)),
                        RData::AAAA(a) => ips.push(IpAddr::V6(a.0)),
                        _ => {}
                    }
                }
            }
        }
    }
    ips
}

pub async fn ptr_lookup(resolver: &TokioAsyncResolver, ip: IpAddr) -> Option<String> {
    let name = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(_) => return None,
    };
    if let Ok(lookup) = resolver.lookup(name, RecordType::PTR).await {
        for rec in lookup.records() {
            if let Some(RData::PTR(p)) = rec.data() {
                return Some(strip_domain(&p.0.to_string()));
            }
        }
    }
    None
}

/// Detect DNS wildcarding: random subdomain resolving => wildcard present.
pub async fn detect_wildcard(resolver: &TokioAsyncResolver, domain: &str) -> Option<String> {
    let probe: String = format!(
        "wildcard-probe-{}",
        rand::thread_rng().gen::<u32>()
    );
    let fqdn = format!("{}.{}", probe, domain);
    let ips = resolve_a(resolver, &fqdn).await;
    if ips.is_empty() {
        None
    } else {
        Some(ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "))
    }
}

// ----------------------------------------------------------------------------
// Raw AXFR over TCP — minimal DNS wire codec
// ----------------------------------------------------------------------------

fn encode_query(id: u16, zone: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x00]); // flags: standard query
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN NS AR
    for label in zone.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // class IN
    q
}

fn tcp_wrap(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 2);
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Result<u8> {
        if self.p >= self.b.len() {
            return Err(anyhow!("dns cursor overrun"));
        }
        let v = self.b[self.p];
        self.p += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(((self.u8()? as u16) << 8) | self.u8()? as u16)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(((self.u16()? as u32) << 16) | self.u16()? as u32)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.p + n > self.b.len() {
            return Err(anyhow!("dns cursor overrun"));
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
}

fn read_name(c: &mut Cursor, depth: u8) -> Result<String> {
    if depth > 12 {
        return Err(anyhow!("name compression loop"));
    }
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    loop {
        let len = c.u8()?;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = (((len & 0x3F) as usize) << 8) | c.u8()? as usize;
            let saved = c.p;
            c.p = ptr;
            let tail = read_name(c, depth + 1)?;
            labels.push(tail);
            c.p = saved;
            jumped = true;
            break;
        }
        labels.push(String::from_utf8_lossy(c.take(len as usize)?).to_string());
    }
    if jumped {
        return Ok(labels.join("."));
    }
    Ok(labels.join("."))
}

fn parse_rdata(c: &mut Cursor, rtype: u16) -> Result<String> {
    match rtype {
        1 => {
            let b = c.take(4)?;
            Ok(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
        }
        28 => {
            let b = c.take(16)?;
            let mut arr = [0u8; 16];
            arr.copy_from_slice(b);
            Ok(std::net::Ipv6Addr::from(arr).to_string())
        }
        2 | 5 | 12 => {
            let n = read_name(c, 0)?;
            Ok(n)
        }
        15 => {
            let pref = c.u16()?;
            let ex = read_name(c, 0)?;
            Ok(format!("{} {}", pref, ex))
        }
        6 => {
            let mname = read_name(c, 0)?;
            let rname = read_name(c, 0)?;
            let serial = c.u32()?;
            Ok(format!("{} {} serial:{}", mname, rname, serial))
        }
        16 => {
            let mut txts: Vec<String> = Vec::new();
            while c.p < c.b.len() {
                let l = c.u8()?;
                if l == 0 {
                    break;
                }
                txts.push(String::from_utf8_lossy(c.take(l as usize)?).to_string());
            }
            Ok(txts.join(" | "))
        }
        33 => {
            let _prio = c.u16()?;
            let _weight = c.u16()?;
            let port = c.u16()?;
            let target = read_name(c, 0)?;
            Ok(format!("{}:{}", target, port))
        }
        _ => {
            // unknown: hex
            let rest = &c.b[c.p.min(c.b.len())..];
            Ok(format!("(rdata {} bytes) {:02x?}", rest.len(), &rest[..rest.len().min(48)]))
        }
    }
}

fn parse_message(buf: &[u8], zone: &str, out: &mut Vec<DnsRecord>, soa_count: &mut usize) -> Result<bool> {
    let mut c = Cursor { b: buf, p: 0 };
    let _id = c.u16()?;
    let _flags = c.u16()?;
    let qd = c.u16()?;
    let an = c.u16()?;
    let _ns = c.u16()?;
    let _ar = c.u16()?;

    if an == 0 {
        return Err(anyhow!("AXFR refused (no answers, rcode in flags = {:04x})", _flags & 0x000F));
    }

    for _ in 0..qd {
        let _ = read_name(&mut c, 0)?;
        let _qtype = c.u16()?;
        let _qclass = c.u16()?;
    }

    for _ in 0..an {
        let name = read_name(&mut c, 0)?;
        let rtype = c.u16()?;
        let _class = c.u16()?;
        let _ttl = c.u32()?;
        let rdlen = c.u16()? as usize;
        let end = c.p + rdlen;
        if end > buf.len() {
            return Err(anyhow!("rdlength overruns message"));
        }
        if rtype == 6 {
            *soa_count += 1;
        }
        // parse rdata strictly within its own bounds
        let mut rcur = Cursor { b: &buf[c.p..end], p: 0 };
        if let Ok(val) = parse_rdata(&mut rcur, rtype) {
            let rname = match rtype {
                2 => "NS",
                1 => "A",
                28 => "AAAA",
                5 => "CNAME",
                12 => "PTR",
                15 => "MX",
                16 => "TXT",
                6 => "SOA",
                33 => "SRV",
                _ => "OTHER",
            };
            out.push(DnsRecord {
                rtype: rname.to_string(),
                name: strip_domain(&if name.is_empty() { zone.to_string() } else { name }),
                value: val,
                ttl: None,
            });
        }
        c.p = end; // resync in case of trailing junk
    }
    Ok(*soa_count >= 2)
}

/// Attempt a full zone transfer against a nameserver.
pub fn try_axfr(ns_ip: IpAddr, port: u16, zone: &str) -> std::io::Result<Vec<DnsRecord>> {
    let addr = SocketAddr::new(ns_ip, port);
    let mut stream = StdTcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let _ = stream.set_nodelay(true);

    let id: u16 = rand::thread_rng().gen();
    let q = tcp_wrap(&encode_query(id, zone, 252));
    stream.write_all(&q)?;

    let mut records: Vec<DnsRecord> = Vec::new();
    let mut soa_count = 0usize;
    let mut msg_count = 0;
    loop {
        let mut lenbuf = [0u8; 2];
        read_exact_timeout(&mut stream, &mut lenbuf)?;
        let len = u16::from_be_bytes(lenbuf) as usize;
        if len == 0 || len > 65535 {
            break;
        }
        let mut msg = vec![0u8; len];
        read_exact_timeout(&mut stream, &mut msg)?;
        msg_count += 1;
        match parse_message(&msg, zone, &mut records, &mut soa_count) {
            Ok(finished) => {
                if finished {
                    break;
                }
            }
            Err(_) => break,
        }
        if msg_count > 200 || records.len() > 20000 {
            break;
        }
    }
    Ok(records)
}

fn read_exact_timeout(stream: &mut StdTcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    let mut read = 0;
    while read < buf.len() {
        let n = stream.read(&mut buf[read..])?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
        }
        read += n;
    }
    Ok(())
}

use std::io::Write;

/// Run DNS recon for a domain: standard records + AXFR attempts against each NS.
pub async fn dns_recon(resolver: &TokioAsyncResolver, domain: &str) -> Result<DnsResults> {
    let records = query_records(resolver, domain).await;

    // NS servers -> AXFR
    let mut axfr_servers: Vec<String> = Vec::new();
    let mut axfr_records: Vec<DnsRecord> = Vec::new();
    let mut axfr_note = String::new();
    let ns_names: Vec<String> = records
        .iter()
        .filter(|r| r.rtype == "NS")
        .map(|r| r.value.clone())
        .collect();

    for ns in &ns_names {
        let ips = resolve_a(resolver, ns).await;
        for ip in ips {
            match try_axfr(ip, 53, domain) {
                Ok(recs) if !recs.is_empty() => {
                    axfr_servers.push(format!("{} ({})", ns, ip));
                    axfr_records.extend(recs);
                }
                Ok(_) => {}
                Err(e) => {
                    axfr_note.push_str(&format!("{}: {}; ", ns, e));
                }
            }
        }
    }

    let axfr_success = !axfr_records.is_empty();
    let wildcard = detect_wildcard(resolver, domain).await;
    let axfr_note = if axfr_success {
        format!("Zone transfer SUCCEEDED — {} records leaked", axfr_records.len())
    } else {
        axfr_note
    };

    Ok(DnsResults {
        records,
        axfr_servers,
        axfr_records,
        axfr_success,
        axfr_note,
        wildcard,
        resolver_note: "hickory system resolver".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_axfr_message() {
        let msg = include_bytes!("../../tests/axfr_fixture.bin");
        let mut records: Vec<DnsRecord> = Vec::new();
        let mut soa_count = 0;
        let finished = parse_message(msg, "example.com", &mut records, &mut soa_count).unwrap();
        println!("records: {} soa_count: {} finished: {}", records.len(), soa_count, finished);
        for r in &records {
            println!("  {} {} -> {}", r.rtype, r.name, r.value);
        }
        assert_eq!(soa_count, 2);
        assert!(finished);
        assert!(records.iter().any(|r| r.rtype == "A" && r.value == "192.0.2.10"));
        assert!(records.iter().any(|r| r.rtype == "TXT" && r.value.contains("v=spf1")));
        assert!(records.iter().any(|r| r.rtype == "MX" && r.value.contains("mail.example.com")));
    }
}
