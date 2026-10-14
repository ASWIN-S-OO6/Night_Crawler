use crate::types::SnmpResults;
use anyhow::{anyhow, Result};
use rand::Rng;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

pub const DEFAULT_COMMUNITIES: &str = include_str!("../assets/snmp_communities.txt");

// ---------------------------------------------------------------------------
// BER primitives
// ---------------------------------------------------------------------------

fn ber_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes: Vec<u8> = Vec::new();
        let mut l = len;
        while l > 0 {
            bytes.push((l & 0xff) as u8);
            l >>= 8;
        }
        bytes.reverse();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend_from_slice(&bytes);
        out
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&ber_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn ber_int(v: i64) -> Vec<u8> {
    if v == 0 {
        return tlv(0x02, &[0]);
    }
    let mut content: Vec<u8> = Vec::new();
    let mut n = v;
    for i in 0..8 {
        content.push(((n >> (8 * (7 - i))) & 0xff) as u8);
    }
    // trim leading zeros
    let mut start = 0;
    while start < 7 && content[start] == 0 && content[start + 1] & 0x80 == 0 {
        start += 1;
    }
    // for negative: trim leading 0xff
    if v < 0 {
        while start < 7 && content[start] == 0xff && content[start + 1] & 0x80 != 0 {
            start += 1;
        }
    }
    tlv(0x02, &content[start..])
}

fn ber_oid(oid: &[u32]) -> Vec<u8> {
    let mut content: Vec<u8> = Vec::new();
    if oid.len() >= 2 {
        content.push((oid[0] * 40 + oid[1]) as u8);
    } else if oid.len() == 1 {
        content.push((oid[0] * 40) as u8);
    }
    for &v in oid.iter().skip(2) {
        let mut tmp: Vec<u8> = vec![(v & 0x7f) as u8];
        let mut n = v >> 7;
        while n > 0 {
            tmp.push(((n & 0x7f) | 0x80) as u8);
            n >>= 7;
        }
        tmp.reverse();
        content.extend_from_slice(&tmp);
    }
    tlv(0x06, &content)
}

fn ber_str(s: &str) -> Vec<u8> {
    tlv(0x04, s.as_bytes())
}

// --- decoding ---

struct Ber<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Ber<'a> {
    fn new(b: &'a [u8]) -> Self {
        Ber { b, p: 0 }
    }
    fn u8(&mut self) -> Result<u8> {
        if self.p >= self.b.len() {
            return Err(anyhow!("BER overrun"));
        }
        let v = self.b[self.p];
        self.p += 1;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.p + n > self.b.len() {
            return Err(anyhow!("BER overrun"));
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = self.u8()?;
        let l0 = self.u8()?;
        let len = if l0 & 0x80 == 0 {
            l0 as usize
        } else {
            let n = (l0 & 0x7f) as usize;
            if n > 4 {
                return Err(anyhow!("BER length too large"));
            }
            let mut len: usize = 0;
            for _ in 0..n {
                len = (len << 8) | self.u8()? as usize;
            }
            len
        };
        let content = self.take(len)?;
        Ok((tag, content))
    }
}

fn oid_to_string(oid: &[u32]) -> String {
    oid.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(".")
}

fn decode_oid(mut b: &[u8]) -> Result<Vec<u32>> {
    if b.is_empty() {
        return Err(anyhow!("empty oid"));
    }
    let first = b[0];
    b = &b[1..];
    let mut out = vec![(first / 40) as u32, (first % 40) as u32];
    let mut val: u32 = 0;
    for &byte in b {
        val = (val << 7) | ((byte & 0x7f) as u32);
        if byte & 0x80 == 0 {
            out.push(val);
            val = 0;
        }
    }
    Ok(out)
}

fn decode_value(tag: u8, content: &[u8]) -> String {
    match tag {
        0x02 => {
            // INTEGER
            let mut v: i64 = if !content.is_empty() && content[0] & 0x80 != 0 {
                -1
            } else {
                0
            };
            for &b in content {
                v = (v << 8) | b as i64;
            }
            v.to_string()
        }
        0x04 | 0x44 => {
            let s = String::from_utf8_lossy(content);
            let printable = content
                .iter()
                .filter(|&&c| c == 9 || c == 10 || c == 13 || (32..=126).contains(&c))
                .count();
            if content.is_empty() || printable * 4 >= content.len() * 3 {
                s.trim().to_string()
            } else {
                format!("hex:{}", hex_preview(content))
            }
        }
        0x05 => "NULL".into(),
        0x06 => decode_oid(content).map(|o| oid_to_string(&o)).unwrap_or_default(),
        0x40 => {
            if content.len() == 4 {
                format!("{}.{}.{}.{}", content[0], content[1], content[2], content[3])
            } else {
                hex_preview(content)
            }
        }
        0x41 => read_unsigned(content, "Counter32"),
        0x42 => read_unsigned(content, "Gauge32"),
        0x43 => format!("{} ticks", read_unsigned(content, "")),
        0x46 => read_unsigned(content, "Counter64"),
        0x30 => "(sequence)".into(),
        other => format!("tag-{:02x}:{}", other, hex_preview(content)),
    }
}

fn read_unsigned(content: &[u8], label: &str) -> String {
    let mut v: u64 = 0;
    for &b in content {
        v = (v << 8) | b as u64;
    }
    if label.is_empty() {
        v.to_string()
    } else {
        format!("{}={}", label, v)
    }
}

fn hex_preview(b: &[u8]) -> String {
    b.iter().take(32).map(|x| format!("{:02x}", x)).collect::<String>()
}

// ---------------------------------------------------------------------------
// SNMP messages
// ---------------------------------------------------------------------------

fn build_msg(version: i64, community: &str, pdu_tag: u8, reqid: u32, varbinds: &[(Vec<u32>, &[u8])], bulk: Option<(i64, i64)>) -> Vec<u8> {
    // varbinds: (oid, encoded value TLV bytes)
    let mut vb_list = Vec::new();
    for (oid, val) in varbinds {
        let vb = tlv(0x30, &[ber_oid(oid), val.to_vec()].concat());
        vb_list.extend_from_slice(&vb);
    }
    let vb_list = tlv(0x30, &vb_list);

    let mut pdu_content = ber_int(reqid as i64);
    match bulk {
        Some((non_rep, max_rep)) => {
            pdu_content.extend_from_slice(&ber_int(non_rep));
            pdu_content.extend_from_slice(&ber_int(max_rep));
        }
        None => {
            pdu_content.extend_from_slice(&ber_int(0));
            pdu_content.extend_from_slice(&ber_int(0));
        }
    }
    pdu_content.extend_from_slice(&vb_list);
    let pdu = tlv(pdu_tag, &pdu_content);

    let msg_content = [
        ber_int(version),
        ber_str(community),
        pdu,
    ].concat();
    tlv(0x30, &msg_content)
}

pub struct SnmpVarBind {
    pub oid: Vec<u32>,
    pub value: String,
}

pub struct SnmpResponse {
    pub error_status: i64,
    pub varbinds: Vec<SnmpVarBind>,
}

fn parse_response(buf: &[u8]) -> Result<SnmpResponse> {
    let mut top = Ber::new(buf);
    let (tag, content) = top.tlv()?;
    if tag != 0x30 {
        return Err(anyhow!("not a sequence: {:#x}", tag));
    }
    let mut outer = Ber::new(content);
    let (_t, _ver) = outer.tlv()?;
    let (_t, _comm) = outer.tlv()?;
    let (pdu_tag, pdu_content) = outer.tlv()?;
    if pdu_tag != 0xa2 {
        return Err(anyhow!("not a GetResponse: {:#x}", pdu_tag));
    }
    let mut pdu = Ber::new(pdu_content);
    let (_t, _reqid) = pdu.tlv()?;
    let (_t, err_c) = pdu.tlv()?;
    let err_status = decode_value(0x02, err_c).parse().unwrap_or(0);
    let (_t, _erridx) = pdu.tlv()?;
    let (_t, vbl) = pdu.tlv()?;

    let mut ber = Ber::new(vbl);
    let mut varbinds = Vec::new();
    while ber.p < ber.b.len() {
        let (t, vb) = ber.tlv()?;
        if t != 0x30 {
            break;
        }
        let mut v = Ber::new(vb);
        let (_t, oid_bytes) = v.tlv()?;
        let oid = decode_oid(oid_bytes)?;
        let (val_tag, val_content) = v.tlv()?;
        varbinds.push(SnmpVarBind {
            oid,
            value: decode_value(val_tag, val_content),
        });
    }
    Ok(SnmpResponse {
        error_status: err_status,
        varbinds,
    })
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct SnmpClient {
    sock: UdpSocket,
    target: SocketAddr,
    timeout: Duration,
    retries: u32,
}

impl SnmpClient {
    pub async fn new(ip: IpAddr, port: u16, timeout: Duration, retries: u32) -> Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(SocketAddr::new(ip, port)).await?;
        Ok(SnmpClient {
            sock,
            target: SocketAddr::new(ip, port),
            timeout,
            retries,
        })
    }

    async fn transceive(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        let mut last_err: Option<anyhow::Error> = None;
        for _ in 0..self.retries {
            self.sock.send_to(msg, self.target).await?;
            match tokio::time::timeout(self.timeout, self.sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => return Ok(buf[..n].to_vec()),
                Ok(Err(e)) => last_err = Some(e.into()),
                Err(_) => last_err = Some(anyhow!("timeout")),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no response")))
    }

    pub async fn get(&self, community: &str, oid: &[u32]) -> Result<SnmpResponse> {
        let reqid: u32 = rand::thread_rng().gen();
        let msg = build_msg(1, community, 0xa0, reqid, &[(oid.to_vec(), &[0x05, 0x00])], None);
        let resp = self.transceive(&msg).await?;
        parse_response(&resp)
    }

    pub async fn getbulk(&self, community: &str, oids: &[Vec<u32>], max_rep: i64) -> Result<SnmpResponse> {
        let reqid: u32 = rand::thread_rng().gen();
        const NULL_TLV: &[u8] = &[0x05, 0x00];
        let vbs: Vec<(Vec<u32>, &[u8])> = oids
            .iter()
            .map(|o| (o.clone(), NULL_TLV))
            .collect();
        let msg = build_msg(1, community, 0xa5, reqid, &vbs, Some((0, max_rep)));
        let resp = self.transceive(&msg).await?;
        parse_response(&resp)
    }

    pub async fn getnext(&self, community: &str, oid: &[u32]) -> Result<SnmpResponse> {
        let reqid: u32 = rand::thread_rng().gen();
        let msg = build_msg(1, community, 0xa1, reqid, &[(oid.to_vec(), &[0x05, 0x00])], None);
        let resp = self.transceive(&msg).await?;
        parse_response(&resp)
    }
}

fn oid_starts_with(oid: &[u32], prefix: &[u32]) -> bool {
    oid.len() >= prefix.len() && oid[..prefix.len()] == *prefix
}

pub const OID_MIB2: &[u32] = &[1, 3, 6, 1, 2, 1];
pub const OID_SYSDESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
pub const OID_SYSNAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
pub const OID_SYSLOCATION: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 6, 0];
pub const OID_SYSCONTACT: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 4, 0];
pub const OID_SYSUPTIME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
pub const OID_SYSOBJECTID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];

fn vendor_from_oid(oid: &str) -> Option<&'static str> {
    if oid.contains("1.3.6.1.4.1.9.") {
        Some("Cisco")
    } else if oid.contains("1.3.6.1.4.1.2021.") {
        Some("net-snmp / Linux")
    } else if oid.contains("1.3.6.1.4.1.311.") {
        Some("Microsoft Windows")
    } else if oid.contains("1.3.6.1.4.1.8072.") {
        Some("HP/Unix (net-snmp)")
    } else if oid.contains("1.3.6.1.4.1.11.") {
        Some("HP")
    } else if oid.contains("1.3.6.1.4.1.2636.") {
        Some("Juniper")
    } else if oid.contains("1.3.6.1.4.1.12356.") {
        Some("Fortinet")
    } else if oid.contains("1.3.6.1.4.1.253.") {
        Some("Ricoh printer")
    } else if oid.contains("1.3.6.1.4.1.2435.") {
        Some("Brother printer")
    } else if oid.contains("1.3.6.1.4.1.23.") {
        Some("Dell")
    } else if oid.contains("1.3.6.1.4.1.2011.") {
        Some("Huawei")
    } else if oid.contains("1.3.6.1.4.1.6889.") {
        Some("Avaya")
    } else if oid.contains("1.3.6.1.4.1.43.") {
        Some("Brocade/Ruckus")
    } else {
        None
    }
}

/// Try communities; on success do a MIB-2 walk and summarize.
pub async fn snmp_enum(
    ip: IpAddr,
    port: u16,
    communities: Option<Vec<String>>,
) -> Result<SnmpResults> {
    let comm_list: Vec<String> = communities.unwrap_or_else(|| {
        DEFAULT_COMMUNITIES
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    });

    let client = SnmpClient::new(ip, port, Duration::from_millis(1800), 2).await?;

    // find a working community
    let mut working: Option<String> = None;
    for c in &comm_list {
        if let Ok(resp) = client.get(c, OID_SYSDESCR).await {
            if resp.error_status == 0 {
                working = Some(c.clone());
                break;
            }
        }
    }

    let community = working.ok_or_else(|| anyhow!("no working community string"))?;

    async fn get_one(client: &SnmpClient, community: &str, oid: &[u32]) -> Option<String> {
        if let Ok(r) = client.get(community, oid).await {
            if let Some(vb) = r.varbinds.first() {
                return Some(vb.value.clone());
            }
        }
        None
    }

    let sysdescr = get_one(&client, &community, OID_SYSDESCR).await;
    let sysname = get_one(&client, &community, OID_SYSNAME).await;
    let syslocation = get_one(&client, &community, OID_SYSLOCATION).await;
    let syscontact = get_one(&client, &community, OID_SYSCONTACT).await;
    let uptime = get_one(&client, &community, OID_SYSUPTIME).await;
    let sysobjectid = get_one(&client, &community, OID_SYSOBJECTID).await;
    let vendor_guess = sysobjectid.as_deref().and_then(vendor_from_oid).map(|s| s.to_string());

    // walk mib-2 with GETBULK
    let mut objects: Vec<(String, String)> = Vec::new();
    let mut cur: Vec<u32> = OID_MIB2.to_vec();
    let mut done = false;
    for _ in 0..60 {
        if done {
            break;
        }
        let resp = match client.getbulk(&community, &[cur.clone()], 25).await {
            Ok(r) => r,
            Err(_) => break,
        };
        if resp.varbinds.is_empty() {
            break;
        }
        let mut last_oid: Option<Vec<u32>> = None;
        for vb in &resp.varbinds {
            if !oid_starts_with(&vb.oid, OID_MIB2) {
                done = true;
                break;
            }
            objects.push((oid_to_string(&vb.oid), vb.value.clone()));
            last_oid = Some(vb.oid.clone());
        }
        if let Some(last) = last_oid {
            cur = last;
        }
        if objects.len() > 3000 {
            break;
        }
    }

    let varbind_count = objects.len();

    Ok(SnmpResults {
        community,
        version: "v2c (GETBULK) / v1 compatible".into(),
        sysdescr,
        sysname,
        syslocation,
        syscontact,
        sysobjectid,
        uptime,
        vendor_guess,
        objects,
        varbind_count,
    })
}
