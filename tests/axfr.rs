//! Integration test for the raw DNS AXFR (zone transfer) wire codec.

use std::net::{IpAddr, Ipv4Addr};
use std::process::{Child, Command, Stdio};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

struct Responder(Child);

impl Drop for Responder {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_axfr(port: u16) -> Responder {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/axfr_responder.py");
    let child = Command::new("python3")
        .args([script, &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start axfr responder");
    Responder(child)
}

#[test]
fn axfr_zone_transfer_success() {
    let _r = start_axfr(15301);
    std::thread::sleep(std::time::Duration::from_millis(600));

    let records = night_crawler::modules::dnsrecon::try_axfr(IP, 15301, "example.com")
        .expect("axfr should succeed against the test server");

    assert!(records.len() >= 6, "expected >=6 records, got {}", records.len());
    let a_www = records
        .iter()
        .find(|r| r.name == "www.example.com" && r.rtype == "A")
        .expect("www A record missing");
    assert_eq!(a_www.value, "192.0.2.10");
    let mx = records.iter().find(|r| r.rtype == "MX").expect("MX missing");
    assert!(mx.value.contains("mail.example.com"), "mx: {}", mx.value);
    let txt = records.iter().find(|r| r.rtype == "TXT").expect("TXT missing");
    assert!(txt.value.contains("v=spf1"), "txt: {}", txt.value);
    let soas = records.iter().filter(|r| r.rtype == "SOA").count();
    assert_eq!(soas, 2, "expected 2 SOAs (start+end), got {}", soas);
}

#[test]
fn axfr_refused() {
    let _r = start_axfr(15302);
    std::thread::sleep(std::time::Duration::from_millis(600));

    let res = night_crawler::modules::dnsrecon::try_axfr(IP, 15302, "refused.example");
    let empty = match res {
        Ok(r) => r.is_empty(),
        Err(_) => true,
    };
    assert!(empty, "refused zone must yield no records");
}
