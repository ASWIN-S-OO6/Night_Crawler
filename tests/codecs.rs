//! Integration tests for the hand-rolled SNMP (BER) and NetBIOS (NBNS) codecs.
//! Spawns a tiny Python responder and drives the real client code paths.

use std::net::IpAddr;
use std::process::{Child, Command, Stdio};

struct Responder(Child);

impl Drop for Responder {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_responder(snmp_port: u16, nbns_port: u16) -> Responder {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/snmp_responder.py"
    );
    let child = Command::new("python3")
        .args([
            script,
            &snmp_port.to_string(),
            &nbns_port.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start python responder");
    Responder(child)
}

const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

#[tokio::test]
async fn snmp_get_and_walk() {
    let r = start_responder(16161, 16137);
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let res = night_crawler::modules::snmp::snmp_enum(
        IP,
        16161,
        Some(vec!["public".into(), "wrong".into()]),
    )
    .await
    .expect("snmp enum should succeed against responder");

    assert_eq!(res.community, "public");
    assert_eq!(
        res.sysdescr.as_deref(),
        Some("Linux testbox 6.1.0 #1 SMP x86_64")
    );
    assert_eq!(res.sysname.as_deref(), Some("testhost"));
    assert_eq!(res.syslocation.as_deref(), Some("Server Room Rack 4"));

    // walk should collect in-subtree varbinds and stop at the out-of-subtree OID
    let collected: Vec<&(String, String)> = res
        .objects
        .iter()
        .filter(|(oid, _)| oid.starts_with("1.3.6.1.2.1"))
        .collect();
    assert!(
        collected.len() >= 3,
        "expected at least 3 walked varbinds, got {}: {:?}",
        collected.len(),
        collected
    );
    assert!(
        !res
            .objects
            .iter()
            .any(|(oid, _)| oid.starts_with("1.3.6.1.3")),
        "walk must stop before leaving mib-2"
    );
    drop(r);
}

#[tokio::test]
async fn snmp_wrong_community_fails() {
    let r = start_responder(16162, 16138);
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let res = night_crawler::modules::snmp::snmp_enum(
        IP,
        16162,
        Some(vec!["private".into(), "letmein".into()]),
    )
    .await;
    assert!(res.is_err(), "no community should be accepted");
    drop(r);
}

#[tokio::test]
async fn nbns_node_status() {
    let r = start_responder(16163, 16139);
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let res = night_crawler::modules::netbios::nbns_query(IP, 16139)
        .await
        .expect("nbns query should succeed against responder");

    assert_eq!(res.mac_address, "DE:AD:BE:EF:00:42");
    let names: Vec<&str> = res.names.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"TESTBOX"), "names: {:?}", names);
    assert!(names.contains(&"WORKGROUP"), "names: {:?}", names);

    let has_file_server = res
        .names
        .iter()
        .any(|(_, svc)| svc.contains("File Server"));
    let has_master_browser = res
        .names
        .iter()
        .any(|(_, svc)| svc.contains("Master Browser"));
    assert!(has_file_server, "0x20 suffix should map to File Server: {:?}", res.names);
    assert!(has_master_browser, "0x1D suffix should map to Master Browser: {:?}", res.names);
    drop(r);
}

#[tokio::test]
async fn nbns_unreachable() {
    let res = night_crawler::modules::netbios::nbns_query(IP, 16199).await;
    assert!(res.is_err());
}
