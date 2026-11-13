//! Nmap integration — the gold-standard port scanner with NSE scripts.
//! When nmap is installed, Night Crawler uses it for accurate port
//! discovery, service/version detection (-sV), OS fingerprinting (-O),
//! and vulnerability-oriented NSE scripts. Falls back to the built-in
//! async scanner when nmap is absent.

use crate::types::PortResult;
use anyhow::Result;
use std::net::IpAddr;
use std::time::Duration;

pub fn nmap_available() -> bool {
    std::process::Command::new("sh")
        .args(["-c", "command -v nmap >/dev/null 2>&1"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run nmap with service/version detection and default safe NSE scripts.
/// Returns parsed PortResults. Port discovery uses the AI-chosen spec
/// (top/full/custom) passed in as `ports_arg`.
pub async fn nmap_scan(
    ip: IpAddr,
    host_header: &str,
    ports_arg: &str,
    timing_template: u8,
) -> Result<Vec<PortResult>> {
    let mut args: Vec<String> = vec![
        "-Pn".into(),
        format!("-T{}", timing_template),
        "-sV".into(),           // service/version detection
        "--version-all".into(),  // try every probe
        "-O".into(),             // OS fingerprint
        "--script".into(),
        // safe + recon NSE scripts (no exploitation)
        "default,vuln,http-enum,http-title,http-headers,http-server-header,ssl-cert,ftp-anon,smb-os-discovery,smb-shares".into(),
        "--open".into(),
        "-oN".into(),
        "-".into(), // stdout
        "-p".into(),
        ports_arg.into(),
    ];
    args.push(ip.to_string());

    let out = tokio::process::Command::new("nmap")
        .args(&args)
        .kill_on_drop(true)
        .output()
        .await?;

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() {
        anyhow::bail!("nmap exited {}: {}", out.status, text);
    }
    Ok(parse_nmap_output(&text, host_header))
}

/// Parse nmap's human-readable output into PortResults.
pub fn parse_nmap_output(text: &str, _host_header: &str) -> Vec<PortResult> {
    let mut ports: Vec<PortResult> = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        // e.g. "80/tcp   open  http    cloudflare (V8.4.4)"
        // or "443/tcp  open  https   CloudflareSSL"
        if !l.contains("/tcp") && !l.contains("/udp") {
            continue;
        }
        let parts: Vec<&str> = l.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let (port_s, proto) = match parts[0].split_once('/') {
            Some((p, pr)) => (p.to_string(), pr.to_string()),
            None => continue,
        };
        let port: u16 = match port_s.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let state = parts[1].to_string();
        if state != "open" && state != "open|filtered" {
            continue;
        }
        let service = parts.get(2).unwrap_or(&"unknown").to_string();
        // remaining parts = version banner
        let banner: String = if parts.len() > 3 {
            parts[3..].join(" ")
        } else {
            String::new()
        };
        let (product, version) = crate::modules::banner::parse_product(&banner);

        ports.push(PortResult {
            port,
            proto,
            open: true,
            service: crate::config::service_for_port(port).to_string()
                .replace("unknown", &service)
                .to_string(),
            banner: Some(banner),
            product,
            version,
            http: None,
            notes: vec!["nmap+NSE".into()],
        });
    }
    ports.sort_by_key(|p| p.port);
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmap_output_parsed() {
        let out = r#"
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up (0.05s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu-3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.57
443/tcp  open  https
3306/tcp open  mysql   MySQL 8.0.36
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 5.23 seconds
"#;
        let ports = parse_nmap_output(out, "example.com");
        assert_eq!(ports.len(), 4);
        assert_eq!(ports[0].port, 22);
        assert!(ports[0].product.as_deref().unwrap_or("").contains("OpenSSH"));
        assert_eq!(ports[1].port, 80);
        assert!(ports[1].version.as_deref() == Some("2.4.57"));
        assert_eq!(ports[3].service, "mysql");
        assert_eq!(ports[3].notes[0], "nmap+NSE");
    }

    #[test]
    fn filtered_closed_ignored() {
        let out = "25/tcp   closed smtp\n99/tcp   filtered oracle\n80/tcp open http nginx 1.24\n";
        let ports = parse_nmap_output(out, "h");
        assert_eq!(ports.len(), 1);
    }
}
