use crate::config::service_for_port;
use crate::types::{HttpInfo, PortResult};
use crate::util::html_title;
use anyhow::Result;
use rand::Rng;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_PORTS_BANNER: usize = 300;

/// For every open TCP port: grab a banner, classify the service, extract product/version.
/// `ip` is the resolved IP; `host_header` is the hostname (or IP string) for HTTP probes.
pub async fn detect_services(
    ip: IpAddr,
    host_header: &str,
    open_ports: &[u16],
    http_timeout_ms: u64,
) -> Result<Vec<PortResult>> {
    let mut out: Vec<PortResult> = Vec::new();
    let ports: Vec<u16> = open_ports.iter().take(MAX_PORTS_BANNER).cloned().collect();

    for port in ports {
        let service = service_for_port(port).to_string();
        let mut pr = PortResult {
            port,
            proto: "tcp".into(),
            open: true,
            service: service.clone(),
            banner: None,
            product: None,
            version: None,
            http: None,
            notes: Vec::new(),
        };

        // 1. Passive banner (SSH, FTP, SMTP, POP3, IMAP, Redis-ish, etc.)
        let banner = read_banner(ip, port).await;
        let mut banner_text = banner.clone();

        // 2. HTTP probe when no banner or known HTTP-ish port
        let is_http_port = matches!(
            port,
            80 | 81 | 88 | 443 | 591 | 2082 | 2083 | 2086 | 2087 | 2095 | 2096 | 3000 | 3128
                | 4443 | 4444 | 5000 | 5601 | 7000 | 7070 | 7777 | 8000..=8010 | 8080..=8090
                | 8443 | 8444 | 8888 | 9000 | 9090 | 10000
        );

        if let Some(b) = &banner_text {
            let (product, version) = parse_product(b);
            pr.product = product.clone();
            pr.version = version;
            if let Some(p) = product {
                if let Some(svc) = product_to_service(&p) {
                    pr.service = svc.to_string();
                }
            }
        } else {
            // Active probes
            if port == 6379 {
                if let Some(resp) = send_recv(ip, port, b"PING\r\n", http_timeout_ms).await {
                    if resp.trim().starts_with('+') {
                        banner_text = Some(format!("Redis-like response: {}", one_line(&resp)));
                        pr.service = "redis".into();
                        pr.product = Some("Redis".into());
                        pr.notes.push("responds to PING without auth".into());
                    }
                }
            } else if port == 27017 {
                pr.service = "mongodb".into();
            }

            if pr.product.is_none() && is_http_port || (banner_text.is_none() && is_http_port) {
                // plain HTTP first
                if let Some(h) = http_probe(ip, host_header, port, false, http_timeout_ms).await {
                    pr.service = "http".into();
                    pr.http = Some(h.clone());
                    let b = synth_banner(&h);
                    banner_text = Some(b);
                } else if let Some(h) = http_probe(ip, host_header, port, true, http_timeout_ms).await {
                    pr.service = "https".into();
                    pr.http = Some(h.clone());
                    let b = synth_banner(&h);
                    banner_text = Some(b);
                }
            }

            if let Some(b) = &banner_text {
                let (product, version) = parse_product(b);
                if pr.product.is_none() {
                    pr.product = product.clone();
                    pr.version = version;
                    if let Some(p) = product {
                        if let Some(svc) = product_to_service(&p) {
                            pr.service = svc.to_string();
                        }
                    }
                }
            }
        }

        // HTTPS catch-up for TLS-only ports that had no plain HTTP
        if pr.http.is_none() && (port == 443 || port == 8443 || port == 4443) {
            if let Some(h) = http_probe(ip, host_header, port, true, http_timeout_ms).await {
                pr.service = "https".into();
                pr.http = Some(h);
            }
        }

        if let Some(b) = banner_text {
            pr.banner = Some(
                b.chars()
                    .map(|c| if c.is_control() { '.' } else { c })
                    .take(220)
                    .collect(),
            );
        }
        out.push(pr);
    }

    Ok(out)
}

fn synth_banner(h: &HttpInfo) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(s) = &h.server {
        parts.push(format!("Server: {}", s));
    }
    if let Some(p) = &h.powered_by {
        parts.push(format!("X-Powered-By: {}", p));
    }
    if let Some(t) = &h.title {
        parts.push(format!("Title: {}", t));
    }
    if parts.is_empty() {
        format!("HTTP/1.1 {} (len {})", h.status, h.length_of())
    } else {
        parts.join(" | ")
    }
}

impl HttpInfo {
    pub fn length_of(&self) -> u64 {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.trim().parse().ok())
            .unwrap_or(0)
    }
}

fn one_line(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect::<String>()
}

/// Connect and wait briefly for a server-initiated banner.
async fn read_banner(ip: IpAddr, port: u16) -> Option<String> {
    let mut sock = tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    let _ = sock.set_nodelay(true);
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_millis(2500), sock.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    if text.chars().filter(|c| c.is_control() && *c != '\r' && *c != '\n').count() > n / 2 {
        return None; // binary junk
    }
    Some(text.trim().to_string())
}

/// Send bytes, read whatever comes back.
async fn send_recv(ip: IpAddr, port: u16, payload: &[u8], timeout_ms: u64) -> Option<String> {
    let mut sock = tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    let _ = sock.write_all(payload).await.ok()?;
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_millis(timeout_ms.max(1500)), sock.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}

/// Minimal HTTP client over raw TCP for fingerprinting (also handles invalid TLS hosts via reqwest).
async fn http_probe(
    ip: IpAddr,
    host: &str,
    port: u16,
    tls: bool,
    timeout_ms: u64,
) -> Option<HttpInfo> {
    let url = format!("{}://{}:{}", if tls { "https" } else { "http" }, host, port);
    probe_http_url(&url, ip, port, tls, timeout_ms).await.ok()
}

/// Full HTTP fingerprint via reqwest (follows redirects, captures headers/title/robots).
pub async fn probe_http_url(
    url: &str,
    ip: IpAddr,
    port: u16,
    tls: bool,
    timeout_ms: u64,
) -> Result<HttpInfo> {
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 NightCrawler/0.1")
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(4))
        .timeout(Duration::from_millis(timeout_ms))
        .build()?;

    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let cookies = resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();
    let server = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("server"))
        .map(|(_, v)| v.clone());
    let powered_by = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-powered-by"))
        .map(|(_, v)| v.clone());
    let body = resp.text().await.unwrap_or_default();
    let title = html_title(&body);

    let sec_checks = [
        ("Strict-Transport-Security", headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("strict-transport-security"))),
        ("Content-Security-Policy", headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-security-policy"))),
        ("X-Frame-Options", headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-frame-options"))),
        ("X-Content-Type-Options", headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-content-type-options"))),
        ("X-XSS-Protection", headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-xss-protection"))),
    ];
    let security_headers: Vec<(String, bool)> = sec_checks
        .iter()
        .map(|(k, ok)| (k.to_string(), *ok))
        .collect();

    // robots.txt
    let mut robots_disallow: Vec<String> = Vec::new();
    let robots_url = format!("{}/robots.txt", url.trim_end_matches('/'));
    if let Ok(rr) = client.get(&robots_url).send().await {
        if rr.status().is_success() {
            let text = rr.text().await.unwrap_or_default();
            for line in text.lines() {
                let l = line.trim();
                if let Some(p) = l.to_ascii_lowercase().strip_prefix("disallow:") {
                    if !p.trim().is_empty() {
                        robots_disallow.push(p.trim().to_string());
                    }
                }
            }
        }
    }

    let mut info = HttpInfo {
        url: url.to_string(),
        status,
        title,
        server,
        powered_by,
        headers,
        cookies,
        robots_disallow: robots_disallow.clone(),
        security_headers,
        tls_issuer: None,
        tls_subject: None,
        tls_valid_until: None,
        tls_san: Vec::new(),
    };

    if tls {
        crate::modules::tls_capture::enrich_http_tls(&mut info, ip, port, true).await;
    }
    Ok(info)
}

/// Map a detected product to a canonical service name.
fn product_to_service(product: &str) -> Option<&'static str> {
    Some(match product {
        "ProFTPD" | "vsftpd" | "Pure-FTPd" | "VSFTPD" => "ftp",
        "OpenSSH" | "Dropbear" => "ssh",
        "Postfix" | "Exim" | "Sendmail" => "smtp",
        "Dovecot" | "Courier IMAP" => "imap",
        "MySQL" | "MariaDB" => "mysql",
        "PostgreSQL" => "postgresql",
        "Microsoft SQL Server" => "ms-sql-s",
        "Redis" => "redis",
        "MongoDB" => "mongodb",
        "Elasticsearch" => "elasticsearch",
        "memcached" => "memcached",
        "Apache Tomcat" => "http",
        _ => return None,
    })
}

/// Pull (product, version) out of banner text.
pub fn parse_product(banner: &str) -> (Option<String>, Option<String>) {
    let patterns: &[(&str, &str)] = &[
        ("OpenSSH", r"OpenSSH[_\- ]?([\w.]+)"),
        ("Apache httpd", r"Apache(?:_httpd)?/([\d.]+)"),
        ("Apache Tomcat", r"Apache[- ]Coyote/([\d.]+)"),
        ("Apache Tomcat", r"Apache[- ]Tomcat/([\d.]+)"),
        ("nginx", r"nginx/([\d.]+)"),
        ("lighttpd", r"lighttpd/([\d.]+)"),
        ("Microsoft IIS", r"(?:Microsoft[- ])?IIS(?:/)?([\d.]+)?"),
        ("ProFTPD", r"ProFTPD(?:\s*Version)?\s*([\d.]+\w*)"),
        ("vsftpd", r"vsftpd\s*(?:\(vsFTPd\)?\s*)?([\d.]+)"),
        ("Pure-FTPd", r"Pure-FTPd\s*\(?([\d.a-zA-Z]+)\)?"),
        ("Postfix", r"(?:\d+\s+)?Postfix(?:\s*\(?Postfox\)?)?\s*\(?([\d.]+)?"),
        ("Exim", r"Exim\s*([\d.]+)"),
        ("Sendmail", r"Sendmail\s*([\d.]+)?"),
        ("Dovecot", r"Dovecot\s*(?:\(Dovecot\))?\s*\(?([\d.]+)?"),
        ("Courier IMAP", r"Courier[- ]IMAP\s*([\d.]+)"),
        ("MySQL", r"(?:mysql|MariaDB)[\s-]+(?:serv[a-z]*\s*)?([\d.a-zA-Z]+)"),
        ("MariaDB", r"MariaDB(?:\s*serv[a-z]*)?\s*([\d.a-zA-Z]+)"),
        ("PostgreSQL", r"PostgreSQL\s*([\d.]+)"),
        ("Microsoft SQL Server", r"Microsoft SQL Server\s*([\d.]+)"),
        ("Redis", r"(?:Redis)[\s-]*v?([\d.]+)"),
        ("Node.js", r"Node[.\s-]*v?([\d.]+)"),
        ("PHP", r"PHP/([\d.]+)"),
        ("OpenSSL", r"OpenSSL/([\d.a-z]+)"),
        ("Werkzeug", r"Werkzeug/([\d.]+)"),
        ("Jetty", r"Jetty\(?([\d.a-zA-Z.]+)\)?"),
        ("VSFTPD", r"vsFTPD\s*([\d.]+)"),
        ("vsftpd", r"vsftpd\s*([\d.]+)"),
        ("Redis", r"Redis\s*version[=:]\s*([\d.]+)"),
        ("Elasticsearch", r#""number"\s*:\s*"([\d.]+)""#),
        ("JBoss", r"JBoss(?:-Web)?[/ ]([\d.]+)"),
        ("WebLogic", r"WebLogic\s*([\d.]+)"),
        ("WebSphere", r"WebSphere\s*([\d.]+)"),
        ("IBM Lotus Domino", r"Lotus[- ]Domino(?:/([\d.]+))?"),
        ("Varnish", r"Varnish(?:-cache)?[/ ]([\d.]+)"),
        ("HAProxy", r"HA-?Proxy[\s-]*([\d.]+)"),
        ("cPanel", r"cPanel(?:/([\d.]+))?"),
        ("Jenkins", r"X-Jenkins:\s*([\d.]+)"),
        ("WordPress", r"WordPress\s*([\d.]+)"),
        ("Dropbear", r"dropbear[_-]?([\d.]+)"),
        ("Libreswan", r"Libreswan\s*([\d.]+)"),
        ("strongSwan", r"strongSwan\s*([\d.]+)"),
        ("UnrealIRCd", r"Unreal[.\d]+(?:-IRCd)?"),
        ("MongoDB", r"MongoDB\s*([\d.]+)"),
        ("memcached", r"memcached\s*([\d.]+)"),
        ("BusyBox", r"BusyBox\s*v([\d.]+)"),
        ("OpenVPN", r"OpenVPN\s*([\d.]+)"),
        ("Telnetd", r"(?:Telnet|telnetd)\s*([\d.]+)?"),
        ("Ubuntu", r"Ubuntu[\s-]*([\d.]+)"),
        ("Debian", r"Debian[/ ]([\d.]+)"),
    ];

    for (product, pat) in patterns {
        if let Ok(re) = regex::Regex::new(pat) {
            if let Some(caps) = re.captures(banner) {
                let ver = caps.get(1).map(|m| m.as_str().to_string());
                return (Some(product.to_string()), ver.filter(|v| !v.is_empty()));
            }
        }
    }
    (None, None)
}

/// Return a random ID for DNS/SNMP packets.
pub fn txid() -> u16 {
    rand::thread_rng().gen()
}
