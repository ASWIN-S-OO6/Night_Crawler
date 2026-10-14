use crate::types::{PortResult, Severity, VulnFinding};
use crate::util::{parse_version, version_in};
use std::net::IpAddr;

/// Doctrine confidence levels.
pub const CONFIRMED: &str = "CONFIRMED";
pub const LIKELY: &str = "LIKELY";
pub const POSSIBLE: &str = "POSSIBLE";

struct VulnRule {
    product: &'static str,
    min: Option<(u64, u64, u64)>,
    max: Option<(u64, u64, u64)>,
    equal: Option<&'static str>, // banner substring must contain this
    severity: Severity,
    cve: Option<&'static str>,
    title: &'static str,
    description: &'static str,
    reference: Option<&'static str>,
}

fn rules() -> Vec<VulnRule> {
    vec![
        VulnRule {
            product: "vsftpd",
            min: None, max: None, equal: Some("2.3.4"),
            severity: Severity::Critical,
            cve: Some("CVE-2011-2523"),
            title: "vsftpd 2.3.4 backdoor (smiling hacker)",
            description: "vsftpd 2.3.4 shipped with a backdoored build: a ':)' in the username opens a root shell on port 6200.",
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2011-2523"),
        },
        VulnRule {
            product: "ProFTPD",
            min: Some((1, 3, 5)), max: Some((1, 3, 5)), equal: None,
            severity: Severity::High,
            cve: Some("CVE-2015-3306"),
            title: "ProFTPD 1.3.5 mod_copy remote code execution",
            description: "ProFTPD 1.3.5 before 1.3.5a allows unauthenticated copying of files via SITE CPFR/CPTO commands, leading to RCE.",
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2015-3306"),
        },
        VulnRule {
            product: "ProFTPD",
            min: None, max: None, equal: Some("1.3.3c"),
            severity: Severity::Critical,
            cve: None,
            title: "ProFTPD 1.3.3c backdoored build (trojanized source)",
            description: "ProFTPD 1.3.3c distributed from a compromised mirror contains a backdoor granting root shell access.",
            reference: None,
        },
        VulnRule {
            product: "Exim",
            min: Some((4, 87, 0)), max: Some((4, 91, 0)), equal: None,
            severity: Severity::Critical,
            cve: Some("CVE-2019-10149"),
            title: "Exim RCE via return string orification (CVE-2019-10149)",
            description: "Exim 4.87-4.91 allows remote command execution as root through a flaw in the string_expand function handling of ${run{...}}.",
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2019-10149"),
        },
        VulnRule {
            product: "OpenSSH",
            min: Some((8, 5, 0)), max: Some((9, 7, 0)), equal: None,
            severity: Severity::High,
            cve: Some("CVE-2024-6387"),
            title: "regreSSHion — OpenSSH signal handler race condition RCE",
            description: "OpenSSH 8.5p1 through 9.7p1 is vulnerable to a signal handler race (regreSSHion) that may allow unauthenticated remote code execution as root (glibc-based systems).",
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2024-6387"),
        },
        VulnRule {
            product: "OpenSSH",
            min: Some((2, 3, 0)), max: Some((7, 7, 0)), equal: None,
            severity: Severity::Medium,
            cve: Some("CVE-2018-15473"),
            title: "OpenSSH user enumeration via malformed authentication",
            description: "OpenSSH through 7.7 leaks whether a username exists via a timing/disconnect discrepancy in auth handling.",
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2018-15473"),
        },
        VulnRule {
            product: "Apache httpd",
            min: Some((2, 4, 49)), max: Some((2, 4, 50)), equal: None,
            severity: Severity::Critical,
            cve: Some("CVE-2021-42013"),
            title: "Apache path traversal & RCE (CVE-2021-41773 / CVE-2021-42013)",
            description: "Apache 2.4.49/2.4.50 with Alias-like directives allows path traversal (and RCE when mod_cgi is enabled).",
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2021-42013"),
        },
        VulnRule {
            product: "Apache httpd",
            min: Some((2, 2, 0)), max: Some((2, 2, 34)), equal: None,
            severity: Severity::Medium,
            cve: None,
            title: "Apache 2.2.x is end-of-life",
            description: "Apache httpd 2.2 reached end of life in 2017; numerous unpatched CVEs apply. Upgrade to a supported release.",
            reference: None,
        },
        VulnRule {
            product: "Microsoft IIS",
            min: Some((6, 0, 0)), max: Some((6, 0, 0)), equal: None,
            severity: Severity::High,
            cve: Some("CVE-2017-7269"),
            title: "IIS 6.0 WebDAV buffer overflow RCE",
            description: "Microsoft IIS 6.0 with WebDAV enabled is vulnerable to a stack buffer overflow in ScStoragePathFromUrl allowing remote code execution (used widely by attackers).",
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2017-7269"),
        },
        VulnRule {
            product: "Microsoft IIS",
            min: Some((1, 0, 0)), max: Some((7, 0, 0)), equal: None,
            severity: Severity::Low,
            cve: None,
            title: "IIS short-filename (8.3) enumeration",
            description: "IIS versions below 7.0 with short names enabled disclose file/folder names via tilde character requests (~1).",
            reference: None,
        },
        VulnRule {
            product: "MySQL",
            min: Some((5, 1, 0)), max: Some((5, 5, 23)), equal: None,
            severity: Severity::Medium,
            cve: Some("CVE-2012-2122"),
            title: "MySQL/MariaDB authentication bypass",
            description: "When compiled/run in certain configurations, comparing a malformed token to the hash always succeeds, allowing auth bypass (~2500 attempts).",
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2012-2122"),
        },
        VulnRule {
            product: "OpenSSL",
            min: Some((1, 0, 1)), max: Some((1, 0, 1)), equal: Some("1.0.1"),
            severity: Severity::High,
            cve: Some("CVE-2014-0160"),
            title: "Heartbleed — OpenSSL 1.0.1 through 1.0.1f memory disclosure",
            description: "Missing bounds check in TLS heartbeat permits leaking up to 64KB of server memory per request (keys, credentials).",
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2014-0160"),
        },
        VulnRule {
            product: "PHP",
            min: Some((5, 0, 0)), max: Some((7, 3, 99)), equal: None,
            severity: Severity::Medium,
            cve: None,
            title: "PHP version is end-of-life",
            description: "PHP releases below 7.4 are end-of-life; many public CVEs (including RCE-class bugs) are unpatched.",
            reference: None,
        },
        VulnRule {
            product: "Apache Tomcat",
            min: Some((5, 0, 0)), max: Some((9, 0, 90)), equal: None,
            severity: Severity::Medium,
            cve: None,
            title: "Apache Tomcat — verify manager exposure",
            description: "Tomcat with exposed /manager or host-manager app is a common compromise vector (default creds, WAR deploy).",
            reference: None,
        },
        VulnRule {
            product: "Samba",
            min: Some((3, 5, 0)), max: Some((4, 6, 4)), equal: None,
            severity: Severity::High,
            cve: Some("CVE-2017-7494"),
            title: "Samba (EternalRed) — malicious shared library RCE",
            description: "Samba 3.5.0 through 4.6.4 allows an attacker with write access to a share to upload and execute a malicious library as root (CVE-2017-7494).",
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2017-7494"),
        },
        VulnRule {
            product: "Jenkins",
            min: Some((1, 0, 0)), max: Some((2, 441, 99)), equal: None,
            severity: Severity::High,
            cve: Some("CVE-2024-23897"),
            title: "Jenkins arbitrary file read via CLI (CVE-2024-23897)",
            description: "Jenkins through 2.441 allows unauthenticated arbitrary file reads via crafted CLI commands (@file expansion), often chained to credential theft and RCE.",
            reference: Some("https://nvd.nist.gov/vuln/detail/CVE-2024-23897"),
        },
        VulnRule {
            product: "WordPress",
            min: Some((1, 0, 0)), max: Some((5, 9, 99)), equal: None,
            severity: Severity::Medium,
            cve: None,
            title: "Outdated WordPress core detected",
            description: "WordPress below 6.x is behind on security fixes; enumerate plugins/themes and check for known plugin CVEs before assuming core is the issue.",
            reference: None,
        },
    ]
}

/// Compare found vulns against ports/services. Adds rule-based contextual findings too.
/// Version-match CVEs are LIKELY; behavioral checks elsewhere in the pipeline are CONFIRMED.
pub fn fingerprint(ports: &[PortResult], ip: IpAddr) -> Vec<VulnFinding> {
    let mut out: Vec<VulnFinding> = Vec::new();
    let ip_s = ip.to_string();

    for rule in rules() {
        for pr in ports {
            let product_match = pr
                .product
                .as_deref()
                .map(|p| p.eq_ignore_ascii_case(rule.product))
                .unwrap_or(false);
            if !product_match {
                continue;
            }
            let banner = pr.banner.as_deref().unwrap_or("");
            if let Some(eq) = rule.equal {
                if !banner.contains(eq) {
                    continue;
                }
            }
            if let (Some(vstr), Some(_)) = (&pr.version, parse_version(pr.version.as_deref().unwrap_or(""))) {
                if !version_in(parse_version(vstr).unwrap(), rule.min, rule.max) {
                    continue;
                }
            } else if rule.min.is_some() {
                continue; // rule needs a version but we didn't parse one
            }
            out.push(VulnFinding {
                title: rule.title.to_string(),
                severity: rule.severity,
                confidence: LIKELY.to_string(),
                cve: rule.cve.map(|c| c.to_string()),
                affected: format!("{}:{}/{} {}", ip_s, pr.port, pr.proto, pr.service),
                evidence: format!("banner: {}", pr.banner.as_deref().unwrap_or("(none)")),
                description: rule.description.to_string(),
                reference: rule.reference.map(|r| r.to_string()),
            });
        }
    }

    // Contextual exposure findings (port-based; exposure itself is CONFIRMED,
    // the exploitability risk is what varies — doctrine §5)
    for pr in ports {
        let svc = pr.service.to_ascii_lowercase();
        let banner = pr.banner.as_deref().unwrap_or("").to_string();

        if matches!(pr.port, 512 | 513 | 514) {
            out.push(VulnFinding {
                title: "Legacy r-services (rlogin/rexec/rsh) exposed".into(),
                severity: Severity::High,
                confidence: CONFIRMED.to_string(),
                cve: None,
                affected: format!("{}:{}/tcp", ip_s, pr.port),
                evidence: format!("port {} open ({})", pr.port, svc),
                description: "r-services rely on host-based trust and transmit credentials in cleartext; trivially abused for lateral movement."
                    .into(),
                reference: None,
            });
        }
        if pr.port == 23 {
            out.push(VulnFinding {
                title: "Telnet exposed (cleartext protocol)".into(),
                severity: Severity::High,
                confidence: CONFIRMED.to_string(),
                cve: None,
                affected: format!("{}:23/tcp", ip_s),
                evidence: banner.clone(),
                description: "Telnet sends credentials in cleartext and is a common initial-access vector. Replace with SSH.".into(),
                reference: None,
            });
        }
        if pr.port == 21 {
            out.push(VulnFinding {
                title: "FTP exposed (cleartext protocol)".into(),
                severity: Severity::Low,
                confidence: CONFIRMED.to_string(),
                cve: None,
                affected: format!("{}:21/tcp", ip_s),
                evidence: banner.clone(),
                description: "FTP transmits credentials in cleartext; check for anonymous login and writable directories.".into(),
                reference: None,
            });
        }
        if matches!(pr.port, 3306 | 5432 | 1433 | 1521 | 27017 | 6379 | 9200 | 11211 | 5984 | 7000 | 7474) {
            out.push(VulnFinding {
                title: format!("Database/cache service exposed: {} ({})", pr.port, svc),
                severity: Severity::High,
                confidence: POSSIBLE.to_string(),
                cve: None,
                affected: format!("{}:{}/tcp", ip_s, pr.port),
                evidence: banner.clone(),
                description: "A data-store service is reachable from the network perimeter. Verify authentication, network ACLs, and whether it should be internet-facing at all.".into(),
                reference: None,
            });
        }
        if matches!(pr.port, 5900 | 5901 | 5800 | 3389 | 3390) {
            out.push(VulnFinding {
                title: format!("Remote-access service exposed: {} ({})", pr.port, svc),
                severity: Severity::Medium,
                confidence: POSSIBLE.to_string(),
                cve: None,
                affected: format!("{}:{}/tcp", ip_s, pr.port),
                evidence: banner.clone(),
                description: "Graphical remote access is exposed. Confirm MFA/NLA and rate-limiting; VNC without auth is a common foothold.".into(),
                reference: None,
            });
        }
        if pr.service == "redis" && banner.contains("responds to PING") {
            out.push(VulnFinding {
                title: "Unauthenticated Redis instance".into(),
                severity: Severity::Critical,
                confidence: CONFIRMED.to_string(),
                cve: None,
                affected: format!("{}:6379/tcp", ip_s),
                evidence: banner.clone(),
                description: "Redis answered PING without authentication (behaviorally CONFIRMED). Commonly abused for RCE via module load / CONFIG SET dir / ssh key writes / cron writes."
                    .into(),
                reference: None,
            });
        }
        if pr.port == 2375 {
            out.push(VulnFinding {
                title: "Docker API exposed without TLS".into(),
                severity: Severity::Critical,
                confidence: CONFIRMED.to_string(),
                cve: None,
                affected: format!("{}:2375/tcp", ip_s),
                evidence: banner.clone(),
                description: "Unauthenticated Docker Engine API gives instant host takeover (docker -H tcp://host run -v /:/host privileged).".into(),
                reference: None,
            });
        }
        if pr.port == 6443 || (pr.port == 10250) {
            out.push(VulnFinding {
                title: format!("Kubernetes control-plane port exposed: {}", pr.port),
                severity: Severity::High,
                confidence: POSSIBLE.to_string(),
                cve: None,
                affected: format!("{}:{}/tcp", ip_s, pr.port),
                evidence: banner.clone(),
                description: "Kube-apiserver/kubelet ports are internet-reachable; check for anonymous auth and exec privileges (Kubelet 10250 read-only API is a classic node takeover)."
                    .into(),
                reference: None,
            });
        }
    }

    // Dedup by title+affected
    let mut seen = std::collections::HashSet::new();
    out.retain(|f| seen.insert((f.title.clone(), f.affected.clone())));
    out
}
