//! CVE mapping engine — the same approach the OpenVAS/Greenbone scanner
//! uses: match detected product/version pairs against the authoritative
//! CVE database (NVD), then rank by CVSS severity. Falls back to the
//! CIRCL CVE search API when NVD is rate-limiting.
//!
//! NVD API 2.0 (no key, ~5 req/30s): keywordSearch queries.
//! CIRCL: https://cve.circl.lu/api/search/{product}/{version}

use crate::types::CveEntry;
use crate::util::parse_version;
use anyhow::{anyhow, Result};
use std::time::Duration;

/// Well-known CPE identifications for the products our fingerprinter
/// detects (mirrors the OpenVAS product-to-CPE dictionary).
fn cpe_for(product: &str) -> Option<(String, String)> {
    let p = product.to_ascii_lowercase();
    Some(match p.as_str() {
        "apache httpd" | "apache" | "apache http server" => ("apache".into(), "http_server".into()),
        "nginx" => ("nginx".into(), "nginx".into()),
        "openssh" => ("openbsd".into(), "openssh".into()),
        "dropbear" => ("matt".into(), "dropbear_ssh".into()),
        "proftpd" => ("proftpd".into(), "proftpd".into()),
        "vsftpd" => ("vsftpd".into(), "vsftpd".into()),
        "pure-ftpd" => ("pureftpd".into(), "pure-ftpd".into()),
        "mysql" => ("oracle".into(), "mysql".into()),
        "mariadb" => ("mariadb".into(), "mariadb".into()),
        "postgresql" => ("postgresql".into(), "postgresql".into()),
        "microsoft iis" | "iis" => ("microsoft".into(), "internet_information_server".into()),
        "microsoft sql server" => ("microsoft".into(), "sql_server".into()),
        "php" => ("php".into(), "php".into()),
        "apache tomcat" | "tomcat" => ("apache".into(), "tomcat".into()),
        "exim" => ("exim".into(), "exim".into()),
        "sendmail" => ("sendmail".into(), "sendmail".into()),
        "postfix" => ("postfix".into(), "postfix".into()),
        "dovecot" => ("dovecot".into(), "dovecot".into()),
        "courier imap" => ("courier".into(), "courier_imap_server".into()),
        "samba" => ("samba".into(), "samba".into()),
        "jenkins" => ("jenkins".into(), "jenkins".into()),
        "wordpress" => ("wordpress".into(), "wordpress".into()),
        "redis" => ("redis".into(), "redis".into()),
        "node.js" => ("nodejs".into(), "node.js".into()),
        "lighttpd" => ("lighttpd".into(), "lighttpd".into()),
        "openssl" => ("openssl".into(), "openssl".into()),
        "mongodb" => ("mongodb".into(), "mongodb".into()),
        "memcached" => ("memcached".into(), "memcached".into()),
        "elasticsearch" => ("elasticsearch".into(), "elasticsearch".into()),
        "varnish" => ("varnish".into(), "varnish_cache".into()),
        "jetty" => ("jetty".into(), "jetty".into()),
        "weblogic" => ("oracle".into(), "weblogic_server".into()),
        _ => return None,
    })
}

/// Map every (product, version) pair to real CVEs from NVD.
/// Friendly to the unauthenticated rate limit (7s spacing, capped queries).
pub async fn map_cves(
    products: &[(String, Option<String>)],
    http_timeout: Duration,
) -> Vec<CveEntry> {
    let mut out: Vec<CveEntry> = Vec::new();
    let client = match reqwest::Client::builder()
        .user_agent("NightCrawler/0.1 (recon agent)")
        .timeout(http_timeout)
        .build()
    {
        Ok(c) => c,
        Err(_) => return out,
    };

    let mut seen_products = std::collections::HashSet::new();
    let mut queries: Vec<(String, Option<String>)> = Vec::new(); // (product, version)
    for (product, version) in products {
        let p = product.trim();
        if p.is_empty() || !seen_products.insert(p.to_ascii_lowercase()) {
            continue;
        }
        queries.push((p.to_string(), version.clone()));
        if queries.len() >= 8 {
            break;
        }
    }

    let mut engine_note: Option<String> = None;
    for (i, (product, version)) in queries.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(Duration::from_secs(7)).await; // NVD unauth rate limit
        }
        match query_product(&client, product, version.as_deref()).await {
            Ok(entries) => {
                for e in entries {
                    if !out.iter().any(|x| x.id == e.id) {
                        out.push(e);
                    }
                }
            }
            Err(e) => {
                engine_note = Some(format!("{}: {}", product, e));
            }
        }
    }

    if out.is_empty() {
        if let Some(note) = engine_note {
            out.push(CveEntry {
                id: "NVD-UNAVAILABLE".into(),
                product: note,
                description: "CVE mapping engines unreachable or rate-limited — no NVD matches could be verified.".into(),
                severity: "INFO".into(),
                score: 0.0,
                url: String::new(),
            });
        }
    }

    out.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    out.truncate(60);
    out
}

async fn query_product(
    client: &reqwest::Client,
    product: &str,
    version: Option<&str>,
) -> Result<Vec<CveEntry>> {
    // 1) CPE identification + client-side version verification (OpenVAS-style)
    if let Some((vendor, prod)) = cpe_for(product) {
        if let Some(v) = version {
            let cpe = format!("cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*", vendor, prod, v);
            if let Ok(v_json) = nvd_query(client, &format!("cpeName={}", urlencode(&cpe))).await {
                let filtered = parse_nvd_filtered(&v_json, &vendor, &prod, Some(v));
                if !filtered.is_empty() {
                    return Ok(filtered);
                }
            }
        }
    }
    // 2) keyword search fallback
    let keyword = match (product, version) {
        (p, Some(v)) if !v.trim().is_empty() => format!("{} {}", p, v.trim()),
        (p, _) => p.to_string(),
    };
    if let Ok(v_json) = nvd_query(client, &format!("keywordSearch={}", urlencode(&keyword))).await {
        let entries = parse_nvd(&v_json)?;
        if !entries.is_empty() {
            return Ok(entries);
        }
    }
    // 3) CIRCL mirror
    circl_search(client, product, version).await
}

async fn nvd_query(client: &reqwest::Client, param: &str) -> Result<serde_json::Value> {
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?{}&resultsPerPage=200",
        param
    );
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await?;
    let status = resp.status();
    if status.as_u16() == 403 || status.as_u16() == 429 {
        return Err(anyhow!("NVD rate-limited (HTTP {})", status.as_u16()));
    }
    if !status.is_success() {
        return Err(anyhow!("NVD HTTP {}", status.as_u16()));
    }
    Ok(resp.json().await?)
}

/// Parse an NVD 2.0 response, keeping only CVEs whose CPE range actually
/// covers the detected product+version (OpenVAS-style version checking).
pub fn parse_nvd_filtered(
    v: &serde_json::Value,
    vendor: &str,
    product: &str,
    version: Option<&str>,
) -> Vec<CveEntry> {
    let mut out = Vec::new();
    let vulns = match v.get("vulnerabilities").and_then(|x| x.as_array()) {
        Some(a) => a,
        None => return out,
    };
    for item in vulns {
        let cve = match item.get("cve") {
            Some(c) => c,
            None => continue,
        };
        if !cpe_covers(cve, vendor, product, version) {
            continue;
        }
        if let Some(mut e) = cve_to_entry(cve) {
            e.product = product.to_string();
            out.push(e);
        }
    }
    out
}

/// Parse an NVD response without CPE filtering (keyword path).
pub fn parse_nvd(v: &serde_json::Value) -> Result<Vec<CveEntry>> {
    let vulns = v
        .get("vulnerabilities")
        .and_then(|x| x.as_array())
        .ok_or_else(|| anyhow!("no vulnerabilities array"))?;
    let mut out = Vec::new();
    for item in vulns.iter().take(20) {
        if let Some(cve) = item.get("cve") {
            if let Some(e) = cve_to_entry(cve) {
                out.push(e);
            }
        }
    }
    Ok(out)
}

fn cve_to_entry(cve: &serde_json::Value) -> Option<CveEntry> {
    let id = cve.get("id")?.as_str()?.to_string();
    let desc = cve
        .get("descriptions")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en"))
                .or_else(|| arr.first())
                .and_then(|d| d.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        })
        .unwrap_or_default();
    let (score, severity) = extract_cvss(cve);
    let url = format!("https://nvd.nist.gov/vuln/detail/{}", id);
    Some(CveEntry {
        id,
        product: String::new(),
        description: desc,
        severity,
        score,
        url,
    })
}

/// True when any of the CVE's CPE match criteria covers vendor:product at
/// exactly `version` (or within a declared version range).
fn cpe_covers(cve: &serde_json::Value, vendor: &str, product: &str, version: Option<&str>) -> bool {
    let ver = match version {
        Some(v) if !v.trim().is_empty() => v.trim(),
        _ => return false,
    };
    let target = parse_version(ver);
    let empty: Vec<serde_json::Value> = Vec::new();
    for conf in cve.get("configurations").and_then(|c| c.as_array()).unwrap_or(&empty) {
        for node in conf.get("nodes").and_then(|n| n.as_array()).unwrap_or(&empty) {
            for m in node.get("cpeMatch").and_then(|c| c.as_array()).unwrap_or(&empty) {
                let criteria = m.get("criteria").and_then(|c| c.as_str()).unwrap_or("");
                let parts: Vec<&str> = criteria.split(':').collect();
                if parts.len() < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
                    continue;
                }
                let (c_vendor, c_product, c_version) = (parts[3], parts[4], parts[5]);
                if c_vendor != vendor || c_product != product {
                    continue;
                }
                if c_version == ver {
                    return true;
                }
                if let Some(t) = target {
                    let start_incl = m.get("versionStartIncluding").and_then(|x| x.as_str());
                    let end_incl = m.get("versionEndIncluding").and_then(|x| x.as_str());
                    let end_excl = m.get("versionEndExcluding").and_then(|x| x.as_str());
                    if let Some(lo) = start_incl {
                        if let Some(l) = parse_version(lo) {
                            if t < l {
                                continue;
                            }
                        }
                    }
                    if let Some(hi) = end_incl {
                        if let Some(h) = parse_version(hi) {
                            if t > h {
                                continue;
                            }
                        }
                        return true;
                    }
                    if let Some(hi) = end_excl {
                        if let Some(h) = parse_version(hi) {
                            if t >= h {
                                continue;
                            }
                        }
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn extract_cvss(cve: &serde_json::Value) -> (f64, String) {
    for key in ["metrics"] {
        let metrics = match cve.get(key).and_then(|m| m.as_object()) {
            Some(m) => m,
            None => return (0.0, "UNKNOWN".into()),
        };
        for metric in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
            if let Some(arr) = metrics.get(metric).and_then(|m| m.as_array()) {
                if let Some(first) = arr.first() {
                    let data = first.get("cvssData").unwrap_or(first);
                    let score = data
                        .get("baseScore")
                        .and_then(|s| s.as_f64())
                        .unwrap_or(0.0);
                    let severity = data
                        .get("baseSeverity")
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_uppercase())
                        .or_else(|| first.get("baseSeverity").and_then(|s| s.as_str()).map(|s| s.to_uppercase()))
                        .unwrap_or_else(|| {
                            if score >= 9.0 {
                                "CRITICAL".into()
                            } else if score >= 7.0 {
                                "HIGH".into()
                            } else if score >= 4.0 {
                                "MEDIUM".into()
                            } else if score > 0.0 {
                                "LOW".into()
                            } else {
                                "UNKNOWN".into()
                            }
                        });
                    return (score, severity);
                }
            }
        }
    }
    (0.0, "UNKNOWN".into())
}

/// CIRCL CVE-search fallback (used by many scanners as a mirror).
pub async fn circl_search(
    client: &reqwest::Client,
    product: &str,
    _version: Option<&str>,
) -> Result<Vec<CveEntry>> {
    let url = format!(
        "https://cve.circl.lu/api/search/{}",
        urlencode(&product.to_ascii_lowercase().replace(' ', "_"))
    );
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow!("CIRCL HTTP {}", status));
    }
    let v: serde_json::Value = resp.json().await?;
    let arr = v
        .as_array()
        .ok_or_else(|| anyhow!("CIRCL: unexpected shape"))?;
    let mut out = Vec::new();
    for item in arr.iter().take(15) {
        let id = item
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string();
        if id.is_empty() {
            continue;
        }
        let desc = item
            .get("summary")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string();
        out.push(CveEntry {
            id: id.clone(),
            product: String::new(),
            description: desc,
            severity: "UNKNOWN".into(),
            score: 0.0,
            url: format!("https://nvd.nist.gov/vuln/detail/{}", id),
        });
    }
    Ok(out)
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvd_response_parsed() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{
              "vulnerabilities": [
                {"cve": {"id": "CVE-2015-3306",
                  "descriptions": [{"lang":"en","value":"The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write to arbitrary files."}],
                  "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}
              ]
            }"#,
        )
        .unwrap();
        let entries = parse_nvd(&v).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "CVE-2015-3306");
        assert_eq!(entries[0].severity, "CRITICAL");
        assert!((entries[0].score - 9.8).abs() < 0.01);
        assert!(entries[0].description.contains("mod_copy"));
    }

    #[test]
    fn cvss_v2_fallback() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"vulnerabilities":[{"cve":{"id":"CVE-2012-2122","descriptions":[{"lang":"en","value":"auth bypass"}],
              "metrics":{"cvssMetricV2":[{"cvssData":{"baseScore":7.5,"baseSeverity":"MEDIUM"}}]}}}]}"#,
        )
        .unwrap();
        let entries = parse_nvd(&v).unwrap();
        assert_eq!(entries[0].severity, "MEDIUM");
        assert!((entries[0].score - 7.5).abs() < 0.01);
    }
}
