use crate::config::{resolve_cse_cx, resolve_cse_key, Config};
use crate::types::DorkResult;
use crate::util::pct_decode;
use anyhow::Result;
use std::time::Duration;

pub fn build_dorks(domain: &str) -> Vec<String> {
    vec![
        format!("site:{}", domain),
        format!("site:{} inurl:admin", domain),
        format!("site:{} inurl:login", domain),
        format!("site:{} inurl:signup OR inurl:register", domain),
        format!("site:{} intitle:\"index of\"", domain),
        format!("site:{} filetype:pdf", domain),
        format!("site:{} filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx", domain),
        format!("site:{} filetype:env OR filetype:bak OR filetype:sql", domain),
        format!("site:{} inurl:api", domain),
        format!("site:{} inurl:wp-admin OR inurl:wp-content", domain),
        format!("site:{} intitle:\"admin\" OR intitle:\"administrator\"", domain),
        format!("site:{} \"index.php?\" inurl:include OR inurl:page", domain),
        format!("site:pastebin.com \"{}\"", domain),
        format!("site:{} inurl:config OR inurl:settings", domain),
        format!("site:{} intext:\"username\" OR intext:\"password\" filetype:log OR filetype:txt", domain),
        format!("site:github.com OR site:gitlab.com \"{}\"", domain),
    ]
}

/// Build CVE-mapping queries for every detected product/version pair.
pub fn build_cve_queries(products: &[(String, Option<String>)]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (product, version) in products {
        let p = product.trim();
        if p.is_empty() {
            continue;
        }
        let q = match version {
            Some(v) if !v.trim().is_empty() => format!("{} {} CVE vulnerability exploit", p, v.trim()),
            _ => format!("{} known vulnerabilities CVE exploit", p),
        };
        if seen.insert(q.clone()) {
            out.push(q);
        }
    }
    out.truncate(8);
    out
}

/// Execute dorks with the best available engine:
/// Google Programmable Search (CSE) > SerpAPI > DuckDuckGo (no key needed).
pub async fn run_dorks(
    domain: &str,
    cfg: &Config,
    max_per_dork: usize,
) -> Result<Vec<DorkResult>> {
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
        .timeout(Duration::from_secs(25))
        .build()?;

    let dorks = build_dorks(domain);
    let mut out: Vec<DorkResult> = Vec::new();

    for (i, q) in dorks.iter().enumerate() {
        if resolve_cse_key(cfg).is_none() && cfg.dorking.serpapi_key.is_none() && i > 0 {
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }

        let (engine, results, err): (String, Vec<String>, Option<String>) =
            if let Some(key) = resolve_cse_key(cfg) {
                let cx = resolve_cse_cx(cfg);
                match google_cse(&client, &key, &cx, q, max_per_dork).await {
                    Ok(r) => ("google-cse".into(), r, None),
                    Err(e) => ("google-cse".into(), vec![], Some(e.to_string())),
                }
            } else if let Some(key) = &cfg.dorking.serpapi_key {
                match serpapi(&client, key, q, max_per_dork).await {
                    Ok(r) => ("serpapi".into(), r, None),
                    Err(e) => ("serpapi".into(), vec![], Some(e.to_string())),
                }
            } else {
                match duckduckgo(&client, q, max_per_dork).await {
                    Ok(r) => ("duckduckgo".into(), r, None),
                    Err(e) => ("duckduckgo".into(), vec![], Some(e.to_string())),
                }
            };

        out.push(DorkResult {
            query: q.clone(),
            engine,
            results,
            error: err,
        });
    }
    Ok(out)
}

/// CVE mapping: search the Google Programmable Search Engine for each
/// detected product/version's known vulnerabilities and exploits.
pub async fn run_cve_search(
    products: &[(String, Option<String>)],
    cfg: &Config,
    max_per_query: usize,
) -> Vec<DorkResult> {
    let key = match resolve_cse_key(cfg) {
        Some(k) => k,
        None => return Vec::new(), // caller marks the phase skipped
    };
    let cx = resolve_cse_cx(cfg);
    let client = match reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
        .timeout(Duration::from_secs(20))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for q in build_cve_queries(products) {
        let (results, err) = match google_cse(&client, &key, &cx, &q, max_per_query).await {
            Ok(r) => (r, None),
            Err(e) => (vec![], Some(e.to_string())),
        };
        out.push(DorkResult {
            query: format!("cve: {}", q),
            engine: "google-cse".into(),
            results,
            error: err,
        });
        tokio::time::sleep(Duration::from_millis(350)).await;
    }
    out
}

/// Google Programmable Search Engine — official JSON API.
pub async fn google_cse(
    client: &reqwest::Client,
    key: &str,
    cx: &str,
    query: &str,
    max: usize,
) -> Result<Vec<String>> {
    let url = format!(
        "https://www.googleapis.com/customsearch/v1?key={}&cx={}&num={}&q={}",
        key,
        cx,
        max.min(10),
        urlencode(query)
    );
    let resp: serde_json::Value = client.get(&url).send().await?.error_for_status()?.json().await?;
    parse_cse_response(&resp, max)
}

/// Parse a CSE API response — unit-testable.
pub fn parse_cse_response(v: &serde_json::Value, max: usize) -> Result<Vec<String>> {
    let mut links = Vec::new();
    if let Some(items) = v.get("items").and_then(|i| i.as_array()) {
        for it in items.iter().take(max) {
            if let Some(l) = it.get("link").and_then(|l| l.as_str()) {
                links.push(l.to_string());
            }
        }
    }
    Ok(links)
}

async fn serpapi(
    client: &reqwest::Client,
    key: &str,
    query: &str,
    max: usize,
) -> Result<Vec<String>> {
    let url = format!(
        "https://serpapi.com/search.json?engine=google&num={}&q={}&api_key={}",
        max.min(20),
        urlencode(query),
        key
    );
    let resp: serde_json::Value = client.get(&url).send().await?.error_for_status()?.json().await?;
    let mut links = Vec::new();
    if let Some(items) = resp.get("organic_results").and_then(|v| v.as_array()) {
        for it in items.iter().take(max) {
            if let Some(l) = it.get("link").and_then(|v| v.as_str()) {
                links.push(l.to_string());
            }
        }
    }
    Ok(links)
}

/// No-key fallback: parse the DuckDuckGo HTML endpoint.
async fn duckduckgo(
    client: &reqwest::Client,
    query: &str,
    max: usize,
) -> Result<Vec<String>> {
    let resp = client
        .post("https://html.duckduckgo.com/html/")
        .form(&[("q", query)])
        .send()
        .await?;
    let status = resp.status().as_u16();
    let body = resp.text().await?;
    if status == 403 || status == 429 {
        return Err(anyhow::anyhow!("DDG rate-limited (HTTP {})", status));
    }
    let lower = body.to_ascii_lowercase();
    if lower.contains("anomaly") || lower.contains("unusual traffic") || lower.contains("captcha") {
        return Err(anyhow::anyhow!("DDG anti-bot challenge (no CSE key configured)"));
    }
    let re = regex::Regex::new(r#"uddg=([^"&]+)"#)?;
    let mut links: Vec<String> = Vec::new();
    for cap in re.captures_iter(&body) {
        let url = pct_decode(&cap[1]);
        if url.starts_with("http") && !links.contains(&url) {
            links.push(url);
        }
        if links.len() >= max {
            break;
        }
    }
    if links.is_empty() && body.len() < 2000 {
        return Err(anyhow::anyhow!("DDG returned no/blocked content"));
    }
    Ok(links)
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
    fn cse_response_parsed() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"items": [{"link": "https://nvd.nist.gov/vuln/detail/CVE-2015-3306"},
                          {"link": "https://www.exploit-db.com/exploits/36742"}]}"#,
        )
        .unwrap();
        let links = parse_cse_response(&v, 10).unwrap();
        assert_eq!(links.len(), 2);
        assert!(links[0].contains("CVE-2015-3306"));
    }

    #[test]
    fn cse_response_empty_is_ok() {
        let v: serde_json::Value = serde_json::from_str("{}").unwrap();
        assert!(parse_cse_response(&v, 10).unwrap().is_empty());
    }

    #[test]
    fn cve_queries_built() {
        let q = build_cve_queries(&[
            ("ProFTPD".into(), Some("1.3.5".into())),
            ("Apache httpd".into(), Some("2.4.7".into())),
            ("ProFTPD".into(), Some("1.3.5".into())), // dedup
        ]);
        assert_eq!(q.len(), 2);
        assert!(q[0].contains("ProFTPD 1.3.5"));
        assert!(q[0].contains("CVE"));
    }
}
