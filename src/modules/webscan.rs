//! OWASP ZAP-style web application scanning: passive and active checks
//! against each discovered HTTP endpoint, producing ZAP-like alerts
//! (plugin name, risk, confidence, detail, solution).

use crate::types::WebAlert;
use anyhow::Result;
use std::time::Duration;

/// Run passive + active ZAP-style checks against one endpoint.
pub async fn scan_url(
    client: &reqwest::Client,
    url: &str,
    http: &crate::types::HttpInfo,
) -> Vec<WebAlert> {
    let mut alerts: Vec<WebAlert> = Vec::new();
    let base = url.trim_end_matches('/');

    // ---------------- passive checks (headers/cookies/body) ----------------
    passive_checks(http, base, &mut alerts);

    // ---------------- active checks (crafted probes) -----------------------
    // XSS reflection probe
    if let Some(a) = xss_probe(client, base).await {
        alerts.push(a);
    }
    // SQL injection error-based probe on a test param
    if let Some(a) = sqli_probe(client, base).await {
        alerts.push(a);
    }
    // path traversal probe
    if let Some(a) = traversal_probe(client, base).await {
        alerts.push(a);
    }
    // TRACE method / cross-site tracing
    if let Some(a) = trace_probe(client, base).await {
        alerts.push(a);
    }
    // OPTIONS — method disclosure
    if let Some(a) = options_probe(client, base).await {
        alerts.push(a);
    }
    // open redirect probe (only when a redirect param is hinted by robots/dir findings is unreliable — test common param)
    if let Some(a) = redirect_probe(client, base).await {
        alerts.push(a);
    }
    // host header injection
    if let Some(a) = host_header_probe(client, base).await {
        alerts.push(a);
    }
    // old files / backup probing is covered by subdir brute — skip.

    alerts
}

fn passive_checks(http: &crate::types::HttpInfo, base: &str, alerts: &mut Vec<WebAlert>) {
    let hdr = |name: &str| -> Option<String> {
        http.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let has = |name: &str| hdr(name).is_some();

    // ZAP 10038: multiple X-Frame-Options / clickjacking missing
    if !has("x-frame-options") && !has("content-security-policy") {
        alerts.push(WebAlert {
            plugin: "10098 Cross-Domain Misconfiguration / Clickjacking".into(),
            risk: "Medium".into(),
            confidence: "Medium".into(),
            url: base.into(),
            detail: "Neither X-Frame-Options nor a frame-ancestors CSP is set — the page may be clickjackable.".into(),
            solution: "Set `X-Frame-Options: DENY` or add `frame-ancestors 'none'` to the Content-Security-Policy.".into(),
            reference: Some("https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options".into()),
        });
    }
    // ZAP 10035: HSTS missing
    if !has("strict-transport-security") {
        alerts.push(WebAlert {
            plugin: "10035 Strict-Transport-Security Missing".into(),
            risk: "Low".into(),
            confidence: "High".into(),
            url: base.into(),
            detail: "The response does not enforce HSTS, allowing downgrade/interception.".into(),
            solution: "Serve `Strict-Transport-Security: max-age=31536000; includeSubDomains` over HTTPS.".into(),
            reference: None,
        });
    }
    // ZAP 10021: X-Content-Type-Options missing (MIME sniffing)
    if !has("x-content-type-options") {
        alerts.push(WebAlert {
            plugin: "10021 X-Content-Type-Options Missing".into(),
            risk: "Low".into(),
            confidence: "High".into(),
            url: base.into(),
            detail: "Browsers may MIME-sniff responses, enabling content-type confusion.".into(),
            solution: "Add `X-Content-Type-Options: nosniff`.".into(),
            reference: None,
        });
    }
    // ZAP 10027: information disclosure — server banner
    if let Some(server) = hdr("server") {
        if server.len() > 3 {
            alerts.push(WebAlert {
                plugin: "10027 Information Disclosure — Server Banner".into(),
                risk: "Informational".into(),
                confidence: "High".into(),
                url: base.into(),
                detail: format!("Server header reveals software: `{server}`."),
                solution: "Minimize the banner (`ServerTokens Prod` for Apache) or remove it.".into(),
                reference: None,
            });
        }
    }
    // cookie flags
    for c in &http.cookies {
        let l = c.to_ascii_lowercase();
        if l.contains("sessionid") || l.contains("phpsessid") || l.contains("sess") || l.contains("token") {
            let secure = l.contains("secure");
            let httponly = l.contains("httponly");
            if !secure || !httponly {
                alerts.push(WebAlert {
                    plugin: "10011 Cookie Without Secure/HttpOnly Flag".into(),
                    risk: if !secure { "Medium" } else { "Low" }.into(),
                    confidence: "High".into(),
                    url: base.into(),
                    detail: format!(
                        "Session cookie `{}` missing {}{}.",
                        c.split(';').next().unwrap_or("").split('=').next().unwrap_or(""),
                        if secure { "" } else { "Secure " },
                        if httponly { "" } else { "HttpOnly" }
                    ),
                    solution: "Set both `Secure` and `HttpOnly` attributes on session cookies.".into(),
                    reference: None,
                });
            }
        }
    }
    // robots.txt disallow enumeration = hidden paths worth probing
    if !http.robots_disallow.is_empty() {
        alerts.push(WebAlert {
            plugin: "Custom Passive — robots.txt Discloses Hidden Paths".into(),
            risk: "Informational".into(),
            confidence: "High".into(),
            url: format!("{}/robots.txt", base),
            detail: format!("robots.txt disallows {} paths: {}", http.robots_disallow.len(), http.robots_disallow.iter().take(6).cloned().collect::<Vec<_>>().join(", ")),
            solution: "robots.txt is public — do not use it to hide sensitive endpoints; protect them with authentication.".into(),
            reference: None,
        });
    }
}

async fn xss_probe(client: &reqwest::Client, base: &str) -> Option<WebAlert> {
    // reflect a benign marker via a common parameter on the root
    let marker = "ncxss7f9a";
    let url = format!("{}/?q=<script>{}()</script>&search=<b>{}</b>&id=<i>{}</i>", base, marker, marker, marker);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let resp_len = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let body = resp.text().await.ok()?;
    if status != 200 || body.is_empty() {
        return None;
    }
    if body.contains(&format!("<script>{}()</script>", marker)) {
        return Some(WebAlert {
            plugin: "40012 Reflected XSS (parameter reflection)".into(),
            risk: "High".into(),
            confidence: "Medium".into(),
            url,
            detail: format!("The parameter value `<script>{}</script>` is reflected unencoded into the response — stored/reflected XSS is likely.", marker),
            solution: "Contextual output encoding; frameworks' auto-escaping; CSP as a second line of defense.".into(),
            reference: Some("https://owasp.org/www-community/attacks/xss/".into()),
        });
    }
    if body.contains(marker) {
        return Some(WebAlert {
            plugin: "10021-Reflex Parameter Reflected (potential XSS)".into(),
            risk: "Low".into(),
            confidence: "Low".into(),
            url,
            detail: format!("Input `{}` is reflected into the page but HTML tags are filtered/encoded. Verify which contexts it lands in.", marker),
            solution: "Ensure all contexts (attribute, JS, URL) are encoded; test event-handler injection.".into(),
            reference: None,
        });
    }
    None
}

async fn sqli_probe(client: &reqwest::Client, base: &str) -> Option<WebAlert> {
    let normal = client.get(base).send().await.ok()?;
    let normal_len = normal.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let normal_body = normal.text().await.unwrap_or_default();

    let url = format!("{}/?id=1%27%20OR%20%271%27%3D%271&cat=2%27&user=3%27", base);
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let resp_len = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let body = resp.text().await.ok()?;

    let mut signals: Vec<&str> = Vec::new();
    for db_err in [
        "SQL syntax",
        "MySQL",
        "MariaDB",
        "you have an error in your sql",
        "Warning: mysql_",
        "PostgreSQL",
        "SQLite",
        "unterminated quoted string",
        "Unclosed quotation mark",
    ] {
        if body.contains(db_err) {
            signals.push(db_err);
        }
    }
    if !signals.is_empty() {
        return Some(WebAlert {
            plugin: "40018 SQL Injection (error-based)".into(),
            risk: "High".into(),
            confidence: "High".into(),
            url,
            detail: format!("Quote injection produced a database error (signals: {}). The parameter is likely injectable.", signals.join(", ")),
            solution: "Parameterized queries; ORM; input validation; WAF as a mitigation only.".into(),
            reference: Some("https://owasp.org/www-community/attacks/SQL_Injection".into()),
        });
    }
    // blind signal: boolean-based size divergence

    if status == 200
        && normal_len > 0
        && resp_len > 0
        && (resp_len as f64 / normal_len as f64) < 0.55
        && !body.contains("404")
        && normal_body.len() > 200
    {
        return Some(WebAlert {
            plugin: "40018-B SQL Injection (boolean-based heuristic)".into(),
            risk: "Medium".into(),
            confidence: "Low".into(),
            url,
            detail: format!("The injected payload shrinks the response {}% vs baseline ({}B → {}B). Test with sqlmap to confirm.", (100 - (resp_len * 100 / normal_len.max(1))), normal_len, resp_len),
            solution: "Parameterized queries. Confirm with `sqlmap -u <url> --batch` before remediation.".into(),
            reference: Some("https://github.com/sqlmapproject/sqlmap".into()),
        });
    }
    None
}

async fn traversal_probe(client: &reqwest::Client, base: &str) -> Option<WebAlert> {
    let url = format!("{}/?file=../../../../etc/passwd&page=..%2f..%2f..%2fetc%2fpasswd", base);
    let resp = client.get(&url).send().await.ok()?;
    let body = resp.text().await.ok()?;
    if body.contains("root:x:0:0:") {
        return Some(WebAlert {
            plugin: "40028 Path Traversal — /etc/passwd Read".into(),
            risk: "High".into(),
            confidence: "High".into(),
            url,
            detail: "A traversal payload returned the contents of /etc/passwd — arbitrary file read is confirmed.".into(),
            solution: "Normalize and validate paths; serve files via an allowlist; never pass user input to filesystem APIs.".into(),
            reference: Some("https://owasp.org/www-community/attacks/Path_Traversal".into()),
        });
    }
    None
}

async fn trace_probe(client: &reqwest::Client, base: &str) -> Option<WebAlert> {
    let resp = client.request(reqwest::Method::TRACE, base).send().await.ok()?;
    if resp.status().is_success() {
        let body = resp.text().await.ok()?;
        if body.contains("TRACE") {
            return Some(WebAlert {
                plugin: "20003 Cross-Site Tracing (TRACE Enabled)".into(),
                risk: "Low".into(),
                confidence: "Medium".into(),
                url: base.into(),
                detail: "TRACE method is enabled and reflects request content (XST aids header theft via XSS).".into(),
                solution: "Disable the TRACE method at the web server.".into(),
                reference: None,
            });
        }
    }
    None
}

async fn options_probe(client: &reqwest::Client, base: &str) -> Option<WebAlert> {
    let resp = client.request(reqwest::Method::OPTIONS, base).send().await.ok()?;
    let allow = resp
        .headers()
        .get("allow")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let risky = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"];
    let found: Vec<&str> = risky.iter().copied().filter(|m| allow.contains(m)).collect();
    if !found.is_empty() {
        return Some(WebAlert {
            plugin: "20002 Dangerous HTTP Methods Enabled".into(),
            risk: if found.contains(&"PUT") { "Medium" } else { "Low" }.into(),
            confidence: "High".into(),
            url: base.into(),
            detail: format!("OPTIONS discloses risky methods: {}.", found.join(", ")),
            solution: "Disable unused methods; restrict PUT/DELETE behind authentication.".into(),
            reference: None,
        });
    }
    None
}

async fn redirect_probe(client: &reqwest::Client, base: &str) -> Option<WebAlert> {
    let url = format!("{}/?url=https://example.org&redirect=https://example.org&next=https://example.org&goto=https://example.org", base);
    let resp = client.get(&url).send().await.ok()?;
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let _ = resp.status();
    if loc.contains("example.org") {
        return Some(WebAlert {
            plugin: "20006 Open Redirect".into(),
            risk: "Medium".into(),
            confidence: "High".into(),
            url,
            detail: format!("The endpoint redirects to the attacker-supplied `example.org` (Location: {}). Useful for phishing and token theft.", loc),
            solution: "Validate redirect targets against an allowlist; use server-side mapping for navigation parameters.".into(),
            reference: Some("https://owasp.org/www-community/attacks/Null_Code_Injection".into()),
        });
    }
    None
}

async fn host_header_probe(client: &reqwest::Client, base: &str) -> Option<WebAlert> {
    let evil = "evil.example.org";
    let resp = client
        .get(base)
        .header("Host", evil)
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.ok()?;
    if status == 200 && (body.contains(evil) || body.contains(&format!("//{}", evil)) || body.contains(&format!("http://{}", evil))) {
        return Some(WebAlert {
            plugin: "40027 Host Header Injection".into(),
            risk: "Medium".into(),
            confidence: "Medium".into(),
            url: base.into(),
            detail: "The application echoes an attacker-controlled Host header into the response (password-reset poisoning, cache poisoning vectors).".into(),
            solution: "Never trust Host; validate it against a whitelist; configure the server's canonical host.".into(),
            reference: Some("https://portswigger.net/web-security/host-header".into()),
        });
    }
    None
}

/// Run the full ZAP pass over every discovered web root.
pub async fn scan_all(
    roots: Vec<(String, crate::types::HttpInfo)>,
    http_timeout: Duration,
) -> Result<Vec<crate::types::WebScanResult>> {
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 NightCrawler/ZAP")
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(http_timeout)
        .build()?;
    // parallel across roots (bounded) — client is Arc-shared so the
    // stream stays Send-safe inside spawned tasks
    use futures::stream::{self, StreamExt};
    use std::sync::Arc;
    let client = Arc::new(client);
    let out: Vec<crate::types::WebScanResult> = stream::iter(roots.into_iter())
        .map(|(url, http)| {
            let client = client.clone();
            let url = url.clone();
            let http = http.clone();
            async move {
                let alerts = scan_url(&client, &url, &http).await;
                crate::types::WebScanResult { url, alerts }
            }
        })
        .buffer_unordered(6)
        .collect()
        .await;
    Ok(out)
}
