use crate::types::DirResult;
use crate::util::html_title;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use rand::Rng;
use std::time::Duration;

pub const DEFAULT_DIRS: &str = include_str!("../assets/dirs.txt");

struct Target {
    base: String, // http://host:port or https://host:port (no trailing slash)
}

/// Brute-force common web paths over one or more HTTP endpoints.
pub async fn discover(
    bases: &[String],
    wordlist: Option<Vec<String>>,
    max_results: usize,
    concurrency: usize,
) -> Result<Vec<DirResult>> {
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 NightCrawler/0.1")
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;

    let mut targets: Vec<Target> = Vec::new();
    for b in bases {
        let t = b.trim_end_matches('/');
        targets.push(Target { base: t.to_string() });
    }

    let mut words: Vec<String> = wordlist.unwrap_or_else(|| {
        DEFAULT_DIRS
            .lines()
            .map(|l| l.trim().trim_start_matches('/').to_string())
            .filter(|l| !l.is_empty())
            .collect()
    });

    // Pull in robots.txt disallows as candidate paths too
    for t in &targets {
        if let Ok(resp) = client.get(format!("{}/robots.txt", t.base)).send().await {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                for line in body.lines() {
                    let l = line.trim();
                    if let Some(p) = l.to_ascii_lowercase().strip_prefix("disallow:") {
                        let p = p.trim().trim_matches('/');
                        if !p.is_empty() {
                            words.push(p.to_string());
                        }
                    }
                }
            }
        }
    }
    words.sort();
    words.dedup();

    // Soft-404 baseline per target
    let mut baselines: Vec<(u16, u64)> = Vec::new();
    for t in &targets {
        let rnd: u32 = rand::thread_rng().gen();
        let probe = format!("{}/nonexistent-nc-{}", t.base, rnd);
        let (status, len) = fetch_meta(&client, &probe).await;
        baselines.push((status, len));
    }

    let mut jobs: Vec<(String, String)> = Vec::new();
    for (ti, t) in targets.iter().enumerate() {
        let _ = ti;
        for w in &words {
            jobs.push((t.base.clone(), w.clone()));
        }
    }

    let baselines = &baselines;
    let results = stream::iter(jobs.into_iter().map(|(base, word)| {
        let client = &client;
        let url = format!("{}/{}", base, word);
        async move {
            let (status, len) = fetch_meta(client, &url).await;
            (url, status, len)
        }
    }))
    .buffer_unordered(concurrency)
    .collect::<Vec<(String, u16, u64)>>()
    .await;

    let mut out: Vec<DirResult> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let _ = baselines;

    for (url, status, len) in results {
        if matches!(status, 200..=299 | 401 | 403) && status != 404 {
            if !seen.insert(url.clone()) {
                continue;
            }
            let note = match status {
                200 => "found (200)",
                301 | 302 | 308 => "redirect",
                401 => "auth required",
                403 => "forbidden (maybe enumeratable)",
                _ => "interesting status",
            };
            out.push(DirResult {
                url,
                status,
                length: len,
                title: None,
                note: note.into(),
            });
        }
    }

    // Grab titles for the top 200 hits — small burst
    let title_jobs: Vec<(usize, String)> = out
        .iter()
        .enumerate()
        .filter(|(_, d)| d.status == 200)
        .take(40)
        .map(|(i, d)| (i, d.url.clone()))
        .collect();

    for (idx, url) in title_jobs {
        if let Some(Some(t)) = fetch_title(&client, &url).await {
            out[idx].title = Some(t);
        }
    }

    out.sort_by(|a, b| a.status.cmp(&b.status).then(a.url.cmp(&b.url)));
    out.truncate(max_results);
    Ok(out)
}

async fn fetch_meta(client: &reqwest::Client, url: &str) -> (u16, u64) {
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let len = resp
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            (status, len)
        }
        Err(_) => (0, 0),
    }
}

async fn fetch_title(client: &reqwest::Client, url: &str) -> Option<Option<String>> {
    let resp = client.get(url).send().await.ok()?;
    let status = resp.status().as_u16();
    if status != 200 {
        return Some(None);
    }
    let body = resp.text().await.ok()?;
    Some(html_title(&body))
}

/// Identify which base URLs to scan (from open web ports).
pub fn web_bases(host: &str, open_ports: &[u16]) -> Vec<String> {
    let mut bases: Vec<String> = Vec::new();
    for p in open_ports {
        let scheme = match p {
            443 | 8443 | 4443 | 4444 => "https",
            80 | 8080 | 8000 | 8081 | 8888 | 3000 | 5000 | 7000 | 7777 | 9090 | 8090 => "http",
            _ => continue,
        };
        if *p == 80 {
            bases.push(format!("http://{}", host));
        } else if *p == 443 {
            bases.push(format!("https://{}", host));
        } else {
            bases.push(format!("{}://{}:{}", scheme, host, p));
        }
    }
    bases
}
