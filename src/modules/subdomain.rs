use crate::types::SubdomainResult;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use hickory_resolver::TokioAsyncResolver;
use rand::Rng;

pub const DEFAULT_SUBS: &str = include_str!("../assets/subdomains.txt");

/// Combine certificate-transparency (crt.sh) + dictionary brute force.
pub async fn enumerate(
    resolver: &TokioAsyncResolver,
    domain: &str,
    wordlist: Option<Vec<String>>,
    max: usize,
) -> Result<Vec<SubdomainResult>> {
    let mut found: Vec<SubdomainResult> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut wildcard_ips: Vec<String> = Vec::new();

    // Wildcard detection — so brute hits can be filtered
    let probe = format!("wildcard-nc-{}", rand::thread_rng().gen::<u32>());
    for ip in crate::modules::dnsrecon::resolve_a(resolver, &format!("{}.{}", probe, domain)).await {
        wildcard_ips.push(ip.to_string());
    }

    // 1. Certificate transparency via crt.sh
    let ct_names = ct_lookup(domain).await.unwrap_or_default();
    for name in ct_names {
        if seen.insert(name.clone()) {
            let ips = crate::modules::dnsrecon::resolve_a(resolver, &name)
                .await
                .into_iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>();
            if !ips.is_empty() {
                found.push(SubdomainResult {
                    name,
                    ips,
                    source: "crt.sh".into(),
                });
            }
        }
    }

    // 2. Dictionary brute force
    let words: Vec<String> = wordlist
        .unwrap_or_else(|| {
            DEFAULT_SUBS
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        });

    let results = stream::iter(words.into_iter().map(|w| {
        let fqdn = format!("{}.{}", w, domain);
        let fqdn = fqdn.clone();
        async move {
            let ips = crate::modules::dnsrecon::resolve_a(resolver, &fqdn).await;
            (fqdn, ips)
        }
    }))
    .buffer_unordered(64)
    .collect::<Vec<(String, Vec<std::net::IpAddr>)>>()
    .await;

    for (fqdn, ips) in results {
        if ips.is_empty() {
            continue;
        }
        // filter wildcard-only hits
        let ip_strs: Vec<String> = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>();
        if !wildcard_ips.is_empty()
            && ip_strs
                .iter()
                .all(|ip| wildcard_ips.contains(ip))
            && found.iter().all(|f| f.name != fqdn)
        {
            // everything matched the wildcard probe: skip unless CT already validated it
            continue;
        }
        if seen.insert(fqdn.clone()) {
            found.push(SubdomainResult {
                name: fqdn,
                ips: ip_strs,
                source: "brute".into(),
            });
        }
    }

    found.truncate(max);
    found.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(found)
}

/// Query crt.sh JSON API for %-wildcard subdomains.
pub async fn ct_lookup(domain: &str) -> Result<Vec<String>> {
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 NightCrawler/0.1 (recon)")
        .timeout(std::time::Duration::from_secs(45))
        .build()?;
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let resp = client.get(&url).send().await?.error_for_status()?;
    let entries: serde_json::Value = resp.json().await?;
    let arr = entries
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("crt.sh returned non-array"))?;

    let domain = domain.to_ascii_lowercase();
    let mut names: Vec<String> = Vec::new();
    for e in arr {
        if let Some(nv) = e.get("name_value").and_then(|v| v.as_str()) {
            for n in nv.split_whitespace() {
                let n = n.trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();
                if n.ends_with(&domain) && n.len() > domain.len() {
                    names.push(n);
                }
            }
        }
        if let Some(cn) = e.get("common_name").and_then(|v| v.as_str()) {
            let cn = cn.trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();
            if cn.ends_with(&domain) && cn.len() > domain.len() {
                names.push(cn);
            }
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}
