//! The NightCrawler decision engine.
//!
//! Every decision is bounded: the model picks from a fixed menu of
//! capabilities, returns strict JSON, and every response is validated
//! before execution. The AGENTS.md doctrine (embedded below) is the
//! persona and operating protocol for every call.

use crate::ai::NvClient;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

/// The agent's operating doctrine — shipped as AGENTS.md next to the source.
pub const DOCTRINE: &str = include_str!("../AGENTS.md");

fn system(doctrine: bool, task: &str) -> String {
    if doctrine {
        format!(
            "{}\n\n---\nOPERATING CONTEXT: You are running as the embedded decision engine of \
the Night Crawler recon tool. The doctrine above governs every decision you make. Apply it to the \
task below. Respond with the exact JSON shape the task specifies — no markdown fences, no prose.\n\nTASK:\n{}",
            DOCTRINE, task
        )
    } else {
        format!(
            "You are NightCrawler, the embedded decision engine of the Night Crawler recon tool. \
Apply the doctrine in AGENTS.md: authorized scope only, evidence-driven decisions, never invent data.\n\nTASK:\n{}",
            task
        )
    }
}

// ---------------------------------------------------------------------------
// Decision 1: port strategy (after target resolution)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortStrategy {
    pub ports: String,
    pub reason: String,
}

pub async fn decide_port_strategy(client: &NvClient, snapshot: &Value) -> Result<PortStrategy> {
    let task = "Acting as an offensive-security professional whose goal is MAXIMUM information gathering within scope, choose the TCP port scan strategy for the target.

Allowed values for \"ports\":
- \"top\"  : fast sweep of ~500 common service ports.
- \"full\" : all 65535 ports — the professional default when the target is infrastructure, a lab box, a single-purpose host with few services, or when you need full coverage. Prefer this whenever runtime is acceptable.
- a compact custom spec using ranges and lists, e.g. \"1-1024,3306,3389,4443,5900,8000-8100\", when the target profile suggests specific services.

Professional bias: unknown single-host internet targets with no clear profile deserve at least a \"full\" sweep if the operator can afford it; use \"top\" when the evidence (domain, shared hosting, CDN) suggests a narrow set. Err toward more coverage, not less.

JSON shape: {\"ports\": \"...\", \"reason\": \"<= 20 words\"}";

    let user = format!(
        "TARGET SNAPSHOT (JSON):\n{}\n\nChoose the port strategy now. Reply with ONLY the JSON object.",
        serde_json::to_string_pretty(snapshot)?
    );

    let json = chat_json(client, task, &user, 0.1, 1500).await?;
    let parsed: PortStrategy = serde_json::from_str(&json)
        .with_context(|| format!("bad port-strategy JSON: {}", truncate(&json, 160)))?;
    crate::config::parse_ports(&parsed.ports).context("invalid port spec chosen")?;
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// Decision 2: module plan (after service fingerprinting)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModulePlan {
    pub modules: Vec<String>,
    pub priorities: Vec<String>,
    pub rationale: String,
}

pub async fn plan_modules(client: &NvClient, snapshot: &Value) -> Result<ModulePlan> {
    let task = "The first enumeration pass finished for the target. Select which optional modules run next — you are an offensive-security professional gathering maximum information within scope.

Your objective is maximum defensible information gathering (doctrine §3): when uncertain, INCLUDE the module — harmless probes are preferred over missed attack surface. Choose ONLY from these modules:
- \"snmp\"        : SNMP walk. UDP probe, harmless; useful for network gear, printers, servers.
- \"ldap\"        : LDAP enumeration. Applicable when TCP/389, 636 or 3268 is open.
- \"netbios_smb\" : NetBIOS + SMB enumeration. Applicable when 137/139/445 open or target looks like Windows.
- \"subdirs\"     : web directory brute force. Applicable when any HTTP/HTTPS service was detected.
- \"deep_subdomain\": subdomain dictionary brute force. Applicable when the target has a domain.
- \"dorking\"     : OSINT search queries. Applicable when a domain is known.

Every module whose preconditions are even plausibly met should be selected — a refused probe costs seconds, a missed service costs the engagement.

JSON shape: {\"modules\": [\"...\"], \"priorities\": [\"short focus strings\"], \"rationale\": \"one or two sentences\"}";

    let user = format!(
        "SCAN SNAPSHOT (JSON):\n{}\n\nSelect the modules. Reply with ONLY the JSON object.",
        serde_json::to_string_pretty(snapshot)?
    );

    let json = chat_json(client, task, &user, 0.1, 3000).await?;
    let parsed: ModulePlan = serde_json::from_str(&json)
        .with_context(|| format!("bad module-plan JSON: {}", truncate(&json, 160)))?;
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// Decision 3: follow-up tasks (after the first enumeration pass)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum FollowUpAction {
    /// Probe additional web paths (extra dictionary words).
    ExtendDirs {
        #[serde(default)]
        bases: Vec<String>,
        words: Vec<String>,
    },
    /// HTTP-probe the web roots of discovered hostnames.
    ProbeWebRoots {
        hosts: Vec<String>,
    },
    /// DNS recon + AXFR + dorking on in-scope sibling domains.
    PivotDomains {
        domains: Vec<String>,
    },
    /// One extra port pass with a different spec.
    RescanPorts {
        spec: String,
    },
    /// Nothing more to do — write the report.
    Finish,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowUpPlan {
    pub actions: Vec<FollowUpAction>,
    pub reason: String,
}

pub async fn decide_followups(client: &NvClient, snapshot: &Value) -> Result<FollowUpPlan> {
    let task = "The enumeration pass finished. You are an offensive-security professional hunting for the maximum attack surface. Review the combined results and decide follow-up tasks that add NEW information (doctrine §3, §8). You may issue up to 4 actions — use them all if each adds real coverage.

Allowed actions — respond ONLY with these, as a JSON array:
- {\"action\":\"extend_dirs\",\"bases\":[...],\"words\":[...]}  : probe up to 60 extra web path segments (e.g. \"jenkins\", \"backup2\", \"api-old\"). bases must be taken from the provided web_roots evidence.
- {\"action\":\"probe_web_roots\",\"hosts\":[...]}             : fetch titles/headers of up to 20 discovered hostnames' web roots (:80/:443). hosts must be from the provided subdomains evidence.
- {\"action\":\"pivot_domains\",\"domains\":[...]}             : up to 3 domains that are subdomains/siblings of the target's domain (DNS/AXFR/dorks on them). Only domains appearing in the pivot_candidates evidence.
- {\"action\":\"rescan_ports\",\"spec\":\"...\"}               : ONE extra port pass with a different spec (only if the first pass was narrow and the target merits more coverage).
- {\"action\":\"finish\"}                                      : the evidence is sufficient — produce the report.

Rules: pick only actions that reveal something the current results do NOT already contain. If the recon is already sufficient, choose finish.

JSON shape: {\"actions\": [...], \"reason\": \"<= 25 words\"}";

    let user = format!(
        "COMBINED RESULTS SO FAR (JSON):\n{}\n\nDecide the follow-up actions. Reply with ONLY the JSON object.",
        serde_json::to_string_pretty(snapshot)?
    );

    let json = chat_json(client, task, &user, 0.2, 3000).await?;
    let parsed: FollowUpPlan = serde_json::from_str(&json)
        .with_context(|| format!("bad follow-up JSON: {}", truncate(&json, 160)))?;
    if parsed.actions.len() > 4 {
        return Err(anyhow!("model requested > 4 actions"));
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// Final analysis report (doctrine §9 format)
// ---------------------------------------------------------------------------

pub async fn analyze_report(client: &NvClient, results_json: &str, target: &str) -> Result<String> {
    let task = "Write the final assessment report following the doctrine's REPORTING format EXACTLY, with these sections in this order:

## Executive Summary
## Scope
## Methodology
## Attack Surface
## Ports and Services
## Findings
## Attack Paths
## Exploitation Recommendations
## Recommendations
## Limitations
## Conclusion

For each finding inside Findings use this structure:
### [SEVERITY] Title (CVE-if-known)
- Confidence: CONFIRMED | LIKELY | POSSIBLE | UNCONFIRMED
- Affected: service/asset
- Evidence: the exact scan data that supports it
- The Problem: what is wrong, plainly
- How to Start the Attack: concrete first moves — specific tools, commands, or request patterns an operator would run to validate/exploit this
- Impact: confidentiality / integrity / availability
- Remediation: what to fix, prioritized

Attack Paths must be chained, ordered narratives — where the problem is, how to start, what the next moves are from an attacker's perspective, referencing only services actually found in the data.

Exploitation Recommendations is the operator's action list: ordered, concrete suggestions for exploiting the target based on the results — for each, give the exact tool or command to run, what it validates, and the scan evidence that justifies trying it. Never leave this section generic: every recommendation must reference a specific finding.

Use ONLY the evidence provided — never invent ports, versions, CVEs, or hosts. Mark anything inferred as UNCONFIRMED. Be concrete and technical.";

    let user = format!(
        "TARGET: {}\n\nFULL RECON RESULTS (JSON):\n{}\n\nWrite the report now.",
        target, results_json
    );

    let raw = client
        .chat_with_timeout(&system(true, task), &user, 0.2, 10000, Duration::from_secs(900))
        .await?;
    let content = raw
        .trim()
        .trim_start_matches("```markdown")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim()
        .to_string();
    Ok(content)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// One chat call that MUST produce a balanced JSON object. Real models
/// sometimes wrap or lose the JSON — give them exactly one stricter retry.
async fn chat_json(
    client: &NvClient,
    task: &str,
    user: &str,
    temperature: f32,
    max_tokens: u32,
) -> Result<String> {
    let sys = system(true, task);
    let raw = client.chat(&sys, user, temperature, max_tokens).await?;
    if let Some(j) = extract_json(&raw) {
        return Ok(j);
    }
    let retry_user = format!(
        "{}\n\nYour previous reply was not a valid JSON object. Respond now with ONLY the JSON object — no prose, no markdown fences, no explanation.",
        user
    );
    let raw2 = client
        .chat(&sys, &retry_user, 0.0, max_tokens)
        .await
        .map(|r| format!("{}\n{}", raw, r))
        .unwrap_or(raw);
    extract_json(&raw2).ok_or_else(|| anyhow!("no JSON in reply (after retry)"))
}

pub fn extract_json(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let bytes = raw.as_bytes();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if escape {
            escape = false;
            continue;
        }
        match b {
            b'\\' if in_str => escape = true,
            b'"' => in_str = !in_str,
            b'{' if !in_str => depth += 1,
            b'}' if !in_str => {
                depth -= 1;
                if depth == 0 {
                    return Some(raw[start..=i].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctrine_embedded() {
        assert!(DOCTRINE.contains("NightCrawler"));
        assert!(DOCTRINE.contains("How to Start the Attack"));
        assert!(DOCTRINE.contains("CONFIRMED"));
    }
}
