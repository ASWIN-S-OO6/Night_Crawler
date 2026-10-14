use crate::types::{ReconResults, Severity};
use crate::util::timestamp_slug;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Write the full report set: report.md, findings.json, link_analysis.mmd, link_analysis.json
pub fn write_reports(results: &ReconResults, out_root: &Path) -> Result<PathBuf> {
    let dir = out_root.join(format!(
        "nightcrawler_{}_{}",
        crate::util::safe_dir_name(&results.target.input),
        timestamp_slug()
    ));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating report dir {}", dir.display()))?;

    // findings.json — everything, raw
    let json = serde_json::to_string_pretty(results).context("serialize findings")?;
    std::fs::write(dir.join("findings.json"), json)?;

    // graph exports
    let mermaid = build_mermaid_from_graph(&results.graph);
    std::fs::write(dir.join("link_analysis.mmd"), &mermaid)?;
    std::fs::write(
        dir.join("link_analysis.json"),
        serde_json::to_string_pretty(&results.graph)?,
    )?;

    // report.md
    let md = build_markdown(results, &mermaid);
    let report_path = dir.join("report.md");
    std::fs::write(&report_path, md)?;

    Ok(report_path)
}

fn build_mermaid_from_graph(graph: &crate::types::GraphData) -> String {
    let mut gb = crate::graph::GraphBuilder::new();
    // rebuild from data to reuse renderer
    let mut map = std::collections::HashMap::new();
    for n in &graph.nodes {
        let id = gb.add_node(&n.kind, &n.label);
        map.insert(n.id, id);
    }
    for e in &graph.edges {
        if let (Some(a), Some(b)) = (map.get(&e.from), map.get(&e.to)) {
            gb.add_edge(*a, *b, &e.label);
        }
    }
    gb.to_mermaid(140)
}

fn sev_tag(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

pub fn build_markdown(results: &ReconResults, mermaid: &str) -> String {
    let mut m = String::new();
    m.push_str("# Night Crawler — Reconnaissance Report\n\n");
    m.push_str(&format!(
        "| | |\n|---|---|\n| **Target** | {} |\n| **Started** | {} |\n| **Duration** | {}s |\n| **Tool** | {} v{} |\n\n",
        results.target.input,
        results.meta.started_at,
        results.meta.duration_secs,
        results.meta.tool,
        results.meta.version
    ));

    // Executive summary
    if let Some(ai) = &results.ai_report {
        m.push_str(ai.trim());
        m.push_str("\n\n");
    } else {
        m.push_str("## Executive Summary\n\n");
        m.push_str(&fallback_summary(results));
    }

    // Target overview
    let t = &results.target;
    m.push_str("## Target Overview\n\n");
    m.push_str(&format!(
        "| | |\n|---|---|\n| Input kind | {} |\n| IP | {} |\n| Hostname | {} |\n| Reverse DNS | {} |\n| Alive | {} ({}) |\n| RTT | {} ms |\n| Inferred domain (from IP) | {} |\n\n",
        t.input_kind,
        t.ip.map(|i| i.to_string()).unwrap_or("-".into()),
        t.hostname.clone().unwrap_or("-".into()),
        t.reverse_dns.clone().unwrap_or("-".into()),
        t.alive, t.liveness_method,
        t.rtt_ms.map(|r| format!("{:.1}", r)).unwrap_or("-".into()),
        t.inferred_domain.clone().unwrap_or("-".into()),
    ));
    if !t.ptr_domains.is_empty() {
        m.push_str(&format!("PTR domains: {}\n\n", t.ptr_domains.join(", ")));
    }
    if !t.cert_domains.is_empty() {
        m.push_str(&format!(
            "TLS certificate identities: {}\n\n",
            t.cert_domains.join(", ")
        ));
    }

    // Ports
    m.push_str("## Open Ports & Services\n\n");
    if results.ports.is_empty() {
        m.push_str("_No open TCP ports detected._\n\n");
    } else {
        m.push_str("| Port | Proto | Service | Product | Version | Banner |\n|---|---|---|---|---|---|\n");
        for p in &results.ports {
            m.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                p.port,
                p.proto,
                p.service,
                p.product.clone().unwrap_or("-".into()),
                p.version.clone().unwrap_or("-".into()),
                p.banner
                    .clone()
                    .unwrap_or("-".into())
                    .replace('|', "\\|")
                    .replace('\n', " ")
            ));
        }
        m.push('\n');
    }

    // Vulnerability findings
    m.push_str("## Vulnerability Findings (fingerprint-matched)\n\n");
    if results.vulns.is_empty() {
        m.push_str("_No version-based CVE matches or exposure findings from the local fingerprint database._\n\n");
    } else {
        for v in &results.vulns {
            m.push_str(&format!(
                "### [{}] {} {}\n\n- **Severity:** {}\n- **Affected:** {}\n- **Evidence:** {}\n- {}\n{}\n\n",
                sev_tag(v.severity),
                v.title,
                v.cve.clone().map(|c| format!("({})", c)).unwrap_or_default(),
                sev_tag(v.severity),
                v.affected,
                v.evidence.replace('\n', " "),
                v.description,
                v.reference
                    .clone()
                    .map(|r| format!("- **Reference:** {}", r))
                    .unwrap_or_default()
            ));
        }
    }

    // DNS
    if let Some(dns) = &results.dns {
        m.push_str("## DNS Recon\n\n");
        m.push_str(&format!("**Records ({}):**\n\n", dns.records.len()));
        if !dns.records.is_empty() {
            m.push_str("| Type | Name | Value |\n|---|---|---|\n");
            for r in dns.records.iter().take(200) {
                m.push_str(&format!(
                    "| {} | {} | {} |\n",
                    r.rtype,
                    r.name.replace('|', "\\|"),
                    r.value.replace('|', "\\|")
                ));
            }
            m.push('\n');
        }
        m.push_str(&format!(
            "**Wildcard detection:** {}\n\n",
            dns.wildcard
                .clone()
                .map(|w| format!("WILDCARD present ({})", w))
                .unwrap_or("no wildcard".into())
        ));
        m.push_str(&format!(
            "**Zone transfer (AXFR):** {}\n\n",
            if dns.axfr_success {
                format!(
                    "SUCCESS against {} — {} records leaked",
                    dns.axfr_servers.join(", "),
                    dns.axfr_records.len()
                )
            } else {
                "failed on all nameservers (properly configured)".into()
            }
        ));
        if dns.axfr_success {
            m.push_str("| Type | Name | Value |\n|---|---|---|\n");
            for r in dns.axfr_records.iter().take(300) {
                m.push_str(&format!(
                    "| {} | {} | {} |\n",
                    r.rtype,
                    r.name.replace('|', "\\|"),
                    r.value.replace('|', "\\|")
                ));
            }
            m.push('\n');
        }
    }

    // Subdomains
    m.push_str(&format!(
        "## Subdomains ({})\n\n",
        results.subdomains.len()
    ));
    if results.subdomains.is_empty() {
        m.push_str("_No subdomains discovered._\n\n");
    } else {
        m.push_str("| Subdomain | IPs | Source |\n|---|---|---|\n");
        for s in results.subdomains.iter().take(300) {
            m.push_str(&format!(
                "| {} | {} | {} |\n",
                s.name,
                s.ips.join(", "),
                s.source
            ));
        }
        m.push('\n');
    }

    // HTTP fingerprint
    if !results.http.is_empty() {
        m.push_str("## HTTP Fingerprint\n\n");
        for h in &results.http {
            m.push_str(&format!("### {}\n\n", h.url));
            m.push_str(&format!(
                "- Status: {} | Title: {} \n",
                h.status,
                h.title.clone().unwrap_or("-".into())
            ));
            m.push_str(&format!(
                "- Server: {} | X-Powered-By: {}\n",
                h.server.clone().unwrap_or("-".into()),
                h.powered_by.clone().unwrap_or("-".into())
            ));
            let missing: Vec<String> = h
                .security_headers
                .iter()
                .filter(|(_, ok)| !ok)
                .map(|(k, _)| k.clone())
                .collect();
            if !missing.is_empty() {
                m.push_str(&format!(
                    "- Missing security headers: {}\n",
                    missing.join(", ")
                ));
            }
            if !h.cookies.is_empty() {
                m.push_str(&format!(
                    "- Cookies: {}\n",
                    h.cookies
                        .iter()
                        .map(|c| c.split(';').next().unwrap_or("").to_string())
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
            if !h.robots_disallow.is_empty() {
                m.push_str(&format!(
                    "- robots.txt disallows ({}): {}\n",
                    h.robots_disallow.len(),
                    h.robots_disallow.join(", ")
                ));
            }
            if let Some(issuer) = &h.tls_issuer {
                m.push_str(&format!(
                    "- TLS: issuer = {}, subject = {}, valid until {}\n",
                    issuer,
                    h.tls_subject.clone().unwrap_or("-".into()),
                    h.tls_valid_until.clone().unwrap_or("-".into())
                ));
                if !h.tls_san.is_empty() {
                    m.push_str(&format!("- TLS SANs: {}\n", h.tls_san.join(", ")));
                }
            }
            m.push('\n');
        }
    }

    // Directories
    m.push_str(&format!(
        "## Discovered Web Paths ({})\n\n",
        results.subdirs.len()
    ));
    if results.subdirs.is_empty() {
        m.push_str("_No web paths discovered (or no web service)._\n\n");
    } else {
        m.push_str("| URL | Status | Length | Title | Note |\n|---|---|---|---|---|\n");
        for d in results.subdirs.iter().take(400) {
            m.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                d.url,
                d.status,
                d.length,
                d.title.clone().unwrap_or("-".into()),
                d.note
            ));
        }
        m.push('\n');
    }

    // SNMP
    if let Some(snmp) = &results.snmp {
        m.push_str("## SNMP Enumeration\n\n");
        m.push_str(&format!(
            "- Community string: `{}` ({})\n",
            snmp.community, snmp.version
        ));
        m.push_str(&format!("- sysDescr: {}\n", snmp.sysdescr.clone().unwrap_or("-".into())));
        m.push_str(&format!("- sysName: {}\n", snmp.sysname.clone().unwrap_or("-".into())));
        m.push_str(&format!("- sysLocation: {}\n", snmp.syslocation.clone().unwrap_or("-".into())));
        m.push_str(&format!("- sysContact: {}\n", snmp.syscontact.clone().unwrap_or("-".into())));
        m.push_str(&format!("- sysObjectID: {}\n", snmp.sysobjectid.clone().unwrap_or("-".into())));
        m.push_str(&format!("- Uptime: {}\n", snmp.uptime.clone().unwrap_or("-".into())));
        m.push_str(&format!("- Vendor guess: {}\n", snmp.vendor_guess.clone().unwrap_or("-".into())));
        m.push_str(&format!(
            "\nMIB-2 walk collected **{}** varbinds (full data in findings.json). Sample:\n\n",
            snmp.varbind_count
        ));
        for (oid, val) in snmp.objects.iter().take(40) {
            let v: String = val.chars().take(80).collect();
            m.push_str(&format!("- `{}` = {}\n", oid, v));
        }
        m.push('\n');
    }

    // LDAP
    if let Some(ldap) = &results.ldap {
        m.push_str("## LDAP Enumeration\n\n");
        m.push_str(&format!("- Server: `{}`\n", ldap.server));
        m.push_str(&format!(
            "- Anonymous bind: {}\n",
            if ldap.anonymous_bind { "ALLOWED" } else { "denied" }
        ));
        if !ldap.root_dse.is_empty() {
            m.push_str("\n**RootDSE:**\n\n| Attribute | Value |\n|---|---|\n");
            for (k, v) in ldap.root_dse.iter().take(40) {
                m.push_str(&format!("| {} | {} |\n", k, v.replace('|', "\\|")));
            }
            m.push('\n');
        }
        if !ldap.users.is_empty() {
            m.push_str(&format!(
                "\n**Users ({}):** {}\n\n",
                ldap.users.len(),
                ldap.users.join(", ")
            ));
        }
        if !ldap.groups.is_empty() {
            m.push_str(&format!(
                "**Groups ({}):** {}\n\n",
                ldap.groups.len(),
                ldap.groups.join(", ")
            ));
        }
        if !ldap.computers.is_empty() {
            m.push_str(&format!(
                "**Computers ({}):** {}\n\n",
                ldap.computers.len(),
                ldap.computers.join(", ")
            ));
        }
        if !ldap.note.is_empty() {
            m.push_str(&format!("Note: {}\n\n", ldap.note));
        }
    }

    // NetBIOS / SMB
    if let Some(nb) = &results.netbios {
        m.push_str("## NetBIOS Enumeration\n\n");
        m.push_str(&format!("- MAC address: {}\n", nb.mac_address));
        m.push_str("\n| Name | Service |\n|---|---|\n");
        for (name, svc) in &nb.names {
            m.push_str(&format!("| {} | {} |\n", name, svc));
        }
        m.push('\n');
    }
    if let Some(smb) = &results.smb {
        m.push_str("## SMB Enumeration\n\n");
        m.push_str(&format!(
            "- Tools available: {}\n",
            if smb.tools_available.is_empty() {
                "none".into()
            } else {
                smb.tools_available.join(", ")
            }
        ));
        if !smb.shares.is_empty() {
            m.push_str("\n**Shares:**\n\n");
            for s in &smb.shares {
                m.push_str(&format!("- {}\n", s));
            }
        }
        if !smb.users.is_empty() {
            m.push_str(&format!(
                "\n**Domain users ({}):** {}\n",
                smb.users.len(),
                smb.users.join(", ")
            ));
        }
        if !smb.groups.is_empty() {
            m.push_str(&format!(
                "\n**Domain groups ({}):** {}\n",
                smb.groups.len(),
                smb.groups.join(", ")
            ));
        }
        for n in &smb.notes {
            m.push_str(&format!("- {}\n", n));
        }
        m.push('\n');
    }

    // WHOIS
    if let Some(w) = &results.whois {
        m.push_str("## WHOIS\n\n");
        m.push_str(&format!("- Server: {}\n", w.server));
        m.push_str(&format!("- Registrar: {}\n", w.registrar.clone().unwrap_or("-".into())));
        m.push_str(&format!("- Created: {}\n", w.created.clone().unwrap_or("-".into())));
        m.push_str(&format!("- Expires: {}\n", w.expires.clone().unwrap_or("-".into())));
        m.push_str(&format!("- Organization: {}\n", w.org.clone().unwrap_or("-".into())));
        m.push_str(&format!("- Abuse contact: {}\n\n", w.abuse_email.clone().unwrap_or("-".into())));
        m.push_str("<details><summary>Raw WHOIS</summary>\n\n```\n");
        let raw: String = w.raw.chars().take(6000).collect();
        m.push_str(&raw);
        m.push_str("\n```\n</details>\n\n");
    }

    // Dorks
    if !results.dorks.is_empty() {
        m.push_str("## OSINT / Dorking Results\n\n");
        for d in &results.dorks {
            m.push_str(&format!("**`{}`** _({})_\n\n", d.query, d.engine));
            if let Some(e) = &d.error {
                m.push_str(&format!("> error: {}\n\n", e));
            } else if d.results.is_empty() {
                m.push_str("> no results\n\n");
            } else {
                for r in &d.results {
                    m.push_str(&format!("- {}\n", r));
                }
                m.push('\n');
            }
        }
    }

    // Link analysis
    m.push_str("## Link Analysis (entity graph)\n\n");
    m.push_str(&format!(
        "Graph contains **{} nodes** and **{} edges**. Top hub entities:\n\n",
        results.graph.nodes.len(),
        results.graph.edges.len()
    ));
    let mut gb = crate::graph::GraphBuilder::new();
    let mut map = std::collections::HashMap::new();
    for n in &results.graph.nodes {
        let id = gb.add_node(&n.kind, &n.label);
        map.insert(n.id, id);
    }
    for e in &results.graph.edges {
        if let (Some(a), Some(b)) = (map.get(&e.from), map.get(&e.to)) {
            gb.add_edge(*a, *b, &e.label);
        }
    }
    for (kind, label, degree) in gb.hubs(15) {
        m.push_str(&format!("- **{}** `{}` — {} links\n", kind, label, degree));
    }
    m.push_str("\n### Entity Relationship Diagram (Mermaid)\n\n```mermaid\n");
    m.push_str(mermaid);
    m.push_str("\n```\n\n");

    // AI decision timeline
    if !results.ai_decisions.is_empty() {
        m.push_str("## AI Decision Timeline\n\n");
        m.push_str("| Stage | Decision | Rationale |\n|---|---|---|\n");
        for d in &results.ai_decisions {
            m.push_str(&format!(
                "| {} | `{}` | {} |\n",
                d.stage,
                d.decision.replace('|', "\\|"),
                d.rationale.replace('|', "\\|")
            ));
        }
        m.push('\n');
    }

    // Pivot domains
    if !results.pivots.is_empty() {
        m.push_str(&format!(
            "## Pivot Domains ({} — AI-selected)\n\n",
            results.pivots.len()
        ));
        for p in &results.pivots {
            m.push_str(&format!("### {}\n\n", p.domain));
            if let Some(dns) = &p.dns {
                m.push_str(&format!(
                    "- {} DNS records · AXFR: {}\n",
                    dns.records.len(),
                    if dns.axfr_success {
                        format!("SUCCESS ({} records)", dns.axfr_records.len())
                    } else {
                        "refused".to_string()
                    }
                ));
                for r in dns.records.iter().take(15) {
                    m.push_str(&format!("  - {} {} -> {}\n", r.rtype, r.name, r.value));
                }
            }
            let dork_hits: usize = p.dorks.iter().map(|d| d.results.len()).sum();
            m.push_str(&format!("- dorking: {} result URLs\n\n", dork_hits));
        }
    }

    // AI recommendations
    if let Some(plan) = &results.ai_plan {
        m.push_str("## AI Planning Notes\n\n");
        m.push_str(&format!(
            "- Model: `{}`\n- Selected modules: {}\n- Priorities: {}\n- Rationale: {}\n\n",
            plan.model,
            plan.modules.join(", "),
            plan.priorities.join("; "),
            plan.rationale
        ));
    }

    // Module log
    m.push_str("## Execution Log\n\n```\n");
    for (phase, summary) in results.phases.iter().take(60) {
        m.push_str(&format!("[{}] {}\n", phase, summary));
    }
    m.push_str("```\n\n");

    m.push_str("## Appendix\n\n- Full raw data: `findings.json`\n- Mermaid graph: `link_analysis.mmd`\n- Graph JSON: `link_analysis.json`\n\n");
    m.push_str("_Generated by Night Crawler. Use only against systems you are authorized to test._\n");
    m
}

fn fallback_summary(results: &ReconResults) -> String {
    let mut s = String::new();
    s.push_str("_AI analysis disabled or unavailable — rule-based summary._\n\n");
    let open: Vec<_> = results.ports.iter().filter(|p| p.open).collect();
    s.push_str(&format!(
        "- Target `{}` is {} ({} open TCP port{}).",
        results.target.input,
        if results.target.alive { "up" } else { "not responding" },
        open.len(),
        if open.len() == 1 { "" } else { "s" }
    ));
    s.push('\n');
    let crit = results.vulns.iter().filter(|v| v.severity == Severity::Critical).count();
    let high = results.vulns.iter().filter(|v| v.severity == Severity::High).count();
    s.push_str(&format!(
        "- {} critical / {} high fingerprint findings from the local CVE matcher.\n",
        crit, high
    ));
    if let Some(dns) = &results.dns {
        if dns.axfr_success {
            s.push_str(&format!(
                "- **Zone transfer succeeded** against {} — the entire DNS zone is exposed.\n",
                dns.axfr_servers.join(", ")
            ));
        }
    }
    if !results.subdomains.is_empty() {
        s.push_str(&format!(
            "- {} subdomains discovered (sources: crt.sh + dictionary).\n",
            results.subdomains.len()
        ));
    }
    if let Some(snmp) = &results.snmp {
        s.push_str(&format!(
            "- SNMP exposed with community string `{}`.\n",
            snmp.community
        ));
    }
    if let Some(ldap) = &results.ldap {
        if ldap.anonymous_bind {
            s.push_str("- LDAP allows anonymous binds and directory data was retrieved.\n");
        }
    }
    s.push('\n');
    s
}
