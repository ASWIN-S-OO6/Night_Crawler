use crate::agent::{self, FollowUpAction};
use crate::ai::NvClient;
use crate::config::{parse_ports, Config, ScanCfg};
use crate::graph::GraphBuilder;
use crate::modules;
use crate::state::{PhaseStatus, SharedState};
use crate::types::*;
use crate::util::strip_domain;
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Fully autonomous scan options. Everything here is a *hint*; the AI
/// decides the actual strategy at each phase when connected.
pub struct Opts {
    /// None = NightCrawler decides the port strategy (or "top" without a model).
    pub ports_spec: Option<String>,
    pub wordlist_subs: Option<Vec<String>>,
    pub wordlist_dirs: Option<Vec<String>>,
    pub snmp_communities: Option<Vec<String>>,
    pub enable_ai: bool,
    pub allow_pivot: bool,
    pub output_dir: std::path::PathBuf,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            ports_spec: None,
            wordlist_subs: None,
            wordlist_dirs: None,
            snmp_communities: None,
            enable_ai: true,
            allow_pivot: true,
            output_dir: std::path::PathBuf::from("./reports"),
        }
    }
}

/// A compact snapshot builder reused by every NightCrawler decision point.
fn slim_results_json(results: &ReconResults) -> Value {
    let mut slim = serde_json::to_value(results).unwrap_or_default();
    if let Some(obj) = slim.as_object_mut() {
        // drop bulky fields
        if let Some(snmp) = obj.get_mut("snmp") {
            if let Some(so) = snmp.as_object_mut() {
                so.insert("objects".into(), serde_json::json!([]));
            }
        }
        if let Some(whois) = obj.get_mut("whois") {
            if let Some(wo) = whois.as_object_mut() {
                wo.insert("raw".into(), serde_json::json!("(omitted)"));
            }
        }
        if let Some(netbios) = obj.get_mut("netbios") {
            if let Some(n) = netbios.as_object_mut() {
                n.insert("group".into(), serde_json::json!([]));
            }
        }
        if let Some(smb) = obj.get_mut("smb") {
            if let Some(s) = smb.as_object_mut() {
                s.insert("tools_available".into(), serde_json::json!([]));
            }
        }
        obj.insert(
            "subdirs".into(),
            serde_json::json!(results.subdirs.iter().take(80).collect::<Vec<_>>()),
        );
        // decisions shouldn't feed themselves
        obj.insert("ai_decisions".into(), serde_json::json!([]));
        obj.insert(
            "ai_report".into(),
            serde_json::json!(results.ai_report.is_some()),
        );
    }
    slim
}

fn evidence_snapshot(results: &ReconResults) -> Value {
    let subdomain_names: Vec<String> = results.subdomains.iter().map(|s| s.name.clone()).collect();
    let web_roots: Vec<String> = results
        .http
        .iter()
        .map(|h| h.url.trim_end_matches('/').to_string())
        .collect();
    serde_json::json!({
        "target": {
            "input": results.target.input,
            "kind": results.target.input_kind,
            "ip": results.target.ip.map(|i| i.to_string()),
            "hostname": results.target.hostname,
            "ptr": results.target.reverse_dns,
            "inferred_domain": results.target.inferred_domain,
            "cert_domains": results.target.cert_domains,
        },
        "alive": results.target.alive,
        "open_ports": results.ports.iter().map(|p| serde_json::json!({
            "port": p.port, "service": p.service,
            "product": p.product, "version": p.version,
        })).collect::<Vec<_>>(),
        "vulns": results.vulns.iter().map(|v| serde_json::json!({
            "title": v.title, "severity": v.severity, "affected": v.affected,
        })).collect::<Vec<_>>(),
        "dns": results.dns.as_ref().map(|d| serde_json::json!({
            "record_count": d.records.len(),
            "records": d.records.iter().take(60).collect::<Vec<_>>(),
            "axfr_success": d.axfr_success,
            "wildcard": d.wildcard.is_some(),
        })),
        "subdomains": subdomain_names,
        "web_roots": web_roots,
        "discovered_paths": results.subdirs.iter().map(|d| d.url.clone()).take(80).collect::<Vec<_>>(),
        "snmp": results.snmp.as_ref().map(|s| serde_json::json!({
            "community": s.community, "sysdescr": s.sysdescr,
            "sysname": s.sysname, "varbinds": s.varbind_count,
        })),
        "ldap": results.ldap.as_ref().map(|l| serde_json::json!({
            "anonymous": l.anonymous_bind, "users": l.users.len(),
            "groups": l.groups.len(), "computers": l.computers.len(),
            "context": l.naming_context,
        })),
        "netbios": results.netbios.as_ref().map(|n| serde_json::json!({
            "names": n.names, "mac": n.mac_address,
        })),
        "whois": results.whois.as_ref().map(|w| serde_json::json!({
            "registrar": w.registrar, "org": w.org, "created": w.created,
        })),
        "dork_hits": results.dorks.iter().map(|d| serde_json::json!({
            "query": d.query, "results": d.results.len(),
        })).collect::<Vec<_>>(),
    })
}

pub async fn run_scan(
    target_str: &str,
    opts: &Opts,
    cfg: &Config,
    shared: Arc<SharedState>,
    nv: Option<NvClient>,
) -> Result<ReconResults> {
    let started = Instant::now();
    let scan_cfg: &ScanCfg = &cfg.scan;
    let mut g = GraphBuilder::new();
    let mut ai_decisions: Vec<AiDecision> = Vec::new();

    // Show the connected model in the UI from the very start, and verify
    // the key can actually run a chat completion (not just list models).
    if let Some(nv) = nv.as_ref() {
        shared.with(|s| {
            s.ai_note = Some(format!("🤖 {}", nv.model));
        });
        shared.log(format!("verifying chat access for model {}…", nv.model));
        match tokio::time::timeout(Duration::from_secs(60), nv.ping(&nv.model)).await {
            Ok(Ok(())) => shared.log("chat verified — NightCrawler agent online"),
            Ok(Err(e)) => {
                shared.finding(
                    Severity::Medium,
                    "nc",
                    &format!("Model chat check failed — agent degraded: {}", e),
                );
                shared.log(format!("chat ping failed: {} — scan continues with evidence-based defaults", e));
            }
            Err(_) => shared.log("chat ping timed out — agent may be slow"),
        }
    }

    // ------------------------------------------------------------------
    // Phase 1: Resolve target
    // ------------------------------------------------------------------
    shared.running("Resolve Target");
    let resolver = modules::dnsrecon::make_resolver()?;
    let target_str_clean = target_str
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string();

    let as_ip: Option<IpAddr> = target_str_clean.parse().ok();

    let mut target = if let Some(ip) = as_ip {
        TargetInfo {
            input_kind: "ip".into(),
            input: target_str_clean.clone(),
            ip: Some(ip),
            hostname: None,
            reverse_dns: None,
            inferred_domain: None,
            alive: false,
            liveness_method: String::new(),
            rtt_ms: None,
            ptr_domains: Vec::new(),
            cert_domains: Vec::new(),
        }
    } else {
        let ips = modules::dnsrecon::resolve_a(&resolver, &target_str_clean).await;
        if ips.is_empty() {
            shared.failed("Resolve Target", "domain does not resolve");
            return Err(anyhow!("could not resolve domain: {}", target_str_clean));
        }
        let ip = ips
            .iter()
            .find(|i| matches!(i, IpAddr::V4(_)))
            .copied()
            .or_else(|| ips.first().copied());
        TargetInfo {
            input_kind: "domain".into(),
            input: target_str_clean.clone(),
            ip,
            hostname: Some(strip_domain(&target_str_clean)),
            reverse_dns: None,
            inferred_domain: None,
            alive: false,
            liveness_method: String::new(),
            rtt_ms: None,
            ptr_domains: Vec::new(),
            cert_domains: Vec::new(),
        }
    };

    // IP -> domain discovery: PTR + TLS SANs
    if target.input_kind == "ip" {
        let ip = target.ip.unwrap();
        if let Some(ptr) = modules::dnsrecon::ptr_lookup(&resolver, ip).await {
            shared.log(format!("PTR: {}", ptr));
            target.reverse_dns = Some(ptr.clone());
            target.ptr_domains.push(ptr.clone());
            let parts: Vec<&str> = ptr.split('.').collect();
            if parts.len() >= 2 {
                let inferred = parts[parts.len() - 2..].join(".");
                target.inferred_domain = Some(inferred.clone());
            }
        }
        for port in [443u16, 8443] {
            if let Some((_subj, _issuer, sans, _until)) = modules::tls_capture::tls_identity(ip, port).await {
                for san in sans.iter().filter(|s| s.contains('.')) {
                    if !target.cert_domains.contains(san) {
                        target.cert_domains.push(san.clone());
                    }
                }
                if !sans.is_empty() {
                    break;
                }
            }
        }
    }

    let ip = match target.ip {
        Some(ip) => ip,
        None => {
            shared.failed("Resolve Target", "no A/AAAA record");
            return Err(anyhow!("target has no usable IP address"));
        }
    };

    let host_header = target.hostname.clone().unwrap_or_else(|| ip.to_string());
    g.relate("ip", &ip.to_string(), "resolves-to", "domain", &host_header);

    shared.done("Resolve Target", &format!("{} -> {}", target.input, ip));
    shared.log(format!("target resolved: {} ({})", target.input, ip));

    // ------------------------------------------------------------------
    // Phase 2: Liveness
    // ------------------------------------------------------------------
    shared.running("Host Liveness");
    let (alive, rtt, method) = modules::ping::check_alive(&target.input, &[80, 443, 22, 445])
        .await
        .unwrap_or((false, None, "none".into()));
    target.alive = alive;
    target.rtt_ms = rtt;
    target.liveness_method = method.clone();
    if alive {
        let rtt_s = rtt.map(|r| format!(" rtt {:.1}ms", r)).unwrap_or_default();
        shared.finding(Severity::Info, "host", &format!("Host is up ({}){}", method, rtt_s));
        shared.done("Host Liveness", &format!("up ({}){}", method, rtt_s));
    } else {
        shared.finding(
            Severity::Medium,
            "host",
            "Host did not respond to ICMP or TCP ping — scan may still find filtered services",
        );
        shared.done("Host Liveness", "no ping reply (continuing)");
    }

    // ------------------------------------------------------------------
    // Phase 3: NightCrawler Port Strategy (the model chooses)
    // ------------------------------------------------------------------
    let mut ports_spec = opts.ports_spec.clone();
    match (&nv, opts.enable_ai, &ports_spec) {
        (Some(client), true, None) => {
            shared.running("NightCrawler Port Strategy");
            shared.thinking(true);
            let snap = serde_json::json!({
                "input": target.input,
                "kind": target.input_kind,
                "ip": ip.to_string(),
                "hostname": target.hostname,
                "ptr": target.reverse_dns,
                "inferred_domain": target.inferred_domain,
                "cert_domains": target.cert_domains,
                "alive": target.alive,
            });
            let decision = tokio::time::timeout(Duration::from_secs(240), agent::decide_port_strategy(client, &snap)).await;
            shared.thinking(false);
            match decision {
                Ok(Ok(ps)) => {
                    ports_spec = Some(ps.ports.clone());
                    shared.agent_reason(&format!(
                        "Port strategy → {} · because: {}",
                        ps.ports, ps.reason
                    ));
                    shared.finding(
                        Severity::Info,
                        "nc",
                        &format!("Port strategy: {} — {}", ps.ports, ps.reason),
                    );
                    shared.done("NightCrawler Port Strategy", &format!("ports={}", ps.ports));
                    ai_decisions.push(AiDecision {
                        stage: "port-strategy".into(),
                        decision: format!("ports={}", ps.ports),
                        rationale: ps.reason,
                    });
                }
                Ok(Err(e)) => {
                    ports_spec = Some("top".into());
                    shared.skipped("NightCrawler Port Strategy", &format!("model error: {}", e));
                }
                Err(_) => {
                    ports_spec = Some("top".into());
                    shared.skipped("NightCrawler Port Strategy", "model timeout");
                }
            }
        }
        (_, _, Some(spec)) => {
            shared.done("NightCrawler Port Strategy", &format!("fixed by CLI ({})", spec));
        }
        _ => {
            shared.skipped("NightCrawler Port Strategy", "no model — using top ports");
            ports_spec = Some("top".into());
        }
    }

    // ------------------------------------------------------------------
    // Phase 4: Port scan
    // ------------------------------------------------------------------
    shared.running("Port Scan");
    let ports = parse_ports(ports_spec.as_deref().unwrap_or("top"))?;
    let progress = Arc::new(AtomicU64::new(0));
    {
        let progress = progress.clone();
        let shared = shared.clone();
        let ports_total = ports.len() as u64;
        tokio::spawn(async move {
            loop {
                let cur = progress.load(Ordering::Relaxed);
                shared.progress("TCP connect scan", cur, ports_total);
                if cur >= ports_total {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            shared.clear_progress();
        });
    }
    let open_ports = modules::portscan::scan_tcp(
        ip,
        &ports,
        scan_cfg.max_concurrency,
        scan_cfg.timeout_ms,
        Some(progress.clone()),
    )
    .await?;
    shared.clear_progress();
    shared.stat("open_ports", open_ports.len() as u64);
    shared.done(
        "Port Scan",
        &format!("{} open / {} scanned", open_ports.len(), ports.len()),
    );
    shared.log(format!("open ports: {:?}", open_ports));
    for p in &open_ports {
        shared.finding(
            Severity::Info,
            "port",
            &format!("{}/tcp open — {}", p, crate::config::service_for_port(*p)),
        );
        g.relate(
            "ip",
            &ip.to_string(),
            "exposes",
            "service",
            &format!("{}:{}", p, crate::config::service_for_port(*p)),
        );
    }

    // ------------------------------------------------------------------
    // Phase 5: Service & version detection
    // ------------------------------------------------------------------
    shared.running("Service & Version Detection");
    let mut port_results = modules::banner::detect_services(
        ip,
        &host_header,
        &open_ports,
        scan_cfg.http_timeout_ms,
    )
    .await?;
    for pr in &port_results {
        let ver = pr
            .version
            .as_deref()
            .map(|v| format!(" v{}", v))
            .unwrap_or_default();
        shared.finding(
            Severity::Info,
            "service",
            &format!(
                "{}/{} {} — {}{}",
                pr.port,
                pr.proto,
                pr.service,
                pr.product.clone().unwrap_or_else(|| "?".into()),
                ver
            ),
        );
    }
    shared.done(
        "Service & Version Detection",
        &format!("{} services fingerprinted", port_results.len()),
    );

    // HTTP probing for web ports (rich HttpInfo)
    let mut http_infos: Vec<HttpInfo> = Vec::new();
    let web_ports: Vec<u16> = port_results
        .iter()
        .filter(|p| p.http.is_some())
        .map(|p| p.port)
        .collect();
    for pr in &port_results {
        if let Some(mut h) = pr.http.clone() {
            if let Ok(mut full) = modules::banner::probe_http_url(
                &h.url,
                ip,
                pr.port,
                h.url.starts_with("https"),
                scan_cfg.http_timeout_ms,
            )
            .await
            {
                if full.title.is_none() {
                    full.title = h.title.clone();
                }
                h = full;
            }
            if h.url.starts_with("https") && h.tls_subject.is_none() {
                modules::tls_capture::enrich_http_tls(&mut h, ip, pr.port, true).await;
            }
            http_infos.push(h);
        }
    }
    for h in &http_infos {
        if let Some(server) = &h.server {
            shared.log(format!("web {}: {} — {}", h.url, h.status, server));
        }
        for san in &h.tls_san {
            if san.contains('.') && !san.is_empty() {
                g.relate("url", &h.url, "cert-san", "domain", san);
                if !target.cert_domains.contains(san) {
                    target.cert_domains.push(san.clone());
                }
            }
        }
    }

    if target.input_kind == "ip" && target.inferred_domain.is_none() {
        if let Some(first) = target.cert_domains.first() {
            let parts: Vec<&str> = first.split('.').collect();
            if parts.len() >= 2 {
                target.inferred_domain = Some(parts[parts.len() - 2..].join("."));
            }
        }
    }

    let mut results_cves: Vec<CveEntry> = Vec::new();

    // ------------------------------------------------------------------
    // Phase 6: Vulnerability fingerprinting
    // ------------------------------------------------------------------
    shared.running("Vulnerability Fingerprinting");
    let mut vulns = modules::vulns::fingerprint(&port_results, ip);
    for v in &vulns {
        shared.finding(v.severity, "vuln", &format!("{} — {}", v.title, v.affected));
    }
    shared.done(
        "Vulnerability Fingerprinting",
        &format!("{} potential issues", vulns.len()),
    );

    // ------------------------------------------------------------------
    // Phase 6b: CVE mapping — NVD (the engine OpenVAS/Greenbone matches
    // against) + Google CSE exploit references
    // ------------------------------------------------------------------
    let mut cve_refs: Vec<DorkResult> = Vec::new();
    {
        let mut products: Vec<(String, Option<String>)> = port_results
            .iter()
            .filter(|p| p.product.is_some())
            .map(|p| (p.product.clone().unwrap_or_default(), p.version.clone()))
            .collect();
        for v in &vulns {
            if let Some(cve) = &v.cve {
                products.push((cve.clone(), None));
            }
        }
        products.truncate(10);

        if products.is_empty() {
            shared.skipped("CVE Mapping (NVD + CSE)", "no products fingerprinted");
        } else {
            shared.running("CVE Mapping (NVD + CSE)");
            shared.log("querying the NVD CVE database (OpenVAS-style product/version matching)…");
            let nvd = modules::cve::map_cves(&products, Duration::from_secs(20)).await;
            let nvd_count = nvd.len();
            for e in nvd.iter().take(20) {
                if e.id == "NVD-UNAVAILABLE" {
                    shared.log(format!("CVE engine: {}", e.description));
                    continue;
                }
                let sev = if e.score >= 9.0 {
                    Severity::Critical
                } else if e.score >= 7.0 {
                    Severity::High
                } else if e.score >= 4.0 {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                shared.finding(
                    sev,
                    "cve",
                    &format!(
                        "{} [{}] CVSS {:.1} — {} (NVD match for {})",
                        e.id,
                        e.severity,
                        e.score,
                        crate::util::truncate_chars(&e.description, 70),
                        e.product
                    ),
                );
                g.relate("service", &e.product, "affected-by", "cve", &e.id);
            }
            results_cves = nvd;

            // Google CSE exploit references on top (when a key exists)
            if crate::config::resolve_cse_key(cfg).is_some() {
                let refs = modules::dork::run_cve_search(&products, cfg, 6).await;
                let mut hits = 0usize;
                for r in &refs {
                    hits += r.results.len();
                    if let Some(e) = &r.error {
                        shared.log(format!("cse exploit search '{}': {}", r.query, e));
                    }
                }
                shared.log(format!("CSE exploit references: {} URLs", hits));
                cve_refs = refs;
            }
            shared.agent_reason(&format!(
                "NVD CVE database matched {} CVEs for the fingerprinted products",
                nvd_count
            ));
            shared.done(
                "CVE Mapping (NVD + CSE)",
                &format!("{} NVD CVEs matched", nvd_count),
            );
        }
    }

    // Working domain for domain-based phases
    let working_domain: Option<String> = if target.input_kind == "domain" {
        target.hostname.clone()
    } else if opts.allow_pivot {
        target.inferred_domain.clone()
    } else {
        None
    };

    // ------------------------------------------------------------------
    // Phase 7: NightCrawler Planning (the model picks the next modules)
    // ------------------------------------------------------------------
    let mut ai_plan: Option<AiPlan> = None;
    let mut selected_modules: Vec<String> = Vec::new();

    let has_web = !web_ports.is_empty() || !http_infos.is_empty();
    let has_ldap = open_ports.contains(&389) || open_ports.contains(&636) || open_ports.contains(&3268);
    let has_smb = open_ports.contains(&445) || open_ports.contains(&139) || open_ports.contains(&137);
    let likely_snmp = true; // UDP probe is harmless; attempt when not opted out

    if likely_snmp { selected_modules.push("snmp".into()); }
    if has_ldap { selected_modules.push("ldap".into()); }
    if has_smb { selected_modules.push("netbios_smb".into()); }
    if has_web { selected_modules.push("subdirs".into()); }
    if working_domain.is_some() {
        selected_modules.push("deep_subdomain".into());
        selected_modules.push("dorking".into());
    }

    match nv.as_ref() {
        Some(client) if opts.enable_ai => {
            shared.running("NightCrawler Planning");
            shared.thinking(true);
            let snap = evidence_snapshot(&ReconResults {
                meta: Meta {
                    tool: "Night Crawler".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    target_input: target.input.clone(),
                    started_at: String::new(),
                    finished_at: String::new(),
                    duration_secs: 0,
                },
                target: target.clone(),
                ports: port_results.clone(),
                vulns: vulns.clone(),
                dns: None,
                subdomains: vec![],
                subdirs: vec![],
                http: http_infos.clone(),
                snmp: None,
                ldap: None,
                netbios: None,
                smb: None,
                whois: None,
                dorks: vec![],
                graph: GraphData::default(),
                ai_plan: None,
                ai_report: None,
                ai_model: None,
                ai_decisions: vec![],
                pivots: vec![],
                cve_refs: vec![],
                cves: vec![],
                module_log: vec![],
                phases: vec![],
            });
            let decision =
                tokio::time::timeout(Duration::from_secs(300), agent::plan_modules(client, &snap)).await;
            shared.thinking(false);
            match decision {
                Ok(Ok(plan)) => {
                    let applicable = selected_modules.clone();
                    let ai_selected: Vec<String> = plan
                        .modules
                        .iter()
                        .filter(|m| applicable.contains(m))
                        .cloned()
                        .collect();
                    if !ai_selected.is_empty() {
                        selected_modules = ai_selected;
                    }
                    let plan = AiPlan {
                        modules: plan.modules,
                        rationale: plan.rationale,
                        priorities: plan.priorities,
                        model: client.model.clone(),
                    };
                    shared.finding(
                        Severity::Info,
                        "nc",
                        &format!(
                            "Module plan: [{}] — {}",
                            selected_modules.join(", "),
                            plan.rationale
                        ),
                    );
                    shared.agent_reason(&format!(
                        "Running [{}] · because: {}",
                        selected_modules.join(", "),
                        plan.rationale
                    ));
                    let tasks: Vec<(String, String)> = selected_modules
                        .iter()
                        .map(|m| (m.clone(), String::new()))
                        .chain(plan.priorities.iter().map(|p| (p.clone(), "priority".into())))
                        .collect();
                    shared.agent_tasks(tasks);
                    for p in &plan.priorities {
                        shared.log(format!("NightCrawler priority: {}", p));
                    }
                    shared.done(
                        "NightCrawler Planning",
                        &format!("chose {} modules", selected_modules.len()),
                    );
                    ai_decisions.push(AiDecision {
                        stage: "module-plan".into(),
                        decision: format!("[{}]", selected_modules.join(", ")),
                        rationale: plan.rationale.clone(),
                    });
                    ai_plan = Some(plan);
                }
                Ok(Err(e)) => {
                    shared.skipped("NightCrawler Planning", &format!("model error: {}", e));
                    shared.log(format!("NightCrawler planning failed: {} — evidence-based selection", e));
                }
                Err(_) => {
                    shared.skipped("NightCrawler Planning", "model timeout — evidence-based selection");
                }
            }
        }
        _ => {
            shared.skipped(
                "NightCrawler Planning",
                if !opts.enable_ai { "agent disabled" } else { "no model" },
            );
        }
    }

    let want = |m: &str| selected_modules.iter().any(|s| s == m);

    // ------------------------------------------------------------------
    // Phases 8-9: DNS recon + AXFR
    // ------------------------------------------------------------------
    let mut dns_results: Option<DnsResults> = None;
    if let Some(domain) = working_domain.clone() {
        shared.running("DNS Recon");
        let dr = modules::dnsrecon::dns_recon(&resolver, &domain).await?;
        for r in &dr.records {
            shared.log(format!("{} {} -> {} ({})", r.rtype, r.name, r.value, domain));
            match r.rtype.as_str() {
                "A" | "AAAA" => g.relate("domain", &r.name, "resolves-to", "ip", &r.value),
                "MX" => {
                    let ex = r.value.split(' ').last().unwrap_or(&r.value);
                    g.relate("domain", &r.name, "mail-server", "domain", ex);
                }
                "NS" => g.relate("domain", &r.name, "nameserver", "domain", &r.value),
                "TXT" => {
                    if r.value.contains('@') {
                        g.relate("domain", &r.name, "txt-email", "email", &r.value);
                    }
                }
                _ => {}
            }
        }
        shared.done("DNS Recon", &format!("{} records for {}", dr.records.len(), domain));

        shared.running("Zone Transfer (AXFR)");
        if dr.axfr_success {
            shared.finding(
                Severity::Critical,
                "dns",
                &format!(
                    "Zone transfer SUCCESS against {} — {} records leaked",
                    dr.axfr_servers.join(", "),
                    dr.axfr_records.len()
                ),
            );
            for rec in dr.axfr_records.iter().take(50) {
                if rec.rtype == "A" {
                    g.relate("domain", &rec.name, "axfr->", "ip", &rec.value);
                }
            }
            shared.done(
                "Zone Transfer (AXFR)",
                &format!("{} records leaked", dr.axfr_records.len()),
            );
        } else {
            shared.done("Zone Transfer (AXFR)", "refused on all NS (good)");
        }
        if let Some(w) = &dr.wildcard {
            shared.finding(
                Severity::Info,
                "dns",
                &format!("DNS wildcard detected ({}) — brute results filtered", w),
            );
        }
        dns_results = Some(dr);
    } else {
        shared.skipped("DNS Recon", "no domain");
        shared.skipped("Zone Transfer (AXFR)", "no domain");
    }

    // ------------------------------------------------------------------
    // Phase 10: Subdomain enumeration
    // ------------------------------------------------------------------
    let mut subdomains: Vec<SubdomainResult> = Vec::new();
    if let Some(domain) = working_domain.clone() {
        shared.agent_task_status("deep_subdomain", PhaseStatus::Running);
        shared.running("Subdomain Enumeration");
        match modules::subdomain::enumerate(
            &resolver,
            &domain,
            opts.wordlist_subs.clone(),
            scan_cfg.max_subdomains,
        )
        .await
        {
            Ok(subs) => {
                for s in &subs {
                    shared.finding(
                        Severity::Info,
                        "subdomain",
                        &format!("{} [{}] {}", s.name, s.source, s.ips.join(",")),
                    );
                    g.relate("domain", &domain, "parent-of", "subdomain", &s.name);
                    if let Some(first_ip) = s.ips.first() {
                        g.relate("subdomain", &s.name, "resolves-to", "ip", first_ip);
                    }
                }
                subdomains = subs;
                shared.done(
                    "Subdomain Enumeration",
                    &format!("{} found (crt.sh + brute)", subdomains.len()),
                );
            }
            Err(e) => shared.failed("Subdomain Enumeration", &format!("{}", e)),
        }
    } else {
        shared.skipped("Subdomain Enumeration", "no domain");
    }

    // ------------------------------------------------------------------
    // Phase 11: Web & directory discovery
    // ------------------------------------------------------------------
    let mut subdirs: Vec<DirResult> = Vec::new();
    let mut web_bases: Vec<String> = Vec::new();
    if has_web {
        shared.agent_task_status("subdirs", PhaseStatus::Running);
        shared.running("Web & Directory Discovery");
        let bases = modules::subdir::web_bases(&host_header, &open_ports);
        web_bases = if bases.is_empty() {
            vec![format!("http://{}", ip), format!("https://{}", ip)]
        } else {
            bases
        };
        shared.log(format!("probing bases: {:?}", web_bases));
        match modules::subdir::discover(
            &web_bases,
            opts.wordlist_dirs.clone(),
            scan_cfg.max_subdirs,
            24,
        )
        .await
        {
            Ok(dirs) => {
                let mut graph_urls = 0usize;
                for d in &dirs {
                    let sev = if d.status == 200
                        && (d.url.contains("admin") || d.url.contains("backup") || d.url.contains(".git"))
                    {
                        Severity::Medium
                    } else {
                        Severity::Info
                    };
                    shared.finding(sev, "web-path", &format!("{} ({} {})", d.url, d.status, d.note));
                    // keep the graph meaningful: only notable paths become entities
                    let notable = d.status == 200
                        && (d.url.contains("admin")
                            || d.url.contains("backup")
                            || d.url.contains(".git")
                            || d.url.contains("config")
                            || d.url.ends_with("index.html"));
                    if notable && graph_urls < 12 {
                        if let Some(b) = web_bases.first() {
                            g.relate("url", &d.url, "discovered-under", "url", b);
                            graph_urls += 1;
                        }
                    }
                }
                subdirs = dirs;
                shared.done(
                    "Web & Directory Discovery",
                    &format!("{} paths found", subdirs.len()),
                );
            }
            Err(e) => shared.failed("Web & Directory Discovery", &format!("{}", e)),
        }
    } else {
        shared.skipped("Web & Directory Discovery", "no web service");
    }

    // ------------------------------------------------------------------
    // Phase 12: SNMP
    // ------------------------------------------------------------------
    let mut snmp_res: Option<SnmpResults> = None;
    if want("snmp") {
        shared.agent_task_status("snmp", PhaseStatus::Running);
        shared.running("SNMP Enumeration");
        shared.log("probing UDP/161 with common community strings…");
        match modules::snmp::snmp_enum(ip, 161, opts.snmp_communities.clone()).await {
            Ok(s) => {
                shared.finding(
                    Severity::High,
                    "snmp",
                    &format!(
                        "SNMP accessible with community '{}' ({})",
                        s.community,
                        s.vendor_guess.clone().unwrap_or_else(|| "unknown vendor".into())
                    ),
                );
                if let Some(d) = &s.sysdescr {
                    shared.log(format!("sysDescr: {}", d));
                }
                shared.done(
                    "SNMP Enumeration",
                    &format!("community='{}', {} varbinds", s.community, s.varbind_count),
                );
                if let Some(name) = &s.sysname {
                    g.relate("ip", &ip.to_string(), "snmp-name", "host", name);
                }
                shared.agent_task_status("snmp", PhaseStatus::Done);
                snmp_res = Some(s);
            }
            Err(_) => {
                shared.agent_task_status("snmp", PhaseStatus::Skipped("no response".into()));
                shared.skipped("SNMP Enumeration", "no community accepted")
            }
        }
    } else {
        shared.skipped("SNMP Enumeration", "not selected");
    }

    // ------------------------------------------------------------------
    // Phase 13: LDAP
    // ------------------------------------------------------------------
    let mut ldap_res: Option<LdapResults> = None;
    if want("ldap") && has_ldap {
        shared.agent_task_status("ldap", PhaseStatus::Running);
        shared.running("LDAP Enumeration");
        match modules::ldap::ldap_enum(ip, 389).await {
            Ok(l) => {
                if l.anonymous_bind {
                    shared.finding(Severity::High, "ldap", "LDAP anonymous bind allowed");
                }
                shared.done(
                    "LDAP Enumeration",
                    &format!(
                        "users:{} groups:{} computers:{}",
                        l.users.len(),
                        l.groups.len(),
                        l.computers.len()
                    ),
                );
                for u in l.users.iter().take(30) {
                    g.relate("ip", &ip.to_string(), "ldap-user", "user", u);
                }
                shared.agent_task_status("ldap", PhaseStatus::Done);
                ldap_res = Some(l);
            }
            Err(e) => shared.failed("LDAP Enumeration", &format!("{}", e)),
        }
    } else {
        shared.skipped("LDAP Enumeration", "no LDAP service");
    }

    // ------------------------------------------------------------------
    // Phase 14: NetBIOS / SMB
    // ------------------------------------------------------------------
    let mut netbios_res: Option<NbnsResults> = None;
    let mut smb_res: Option<SmbResults> = None;
    if want("netbios_smb") && has_smb {
        shared.agent_task_status("netbios_smb", PhaseStatus::Running);
        shared.running("NetBIOS / SMB Enumeration");
        match modules::netbios::nbns_query(ip, 137).await {
            Ok(nb) => {
                shared.finding(
                    Severity::Medium,
                    "netbios",
                    &format!(
                        "NetBIOS names: {} (MAC {})",
                        nb.names.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>().join(", "),
                        nb.mac_address
                    ),
                );
                for (name, _) in &nb.names {
                    g.relate("ip", &ip.to_string(), "netbios-name", "host", name);
                }
                netbios_res = Some(nb);
            }
            Err(_) => shared.log("no NBNS response on UDP/137"),
        }
        match modules::smb::smb_enum(ip).await {
            Ok(s) => {
                if !s.shares.is_empty() {
                    shared.finding(
                        Severity::Medium,
                        "smb",
                        &format!("{} SMB shares visible via null session", s.shares.len()),
                    );
                }
                shared.done(
                    "NetBIOS / SMB Enumeration",
                    &format!("shares:{} users:{}", s.shares.len(), s.users.len()),
                );
                shared.agent_task_status("netbios_smb", PhaseStatus::Done);
                smb_res = Some(s);
            }
            Err(e) => shared.failed("NetBIOS / SMB Enumeration", &format!("{}", e)),
        }
    } else {
        shared.skipped("NetBIOS / SMB Enumeration", "no SMB/NetBIOS service");
    }

    // ------------------------------------------------------------------
    // Phase 15: WHOIS
    // ------------------------------------------------------------------
    let mut whois_res: Option<WhoisResults> = None;
    if let Some(domain) = working_domain.clone() {
        shared.running("WHOIS");
        let base_domain = registrable(&domain);
        match modules::whois::whois_domain(&base_domain).await {
            Ok(w) => {
                shared.log(format!(
                    "whois: registrar={} created={}",
                    w.registrar.clone().unwrap_or("?".into()),
                    w.created.clone().unwrap_or("?".into())
                ));
                if let Some(org) = &w.org {
                    g.relate("domain", &base_domain, "owned-by", "org", org);
                }
                shared.done("WHOIS", &format!("registrar: {}", w.registrar.clone().unwrap_or("?".into())));
                whois_res = Some(w);
            }
            Err(e) => shared.failed("WHOIS", &format!("{}", e)),
        }
    } else if target.input_kind == "ip" {
        shared.running("WHOIS");
        match modules::whois::whois_ip(&ip.to_string()).await {
            Ok(w) => {
                if let Some(org) = &w.org {
                    g.relate("ip", &ip.to_string(), "allocated-to", "org", org);
                }
                shared.done("WHOIS", &format!("netblock org: {}", w.org.clone().unwrap_or("?".into())));
                whois_res = Some(w);
            }
            Err(e) => shared.failed("WHOIS", &format!("{}", e)),
        }
    } else {
        shared.skipped("WHOIS", "nothing to look up");
    }

    // ------------------------------------------------------------------
    // Phase 16: Dorking
    // ------------------------------------------------------------------
    let mut dorks: Vec<DorkResult> = Vec::new();
    if let Some(domain) = working_domain.clone() {
        if want("dorking") {
            shared.agent_task_status("dorking", PhaseStatus::Running);
        shared.running("OSINT Dorking");
            let base = registrable(&domain);
            match modules::dork::run_dorks(&base, cfg, 10).await {
                Ok(ds) => {
                    let mut hits = 0usize;
                    for d in &ds {
                        hits += d.results.len();
                        if !d.results.is_empty() {
                            shared.finding(
                                Severity::Low,
                                "osint",
                                &format!("dork '{}' -> {} results", d.query, d.results.len()),
                            );
                            for r in d.results.iter().take(3) {
                                g.relate("domain", &base, "osint-hit", "url", r);
                            }
                        }
                    }
                    shared.done("OSINT Dorking", &format!("{} result URLs", hits));
                    dorks = ds;
                }
                Err(e) => shared.failed("OSINT Dorking", &format!("{}", e)),
            }
        } else {
            shared.agent_task_status("dorking", PhaseStatus::Skipped("not selected".into()));
        shared.skipped("OSINT Dorking", "not selected by plan");
        }
    } else {
        shared.skipped("OSINT Dorking", "no domain");
    }

    // ------------------------------------------------------------------
    // Assemble intermediate results for follow-up decisions
    // ------------------------------------------------------------------
    // (results are assembled by `assemble_results` — see bottom of file)

    // ------------------------------------------------------------------
    // Phase 17: NightCrawler Follow-up (autonomous chaining)
    // ------------------------------------------------------------------
    let mut pivots: Vec<PivotData> = Vec::new();
    let mut ai_report: Option<String> = None;
    let mut final_decisions: Vec<AiDecision> = ai_decisions.clone();

    if nv.is_some() && opts.enable_ai {
        shared.running("NightCrawler Follow-up");
        shared.thinking(true);

        let mut rounds = 0;
        let mut rescan_done = false;
        let mut rescan_pending: Option<String> = None;
        'followup: loop {
            rounds += 1;
            let inter = assemble_results(&cve_refs, &results_cves, &started, &shared, nv.as_ref().map(|c| c.model.clone()), &target,
                &port_results, &vulns, &dns_results, &subdomains, &subdirs, &http_infos,
                &snmp_res, &ldap_res, &netbios_res, &smb_res, &whois_res, &dorks, g.data(),
                ai_plan.clone(), final_decisions.clone(), pivots.clone());
            let mut snap = evidence_snapshot(&inter);
            if let Some(obj) = snap.as_object_mut() {
                obj.insert(
                    "pivot_candidates".into(),
                    serde_json::json!(pivot_candidates(&inter, &working_domain)),
                );
                obj.insert("round".into(), serde_json::json!(rounds));
                // coverage context: let the model see what already ran so it
                // doesn't repeat work (doctrine §3, §21-efficiency)
                obj.insert(
                    "coverage".into(),
                    serde_json::json!({
                        "initial_ports_scanned": ports.len(),
                        "full_range_rescans_done": if rescan_done { 1 } else { 0 },
                        "dirs_probed": subdirs.len(),
                        "open_ports_total": port_results.len(),
                    }),
                );
            }

            let client = nv.as_ref().unwrap();
            let decision =
                tokio::time::timeout(Duration::from_secs(300), agent::decide_followups(client, &snap)).await;
            shared.thinking(false);

            let plan = match decision {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    shared.log(format!("NightCrawler follow-up decision failed: {}", e));
                    break 'followup;
                }
                Err(_) => {
                    shared.log("NightCrawler follow-up decision timed out");
                    break 'followup;
                }
            };

            let action_names: Vec<String> = plan
                .actions
                .iter()
                .map(|a| match a {
                    FollowUpAction::ExtendDirs { .. } => "extend_dirs",
                    FollowUpAction::ProbeWebRoots { .. } => "probe_web_roots",
                    FollowUpAction::PivotDomains { .. } => "pivot_domains",
                    FollowUpAction::RescanPorts { .. } => "rescan_ports",
                    FollowUpAction::Finish => "finish",
                })
                .map(|s| s.to_string())
                .collect();
            shared.finding(
                Severity::Info,
                "nc",
                &format!("Follow-up plan: [{}] — {}", action_names.join(", "), plan.reason),
            );
            shared.agent_reason(&format!(
                "Follow-ups → [{}] · because: {}",
                action_names.join(", "),
                plan.reason
            ));
            final_decisions.push(AiDecision {
                stage: format!("follow-up-{}", rounds),
                decision: format!("[{}]", action_names.join(", ")),
                rationale: plan.reason.clone(),
            });

            if plan.actions.is_empty() || plan.actions.iter().any(|a| matches!(a, FollowUpAction::Finish)) {
                if !plan.actions.is_empty() {
                    shared.done("NightCrawler Follow-up", "model chose finish");
                }
                break 'followup;
            }

            shared.thinking(true);
            for action in &plan.actions {
                match action {
                    FollowUpAction::ExtendDirs { bases, words } => {
                        let valid_bases: Vec<String> = if bases.is_empty() {
                            web_bases.clone()
                        } else {
                            bases
                                .iter()
                                .filter(|b| web_bases.contains(b) || b.contains(&host_header))
                                .cloned()
                                .collect()
                        };
                        let valid_bases = if valid_bases.is_empty() { web_bases.clone() } else { valid_bases };
                        let words = sanitize_words(words);
                        if valid_bases.is_empty() || words.is_empty() {
                            shared.log("extend_dirs: nothing applicable");
                            continue;
                        }
                        shared.log(format!("extend_dirs: {:?} words on {:?}", words.len(), valid_bases));
                        if let Ok(mut found) =
                            modules::subdir::discover(&valid_bases, Some(words), 120, 12).await
                        {
                            for d in found.drain(..) {
                                if !subdirs.iter().any(|x| x.url == d.url) {
                                    shared.finding(
                                        Severity::Info,
                                        "web-path",
                                        &format!("{} ({} {}) [AI follow-up]", d.url, d.status, d.note),
                                    );
                                    subdirs.push(d);
                                }
                            }
                        }
                    }
                    FollowUpAction::ProbeWebRoots { hosts } => {
                        let known: Vec<String> = subdomains.iter().map(|s| s.name.clone()).collect();
                        let valid: Vec<String> = hosts
                            .iter()
                            .filter(|h| known.contains(h) || **h == host_header)
                            .take(20)
                            .cloned()
                            .collect();
                        for h in &valid {
                            for scheme in ["http", "https"] {
                                let url = format!("{}://{}/", scheme, h);
                                if let Ok(info) = modules::banner::probe_http_url(
                                    &url,
                                    ip,
                                    if scheme == "https" { 443 } else { 80 },
                                    scheme == "https",
                                    scan_cfg.http_timeout_ms,
                                )
                                .await
                                {
                                    shared.finding(
                                        Severity::Info,
                                        "web-probe",
                                        &format!(
                                            "{} → {} ({})",
                                            url,
                                            info.status,
                                            info.title.clone().unwrap_or_else(|| info.server.clone().unwrap_or_default())
                                        ),
                                    );
                                    g.relate("subdomain", h, "web-root", "url", &url);
                                    http_infos.push(info);
                                }
                            }
                        }
                    }
                    FollowUpAction::PivotDomains { domains } => {
                        let candidates = pivot_candidates(
                            &assemble_results(&cve_refs, &results_cves, &started, &shared, nv.as_ref().map(|c| c.model.clone()), &target,
                                &port_results, &vulns, &dns_results, &subdomains, &subdirs, &http_infos,
                                &snmp_res, &ldap_res, &netbios_res, &smb_res, &whois_res, &dorks, g.data(),
                                ai_plan.clone(), final_decisions.clone(), pivots.clone()),
                            &working_domain,
                        );
                        let valid: Vec<String> = domains
                            .iter()
                            .filter(|d| candidates.contains(d))
                            .take(3)
                            .cloned()
                            .collect();
                        for d in valid {
                            shared.log(format!("pivot: deep recon on {}", d));
                            let mut pd = PivotData {
                                domain: d.clone(),
                                dns: None,
                                dorks: vec![],
                            };
                            if let Ok(dr) = modules::dnsrecon::dns_recon(&resolver, &d).await {
                                if dr.axfr_success {
                                    shared.finding(
                                        Severity::Critical,
                                        "dns",
                                        &format!("AXFR success on pivot domain {}", d),
                                    );
                                }
                                pd.dns = Some(dr);
                            }
                            if let Ok(ds) = modules::dork::run_dorks(&registrable(&d), cfg, 8).await {
                                pd.dorks = ds;
                            }
                            g.relate("domain", &registrable(&d), "pivot-of", "domain", &d);
                            pivots.push(pd);
                        }
                    }
                    FollowUpAction::RescanPorts { spec } => {
                        if rescan_done {
                            shared.log("rescan_ports skipped: a port rescan already ran this scan (efficiency rule)");
                            continue;
                        }
                        if let Ok(extra) = parse_ports(spec) {
                            let existing: std::collections::HashSet<u16> =
                                open_ports.iter().copied().collect();
                            let fresh: Vec<u16> = extra
                                .iter()
                                .copied()
                                .filter(|p| !existing.contains(p))
                                .collect();
                            shared.log(format!("rescan_ports: {} new candidates", fresh.len()));
                            rescan_done = true;
                            if !fresh.is_empty() {
                                let found = modules::portscan::scan_tcp(
                                    ip,
                                    &fresh,
                                    scan_cfg.max_concurrency,
                                    scan_cfg.timeout_ms,
                                    None,
                                )
                                .await
                                .unwrap_or_default();
                                if !found.is_empty() {
                                    let more = modules::banner::detect_services(
                                        ip,
                                        &host_header,
                                        &found,
                                        scan_cfg.http_timeout_ms,
                                    )
                                    .await
                                    .unwrap_or_default();
                                    for pr in more {
                                        shared.finding(
                                            Severity::Info,
                                            "port",
                                            &format!("NightCrawler rescan found {}/tcp {} — {}", pr.port, pr.service, pr.product.clone().unwrap_or_default()),
                                        );
                                        port_results.push(pr);
                                    }
                                }
                            }
                        }
                    }
                    FollowUpAction::Finish => {}
                }
            }
            shared.thinking(false);

            if rounds >= 3 {
                shared.done("NightCrawler Follow-up", "round limit reached (3)");
                break 'followup;
            }
        }
        shared.thinking(false);
        if pivots.is_empty() {
            shared.skipped("Pivot Domains", "none selected by AI");
        } else {
            shared.done(
                "Pivot Domains",
                &format!("{} pivots analyzed", pivots.len()),
            );
        }
    } else {
        shared.skipped("NightCrawler Follow-up", "no model / agent offline");
        shared.skipped("Pivot Domains", "requires AI");
    }

    // ------------------------------------------------------------------
    // Phase 19: Link analysis
    // ------------------------------------------------------------------
    shared.running("Link Analysis");
    for p in &pivots {
        if let Some(dns) = &p.dns {
            for r in &dns.records {
                if r.rtype == "A" {
                    g.relate("domain", &r.name, "resolves-to", "ip", &r.value);
                }
            }
        }
        for d in &p.dorks {
            for r in d.results.iter().take(2) {
                g.relate("domain", &p.domain, "osint-hit", "url", r);
            }
        }
    }
    let graph = g.data();
    let hubs = g.hubs(10);
    for (kind, label, deg) in &hubs {
        shared.log(format!("hub: {} '{}' ({} links)", kind, label, deg));
    }
    shared.stat("graph_nodes", graph.nodes.len() as u64);
    shared.stat("graph_edges", graph.edges.len() as u64);
    shared.done(
        "Link Analysis",
        &format!("{} nodes / {} edges", graph.nodes.len(), graph.edges.len()),
    );

    let mut results = assemble_results(&cve_refs, &results_cves, &started, &shared, nv.as_ref().map(|c| c.model.clone()), &target,
        &port_results, &vulns, &dns_results, &subdomains, &subdirs, &http_infos,
        &snmp_res, &ldap_res, &netbios_res, &smb_res, &whois_res, &dorks, graph.clone(),
        ai_plan.clone(), final_decisions, pivots);
    results.graph = graph;

    // ------------------------------------------------------------------
    // Phase 20: NightCrawler analysis & report (doctrine §9 format)
    // ------------------------------------------------------------------
    match nv.as_ref() {
        Some(client) if opts.enable_ai => {
            shared.running("NightCrawler Analysis & Report");
            shared.log("writing the assessment — this can take a few minutes on the free tier");
            shared.thinking(true);
            let json = serde_json::to_string_pretty(&slim_results_json(&results))?;
            let decision =
                tokio::time::timeout(Duration::from_secs(700), crate::agent::analyze_report(client, &json, &results.target.input));
            shared.thinking(false);
            match decision.await {
                Ok(Ok(md)) => {
                    results.ai_report = Some(md.clone());
                    shared.done("NightCrawler Analysis & Report", "assessment written");
                }
                Ok(Err(e)) => {
                    shared.skipped("NightCrawler Analysis & Report", &format!("{}", e));
                    shared.log(format!("NightCrawler report failed: {}", e));
                }
                Err(_) => {
                    shared.skipped("NightCrawler Analysis & Report", "model timeout");
                }
            }
        }
        _ => shared.skipped("NightCrawler Analysis & Report", "no model / agent offline"),
    }

    // ------------------------------------------------------------------
    // Phase 21: Final report
    // ------------------------------------------------------------------
    shared.running("Final Report");
    results.meta.finished_at = crate::util::now_string();
    match crate::report::write_reports(&results, &opts.output_dir) {
        Ok(path) => {
            shared.with(|s| {
                s.report_path = Some(path.display().to_string());
            });
            shared.done("Final Report", &format!("saved to {}", path.display()));
        }
        Err(e) => {
            shared.failed("Final Report", &format!("{}", e));
        }
    }

    shared.with(|s| {
        s.done = true;
    });
    Ok(results)
}

/// Candidate domains the AI may pivot to: cert SANs + wildcard-level siblings
/// of the working domain, restricted to the same registrable domain.
fn pivot_candidates(results: &ReconResults, working_domain: &Option<String>) -> Vec<String> {
    let mut cands: Vec<String> = Vec::new();
    let main = match working_domain {
        Some(d) => registrable(d),
        None => return cands,
    };
    for san in &results.target.cert_domains {
        let d = san.trim_start_matches("*.").to_ascii_lowercase();
        if d.ends_with(&main) && d != main {
            cands.push(d);
        }
    }
    if let Some(dns) = &results.dns {
        for r in &dns.records {
            if r.rtype == "CNAME" || r.rtype == "MX" {
                let target = r.value.split(' ').last().unwrap_or(&r.value);
                let t = strip_domain(target).trim_end_matches('.').to_ascii_lowercase();
                if t.ends_with(&main) && t != main {
                    cands.push(t);
                }
            }
        }
    }
    cands.sort();
    cands.dedup();
    cands.truncate(10);
    cands
}

fn sanitize_words(words: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for w in words {
        let w = w.trim().trim_matches('/');
        if w.is_empty() || w.len() > 40 {
            continue;
        }
        let ok = w.chars().all(|c| c.is_ascii_alphanumeric() || "-_.~".contains(c));
        if ok && !out.contains(&w.to_string()) {
            out.push(w.to_string());
        }
        if out.len() >= 60 {
            break;
        }
    }
    out
}

/// Best-effort "registrable domain": last two labels.
fn registrable(domain: &str) -> String {
    let d = strip_domain(domain);
    let parts: Vec<&str> = d.split('.').collect();
    if parts.len() >= 2 {
        let two_part = [
            "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
            "com.br", "com.cn", "com.tw", "co.in", "co.jp", "com.mx", "co.za",
        ];
        let last_two = parts[parts.len() - 2..].join(".");
        if two_part.contains(&last_two.as_str()) && parts.len() >= 3 {
            return parts[parts.len() - 3..].join(".");
        }
        return last_two;
    }
    d
}

/// True if the string is an IPv4 literal (used by CLI validation).
pub fn is_ip_literal(s: &str) -> bool {
    if let Ok(v4) = s.parse::<Ipv4Addr>() {
        let _ = v4;
        return true;
    }
    s.parse::<std::net::Ipv6Addr>().is_ok()
}

fn assemble_results(cve_refs: &[DorkResult], cves: &[CveEntry],
    started: &Instant,
    shared: &SharedState,
    ai_model: Option<String>,
    target: &TargetInfo,
    port_results: &[PortResult],
    vulns: &[VulnFinding],
    dns_results: &Option<DnsResults>,
    subdomains: &[SubdomainResult],
    subdirs: &[DirResult],
    http_infos: &[HttpInfo],
    snmp: &Option<SnmpResults>,
    ldap: &Option<LdapResults>,
    netbios: &Option<NbnsResults>,
    smb: &Option<SmbResults>,
    whois: &Option<WhoisResults>,
    dorks: &[DorkResult],
    graph: GraphData,
    ai_plan: Option<AiPlan>,
    ai_decisions: Vec<AiDecision>,
    pivots: Vec<PivotData>,
) -> ReconResults {
    let cve_refs = cve_refs.to_vec();
    let cves = cves.to_vec();
    let duration = started.elapsed().as_secs();
    ReconResults {
        meta: Meta {
            tool: "Night Crawler".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            target_input: target.input.clone(),
            started_at: crate::util::now_string(),
            finished_at: crate::util::now_string(),
            duration_secs: duration,
        },
        target: target.clone(),
        ports: port_results.to_vec(),
        vulns: vulns.to_vec(),
        dns: dns_results.clone(),
        subdomains: subdomains.to_vec(),
        subdirs: subdirs.to_vec(),
        http: http_infos.to_vec(),
        snmp: snmp.clone(),
        ldap: ldap.clone(),
        netbios: netbios.clone(),
        smb: smb.clone(),
        whois: whois.clone(),
        dorks: dorks.to_vec(),
        graph,
        ai_plan,
        ai_report: None,
        ai_model,
        ai_decisions,
        pivots,
        cve_refs,
        cves,
        module_log: vec![],
        phases: shared.with(|s| {
            s.phases
                .iter()
                .map(|p| {
                    (
                        p.name.clone(),
                        match &p.status {
                            PhaseStatus::Pending => "pending".to_string(),
                            PhaseStatus::Running => "running".to_string(),
                            PhaseStatus::Done => format!("done: {}", p.summary),
                            PhaseStatus::Skipped(r) => format!("skipped: {}", r),
                            PhaseStatus::Failed(r) => format!("failed: {}", r),
                        },
                    )
                })
                .collect()
        }),
    }
}
