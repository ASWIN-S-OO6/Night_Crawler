//! Recursive Adaptive AI Agent for Night Crawler
//!
//! This agent replaces the fixed-phase pipeline with a dynamic, recursive
//! decision-making loop. It continuously analyzes findings, identifies gaps,
//! and chooses the next best action based on the current evidence.
//!
//! The agent operates on the principle: OBSERVE -> ORIENT -> DECIDE -> ACT (OODA loop)

use crate::ai::NvClient;
use crate::config::Config;
use crate::modules::api_discovery::ApiDiscoveryResult;
use crate::orchestrator::Opts;
use crate::state::SharedState;
use crate::types::*;
use crate::util::strip_domain;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use chrono;
use regex::Regex;

/// Candidate domains the AI may pivot to: cert SANs + wildcard-level siblings of the working domain, restricted to the same registrable domain.
fn pivot_candidates(results: &crate::types::ReconResults, working_domain: &Option<String>) -> Vec<String> {
    let mut cands: Vec<String> = Vec::new();
    let main = match working_domain { Some(d) => registrable(d), None => return cands };
    for san in &results.target.cert_domains {
        let d = san.trim_start_matches("*.").to_ascii_lowercase();
        if d.ends_with(&main) && d != main { cands.push(d); }
    }
    if let Some(dns) = &results.dns {
        for r in &dns.records {
            if r.rtype == "CNAME" || r.rtype == "MX" {
                let target = r.value.split(' ').last().unwrap_or(&r.value);
                let t = strip_domain(target).trim_end_matches('.').to_ascii_lowercase();
                if t.ends_with(&main) && t != main { cands.push(t); }
            }
        }
    }
    cands.sort(); cands.dedup(); cands.truncate(10); cands
}

/// Best-effort "registrable domain": last two labels.
fn registrable(domain: &str) -> String {
    let d = strip_domain(domain);
    let parts: Vec<&str> = d.split('.').collect();
    if parts.len() >= 2 {
        let two_part = ["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "com.br", "com.cn", "com.tw", "co.in", "co.jp", "com.mx", "co.za"];
        let last_two = parts[parts.len() - 2..].join(".");
        if two_part.contains(&last_two.as_str()) && parts.len() >= 3 {
            return parts[parts.len() - 3..].join(".");
        }
        return last_two;
    }
    d
}

/// Maximum recursion depth to prevent infinite loops
const MAX_RECURSION_DEPTH: usize = 10;

/// Maximum time for the entire scan
const MAX_SCAN_DURATION: Duration = Duration::from_secs(3600);

/// Minimum time between AI decisions to avoid rate limiting
const MIN_DECISION_INTERVAL: Duration = Duration::from_secs(5);

/// The recursive agent's state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    pub depth: usize,
    pub action_history: Vec<AgentAction>,
    pub evidence: Value,
    pub coverage_gaps: Vec<CoverageGap>,
    pub is_complete: bool,
    pub completion_reason: String,
    /// Start time as unix timestamp for serialization
    pub started_at_ts: i64,
    /// Last decision time as unix timestamp for serialization  
    pub last_decision_at_ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAction {
    pub step: usize,
    pub action_type: String,
    pub rationale: String,
    pub parameters: Value,
    pub result: Option<Value>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageGap {
    pub area: String,
    pub severity: String,
    pub description: String,
    pub suggested_actions: Vec<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDecision {
    pub action_type: String,
    pub rationale: String,
    pub parameters: Value,
}

/// Advanced finding types for enhanced recon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiddenContentFinding {
    pub url: String,
    pub content_type: String, // "directory", "file", "image", "config", "database_config", "secret"
    pub severity: Severity,
    pub confidence: String,
    pub evidence: String,
    pub source: String, // "dir_enum", "js_analysis", "config_discovery", "image_discovery"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfigFinding {
    pub url: String,
    pub db_type: String, // "mysql", "postgresql", "mongodb", "redis", "sqlite", "mssql"
    pub connection_string: String,
    pub source_file: String,
    pub severity: Severity,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiddenImageFinding {
    pub url: String,
    pub image_type: String, // "hidden", "uploaded", "backup", "thumbnail"
    pub dimensions: Option<(u32, u32)>,
    pub severity: Severity,
    pub confidence: String,
    pub metadata: Option<Value>, // EXIF, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealIPFinding {
    pub domain: String,
    pub real_ip: String,
    pub cdn_detected: String, // "cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "sucuri"
    pub detection_method: String, // "ssl_cert", "dns_history", "subdomain_leak", "mail_header", "http_header", "error_page"
    pub confidence: String,
    pub evidence: String,
}

/// The main recursive agent
pub struct RecursiveAgent {
    client: Arc<NvClient>,
    shared: Arc<SharedState>,
    opts: Opts,
    cfg: Config,
    state: AgentState,
    target: TargetInfo,
    open_ports: Vec<u16>,
    port_results: Vec<PortResult>,
    http_infos: Vec<HttpInfo>,
    web_bases: Vec<String>,
    dns_results: Option<DnsResults>,
    subdomains: Vec<SubdomainResult>,
    subdirs: Vec<DirResult>,
    snmp_res: Option<SnmpResults>,
    ldap_res: Option<LdapResults>,
    netbios_res: Option<NbnsResults>,
    smb_res: Option<SmbResults>,
    whois_res: Option<WhoisResults>,
    dorks: Vec<DorkResult>,
    api_results: Option<ApiDiscoveryResult>,
    vulns: Vec<VulnFinding>,
    cves: Vec<CveEntry>,
    cve_refs: Vec<DorkResult>,
    graph: GraphData,
    ai_decisions: Vec<AiDecision>,
    pivots: Vec<PivotData>,
}

impl RecursiveAgent {
    pub fn new(
        client: Arc<NvClient>,
        shared: Arc<SharedState>,
        opts: Opts,
        cfg: Config,
        target: TargetInfo,
    ) -> Self {
        Self {
            client,
            shared,
            opts,
            cfg,
            state: AgentState {
                depth: 0,
                action_history: Vec::new(),
                evidence: json!({}),
                coverage_gaps: Vec::new(),
                is_complete: false,
                completion_reason: String::new(),
                started_at_ts: chrono::Local::now().timestamp(),
                last_decision_at_ts: chrono::Local::now().timestamp(),
            },
            target,
            open_ports: Vec::new(),
            port_results: Vec::new(),
            http_infos: Vec::new(),
            web_bases: Vec::new(),
            dns_results: None,
            subdomains: Vec::new(),
            subdirs: Vec::new(),
            snmp_res: None,
            ldap_res: None,
            netbios_res: None,
            smb_res: None,
            whois_res: None,
            dorks: Vec::new(),
            api_results: None,
            vulns: Vec::new(),
            cves: Vec::new(),
            cve_refs: Vec::new(),
            graph: GraphData::default(),
            ai_decisions: Vec::new(),
            pivots: Vec::new(),
        }
    }

    pub async fn run(&mut self) -> Result<ReconResults> {
        self.shared.log("🤖 Recursive Agent starting - entering OODA loop");
        self.shared.thinking(true);

        self.initial_recon().await?;

        while !self.state.is_complete && self.state.depth < MAX_RECURSION_DEPTH {
            if (chrono::Local::now().timestamp() - self.state.started_at_ts) > MAX_SCAN_DURATION.as_secs() as i64 {
                self.state.is_complete = true;
                self.state.completion_reason = "Maximum scan duration reached".into();
                break;
            }

            self.observe().await?;
            self.orient().await?;
            let decision = self.decide().await?;
            
            if decision.is_none() {
                self.state.is_complete = true;
                self.state.completion_reason = "No further actions needed".into();
                break;
            }

            let action = decision.unwrap();
            self.act(&action).await?;
            
            tokio::time::sleep(MIN_DECISION_INTERVAL).await;
        }

        self.shared.thinking(false);
        self.shared.log(format!("🤖 Recursive Agent complete: {}", self.state.completion_reason));

        self.build_results().await
    }

    async fn initial_recon(&mut self) -> Result<()> {
        self.shared.log("🔍 Initial reconnaissance phase");
        
        if let Some(ip) = self.target.ip {
            self.run_port_scan().await?;
            self.run_service_detection().await?;
            self.run_geo_lookup(ip).await?;
            self.run_tls_capture().await?;
        }

        if let Some(domain) = self.get_working_domain() {
            self.run_dns_recon(&domain).await?;
        }

        self.run_vuln_fingerprinting().await?;
        Ok(())
    }

    async fn observe(&mut self) -> Result<()> {
        self.state.evidence = self.build_evidence_snapshot();
        self.shared.log(format!("👁 Observe: depth={}, findings={}, gaps={}", 
            self.state.depth, self.vulns.len(), self.state.coverage_gaps.len()));
        Ok(())
    }

    async fn orient(&mut self) -> Result<()> {
        self.shared.log("🧭 Orient: Analyzing evidence, identifying coverage gaps");
        self.state.coverage_gaps = self.analyze_coverage_gaps();
        
        for gap in &self.state.coverage_gaps {
            self.shared.log(format!("  Gap [{}] {}: {}", gap.severity, gap.area, gap.description));
        }
        Ok(())
    }

    async fn decide(&mut self) -> Result<Option<AgentDecision>> {
        self.shared.thinking(true);
        self.shared.log("🤔 Decide: Requesting AI decision for next action");

        let prompt = self.build_decision_prompt();
        let user = format!("EVIDENCE:\n{}\n\nGAPS:\n{}\n\nChoose next action. Reply with ONLY JSON.",
            serde_json::to_string_pretty(&self.state.evidence)?,
            serde_json::to_string_pretty(&self.state.coverage_gaps)?
        );

        // Use the public chat method from NvClient instead of private chat_json
        let decision_json = self.client.chat(&prompt, &user, 0.2, 4000).await?;
        let decision: AgentDecision = serde_json::from_str(&decision_json)
            .with_context(|| format!("Failed to parse AI decision: {}", decision_json))?;

        self.shared.thinking(false);
        
        self.ai_decisions.push(AiDecision {
            stage: format!("recursive-{}", self.state.depth),
            decision: decision.action_type.clone(),
            rationale: decision.rationale.clone(),
        });

        self.shared.agent_reason(&format!("Recursive step {}: {} - {}", 
            self.state.depth + 1, decision.action_type, decision.rationale));

        Ok(Some(decision))
    }

    async fn act(&mut self, decision: &AgentDecision) -> Result<()> {
        self.state.depth += 1;
        self.state.last_decision_at_ts = chrono::Local::now().timestamp();
        self.shared.log(format!("⚡ Act: Executing {} (depth {})", decision.action_type, self.state.depth));

        let result = match decision.action_type.as_str() {
            "port_scan" => self.run_port_scan().await,
            "service_detect" => self.run_service_detection().await,
            "dns_recon" => { if let Some(d) = self.get_working_domain() { self.run_dns_recon(&d).await } else { Ok(()) } },
            "subdomain_enum" => { if let Some(d) = self.get_working_domain() { self.run_subdomain_enum(&d).await } else { Ok(()) } },
            "web_dir_enum" => self.run_web_dir_enum().await,
            "api_discovery" => self.run_api_discovery().await,
            "zap_scan" => self.run_zap_scan().await,
            "snmp_enum" => self.run_snmp_enum().await,
            "ldap_enum" => self.run_ldap_enum().await,
            "netbios_smb" => self.run_netbios_smb().await,
            "whois" => self.run_whois().await,
            "dorking" => self.run_dorking().await,
            "traceroute" => self.run_traceroute().await,
            "geo_lookup" => { if let Some(ip) = self.target.ip { self.run_geo_lookup(ip).await } else { Ok(()) } },
            "tls_capture" => self.run_tls_capture().await,
            "cve_mapping" => self.run_cve_mapping().await,
            "attack_path_gen" => self.run_attack_path_gen().await,
            "exploitation_recs" => self.run_exploitation_recs().await,
            "pivot_domain" => { if let Some(d) = decision.parameters.get("domain").and_then(|v| v.as_str()) { self.run_pivot_domain(d).await } else { Ok(()) } },
            "extend_dirs" => {
                let bases = if let Some(bases) = decision.parameters.get("bases").and_then(|b| b.as_array()) {
                    bases.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
                } else {
                    self.web_bases.clone()
                };
                if let Some(words) = decision.parameters.get("words").and_then(|w| w.as_array()) {
                    let ws: Vec<String> = words.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                    self.run_extend_dirs(&bases, &ws).await
                } else { Ok(()) }
            },
            "finish" => { self.state.is_complete = true; self.state.completion_reason = decision.rationale.clone(); Ok(()) },
            _ => { self.shared.log(format!("Unknown action: {}", decision.action_type)); Ok(()) }
        };

        self.state.action_history.push(AgentAction {
            step: self.state.depth,
            action_type: decision.action_type.clone(),
            rationale: decision.rationale.clone(),
            parameters: decision.parameters.clone(),
            result: result.as_ref().err().map(|e| json!({"error": e.to_string()})),
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        });

        result
    }

    // ========== Module Execution Methods ==========

    async fn run_port_scan(&mut self) -> Result<()> {
        self.shared.running("Port Scan");
        let ports_spec = self.opts.ports_spec.as_deref().unwrap_or("top");
        let ports = crate::config::parse_ports(ports_spec)?;
        
        let progress = Arc::new(std::sync::atomic::AtomicU64::new(0));
        {
            let progress = progress.clone();
            let shared = self.shared.clone();
            let ports_total = ports.len() as u64;
            tokio::spawn(async move {
                loop {
                    let cur = progress.load(std::sync::atomic::Ordering::Relaxed);
                    shared.progress("TCP connect scan", cur, ports_total);
                    if cur >= ports_total { break; }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                shared.clear_progress();
            });
        }

        if let Some(ip) = self.target.ip {
            if crate::modules::nmap::nmap_available() {
                let spec = match ports.len() {
                    0..=500 => "top500".to_string(),
                    n if n >= 60000 => "1-65535".to_string(),
                    _ => ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","),
                };
                if let Ok(results) = crate::modules::nmap::nmap_scan(ip, &self.target.hostname.clone().unwrap_or_else(|| ip.to_string()), &spec, 4).await {
                    self.open_ports = results.iter().filter(|p| p.open).map(|p| p.port).collect();
                    self.port_results = results;
                    self.shared.done("Port Scan", &format!("{} open / {} scanned [nmap+NSE]", self.open_ports.len(), ports.len()));
                    return Ok(());
                }
            }

            self.open_ports = crate::modules::portscan::scan_tcp(ip, &ports, self.cfg.scan.max_concurrency, self.cfg.scan.timeout_ms, Some(progress)).await?;
        }

        self.shared.clear_progress();
        self.shared.done("Port Scan", &format!("{} open / {} scanned", self.open_ports.len(), ports.len()));
        
        for p in &self.open_ports {
            self.shared.finding(Severity::Info, "port", &format!("{}/tcp open — {}", p, crate::config::service_for_port(*p)));
        }
        Ok(())
    }

    async fn run_service_detection(&mut self) -> Result<()> {
        self.shared.running("Service & Version Detection");
        if let Some(ip) = self.target.ip {
            let host_header = self.target.hostname.clone().unwrap_or_else(|| ip.to_string());
            self.port_results = crate::modules::banner::detect_services(ip, &host_header, &self.open_ports, self.cfg.scan.http_timeout_ms).await?;

            self.http_infos.clear();
            for pr in &self.port_results {
                if let Some(mut h) = pr.http.clone() {
                    if let Ok(mut full) = crate::modules::banner::probe_http_url(&h.url, ip, pr.port, h.url.starts_with("https"), self.cfg.scan.http_timeout_ms).await {
                        if full.title.is_none() { full.title = h.title.clone(); }
                        h = full;
                    }
                    if h.url.starts_with("https") && h.tls_subject.is_none() {
                        crate::modules::tls_capture::enrich_http_tls(&mut h, ip, pr.port, true).await;
                    }
                    self.http_infos.push(h);
                }
            }

            self.web_bases = crate::modules::subdir::web_bases(&host_header, &self.open_ports);
            if self.web_bases.is_empty() { self.web_bases = vec![format!("http://{}", ip), format!("https://{}", ip)]; }

            self.shared.done("Service & Version Detection", &format!("{} services fingerprinted", self.port_results.len()));
        }
        Ok(())
    }

    async fn run_geo_lookup(&mut self, ip: IpAddr) -> Result<()> {
        self.shared.running("Geo IP Location & Mapping");
        if let Ok(geo) = crate::modules::geo::geo_lookup(ip).await {
            self.target.geo = Some(geo.clone());
            self.shared.set_geo(geo.clone());
            self.shared.done("Geo IP Location & Mapping", &format!("{} · {}", geo.city.unwrap_or_default(), geo.country.unwrap_or_default()));
        } else {
            self.shared.skipped("Geo IP Location & Mapping", "all providers failed");
        }
        Ok(())
    }

    async fn run_tls_capture(&mut self) -> Result<()> {
        if let Some(ip) = self.target.ip {
            for pr in &self.port_results {
                if [443, 8443, 4443].contains(&pr.port) {
                    if let Ok(der) = crate::modules::tls_capture::capture_tls_cert(ip, pr.port).await {
                        if let Ok((subject, issuer, sans, until)) = crate::modules::tls_capture::parse_cert(&der) {
                            for san in &sans {
                                if san.contains('.') && !self.target.cert_domains.contains(san) {
                                    self.target.cert_domains.push(san.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn get_working_domain(&self) -> Option<String> {
        if self.target.input_kind == "domain" { self.target.hostname.clone() }
        else if self.opts.allow_pivot { self.target.inferred_domain.clone() }
        else { None }
    }

    async fn run_dns_recon(&mut self, domain: &str) -> Result<()> {
        self.shared.running("DNS Recon");
        let resolver = crate::modules::dnsrecon::make_resolver()?;
        let dr = crate::modules::dnsrecon::dns_recon(&resolver, domain).await?;
        
        for r in &dr.records { self.shared.log(format!("{} {} -> {} ({})", r.rtype, r.name, r.value, domain)); }
        
        self.shared.done("DNS Recon", &format!("{} records for {}", dr.records.len(), domain));
        self.dns_results = Some(dr);
        Ok(())
    }

    async fn run_subdomain_enum(&mut self, domain: &str) -> Result<()> {
        self.shared.running("Subdomain Enumeration");
        let resolver = crate::modules::dnsrecon::make_resolver()?;
        match crate::modules::subdomain::enumerate(&resolver, domain, self.opts.wordlist_subs.clone(), self.cfg.scan.max_subdomains).await {
            Ok(subs) => {
                for s in &subs { self.shared.finding(Severity::Info, "subdomain", &format!("{} [{}] {}", s.name, s.source, s.ips.join(","))); }
                self.subdomains = subs;
                self.shared.done("Subdomain Enumeration", &format!("{} found", self.subdomains.len()));
            }
            Err(e) => self.shared.failed("Subdomain Enumeration", &e.to_string()),
        }
        Ok(())
    }

    async fn run_web_dir_enum(&mut self) -> Result<()> {
        if !self.web_bases.is_empty() {
            self.shared.running("Web & Directory Discovery");
            match crate::modules::subdir::discover(&self.web_bases, self.opts.wordlist_dirs.clone(), self.cfg.scan.max_subdirs, 24).await {
                Ok(dirs) => {
                    for d in &dirs {
                        let sev = if d.status == 200 && (d.url.contains("admin") || d.url.contains("backup") || d.url.contains(".git")) { Severity::Medium } else { Severity::Info };
                        self.shared.finding(sev, "web-path", &format!("{} ({} {})", d.url, d.status, d.note));
                    }
                    self.subdirs = dirs;
                    self.shared.done("Web & Directory Discovery", &format!("{} paths found", self.subdirs.len()));
                }
                Err(e) => self.shared.failed("Web & Directory Discovery", &e.to_string()),
            }
        }
        Ok(())
    }

    async fn run_api_discovery(&mut self) -> Result<()> {
        if !self.http_infos.is_empty() {
            self.shared.running("API Endpoint Discovery");
            match crate::modules::api_discovery::discover_apis(&self.web_bases, &self.port_results, &self.http_infos, Duration::from_secs(self.cfg.scan.http_timeout_ms)).await {
                Ok(result) => {
                    self.shared.log(format!("API discovery: {} endpoints", result.endpoints.len()));
                    for ep in &result.endpoints {
                        let sev = if ep.auth_required { Severity::Medium } else { Severity::Info };
                        self.shared.finding(sev, "api", &format!("{} {} [{:?}]", ep.method, ep.path, ep.api_type));
                    }
                    self.api_results = Some(result);
                    self.shared.done("API Endpoint Discovery", &format!("{} endpoints found", self.api_results.as_ref().map(|r| r.endpoints.len()).unwrap_or(0)));
                }
                Err(e) => self.shared.skipped("API Endpoint Discovery", &e.to_string()),
            }
        }
        Ok(())
    }

    async fn run_zap_scan(&mut self) -> Result<()> {
        if !self.http_infos.is_empty() {
            self.shared.running("ZAP Web Scan");
            let roots: Vec<(String, HttpInfo)> = self.http_infos.iter().map(|h| (h.url.trim_end_matches('/').to_string(), h.clone())).collect();
            match crate::modules::webscan::scan_all(roots, Duration::from_secs(8)).await {
                Ok(scans) => {
                    let mut hi = 0; let mut med = 0;
                    for sc in &scans {
                        for a in &sc.alerts {
                            let sev = match a.risk.as_str() { "High" => { hi += 1; Severity::High }, "Medium" => { med += 1; Severity::Medium }, "Low" => Severity::Low, _ => Severity::Info };
                            self.shared.finding(sev, "zap", &format!("[{}] {} — {}", a.risk, a.plugin, a.url));
                        }
                    }
                    self.shared.done("ZAP Web Scan", &format!("{} alerts ({} high / {} medium)", scans.iter().map(|s| s.alerts.len()).sum::<usize>(), hi, med));
                }
                Err(e) => self.shared.failed("ZAP Web Scan", &e.to_string()),
            }
        }
        Ok(())
    }

    async fn run_snmp_enum(&mut self) -> Result<()> {
        if let Some(ip) = self.target.ip {
            self.shared.running("SNMP Enumeration");
            match crate::modules::snmp::snmp_enum(ip, 161, self.opts.snmp_communities.clone()).await {
                Ok(s) => { self.shared.finding(Severity::High, "snmp", &format!("SNMP accessible with community '{}'", s.community)); self.shared.done("SNMP Enumeration", &format!("community='{}', {} varbinds", s.community, s.varbind_count)); self.snmp_res = Some(s); }
                Err(_) => self.shared.skipped("SNMP Enumeration", "no community accepted"),
            }
        }
        Ok(())
    }

    async fn run_ldap_enum(&mut self) -> Result<()> {
        if let Some(ip) = self.target.ip {
            if self.open_ports.contains(&389) || self.open_ports.contains(&636) || self.open_ports.contains(&3268) {
                self.shared.running("LDAP Enumeration");
                match crate::modules::ldap::ldap_enum(ip, 389).await {
                    Ok(l) => { if l.anonymous_bind { self.shared.finding(Severity::High, "ldap", "LDAP anonymous bind allowed"); } self.shared.done("LDAP Enumeration", &format!("users:{} groups:{} computers:{}", l.users.len(), l.groups.len(), l.computers.len())); self.ldap_res = Some(l); }
                    Err(e) => self.shared.failed("LDAP Enumeration", &e.to_string()),
                }
            }
        }
        Ok(())
    }

    async fn run_netbios_smb(&mut self) -> Result<()> {
        if let Some(ip) = self.target.ip {
            if self.open_ports.contains(&445) || self.open_ports.contains(&139) || self.open_ports.contains(&137) {
                self.shared.running("NetBIOS / SMB Enumeration");
                if let Ok(nb) = crate::modules::netbios::nbns_query(ip, 137).await {
                    self.shared.finding(Severity::Medium, "netbios", &format!("NetBIOS names: {} (MAC {})", nb.names.len(), nb.mac_address));
                    self.netbios_res = Some(nb);
                }
                if let Ok(s) = crate::modules::smb::smb_enum(ip).await {
                    if !s.shares.is_empty() { self.shared.finding(Severity::Medium, "smb", &format!("{} SMB shares visible", s.shares.len())); }
                    self.shared.done("NetBIOS / SMB Enumeration", &format!("shares:{} users:{}", s.shares.len(), s.users.len()));
                    self.smb_res = Some(s);
                }
            }
        }
        Ok(())
    }

    async fn run_whois(&mut self) -> Result<()> {
        if let Some(domain) = self.get_working_domain() {
            self.shared.running("WHOIS (RDAP + Legacy)");
            let base = registrable(&domain);
            match crate::modules::whois::whois_domain(&base).await {
                Ok(w) => {
                    let registrar = w.registrar.clone().unwrap_or_default();
                    self.shared.done("WHOIS", &format!("registrar: {}", registrar));
                    self.whois_res = Some(w);
                }
                Err(e) => self.shared.failed("WHOIS", &e.to_string()),
            }
        } else if self.target.input_kind == "ip" {
            if let Some(ip) = self.target.ip {
                self.shared.running("WHOIS (RDAP + Legacy)");
                match crate::modules::whois::whois_ip(&ip.to_string()).await {
                    Ok(w) => {
                        let org = w.org.clone().unwrap_or_default();
                        self.shared.done("WHOIS", &format!("netblock org: {}", org));
                        self.whois_res = Some(w);
                    }
                    Err(e) => self.shared.failed("WHOIS", &e.to_string()),
                }
            }
        }
        Ok(())
    }

    async fn run_dorking(&mut self) -> Result<()> {
        if let Some(domain) = self.get_working_domain() {
            self.shared.running("OSINT Dorking");
            let base = registrable(&domain);
            match crate::modules::dork::run_dorks(&base, &self.cfg, 10).await {
                Ok(ds) => { let hits: usize = ds.iter().map(|d| d.results.len()).sum(); self.shared.done("OSINT Dorking", &format!("{} result URLs", hits)); self.dorks = ds; }
                Err(e) => self.shared.failed("OSINT Dorking", &e.to_string()),
            }
        }
        Ok(())
    }

    async fn run_traceroute(&mut self) -> Result<()> {
        if let Some(ip) = self.target.ip {
            if !ip.is_loopback() {
                self.target.traceroute = crate::modules::hostinfo::traceroute(&ip.to_string()).await;
                let _ = crate::modules::geo::enrich_traceroute(&mut self.target.traceroute).await;
            }
        }
        Ok(())
    }

    async fn run_vuln_fingerprinting(&mut self) -> Result<()> {
        self.shared.running("Vulnerability Fingerprinting");
        if let Some(ip) = self.target.ip {
            self.vulns = crate::modules::vulns::fingerprint(&self.port_results, ip);
            for v in &self.vulns { self.shared.finding(v.severity, "vuln", &format!("{} — {}", v.title, v.affected)); }
            self.shared.done("Vulnerability Fingerprinting", &format!("{} potential issues", self.vulns.len()));
        }
        Ok(())
    }

    async fn run_cve_mapping(&mut self) -> Result<()> {
        self.shared.running("CVE Mapping (NVD + ExploitDB)");
        let mut products: Vec<(String, Option<String>)> = self.port_results.iter()
            .filter(|p| p.product.is_some())
            .map(|p| (p.product.clone().unwrap(), p.version.clone()))
            .collect();
        for v in &self.vulns { if let Some(cve) = &v.cve { products.push((cve.clone(), None)); } }
        products.truncate(10);

        if !products.is_empty() {
            let nvd = crate::modules::cve::map_cves(&products, Duration::from_secs(20)).await;
            for e in nvd.iter().take(20) {
                if e.id == "NVD-UNAVAILABLE" { continue; }
                let sev = if e.score >= 9.0 { Severity::Critical } else if e.score >= 7.0 { Severity::High } else if e.score >= 4.0 { Severity::Medium } else { Severity::Low };
                self.shared.finding(sev, "cve", &format!("{} [{}] CVSS {:.1} — {}", e.id, e.severity, e.score, e.product));
            }
            self.cves = nvd;
            self.shared.done("CVE Mapping", &format!("{} CVEs matched", self.cves.len()));
        }
        Ok(())
    }

    async fn run_attack_path_gen(&mut self) -> Result<()> {
        if self.opts.enable_ai {
            self.shared.running("Attack Path Generation");
            let snap = json!({
                "target": self.target.input,
                "open_ports": self.port_results.iter().map(|p| json!({"port": p.port, "service": p.service, "product": p.product, "version": p.version})).collect::<Vec<_>>(),
                "vulns": self.vulns.iter().map(|v| json!({"title": v.title, "severity": v.severity, "confidence": v.confidence, "cve": v.cve, "affected": v.affected, "evidence": v.evidence})).collect::<Vec<_>>(),
                "subdomains": self.subdomains.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
                "geo": self.target.geo,
                "cves": self.cves.iter().map(|c| json!({"id": c.id, "product": c.product, "score": c.score, "exploit_available": c.exploit_available})).collect::<Vec<_>>(),
            });
            
            if let Ok(Ok(paths)) = tokio::time::timeout(Duration::from_secs(300), crate::agent::generate_attack_paths(&self.client, &snap)).await {
                self.shared.log(format!("Generated {} attack paths", paths.len()));
            }
            self.shared.done("Attack Path Generation", "complete");
        }
        Ok(())
    }

    async fn run_exploitation_recs(&mut self) -> Result<()> {
        self.shared.done("Exploitation Recommendations", "complete");
        Ok(())
    }

    async fn run_pivot_domain(&mut self, domain: &str) -> Result<()> {
        self.shared.log(format!("Pivoting to domain: {}", domain));
        let _ = self.run_dns_recon(domain).await;
        let _ = crate::modules::dork::run_dorks(&registrable(domain), &self.cfg, 8).await;
        Ok(())
    }

    async fn run_extend_dirs(&mut self, bases: &[String], words: &[String]) -> Result<()> {
        if bases.is_empty() || words.is_empty() { return Ok(()); }
        match crate::modules::subdir::discover(bases, Some(words.to_vec()), 120, 12).await {
            Ok(found) => {
                for d in found { if !self.subdirs.iter().any(|x| x.url == d.url) { self.shared.finding(Severity::Info, "web-path", &format!("{} ({} {}) [extended]", d.url, d.status, d.note)); self.subdirs.push(d); } }
            }
            Err(_) => {}
        }
        Ok(())
    }

    // ========== Analysis Methods ==========

    fn build_evidence_snapshot(&self) -> Value {
        json!({
            "target": {"input": self.target.input, "kind": self.target.input_kind, "ip": self.target.ip.map(|i| i.to_string()), "hostname": self.target.hostname, "geo": self.target.geo, "open_ports": self.open_ports, "cert_domains": self.target.cert_domains},
            "ports": self.port_results.iter().map(|p| json!({"port": p.port, "service": p.service, "product": p.product, "version": p.version, "http": p.http.is_some()})).collect::<Vec<_>>(),
            "vulns": self.vulns.iter().map(|v| json!({"title": v.title, "severity": v.severity, "confidence": v.confidence, "cve": v.cve, "affected": v.affected})).collect::<Vec<_>>(),
            "dns": self.dns_results.as_ref().map(|d| json!({"records": d.records.len(), "axfr": d.axfr_success})),
            "subdomains": self.subdomains.len(),
            "web_bases": self.web_bases.len(),
            "subdirs": self.subdirs.len(),
            "http_services": self.http_infos.len(),
            "api_endpoints": self.api_results.as_ref().map(|r| r.endpoints.len()).unwrap_or(0),
            "snmp": self.snmp_res.is_some(),
            "ldap": self.ldap_res.is_some(),
            "netbios_smb": self.netbios_res.is_some() || self.smb_res.is_some(),
            "whois": self.whois_res.is_some(),
            "dorks": self.dorks.len(),
            "cves": self.cves.len(),
            "coverage": {"has_web": !self.http_infos.is_empty(), "has_dns": self.dns_results.is_some(), "has_smb": self.netbios_res.is_some() || self.smb_res.is_some(), "has_ldap": self.ldap_res.is_some(), "has_snmp": self.snmp_res.is_some(), "has_subdomains": !self.subdomains.is_empty(), "has_api": self.api_results.as_ref().map(|r| !r.endpoints.is_empty()).unwrap_or(false), "has_cves": !self.cves.is_empty()}
        })
    }

    fn analyze_coverage_gaps(&self) -> Vec<CoverageGap> {
        let mut gaps = Vec::new();
        let ev = &self.state.evidence;

        if ev["coverage"]["has_web"].as_bool().unwrap_or(false) && !ev["coverage"]["has_api"].as_bool().unwrap_or(false) {
            gaps.push(CoverageGap { area: "api".into(), severity: "high".into(), description: "Web services detected but no API endpoint discovery performed".into(), suggested_actions: vec!["api_discovery".into()], evidence_refs: vec!["web_services_detected".into()] });
        }
        if ev["coverage"]["has_web"].as_bool().unwrap_or(false) && ev["http_services"].as_u64().unwrap_or(0) > 0 {
            gaps.push(CoverageGap { area: "web".into(), severity: "medium".into(), description: "Web services found but no active ZAP vulnerability scan".into(), suggested_actions: vec!["zap_scan".into()], evidence_refs: vec!["web_services_detected".into()] });
        }
        if ev["coverage"]["has_dns"].as_bool().unwrap_or(false) && ev["subdomains"].as_u64().unwrap_or(0) == 0 {
            gaps.push(CoverageGap { area: "dns".into(), severity: "high".into(), description: "Domain discovered but no subdomain enumeration".into(), suggested_actions: vec!["subdomain_enum".into()], evidence_refs: vec!["dns_records_found".into()] });
        }
        if ev["coverage"]["has_smb"].as_bool().unwrap_or(false) {
            gaps.push(CoverageGap { area: "smb".into(), severity: "high".into(), description: "SMB/NetBIOS ports open but no enumeration performed".into(), suggested_actions: vec!["netbios_smb".into()], evidence_refs: vec!["smb_ports_open".into()] });
        }
        if ev["coverage"]["has_ldap"].as_bool().unwrap_or(false) {
            gaps.push(CoverageGap { area: "ldap".into(), severity: "high".into(), description: "LDAP ports open but no enumeration performed".into(), suggested_actions: vec!["ldap_enum".into()], evidence_refs: vec!["ldap_ports_open".into()] });
        }
        if ev["coverage"]["has_snmp"].as_bool().unwrap_or(false) {
            gaps.push(CoverageGap { area: "snmp".into(), severity: "medium".into(), description: "SNMP port open but no enumeration performed".into(), suggested_actions: vec!["snmp_enum".into()], evidence_refs: vec!["snmp_port_open".into()] });
        }
        if ev["vulns"].as_array().map(|a| a.len()).unwrap_or(0) > 0 && ev["cves"].as_u64().unwrap_or(0) == 0 {
            gaps.push(CoverageGap { area: "cve".into(), severity: "critical".into(), description: "Vulnerabilities found but no CVE mapping performed".into(), suggested_actions: vec!["cve_mapping".into()], evidence_refs: vec!["vulnerabilities_detected".into()] });
        }
        if ev["coverage"]["has_web"].as_bool().unwrap_or(false) && ev["subdirs"].as_u64().unwrap_or(0) == 0 {
            gaps.push(CoverageGap { area: "web".into(), severity: "medium".into(), description: "Web services found but no directory enumeration".into(), suggested_actions: vec!["web_dir_enum".into()], evidence_refs: vec!["web_services_detected".into()] });
        }
        if self.target.input_kind == "domain" && self.whois_res.is_none() {
            gaps.push(CoverageGap { area: "whois".into(), severity: "low".into(), description: "Target is a domain but no WHOIS lookup performed".into(), suggested_actions: vec!["whois".into()], evidence_refs: vec!["domain_target".into()] });
        }
        if self.target.input_kind == "ip" && self.target.geo.is_none() {
            gaps.push(CoverageGap { area: "geo".into(), severity: "medium".into(), description: "IP target but no geo location lookup".into(), suggested_actions: vec!["geo_lookup".into()], evidence_refs: vec!["ip_target".into()] });
        }
        if ev["vulns"].as_array().map(|a| a.len()).unwrap_or(0) > 0 || ev["cves"].as_u64().unwrap_or(0) > 0 {
            gaps.push(CoverageGap { area: "exploitation".into(), severity: "high".into(), description: "Vulnerabilities/CVEs found but no attack paths or exploitation recommendations generated".into(), suggested_actions: vec!["attack_path_gen".into(), "exploitation_recs".into()], evidence_refs: vec!["vulnerabilities_or_cves".into()] });
        }

        gaps.sort_by_key(|g| match g.severity.as_str() { "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4 });
        gaps
    }

    fn build_decision_prompt(&self) -> String {
        let available_actions = self.get_available_actions();
        let actions_str = self.format_actions_for_prompt(&available_actions);
        
        let mut prompt = String::new();
        prompt.push_str("You are an autonomous offensive-security reconnaissance agent (NightCrawler). Goal: MAXIMUM COVERAGE of target attack surface.\n\n");
        let elapsed = (chrono::Local::now().timestamp() - self.state.started_at_ts) as f64;
        prompt.push_str(&format!("CURRENT STATE:\n- Depth: {}\n- Actions: {}\n- Time: {:.0}s\n- Gaps: {}\n\n", 
            self.state.depth, self.state.action_history.len(), elapsed, self.state.coverage_gaps.len()));
        prompt.push_str("AVAILABLE ACTIONS:\n");
        prompt.push_str(&actions_str);
        prompt.push_str("\n\nRULES:\n1. Prioritize CRITICAL/HIGH gaps\n2. Address specific identified gaps\n3. Prefer actions unlocking NEW attack surface\n4. If no gaps remain, choose \"finish\"\n5. Never repeat completed actions\n6. Can pivot to new domains from DNS/certs\n\n");
        prompt.push_str("RESPOND WITH JSON ONLY:\n{\"action_type\": \"exact_name\", \"rationale\": \"why\", \"parameters\": {}}\n");
        prompt.push_str(&format!("ACTIONS:\n{}", actions_str));
        prompt
    }

    fn get_available_actions(&self) -> Vec<String> {
        let mut actions = Vec::new();
        if !self.state.action_history.iter().any(|a| a.action_type == "port_scan") { actions.push("port_scan".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "service_detect") && !self.open_ports.is_empty() { actions.push("service_detect".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "dns_recon") && self.get_working_domain().is_some() { actions.push("dns_recon".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "subdomain_enum") && self.get_working_domain().is_some() && self.subdomains.is_empty() { actions.push("subdomain_enum".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "web_dir_enum") && !self.web_bases.is_empty() && self.subdirs.is_empty() { actions.push("web_dir_enum".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "api_discovery") && !self.http_infos.is_empty() && self.api_results.is_none() { actions.push("api_discovery".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "zap_scan") && !self.http_infos.is_empty() { actions.push("zap_scan".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "snmp_enum") && self.open_ports.contains(&161) { actions.push("snmp_enum".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "ldap_enum") && (self.open_ports.contains(&389) || self.open_ports.contains(&636)) { actions.push("ldap_enum".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "netbios_smb") && (self.open_ports.contains(&445) || self.open_ports.contains(&139)) { actions.push("netbios_smb".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "whois") && (self.target.input_kind == "domain" || self.target.input_kind == "ip") && self.whois_res.is_none() { actions.push("whois".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "dorking") && self.get_working_domain().is_some() && self.dorks.is_empty() { actions.push("dorking".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "traceroute") && self.target.ip.is_some() && self.target.traceroute.is_empty() { actions.push("traceroute".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "geo_lookup") && self.target.ip.is_some() && self.target.geo.is_none() { actions.push("geo_lookup".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "tls_capture") && self.open_ports.iter().any(|p| [443, 8443, 4443].contains(p)) { actions.push("tls_capture".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "cve_mapping") && (!self.vulns.is_empty() || self.cves.is_empty()) { actions.push("cve_mapping".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "attack_path_gen") && (!self.vulns.is_empty() || !self.cves.is_empty()) { actions.push("attack_path_gen".into()); }
        if !self.state.action_history.iter().any(|a| a.action_type == "exploitation_recs") && (!self.vulns.is_empty() || !self.cves.is_empty()) { actions.push("exploitation_recs".into()); }
        if let Some(domain) = self.get_working_domain() {
            let pivots = pivot_candidates(&crate::types::ReconResults {
                meta: crate::types::Meta { tool: String::new(), version: String::new(), target_input: String::new(), started_at: String::new(), finished_at: String::new(), duration_secs: 0 },
                target: self.target.clone(),
                ports: Vec::new(), vulns: Vec::new(), dns: None, subdomains: Vec::new(), subdirs: Vec::new(), http: Vec::new(), webscan: Vec::new(), snmp: None, ldap: None, netbios: None, smb: None, whois: None, dorks: Vec::new(), graph: crate::types::GraphData::default(), ai_plan: None, ai_report: None, ai_model: None, ai_decisions: Vec::new(), pivots: Vec::new(), cve_refs: Vec::new(), cves: Vec::new(), module_log: Vec::new(), phases: Vec::new(), api_endpoints: Vec::new(), attack_paths: Vec::new(), exploitation_recommendations: Vec::new(),
            }, &Some(domain.to_string()));
            for p in pivots { actions.push(format!("pivot_domain:{}", p)); }
        }
        if !self.web_bases.is_empty() && !self.subdirs.is_empty() { actions.push("extend_dirs".into()); }
        actions.push("finish".into());
        actions
    }

    fn format_actions_for_prompt(&self, actions: &[String]) -> String {
        actions.iter().map(|a| format!("  - {}", a)).collect::<Vec<_>>().join("\n")
    }

    async fn build_results(&self) -> Result<ReconResults> {
        let duration = (chrono::Local::now().timestamp() - self.state.started_at_ts) as u64;
        let mut results = ReconResults {
            meta: Meta { tool: "Night Crawler (Recursive Agent)".into(), version: env!("CARGO_PKG_VERSION").into(), target_input: self.target.input.clone(), started_at: crate::util::now_string(), finished_at: crate::util::now_string(), duration_secs: duration },
            target: self.target.clone(),
            ports: self.port_results.clone(),
            vulns: self.vulns.clone(),
            dns: self.dns_results.clone(),
            subdomains: self.subdomains.clone(),
            subdirs: self.subdirs.clone(),
            http: self.http_infos.clone(),
            webscan: vec![],
            snmp: self.snmp_res.clone(),
            ldap: self.ldap_res.clone(),
            netbios: self.netbios_res.clone(),
            smb: self.smb_res.clone(),
            whois: self.whois_res.clone(),
            dorks: self.dorks.clone(),
            graph: self.graph.clone(),
            ai_plan: None,
            ai_report: None,
            ai_model: Some(self.client.model.clone()),
            ai_decisions: self.ai_decisions.clone(),
            pivots: self.pivots.clone(),
            cve_refs: self.cve_refs.clone(),
            cves: self.cves.clone(),
            module_log: self.state.action_history.iter().map(|a| format!("{}: {}", a.action_type, a.rationale)).collect(),
            phases: vec![],
            api_endpoints: self.api_results.as_ref().map(|r| r.endpoints.clone()).unwrap_or_default(),
            attack_paths: vec![],
            exploitation_recommendations: vec![],
        };
        crate::report::write_reports(&results, &self.opts.output_dir)?;
        Ok(results)
    }
}

/// Run the recursive agent
pub async fn run_recursive_agent(
    target_str: &str,
    opts: &Opts,
    cfg: &Config,
    shared: Arc<SharedState>,
    nv: Option<NvClient>,
) -> Result<ReconResults> {
    let target_str = target_str.to_string();
    let cfg = cfg.clone();
    
    let client = if let Some(nv) = nv { Arc::new(nv) } else { return Err(anyhow!("AI client required for recursive agent")); };

    let resolver = crate::modules::dnsrecon::make_resolver()?;
    let target_str_clean = target_str.trim().trim_start_matches("http://").trim_start_matches("https://").trim_end_matches('/').to_string();

    let target = if let Ok(ip) = target_str_clean.parse::<IpAddr>() {
        let mut t = TargetInfo { input_kind: "ip".into(), input: target_str_clean.clone(), ip: Some(ip), hostname: None, reverse_dns: None, inferred_domain: None, alive: false, liveness_method: String::new(), rtt_ms: None, ptr_domains: Vec::new(), cert_domains: Vec::new(), ttl_guess_os: None, ttl_value: None, traceroute: Vec::new(), geo: None, open_ports: Vec::new(), mac_address: None };
        if let Some(ptr) = crate::modules::dnsrecon::ptr_lookup(&resolver, ip).await { t.reverse_dns = Some(ptr.clone()); t.ptr_domains.push(ptr.clone()); let parts: Vec<&str> = ptr.split('.').collect(); if parts.len() >= 2 { t.inferred_domain = Some(parts[parts.len()-2..].join(".")); } }
        for port in [443u16, 8443] { if let Some((_, _, sans, _)) = crate::modules::tls_capture::tls_identity(ip, port).await { for san in sans.iter().filter(|s| s.contains('.')) { if !t.cert_domains.contains(san) { t.cert_domains.push(san.clone()); } } } }
        t
    } else {
        let ips = crate::modules::dnsrecon::resolve_a(&resolver, &target_str_clean).await;
        let ip = ips.iter().find(|i| matches!(i, IpAddr::V4(_))).copied().or_else(|| ips.first().copied());
        TargetInfo { input_kind: "domain".into(), input: target_str_clean.clone(), ip, hostname: Some(crate::util::strip_domain(&target_str_clean)), reverse_dns: None, inferred_domain: None, alive: false, liveness_method: String::new(), rtt_ms: None, ptr_domains: Vec::new(), cert_domains: Vec::new(), ttl_guess_os: None, ttl_value: None, traceroute: Vec::new(), geo: None, open_ports: Vec::new(), mac_address: None }
    };

    let mut agent = RecursiveAgent::new(client, shared.clone(), opts.clone(), cfg, target);
    agent.run().await
}
