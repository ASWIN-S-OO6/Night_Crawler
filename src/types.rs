use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::High => "HIGH",
            Severity::Medium => "MED ",
            Severity::Low => "LOW ",
            Severity::Info => "INFO",
        }
    }
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub tool: String,
    pub version: String,
    pub target_input: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    pub input_kind: String, // "ip" | "domain"
    pub input: String,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub reverse_dns: Option<String>,
    pub inferred_domain: Option<String>,
    pub alive: bool,
    pub liveness_method: String,
    pub rtt_ms: Option<f64>,
    pub ptr_domains: Vec<String>,
    pub cert_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInfo {
    pub url: String,
    pub status: u16,
    pub title: Option<String>,
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<String>,
    pub robots_disallow: Vec<String>,
    pub security_headers: Vec<(String, bool)>,
    pub tls_issuer: Option<String>,
    pub tls_subject: Option<String>,
    pub tls_valid_until: Option<String>,
    pub tls_san: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub proto: String,
    pub open: bool,
    pub service: String,
    pub banner: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub http: Option<HttpInfo>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    pub title: String,
    pub severity: Severity,
    /// CONFIRMED | LIKELY | POSSIBLE | UNCONFIRMED (doctrine §5)
    pub confidence: String,
    pub cve: Option<String>,
    pub affected: String,
    pub evidence: String,
    pub description: String,
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub rtype: String,
    pub name: String,
    pub value: String,
    pub ttl: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResults {
    pub records: Vec<DnsRecord>,
    pub axfr_servers: Vec<String>,
    pub axfr_records: Vec<DnsRecord>,
    pub axfr_success: bool,
    pub axfr_note: String,
    pub wildcard: Option<String>,
    pub resolver_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub name: String,
    pub ips: Vec<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirResult {
    pub url: String,
    pub status: u16,
    pub length: u64,
    pub title: Option<String>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpResults {
    pub community: String,
    pub version: String,
    pub sysdescr: Option<String>,
    pub sysname: Option<String>,
    pub syslocation: Option<String>,
    pub syscontact: Option<String>,
    pub sysobjectid: Option<String>,
    pub uptime: Option<String>,
    pub vendor_guess: Option<String>,
    pub objects: Vec<(String, String)>,
    pub varbind_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapResults {
    pub server: String,
    pub anonymous_bind: bool,
    pub root_dse: Vec<(String, String)>,
    pub naming_context: Option<String>,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub computers: Vec<String>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NbnsResults {
    pub names: Vec<(String, String)>,
    pub mac_address: String,
    pub group: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbResults {
    pub tools_available: Vec<String>,
    pub shares: Vec<String>,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisResults {
    pub server: String,
    pub registrar: Option<String>,
    pub created: Option<String>,
    pub expires: Option<String>,
    pub org: Option<String>,
    pub abuse_email: Option<String>,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DorkResult {
    pub query: String,
    pub engine: String,
    pub results: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GNode {
    pub id: usize,
    pub kind: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GEdge {
    pub from: usize,
    pub to: usize,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphData {
    pub nodes: Vec<GNode>,
    pub edges: Vec<GEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPlan {
    pub modules: Vec<String>,
    pub rationale: String,
    pub priorities: Vec<String>,
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub product: String,
    pub description: String,
    pub severity: String,
    pub score: f64,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiDecision {
    pub stage: String,
    pub decision: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotData {
    pub domain: String,
    pub dns: Option<DnsResults>,
    pub dorks: Vec<DorkResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconResults {
    pub meta: Meta,
    pub target: TargetInfo,
    pub ports: Vec<PortResult>,
    pub vulns: Vec<VulnFinding>,
    pub dns: Option<DnsResults>,
    pub subdomains: Vec<SubdomainResult>,
    pub subdirs: Vec<DirResult>,
    pub http: Vec<HttpInfo>,
    pub snmp: Option<SnmpResults>,
    pub ldap: Option<LdapResults>,
    pub netbios: Option<NbnsResults>,
    pub smb: Option<SmbResults>,
    pub whois: Option<WhoisResults>,
    pub dorks: Vec<DorkResult>,
    pub graph: GraphData,
    pub ai_plan: Option<AiPlan>,
    pub ai_report: Option<String>,
    pub ai_model: Option<String>,
    pub ai_decisions: Vec<AiDecision>,
    pub pivots: Vec<PivotData>,
    pub cve_refs: Vec<DorkResult>,
    pub cves: Vec<CveEntry>,
    pub module_log: Vec<String>,
    pub phases: Vec<(String, String)>,
}
