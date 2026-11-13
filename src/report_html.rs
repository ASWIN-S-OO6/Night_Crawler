//! Self-contained graphical HTML report generator.
//!
//! Produces `report.html`: dark-themed, zero external dependencies
//! (inline CSS + D3.js v7 + Leaflet.js + hand-rolled SVG charts), so the file
//! renders offline in any browser.

use crate::types::{GraphData, ReconResults, Severity, VulnFinding, AttackPath, AttackStep, ExploitationRecommendation, AiDecision, PivotData, CveEntry, DorkResult, Meta, TargetInfo, PortResult, SubdomainResult, DirResult, HttpInfo, WebScanResult};
use crate::modules::api_discovery::{ApiEndpoint, ApiType};
use crate::modules::api_discovery::ApiType as ApiDiscoveryApiType;
use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;

pub fn html_escape(s: &str) -> String {
    let amp: &str = &['&', 'a', 'm', 'p', ';'].iter().collect::<String>();
    let lt: &str = &['&', 'l', 't', ';'].iter().collect::<String>();
    let gt: &str = &['&', 'g', 't', ';'].iter().collect::<String>();
    let quot: &str = &['&', 'q', 'u', 'o', 't', ';'].iter().collect::<String>();
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '&' => out.push_str(amp),
            '<' => out.push_str(lt),
            '>' => out.push_str(gt),
            '"' => out.push_str(quot),
            _ => out.push(c),
        }
    }
    out
}

fn sev_color(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "#ef4444",
        Severity::High => "#f97316",
        Severity::Medium => "#fbbf24",
        Severity::Low => "#22d3ee",
        Severity::Info => "#64748b",
    }
}

fn sev_label(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn api_type_label(t: &ApiType) -> &'static str {
    match t {
        ApiType::Rest => "REST",
        ApiType::Graphql => "GraphQL",
        ApiType::Grpc => "gRPC",
        ApiType::Soap => "SOAP",
        ApiType::Websocket => "WebSocket",
        ApiType::Unknown => "Unknown",
    }
}

fn section_open(title: &str, icon: &str) -> String {
    format!(
        r###"<div class="section"><h2>{} {}</h2>"###,
        icon, html_escape(title)
    )
}

fn section_close() -> String {
    r###"</div>"###.to_string()
}

/// Build the complete HTML dashboard for a finished scan.
pub fn build_html(results: &ReconResults) -> String {
    let mut h = String::with_capacity(512 * 1024);
    h.push_str(&header_block(results));
    h.push_str(&stats_block(results));
    h.push_str(&charts_block(results));
    h.push_str(&host_block(results));
    h.push_str(&attack_surface_map_block(results));
    h.push_str(&kill_chain_graph_block(results));
    h.push_str(&attack_paths_graph_block(results));
    h.push_str(&vulnerability_heatmap_block(results));
    h.push_str(&credential_map_block(results));
    h.push_str(&network_topology_block(results));
    h.push_str(&credential_heatmap_block(results));
    h.push_str(&attack_paths_graph_block_interactive(results));
    h.push_str(&vulnerability_timeline_block(results));
    h.push_str(&mitre_attack_heatmap_block(results));
    h.push_str(&remediation_priority_block(results));
    h.push_str(&evidence_explorer_block(results));

    h.push_str(&host_block(results));

    // Executive summary / AI analysis (converted markdown)
    h.push_str(&section_open("Executive Summary / Analysis", "🧠"));
    if let Some(ai) = &results.ai_report {
        h.push_str(&md_to_html(ai));
    } else {
        h.push_str("<p class='muted'>NightCrawler agent was offline — rule-based summary:</p><ul>");
        for v in results.vulns.iter().take(8) {
            h.push_str(&format!(
                "<li><span class='chip' style='background:{}'>{}</span> <b>{}</b> — {}</li>",
                sev_color(&v.severity),
                sev_label(&v.severity),
                html_escape(&v.title),
                html_escape(&v.affected)
            ));
        }
        h.push_str("</ul>");
    }
    h.push_str(&section_close());

    // Attack Paths
    h.push_str(&attack_paths_block(results));

    // Exploitation Recommendations
    h.push_str(&exploitation_recommendations_block(results));

    // API Endpoints
    h.push_str(&api_endpoints_block(results));

    // Findings
    h.push_str(&findings_block(results));

    // CVE / exploit references from the CSE
    h.push_str(&cve_references_block(results));

    // AI Decisions
    h.push_str(&ai_decisions_block(results));

    // Pivot Log
    h.push_str(&pivot_log_block(results));

    // Methodology
    h.push_str(&methodology_block());

    // Limitations
    h.push_str(&limitations_block());

    h.push_str(&footer_block());

    h
}

// =============================================================================
// HTML Blocks
// =============================================================================

fn header_block(results: &ReconResults) -> String {
    let target_label = html_escape(&results.target.input);
    let target_kind = html_escape(&results.target.input_kind);
    let started = &results.meta.started_at;
    let elapsed = format!("{}s", results.meta.duration_secs);
    let risk_score = compute_risk_score(results);
    
    format!(r###"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NightCrawler — Adversary Simulation Report: {target}</title>
<style>{css}</style>
</head>
<body>
<div class="app">
<header>
  <div class="header-left">
    <h1>🕷 NightCrawler</h1>
    <span class="badge">Adversary Simulation Report</span>
  </div>
  <div class="header-right">
    <div class="risk-gauge" style="--score: {risk_score}">{risk_score}</div>
    <div class="meta">
      <span>Target: <b>{target}</b> ({kind})</span>
      <span>Started: {started}</span>
      <span>Duration: {elapsed}</span>
    </div>
  </div>
</header>
"###,
        target = target_label,
        kind = target_kind,
        started = started,
        elapsed = elapsed,
        risk_score = risk_score,
        css = CSS_STYLES
    )
}

fn footer_block() -> String {
    r###"
<footer>
  <p>NightCrawler v0.1.0 — Autonomous Adversary Simulation Agent</p>
  <p class="muted">Report generated on demand. All data self-contained in this file.</p>
</footer>
</div>
<script>
  // Initialize all visualizations
  document.addEventListener('DOMContentLoaded', () => {
    initAttackSurfaceMap();
    initKillChainGraph();
    initAttackPathGraph();
    initVulnHeatmap();
    initCredentialMap();
    initNetworkTopology();
    initCredentialHeatmap();
    initAttackPathGraphInteractive();
    initVulnTimeline();
    initMitreHeatmap();
    initRemediationMatrix();
    initEvidenceExplorer();
  });
</script>
</body>
</html>
"###.to_string()
}

// CSS Styles - embedded as const
const CSS_STYLES: &str = r###"
* { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg: #0a0e14;
  --panel: #111826;
  --panel2: #161f2e;
  --border: #1e2a3d;
  --text: #dbe4f0;
  --muted: #7a8ba5;
  --accent: #d946ef;
  --accent2: #22d3ee;
  --green: #22c55e;
  --red: #ef4444;
  --orange: #f97316;
  --yellow: #fbbf24;
  --cyan: #06b6d4;
  --purple: #a855f7;
}
body { font-family: 'IBM Plex Sans', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
.app { max-width: 1400px; margin: 0 auto; padding: 24px; }
header { display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px; margin-bottom: 24px; padding: 20px; background: linear-gradient(120deg, #1b0b23, #0a1a2e); border: 1px solid #2c1f3d; border-radius: 14px; }
.header-left { display: flex; align-items: center; gap: 12px; }
.header-left h1 { font-size: 1.8rem; background: linear-gradient(90deg, #e879f9, #22d3ee); -webkit-background-clip: text; background-clip: text; color: transparent; }
.badge { background: linear-gradient(90deg, #d946ef, #22d3ee); color: #0a0e14; padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.5px; }
.header-right { text-align: right; }
.risk-gauge { display: inline-block; width: 80px; height: 80px; border-radius: 50%; background: conic-gradient(var(--red) calc(var(--score) * 3.6deg), #1e2a3d 0deg); font-size: 1.5rem; font-weight: 700; display: flex; align-items: center; justify-content: center; margin-bottom: 8px; }
.risk-gauge::before { content: ""; width: 60px; height: 60px; border-radius: 50%; background: var(--bg); }
.meta { display: flex; flex-direction: column; gap: 4px; font-size: 0.85rem; color: var(--muted); }
.meta b { color: var(--text); }
.section { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 16px; }
.section h2 { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; font-size: 1.25rem; color: var(--text); border-bottom: 1px solid var(--border); padding-bottom: 10px; }
.section h3 { margin: 16px 0 8px; font-size: 1rem; color: var(--accent2); }
.muted { color: var(--muted); font-size: 0.9rem; }
.chip { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: 700; color: #0a0e14; letter-spacing: 0.5px; margin-right: 8px; }
.viz-container { width: 100%; background: #0a0e14; border: 1px solid #17202e; border-radius: 10px; }
.viz-controls { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
.viz-btn { background: var(--panel2); border: 1px solid var(--border); color: var(--text); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 0.8rem; transition: all 0.2s; }
.viz-btn:hover, .viz-btn.active { background: var(--accent); color: #0a0e14; border-color: var(--accent); }
.tooltip { position: fixed; background: #0a0e14; border: 1px solid #2c1f3d; border-radius: 8px; padding: 10px 12px; font-size: 12px; pointer-events: none; z-index: 1000; max-width: 300px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
table { width: 100%; border-collapse: collapse; font-size: 13.5px; margin: 12px 0; }
th { text-align: left; color: #93a6c1; font-weight: 600; padding: 8px 10px; border-bottom: 2px solid var(--border); font-size: 12.5px; text-transform: uppercase; letter-spacing: 0.5px; }
td { padding: 7px 10px; border-bottom: 1px solid #17202e; vertical-align: top; }
tr:hover td { background: #0d1420; }
.finding { background: var(--panel); border: 1px solid var(--border); border-left: 4px solid #333; border-radius: 10px; padding: 14px 16px; margin: 12px 0; }
.finding h3 { margin: 0 0 8px; font-size: 15.5px; }
.finding .meta { color: var(--muted); font-size: 12.5px; margin-bottom: 6px; }
.finding pre { background: #0a0e14; border: 1px solid #17202e; padding: 10px; border-radius: 8px; overflow-x: auto; font-size: 12.5px; }
code { background: #1a2332; padding: 1px 5px; border-radius: 5px; font-size: 12.5px; color: #a5f3fc; }
pre { background: #0a0e14; border: 1px solid #17202e; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 12.5px; }
pre code { background: none; padding: 0; color: inherit; }
a { color: var(--cyan); text-decoration: none; }
a:hover { text-decoration: underline; }
footer { text-align: center; padding: 24px; color: var(--muted); font-size: 0.85rem; border-top: 1px solid var(--border); margin-top: 24px; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 16px; }
.stat-card { background: var(--panel2); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
.stat-card .label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
.stat-card .value { font-size: 2rem; font-weight: 700; color: var(--text); margin-top: 4px; }
.stat-card.critical .value { color: #ef4444; }
.stat-card.high .value { color: #f97316; }
.stat-card.medium .value { color: #fbbf24; }
.stat-card.low .value { color: #22d3ee; }
.charts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 16px; }
.chart-card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; height: 300px; }
.legend { display: flex; gap: 16px; flex-wrap: wrap; margin: 12px 0; font-size: 12px; }
.legend-item { display: flex; align-items: center; gap: 6px; }
.legend-color { width: 12px; height: 12px; border-radius: 3px; }
#evidence-search { width: 100%; padding: 10px 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 14px; margin-bottom: 16px; }
#evidence-search:focus { outline: none; border-color: var(--accent); }
.evidence-row { padding: 8px; border-bottom: 1px solid #17202e; font-family: ui-monospace, monospace; font-size: 12px; cursor: pointer; }
.evidence-row:hover { background: #0d1420; }
.evidence-row.match { background: rgba(217, 70, 239, 0.1); }
.heatmap-cell { transition: transform 0.2s; }
.heatmap-cell:hover { transform: scale(1.02); }
.remediation-item { display: flex; align-items: center; gap: 12px; padding: 12px; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; margin: 8px 0; }
.remediation-item input[type="checkbox"] { width: 20px; height: 20px; accent-color: var(--accent); }
.remediation-priority { width: 80px; text-align: center; font-weight: 700; font-size: 12px; border-radius: 4px; padding: 2px 8px; }
.priority-critical { background: #ef4444; color: #0a0e14; }
.priority-high { background: #f97316; color: #0a0e14; }
.priority-medium { background: #fbbf24; color: #0a0e14; }
.priority-low { background: #22d3ee; color: #0a0e14; }
.timeline-event { display: flex; gap: 16px; padding: 12px 0; border-left: 2px solid var(--border); padding-left: 16px; position: relative; }
.timeline-event::before { content: ""; position: absolute; left: -6px; top: 16px; width: 10px; height: 10px; border-radius: 50%; background: var(--accent); border: 2px solid var(--bg); }
.timeline-event.phase-recon::before { background: #22d3ee; }
.timeline-event.phase-exploit::before { background: #ef4444; }
.timeline-event.phase-lateral::before { background: #f97316; }
.timeline-event.phase-persist::before { background: #e879f9; }
.timeline-event.phase-impact::before { background: #f87171; }
#mitre-heatmap { overflow-x: auto; }
#mitre-heatmap table { min-width: 800px; }
.mitre-cell { text-align: center; font-size: 11px; }
.mitre-cell.covered { background: rgba(34, 197, 94, 0.3); }
.mitre-cell.partial { background: rgba(251, 191, 36, 0.3); }
.mitre-cell.missing { background: rgba(239, 68, 68, 0.3); }
"###;

fn stats_block(results: &ReconResults) -> String {
    let mut h = String::new();
    h.push_str(&section_open("Scan Statistics", "📊"));
    h.push_str("<div class='stats-grid'>");
    
    let critical = results.vulns.iter().filter(|v| matches!(v.severity, Severity::Critical)).count();
    let high = results.vulns.iter().filter(|v| matches!(v.severity, Severity::High)).count();
    let medium = results.vulns.iter().filter(|v| matches!(v.severity, Severity::Medium)).count();
    let low = results.vulns.iter().filter(|v| matches!(v.severity, Severity::Low)).count();
    let info = results.vulns.iter().filter(|v| matches!(v.severity, Severity::Info)).count();
    
    h.push_str(&format!(r###"<div class="stat-card critical"><div class="label">Critical</div><div class="value">{}</div></div>"###, critical));
    h.push_str(&format!(r###"<div class="stat-card high"><div class="label">High</div><div class="value">{}</div></div>"###, high));
    h.push_str(&format!(r###"<div class="stat-card medium"><div class="label">Medium</div><div class="value">{}</div></div>"###, medium));
    h.push_str(&format!(r###"<div class="stat-card low"><div class="label">Low</div><div class="value">{}</div></div>"###, low));
    h.push_str(&format!(r###"<div class="stat-card"><div class="label">Info</div><div class="value">{}</div></div>"###, info));
    h.push_str(&format!(r###"<div class="stat-card"><div class="label">Open Ports</div><div class="value">{}</div></div>"###, results.ports.iter().filter(|p| p.open).count()));
    h.push_str(&format!(r###"<div class="stat-card"><div class="label">Subdomains</div><div class="value">{}</div></div>"###, results.subdomains.len()));
    h.push_str(&format!(r###"<div class="stat-card"><div class="label">Directories</div><div class="value">{}</div></div>"###, results.subdirs.len()));
    h.push_str(&format!(r###"<div class="stat-card"><div class="label">API Endpoints</div><div class="value">{}</div></div>"###, results.api_endpoints.len()));
    h.push_str(&format!(r###"<div class="stat-card"><div class="label">Attack Paths</div><div class="value">{}</div></div>"###, results.attack_paths.len()));
    h.push_str(&format!(r###"<div class="stat-card"><div class="label">Exploit Chains</div><div class="value">{}</div></div>"###, results.exploitation_recommendations.len()));
    // No credentials field in ReconResults
    // h.push_str(&format!(r###"<div class="stat-card"><div class="label">Credentials</div><div class="value">{}</div></div>"###, results.credentials.len()));
    
    h.push_str("</div>");
    h.push_str(&section_close());
    h
}

fn charts_block(results: &ReconResults) -> String {
    let mut h = String::new();
    h.push_str(&section_open("Visual Overview", "📈"));
    h.push_str("<div class='charts-grid'>");
    
    // Port distribution chart
    h.push_str(&port_dist_chart(results));
    
    // Severity pie chart
    h.push_str(&severity_pie_chart(results));
    
    // Service breakdown
    h.push_str(&service_breakdown_chart(results));
    
    // Subdomain discovery sources
    h.push_str(&subdomain_sources_chart(results));
    
    h.push_str("</div>");
    h.push_str(&section_close());
    h
}

fn host_block(results: &ReconResults) -> String {
    let mut h = String::new();
    h.push_str(&section_open("Target Host Information", "🎯"));
    
    if let Some(ip) = &results.target.ip {
        h.push_str(&format!("<p><b>IP:</b> {}</p>", html_escape(&ip.to_string())));
    }
    if let Some(hostname) = &results.target.hostname {
        h.push_str(&format!("<p><b>Hostname:</b> {}</p>", html_escape(hostname)));
    }
    if let Some(geo) = &results.target.geo {
        h.push_str(&format!("<p><b>Location:</b> {}, {} ({})</p>", 
            html_escape(geo.city.as_deref().unwrap_or("")),
            html_escape(geo.country.as_deref().unwrap_or("")),
            html_escape(geo.isp.as_deref().unwrap_or(""))
        ));
        h.push_str(&format!("<p><b>ASN:</b> {}</p>", html_escape(geo.asn.as_deref().unwrap_or(""))));
    }
    
    h.push_str(&section_close());
    h
}

// =============================================================================
// Chart Functions (using Chart.js - no template literal issues)
// =============================================================================

fn port_dist_chart(results: &ReconResults) -> String {
    let mut ports_by_service: HashMap<String, usize> = HashMap::new();
    for p in &results.ports {
        if p.open {
            *ports_by_service.entry(p.service.clone()).or_insert(0) += 1;
        }
    }
    
    let labels: Vec<String> = ports_by_service.keys().cloned().collect();
    let data: Vec<usize> = ports_by_service.values().cloned().collect();
    
    format!(r###"
<div class="chart-card">
  <h3>Open Ports by Service</h3>
  <canvas id="port-chart"></canvas>
  <script>
    if (typeof Chart !== 'undefined') {{
      new Chart(document.getElementById('port-chart'), {{
        type: 'doughnut',
        data: {{ labels: {labels}, datasets: [{{
          data: {data},
          backgroundColor: ['#d946ef','#22d3ee','#ef4444','#f97316','#fbbf24','#22c55e','#a855f7','#06b6d4','#f87171','#eab308']
        }}] }},
        options: {{ responsive: true, maintainAspectRatio: true, plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#dbe4f0', font: {{ size: 11 }} }} }} }} }}
      }});
    }}
  </script>
</div>
"###, 
        labels = serde_json::to_string(&labels).unwrap_or_default(),
        data = serde_json::to_string(&data).unwrap_or_default()
    )
}

fn severity_pie_chart(results: &ReconResults) -> String {
    let critical = results.vulns.iter().filter(|v| matches!(v.severity, Severity::Critical)).count();
    let high = results.vulns.iter().filter(|v| matches!(v.severity, Severity::High)).count();
    let medium = results.vulns.iter().filter(|v| matches!(v.severity, Severity::Medium)).count();
    let low = results.vulns.iter().filter(|v| matches!(v.severity, Severity::Low)).count();
    let info = results.vulns.iter().filter(|v| matches!(v.severity, Severity::Info)).count();
    
    format!(r###"
<div class="chart-card">
  <h3>Vulnerabilities by Severity</h3>
  <canvas id="severity-chart"></canvas>
  <script>
    if (typeof Chart !== 'undefined') {{
      new Chart(document.getElementById('severity-chart'), {{
        type: 'pie',
        data: {{
          labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
          datasets: [{{
            data: [{critical}, {high}, {medium}, {low}, {info}],
            backgroundColor: ['#ef4444', '#f97316', '#fbbf24', '#22d3ee', '#64748b']
          }}]
        }},
        options: {{ responsive: true, maintainAspectRatio: true, plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#dbe4f0', font: {{ size: 11 }} }} }} }} }}
      }});
    }}
  </script>
</div>
"###, 
        critical = critical, high = high, medium = medium, low = low, info = info
    )
}

fn service_breakdown_chart(results: &ReconResults) -> String {
    let mut services: HashMap<String, usize> = HashMap::new();
    for p in &results.ports {
        if p.open {
            let key = format!("{} ({})", p.service, p.product.as_deref().unwrap_or("unknown"));
            *services.entry(key).or_insert(0) += 1;
        }
    }
    
    let labels: Vec<String> = services.keys().cloned().collect();
    let data: Vec<usize> = services.values().cloned().collect();
    
    format!(r###"
<div class="chart-card">
  <h3>Service Breakdown</h3>
  <canvas id="service-chart"></canvas>
  <script>
    if (typeof Chart !== 'undefined') {{
      new Chart(document.getElementById('service-chart'), {{
        type: 'bar',
        data: {{ labels: {labels}, datasets: [{{
          label: 'Count',
          data: {data},
          backgroundColor: '#d946ef'
        }}] }},
        options: {{ indexAxis: 'y', responsive: true, maintainAspectRatio: true, plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ ticks: {{ color: '#dbe4f0' }}, grid: {{ color: '#1e2a3d' }} }}, y: {{ ticks: {{ color: '#dbe4f0' }}, grid: {{ display: false }} }} }} }}
      }});
    }}
  </script>
</div>
"###, 
        labels = serde_json::to_string(&labels).unwrap_or_default(),
        data = serde_json::to_string(&data).unwrap_or_default()
    )
}

fn subdomain_sources_chart(results: &ReconResults) -> String {
    let mut sources: HashMap<String, usize> = HashMap::new();
    for s in &results.subdomains {
        *sources.entry(s.source.clone()).or_insert(0) += 1;
    }
    
    let labels: Vec<String> = sources.keys().cloned().collect();
    let data: Vec<usize> = sources.values().cloned().collect();
    
    format!(r###"
<div class="chart-card">
  <h3>Subdomain Discovery Sources</h3>
  <canvas id="subdomain-chart"></canvas>
  <script>
    if (typeof Chart !== 'undefined') {{
      new Chart(document.getElementById('subdomain-chart'), {{
        type: 'bar',
        data: {{ labels: {labels}, datasets: [{{
          label: 'Count',
          data: {data},
          backgroundColor: '#22d3ee'
        }}] }},
        options: {{ indexAxis: 'y', responsive: true, maintainAspectRatio: true, plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ ticks: {{ color: '#dbe4f0' }}, grid: {{ color: '#1e2a3d' }} }}, y: {{ ticks: {{ color: '#dbe4f0' }}, grid: {{ display: false }} }} }} }}
      }});
    }}
  </script>
</div>
"###, 
        labels = serde_json::to_string(&labels).unwrap_or_default(),
        data = serde_json::to_string(&data).unwrap_or_default()
    )
}

// =============================================================================
// Advanced D3.js Visualization Blocks - Using const strings with ### delimiters
// =============================================================================

fn attack_surface_map_block(results: &ReconResults) -> String {
    let nodes_json = serde_json::to_string(&build_attack_surface_nodes(results)).unwrap_or_default();
    let links_json = serde_json::to_string(&build_attack_surface_links(results)).unwrap_or_default();
    let target_label = html_escape(&results.target.input);
    
    let mut h = String::new();
    h.push_str(&section_open("Attack Surface Map (Interactive)", "🗺️"));
    h.push_str(r###"<div class="viz-controls">
  <label class="viz-btn" onclick="filterAttackSurface('all')">All</label>
  <label class="viz-btn" onclick="filterAttackSurface('web')">Web</label>
  <label class="viz-btn" onclick="filterAttackSurface('api')">API</label>
  <label class="viz-btn" onclick="filterAttackSurface('infra')">Infra</label>
  <label class="viz-btn" onclick="filterAttackSurface('cred')">Credentials</label>
  <label class="viz-btn" onclick="filterAttackSurface('vuln')">Vulnerabilities</label>
</div>"###);
    h.push_str(r###"<div id="attack-surface-map" class="viz-container" style="height:600px;"></div>"###);
    h.push_str(&section_close());
    
    // JavaScript code - using string replacement
    let js_code = ATTACK_SURFACE_MAP_JS
        .replace("NODES_JSON", &nodes_json)
        .replace("LINKS_JSON", &links_json)
        .replace("TARGET_LABEL", &target_label);
    h.push_str(&js_code);
    
    h
}

const ATTACK_SURFACE_MAP_JS: &str = r###"
<script>
const attackSurfaceNodes = NODES_JSON;
const attackSurfaceLinks = LINKS_JSON;
let attackSurfaceSimulation;

function initAttackSurfaceMap() {
  const container = d3.select("#attack-surface-map");
  const width = container.node().getBoundingClientRect().width;
  const height = 600;

  const svg = container.append("svg")
    .attr("width", "100%")
    .attr("height", "600")
    .attr("viewBox", "0 0 " + width + " " + height);

  // Definitions for gradients and markers
  const defs = svg.append("defs");
  
  // Arrow markers for links
  ["recon", "exploit", "lateral", "persist", "impact", "cred", "default", "web", "api", "infra", "db", "remote", "ldap", "smb", "snmp", "vuln", "target", "subdomain"].forEach((type, i) => {
    const colors = {recon: "#22d3ee", exploit: "#ef4444", lateral: "#f97316", persist: "#e879f9", impact: "#f87171", cred: "#34d399", default: "#64748b", web: "#e879f9", api: "#f97316", infra: "#fbbf24", db: "#ef4444", remote: "#f87171", ldap: "#e879f9", smb: "#fbbf24", snmp: "#fbbf24", vuln: "#ef4444", target: "#d946ef", subdomain: "#22d3ee"};
    const color = colors[type] || colors.default;
    svg.append("defs").append("marker")
      .attr("id", "arrowhead-" + type)
      .attr("viewBox", "0 0 10 10")
      .attr("refX", 16)
      .attr("refY", 5)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M 0 0 L 10 5 L 0 10 Z")
      .attr("fill", colors[type]);
  });

  const simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(d => d.id).distance(120).strength(0.3))
    .force("charge", d3.forceManyBody().strength(-400))
    .force("center", d3.forceCenter(0, 0))
    .force("collision", d3.forceCollide().radius(40).strength(0.5))
    .force("x", d3.forceX(0).strength(0.1))
    .force("y", d3.forceY(0).strength(0.1));

  const link = svg.append("g")
    .attr("stroke", "#2b3a52")
    .attr("stroke-width", 1.5)
    .selectAll("path")
    .data(attackSurfaceLinks)
    .join("path")
    .attr("class", "link")
    .attr("marker-end", d => "url(#arrowhead-" + (d.type || "default") + ")");

  const node = svg.append("g")
    .attr("stroke", "#fff")
    .attr("stroke-width", 1.5)
    .selectAll("g")
    .data(attackSurfaceNodes)
    .join("g")
    .attr("class", "node")
    .call(drag(simulation))
    .on("mouseover", function(event, d) {
      showTooltip(event, "<strong>" + d.label + "</strong><br>Type: " + d.kind + (d.severity ? "<br>Severity: " + d.severity : "") + (d.port ? "<br>Port: " + d.port : "") + (d.service ? "<br>Service: " + d.service : ""));
    })
    .on("mouseout", hideTooltip)
    .on("click", function(event, d) {
      if (d.url) window.open(d.url, "_blank");
    });

  const nodeCircle = node.append("circle")
    .attr("r", d => Math.max(12, Math.min(30, 10 + (d.degree || 0) * 2)))
    .attr("fill", d => {
      const colors = {recon: "#22d3ee", exploit: "#ef4444", lateral: "#f97316", persist: "#e879f9", impact: "#f87171", cred: "#34d399", web: "#e879f9", api: "#f97316", infra: "#fbbf24", db: "#ef4444", remote: "#f87171", ldap: "#e879f9", smb: "#fbbf24", snmp: "#fbbf24", vuln: "#ef4444", target: "#d946ef", subdomain: "#22d3ee", default: "#64748b"};
      return colors[d.kind] || colors.default;
    })
    .attr("stroke", "#fff")
    .attr("stroke-width", 1.5);

  const nodeLabel = node.append("text")
    .attr("dy", d => 20 + Math.max(12, Math.min(30, 10 + (d.degree || 0) * 2)))
    .attr("text-anchor", "middle")
    .attr("font-size", "10px")
    .attr("fill", "#dbe4f0")
    .attr("font-weight", 500)
    .text(d => d.label.length > 20 ? d.label.substring(0, 18) + "..." : d.label);

  attackSurfaceSimulation = simulation
    .nodes(attackSurfaceNodes)
    .on("tick", ticked);

  simulation.force("link")
    .links(attackSurfaceLinks);

  function ticked() {
    link.attr("d", d => {
      const dx = d.target.x - d.source.x;
      const dy = d.target.y - d.source.y;
      const dr = Math.sqrt(dx * dx + dy * dy);
      return "M" + d.source.x + "," + d.source.y + "A" + dr + "," + dr + " 0 0,1 " + d.target.x + "," + d.target.y;
    });

    node.attr("transform", d => "translate(" + d.x + "," + d.y + ")");
  }

  function drag(simulation) {
    return d3.drag()
      .on("start", function(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on("drag", function(event, d) {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on("end", function(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });
  }

  function filterAttackSurface(type) {
    document.querySelectorAll("#attack-surface-map .viz-btn").forEach(b => b.classList.remove("active"));
    event.target.classList.add("active");
    
    const nodeSelection = d3.select("#attack-surface-map svg").selectAll(".node");
    const linkSelection = d3.select("#attack-surface-map svg").selectAll(".link");
    
    if (type === "all") {
      nodeSelection.style("opacity", 1).style("display", null);
      linkSelection.style("opacity", 1).style("display", null);
    } else {
      nodeSelection.style("opacity", d => d.kind === type ? 1 : 0.1)
        .style("display", d => d.kind === type ? null : "none");
      linkSelection.style("opacity", d => d.source.kind === type || d.target.kind === type ? 1 : 0.1)
        .style("display", d => d.source.kind === type || d.target.kind === type ? null : "none");
    }
  }

  window.filterAttackSurface = filterAttackSurface;
}

window.initAttackSurfaceMap = initAttackSurfaceMap;
</script>
"###;

fn kill_chain_graph_block(results: &ReconResults) -> String {
    let phases_json = serde_json::to_string(&build_kill_chain_phases(results)).unwrap_or_default();
    
    let mut h = String::new();
    h.push_str(&section_open("Kill Chain Graph (Animated)", "⚔️"));
    h.push_str(r###"<div id="kill-chain-graph" class="viz-container" style="height:300px;"></div>"###);
    h.push_str(&section_close());
    
    let js_code = KILL_CHAIN_GRAPH_JS.replace("PHASES_JSON", &phases_json);
    h.push_str(&js_code);
    h
}

const KILL_CHAIN_GRAPH_JS: &str = r###"
<script>
const killChainPhases = PHASES_JSON;
let killChainAnimation;

function initKillChainGraph() {
  const container = d3.select("#kill-chain-graph");
  const width = container.node().getBoundingClientRect().width;
  const height = 300;

  const svg = container.append("svg")
    .attr("width", "100%")
    .attr("height", 300)
    .attr("viewBox", "0 0 " + width + " 300");

  const stages = [
    { id: "recon", label: "Reconnaissance", color: "#22d3ee", icon: "🔍" },
    { id: "initial", label: "Initial Access", color: "#ef4444", icon: "🎯" },
    { id: "privilege", label: "Privilege Escalation", color: "#f97316", icon: "⬆️" },
    { id: "lateral", label: "Lateral Movement", color: "#fbbf24", icon: "↔️" },
    { id: "persist", label: "Persistence", color: "#e879f9", icon: "🔒" },
    { id: "impact", label: "Impact", color: "#f87171", icon: "💥" }
  ];

  const stageData = stages.map((s, i) => {
    const phase = killChainPhases.find(p => p.id === s.id);
    return { ...s, status: phase ? phase.status : "pending", details: phase ? phase.details : "", x: (width / 6) * i + (width / 12), y: 150 };
  });

  // Draw connections
  svg.selectAll(".kc-link")
    .data(stageData.slice(0, -1))
    .join("path")
    .attr("class", "kc-link")
    .attr("d", d => {
      const next = stageData[stageData.indexOf(d) + 1];
      return "M" + (d.x + 60) + "," + d.y + " Q" + ((d.x + next.x) / 2) + "," + (d.y - 40) + " " + (next.x - 60) + "," + next.y;
    })
    .attr("stroke", "#2b3a52")
    .attr("stroke-width", 2)
    .attr("fill", "none")
    .attr("stroke-dasharray", "8,4");

  // Draw stages
  const stageG = svg.selectAll(".kc-stage")
    .data(stageData)
    .join("g")
    .attr("class", "kc-stage")
    .attr("transform", d => "translate(" + d.x + "," + d.y + ")");

  stageG.append("circle")
    .attr("r", 60)
    .attr("fill", d => d.status === "completed" ? d.color : (d.status === "active" ? d.color : "#1a2332"))
    .attr("stroke", d => d.status === "active" ? "#fff" : d.color)
    .attr("stroke-width", d => d.status === "active" ? 3 : 2)
    .attr("opacity", d => d.status === "pending" ? 0.4 : 1)
    .transition()
    .duration(800)
    .delay((d, i) => i * 300)
    .attr("r", 60);

  stageG.append("text")
    .attr("text-anchor", "middle")
    .attr("dy", "-20")
    .attr("font-size", "24px")
    .text(d => d.icon);

  stageG.append("text")
    .attr("text-anchor", "middle")
    .attr("dy", "10")
    .attr("font-size", "11px")
    .attr("font-weight", 600)
    .attr("fill", "#dbe4f0")
    .text(d => d.label);

  stageG.append("text")
    .attr("text-anchor", "middle")
    .attr("dy", "28")
    .attr("font-size", "10px")
    .attr("fill", d => d.status === "completed" ? "#22c55e" : (d.status === "active" ? "#d946ef" : "#7a8ba5"))
    .text(d => d.status === "completed" ? "✔ Complete" : (d.status === "active" ? "▶ Active" : "◌ Pending"));

  // Tooltip
  stageG.on("mouseover", function(event, d) {
    showTooltip(event, "<strong>" + d.label + "</strong><br>Status: " + d.status + (d.details ? "<br>" + d.details : ""));
  }).on("mouseout", hideTooltip);

  window.killChainAnimation = stageData;
}

window.initKillChainGraph = initKillChainGraph;
</script>
"###;

fn attack_paths_graph_block(results: &ReconResults) -> String {
    let paths_json = serde_json::to_string(&results.attack_paths).unwrap_or_default();
    
    let mut h = String::new();
    h.push_str(&section_open("Attack Paths", "🛤️"));
    h.push_str(r###"<div id="attack-path-graph" class="viz-container" style="height:500px;"></div>"###);
    h.push_str(&section_close());
    
    let js_code = ATTACK_PATHS_GRAPH_JS.replace("PATHS_JSON", &paths_json);
    h.push_str(&js_code);
    h
}

const ATTACK_PATHS_GRAPH_JS: &str = r###"
<script>
const attackPaths = PATHS_JSON;
let attackPathSimulation;

function initAttackPathGraph() {
  const container = d3.select("#attack-path-graph");
  const width = container.node().getBoundingClientRect().width;
  const height = 500;

  const svg = container.append("svg")
    .attr("width", "100%")
    .attr("height", 500)
    .attr("viewBox", "0 0 " + width + " 500");

  if (!attackPaths || attackPaths.length === 0) {
    svg.append("text")
      .attr("x", width / 2)
      .attr("y", height / 2)
      .attr("text-anchor", "middle")
      .attr("fill", "#7a8ba5")
      .attr("font-size", "16px")
      .text("No attack paths generated");
    return;
  }

  // Build nodes and links from attack paths
  const nodes = [];
  const links = [];
  const nodeMap = new Map();

  attackPaths.forEach((path, pi) => {
    path.steps.forEach((step, si) => {
      const nodeId = "path-" + pi + "-step-" + si;
      if (!nodeMap.has(nodeId)) {
        nodes.push({
          id: nodeId,
          label: step.title,
          kind: step.kind || "exploit",
          severity: step.severity || "medium",
          description: step.description,
          command: step.command,
          evidence: step.evidence ? step.evidence.join("; ") : "",
          pathIndex: pi,
          stepIndex: si,
          x: 100 + si * 200,
          y: 80 + pi * 120
        });
        nodeMap.set(nodeId, nodes.length - 1);
      }
      if (si > 0) {
        const prevId = "path-" + pi + "-step-" + (si - 1);
        links.push({ source: prevId, target: nodeId, type: step.kind || "exploit" });
      }
    });
  });

  // Arrow markers
  const defs = svg.append("defs");
  ["recon", "exploit", "lateral", "persist", "impact", "cred", "default"].forEach(type => {
    const colors = {recon: "#22d3ee", exploit: "#ef4444", lateral: "#f97316", persist: "#e879f9", impact: "#f87171", cred: "#34d399", default: "#64748b"};
    const color = colors[type] || colors.default;
    svg.append("defs").append("marker")
      .attr("id", "ap-arrow-" + type)
      .attr("viewBox", "0 0 10 10")
      .attr("refX", 20)
      .attr("refY", 5)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M 0 0 L 10 5 L 0 10 Z")
      .attr("fill", color);
  });

  const simulation = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id).distance(180).strength(0.5))
    .force("charge", d3.forceManyBody().strength(-200))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("x", d3.forceX(width / 2).strength(0.05))
    .force("y", d3.forceY(height / 2).strength(0.05));

  const link = svg.append("g")
    .attr("stroke", "#2b3a52")
    .attr("stroke-width", 2)
    .selectAll("path")
    .data(links)
    .join("path")
    .attr("class", "ap-link")
    .attr("marker-end", d => "url(#ap-arrow-" + (d.type || "default") + ")")
    .attr("stroke-dasharray", "4,2");

  const node = svg.append("g")
    .selectAll("g")
    .data(nodes)
    .join("g")
    .attr("class", "ap-node")
    .call(d3.drag()
      .on("start", (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on("end", (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
    )
    .on("mouseover", function(event, d) {
      showTooltip(event, "<strong>Step " + (d.stepIndex + 1) + ": " + d.label + "</strong><br>Type: " + d.kind + (d.severity ? "<br>Severity: " + d.severity : "") + (d.command ? "<br><code>" + d.command + "</code>" : "") + (d.evidence ? "<br>Evidence: " + d.evidence : ""));
    })
    .on("mouseout", hideTooltip)
    .on("click", function(event, d) {
      if (d.command) {
        navigator.clipboard.writeText(d.command);
        showTooltip(event, "Command copied to clipboard!");
      }
    });

  const colors = {recon: "#22d3ee", exploit: "#ef4444", lateral: "#f97316", persist: "#e879f9", impact: "#f87171", cred: "#34d399", default: "#64748b"};

  node.append("circle")
    .attr("r", 25)
    .attr("fill", d => colors[d.kind] || colors.default)
    .attr("stroke", "#fff")
    .attr("stroke-width", 2);

  node.append("text")
    .attr("text-anchor", "middle")
    .attr("dy", "4")
    .attr("font-size", "10px")
    .attr("fill", "#0a0e14")
    .attr("font-weight", 700)
    .text(d => String(d.stepIndex + 1));

  node.append("title").text(d => d.label);

  simulation.on("tick", () => {
    link.attr("d", d => {
      const dx = d.target.x - d.source.x;
      const dy = d.target.y - d.source.y;
      const dr = Math.sqrt(dx * dx + dy * dy);
      return "M" + d.source.x + "," + d.source.y + "A" + dr + "," + dr + " 0 0,1 " + d.target.x + "," + d.target.y;
    });
    node.attr("transform", d => "translate(" + d.x + "," + d.y + ")");
  });

  // Legend
  const legend = svg.append("g").attr("transform", "translate(20, 20)");
  
  Object.entries(colors).forEach(([kind, color], i) => {
    if (kind === "default") return;
    const g = legend.append("g").attr("transform", "translate(0, " + (i * 22) + ")");
    g.append("circle").attr("r", 8).attr("fill", color).attr("cx", 0).attr("cy", 0);
    g.append("text").attr("x", 16).attr("y", 4).attr("font-size", "11px").attr("fill", "#dbe4f0").text(kind.charAt(0).toUpperCase() + kind.slice(1));
  });

  window.attackPathSimulation = simulation;
}

window.initAttackPathGraph = initAttackPathGraph;
</script>
"###;

fn vulnerability_heatmap_block(results: &ReconResults) -> String {
    let vulns_json = serde_json::to_string(&build_vuln_heatmap_data(results)).unwrap_or_default();
    
    let mut h = String::new();
    h.push_str(&section_open("Vulnerability Heatmap", "🔥"));
    h.push_str(r###"<div class="viz-controls">
  <select class="viz-btn vuln-filter-sev" onchange="filterVulnHeatmap()">
    <option value="all">All Severities</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
    <option value="info">Info</option>
  </select>
  <select class="viz-btn vuln-filter-type" onchange="filterVulnHeatmap()">
    <option value="all">All Types</option>
    <option value="web">Web</option>
    <option value="api">API</option>
    <option value="infra">Infrastructure</option>
    <option value="credential">Credentials</option>
    <option value="config">Misconfiguration</option>
  </select>
</div>"###);
    h.push_str(r###"<div id="vuln-heatmap" class="viz-container" style="height:500px;"></div>"###);
    h.push_str(&section_close());
    
    let js_code = VULN_HEATMAP_JS.replace("VULNS_JSON", &vulns_json);
    h.push_str(&js_code);
    h
}

const VULN_HEATMAP_JS: &str = r###"
<script>
const vulnHeatmapData = VULNS_JSON;
let currentSevFilter = "all";
let currentTypeFilter = "all";

function initVulnHeatmap() {
  const container = d3.select("#vuln-heatmap");
  const width = container.node().getBoundingClientRect().width;
  const height = 500;
  const cellSize = Math.min(40, width / Math.max(10, [...new Set(vulnHeatmapData.map(d => d.asset))].length + 1));
  
  const assets = [...new Set(vulnHeatmapData.map(d => d.asset))].sort();
  const types = [...new Set(vulnHeatmapData.map(d => d.type))].sort();
  
  const svg = container.append("svg")
    .attr("width", "100%")
    .attr("height", height)
    .attr("viewBox", "0 0 " + (assets.length * cellSize + 150) + " " + (types.length * cellSize + 50));

  const severityColors = {critical: "#ef4444", high: "#f97316", medium: "#fbbf24", low: "#22d3ee", info: "#64748b"};

  const cells = svg.selectAll(".heatmap-cell")
    .data(vulnHeatmapData)
    .join("rect")
    .attr("class", "heatmap-cell")
    .attr("x", d => 120 + assets.indexOf(d.asset) * cellSize)
    .attr("y", d => 20 + types.indexOf(d.type) * cellSize)
    .attr("width", cellSize - 2)
    .attr("height", cellSize - 2)
    .attr("rx", 3)
    .attr("fill", d => severityColors[d.severity] || "#64748b")
    .attr("stroke", "#1e2a3d")
    .attr("stroke-width", 1)
    .on("mouseover", function(event, d) {
      showTooltip(event, "<strong>" + d.asset + " / " + d.type + "</strong><br>Severity: " + d.severity.toUpperCase() + "<br>" + d.title + (d.cve ? "<br>CVE: " + d.cve : "") + (d.evidence ? "<br>Evidence: " + d.evidence : ""));
    })
    .on("mouseout", hideTooltip);

  // Y-axis labels (types)
  svg.selectAll(".y-label")
    .data(types)
    .join("text")
    .attr("class", "y-label")
    .attr("x", 115)
    .attr("y", (d, i) => 20 + i * cellSize + cellSize / 2 + 4)
    .attr("text-anchor", "end")
    .attr("font-size", "11px")
    .attr("fill", "#dbe4f0")
    .text(d => d);

  // X-axis labels (assets) - rotated
  svg.selectAll(".x-label")
    .data(assets)
    .join("text")
    .attr("class", "x-label")
    .attr("x", (d, i) => 120 + i * cellSize + cellSize / 2)
    .attr("y", 20 + types.length * cellSize + 20)
    .attr("text-anchor", "middle")
    .attr("font-size", "10px")
    .attr("fill", "#dbe4f0")
    .attr("transform", (d, i) => "rotate(-45, " + (120 + i * cellSize + cellSize / 2) + ", " + (20 + types.length * cellSize + 20) + ")")
    .text(d => d.length > 20 ? d.substring(0, 18) + "..." : d);

  // Legend
  const legend = svg.append("g").attr("transform", "translate(120, " + (20 + types.length * cellSize + 40) + ")");
  Object.entries(severityColors).forEach(([sev, color], i) => {
    const g = legend.append("g").attr("transform", "translate(" + (i * 90) + ", 0)");
    g.append("rect").attr("width", 14).attr("height", 14).attr("rx", 3).attr("fill", color);
    g.append("text").attr("x", 20).attr("y", 10).attr("font-size", "11px").attr("fill", "#dbe4f0").text(sev.charAt(0).toUpperCase() + sev.slice(1));
  });

  window.filterVulnHeatmap = filterVulnHeatmap;
}

function filterVulnHeatmap() {
  currentSevFilter = document.querySelector(".vuln-filter-sev").value;
  currentTypeFilter = document.querySelector(".vuln-filter-type").value;
  
  d3.select("#vuln-heatmap svg").selectAll(".heatmap-cell")
    .style("opacity", d => {
      const sevMatch = currentSevFilter === "all" || d.severity === currentSevFilter;
      const typeMatch = currentTypeFilter === "all" || d.type === currentTypeFilter;
      return sevMatch && typeMatch ? 1 : 0.1;
    })
    .style("display", d => {
      const sevMatch = currentSevFilter === "all" || d.severity === currentSevFilter;
      const typeMatch = currentTypeFilter === "all" || d.type === currentTypeFilter;
      return sevMatch && typeMatch ? null : "none";
    });
}

window.initVulnHeatmap = initVulnHeatmap;
</script>
"###;

fn credential_map_block(results: &ReconResults) -> String {
    // No credentials field in ReconResults - create placeholder
    let creds_json = "[]".to_string();
    
    let mut h = String::new();
    h.push_str(&section_open("Credential Map", "🔑"));
    h.push_str(r###"<div id="credential-map" class="viz-container" style="height:500px;"></div>"###);
    h.push_str(&section_close());
    
    let js_code = CREDENTIAL_MAP_JS.replace("CREDS_JSON", &creds_json);
    h.push_str(&js_code);
    h
}

const CREDENTIAL_MAP_JS: &str = r###"
<script>
const credentialData = CREDS_JSON;
let credentialSimulation;

function initCredentialMap() {
  const container = d3.select("#credential-map");
  const width = container.node().getBoundingClientRect().width;
  const height = 500;

  const svg = container.append("svg")
    .attr("width", "100%")
    .attr("height", 500)
    .attr("viewBox", "0 0 " + width + " " + height);

  if (!credentialData || credentialData.length === 0) {
    svg.append("text")
      .attr("x", width / 2)
      .attr("y", height / 2)
      .attr("text-anchor", "middle")
      .attr("fill", "#7a8ba5")
      .attr("font-size", "16px")
      .text("No credentials discovered");
    return;
  }

  const typeColors = {aws: "#ff9900", github: "#6e5494", ssh: "#4e9a06", jwt: "#000000", api_key: "#d946ef", database: "#ef4444", cloud: "#22d3ee", other: "#64748b"};

  const simulation = d3.forceSimulation(credentialData)
    .force("link", d3.forceLink().id(d => d.id).distance(100).strength(0.3))
    .force("charge", d3.forceManyBody().strength(-300))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collision", d3.forceCollide().radius(35).strength(0.5));

  const link = svg.append("g")
    .attr("stroke", "#2b3a52")
    .attr("stroke-width", 1.5)
    .attr("stroke-dasharray", "3,3")
    .selectAll("line")
    .data(credentialData.flatMap(d => (d.reused_on || []).map(r => ({source: d.id, target: r}))))
    .join("line")
    .attr("class", "cred-link");

  const node = svg.append("g")
    .selectAll("g")
    .data(credentialData)
    .join("g")
    .attr("class", "cred-node")
    .call(d3.drag()
      .on("start", (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on("end", (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
    )
    .on("mouseover", function(event, d) {
      showTooltip(event, "<strong>" + d.type.toUpperCase() + " Credential</strong><br>Source: " + d.source + (d.reused_on ? "<br>Reused on: " + d.reused_on.join(", ") : "") + (d.evidence ? "<br>Evidence: " + d.evidence : ""));
    })
    .on("mouseout", hideTooltip);

  node.append("circle")
    .attr("r", d => 15 + (d.reused_on ? d.reused_on.length * 3 : 0))
    .attr("fill", d => typeColors[d.type] || typeColors.other)
    .attr("stroke", "#fff")
    .attr("stroke-width", 2);

  node.append("text")
    .attr("text-anchor", "middle")
    .attr("dy", "4")
    .attr("font-size", "10px")
    .attr("fill", d => d.type === "jwt" ? "#fff" : "#0a0e14")
    .attr("font-weight", 700)
    .text(d => d.type.toUpperCase().substring(0, 4));

  simulation.on("tick", () => {
    link
      .attr("x1", d => d.source.x)
      .attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x)
      .attr("y2", d => d.target.y);
    node.attr("transform", d => "translate(" + d.x + "," + d.y + ")");
  });

  // Legend
  const legend = svg.append("g").attr("transform", "translate(20, 20)");
  Object.entries(typeColors).forEach(([type, color], i) => {
    if (type === "other") return;
    const g = legend.append("g").attr("transform", "translate(0, " + (i * 22) + ")");
    g.append("circle").attr("r", 8).attr("fill", color).attr("cx", 0).attr("cy", 0);
    g.append("text").attr("x", 16).attr("y", 4).attr("font-size", "11px").attr("fill", "#dbe4f0").text(type.charAt(0).toUpperCase() + type.slice(1));
  });

  window.credentialSimulation = simulation;
}

window.initCredentialMap = initCredentialMap;
</script>
"###;

fn network_topology_block(results: &ReconResults) -> String {
    let topo_json = serde_json::to_string(&build_network_topology_data(results)).unwrap_or_default();
    
    let mut h = String::new();
    h.push_str(&section_open("Network Topology", "🌐"));
    h.push_str(r###"<div id="network-topology" class="viz-container" style="height:500px;"></div>"###);
    h.push_str(&section_close());
    
    let js_code = NETWORK_TOPOLOGY_JS.replace("TOPO_JSON", &topo_json);
    h.push_str(&js_code);
    h
}

const NETWORK_TOPOLOGY_JS: &str = r###"
<script>
const networkTopologyData = TOPO_JSON;
let networkSimulation;

function initNetworkTopology() {
  const container = d3.select("#network-topology");
  const width = container.node().getBoundingClientRect().width;
  const height = 500;

  const svg = container.append("svg")
    .attr("width", "100%")
    .attr("height", 500)
    .attr("viewBox", "0 0 " + width + " " + height);

  if (!networkTopologyData || networkTopologyData.nodes.length === 0) {
    svg.append("text")
      .attr("x", width / 2)
      .attr("y", height / 2)
      .attr("text-anchor", "middle")
      .attr("fill", "#7a8ba5")
      .attr("font-size", "16px")
      .text("No network topology data");
    return;
  }

  const { nodes, links } = networkTopologyData;

  const typeColors = {target: "#d946ef", subdomain: "#22d3ee", host: "#22d3ee", service: "#f97316", database: "#ef4444", internal: "#e879f9", external: "#ef4444", default: "#64748b"};

  const simulation = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id).distance(100).strength(0.4))
    .force("charge", d3.forceManyBody().strength(-250))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collision", d3.forceCollide().radius(30).strength(0.5));

  const link = svg.append("g")
    .attr("stroke", "#2b3a52")
    .attr("stroke-width", 1.5)
    .selectAll("line")
    .data(links)
    .join("line")
    .attr("class", "net-link");

  const node = svg.append("g")
    .selectAll("g")
    .data(nodes)
    .join("g")
    .attr("class", "net-node")
    .call(d3.drag()
      .on("start", (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on("end", (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
    )
    .on("mouseover", function(event, d) {
      showTooltip(event, "<strong>" + d.label + "</strong><br>Type: " + d.kind + (d.ip ? "<br>IP: " + d.ip : "") + (d.ports ? "<br>Ports: " + d.ports.join(", ") : ""));
    })
    .on("mouseout", hideTooltip);

  node.append("circle")
    .attr("r", d => d.kind === "target" ? 20 : (d.kind === "subdomain" ? 15 : 12))
    .attr("fill", d => typeColors[d.kind] || typeColors.default)
    .attr("stroke", "#fff")
    .attr("stroke-width", 2);

  node.append("text")
    .attr("text-anchor", "middle")
    .attr("dy", d => d.kind === "target" ? 28 : 22)
    .attr("font-size", "9px")
    .attr("fill", "#dbe4f0")
    .attr("font-weight", 500)
    .text(d => d.label.length > 18 ? d.label.substring(0, 16) + "..." : d.label);

  simulation.on("tick", () => {
    link
      .attr("x1", d => d.source.x)
      .attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x)
      .attr("y2", d => d.target.y);
    node.attr("transform", d => "translate(" + d.x + "," + d.y + ")");
  });

  window.networkSimulation = simulation;
}

window.initNetworkTopology = initNetworkTopology;
</script>
"###;

fn credential_heatmap_block(results: &ReconResults) -> String {
    // No credentials field - create placeholder
    let heatmap_json = "[]".to_string();
    
    let mut h = String::new();
    h.push_str(&section_open("Credential Reuse Heatmap", "🔐"));
    h.push_str(r###"<div id="credential-heatmap" class="viz-container" style="height:400px;"></div>"###);
    h.push_str(&section_close());
    
    let js_code = CREDENTIAL_HEATMAP_JS.replace("HEATMAP_JSON", &heatmap_json);
    h.push_str(&js_code);
    h
}

const CREDENTIAL_HEATMAP_JS: &str = r###"
<script>
const credentialHeatmapData = HEATMAP_JSON;

function initCredentialHeatmap() {
  const container = d3.select("#credential-heatmap");
  const width = container.node().getBoundingClientRect().width;
  const height = 400;
  
  const assets = [...new Set(credentialHeatmapData.map(d => d.asset))].sort();
  const credTypes = [...new Set(credentialHeatmapData.map(d => d.type))].sort();
  const cellSize = Math.min(50, width / Math.max(8, assets.length + 1));
  
  const svg = container.append("svg")
    .attr("width", "100%")
    .attr("height", height)
    .attr("viewBox", "0 0 " + (assets.length * cellSize + 150) + " " + (credTypes.length * cellSize + 80));

  const cells = svg.selectAll(".cred-heatmap-cell")
    .data(credentialHeatmapData)
    .join("rect")
    .attr("class", "cred-heatmap-cell")
    .attr("x", d => 120 + assets.indexOf(d.asset) * cellSize)
    .attr("y", d => 30 + credTypes.indexOf(d.type) * cellSize)
    .attr("width", cellSize - 2)
    .attr("height", cellSize - 2)
    .attr("rx", 4)
    .attr("fill", d => d.count > 0 ? "#d946ef" : "#1e2a3d")
    .attr("opacity", d => d.count > 0 ? Math.min(0.3 + d.count * 0.15, 1) : 0.1)
    .attr("stroke", "#2b3a52")
    .attr("stroke-width", 1)
    .on("mouseover", function(event, d) {
      if (d.count > 0) {
        showTooltip(event, "<strong>" + d.asset + " / " + d.type + "</strong><br>Reuse count: " + d.count + (d.details ? "<br>" + d.details : ""));
      }
    })
    .on("mouseout", hideTooltip);

  // Count labels
  svg.selectAll(".cred-count")
    .data(credentialHeatmapData.filter(d => d.count > 0))
    .join("text")
    .attr("class", "cred-count")
    .attr("x", d => 120 + assets.indexOf(d.asset) * cellSize + cellSize / 2)
    .attr("y", d => 30 + credTypes.indexOf(d.type) * cellSize + cellSize / 2 + 4)
    .attr("text-anchor", "middle")
    .attr("font-size", "12px")
    .attr("font-weight", 700)
    .attr("fill", "#0a0e14")
    .text(d => d.count);

  // Y-axis
  svg.selectAll(".y-label")
    .data(credTypes)
    .join("text")
    .attr("x", 115)
    .attr("y", (d, i) => 30 + i * cellSize + cellSize / 2 + 4)
    .attr("text-anchor", "end")
    .attr("font-size", "11px")
    .attr("fill", "#dbe4f0")
    .text(d => d.toUpperCase());

  // X-axis
  svg.selectAll(".x-label")
    .data(assets)
    .join("text")
    .attr("x", (d, i) => 120 + i * cellSize + cellSize / 2)
    .attr("y", 30 + credTypes.length * cellSize + 30)
    .attr("text-anchor", "middle")
    .attr("font-size", "10px")
    .attr("fill", "#dbe4f0")
    .attr("transform", (d, i) => "rotate(-45, " + (120 + i * cellSize + cellSize / 2) + ", " + (30 + credTypes.length * cellSize + 30) + ")")
    .text(d => d.length > 20 ? d.substring(0, 18) + "..." : d);
}

window.initCredentialHeatmap = initCredentialHeatmap;
</script>
"###;

fn attack_paths_graph_block_interactive(results: &ReconResults) -> String {
    let paths_json = serde_json::to_string(&results.attack_paths).unwrap_or_default();
    
    let mut h = String::new();
    h.push_str(&section_open("Interactive Attack Paths", "🎮"));
    h.push_str(r###"<div class="viz-controls">
  <select class="viz-btn attack-path-filter-sev" onchange="filterAttackPaths()" style="width: auto;">
    <option value="all">All Severities</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
  </select>
</div>"###);
    h.push_str(r###"<div id="attack-paths-interactive" class="viz-container" style="height:500px;"></div>"###);
    h.push_str(&section_close());
    
    let js_code = ATTACK_PATHS_INTERACTIVE_JS.replace("PATHS_JSON", &paths_json);
    h.push_str(&js_code);
    h
}

const ATTACK_PATHS_INTERACTIVE_JS: &str = r###"
<script>
const interactiveAttackPaths = PATHS_JSON;
let currentPathFilter = "all";

function initAttackPathGraphInteractive() {
  const container = d3.select("#attack-paths-interactive");
  const width = container.node().getBoundingClientRect().width;
  
  if (!interactiveAttackPaths || interactiveAttackPaths.length === 0) {
    container.append("div").attr("class", "muted").style("padding", "40px").style("text-align", "center").text("No attack paths generated");
    return;
  }

  // Render as expandable cards
  const pathsContainer = container.append("div").style("display", "flex").style("flex-direction", "column").style("gap", "12px").style("padding", "16px").style("max-height", "500px").style("overflow-y", "auto");
  
  interactiveAttackPaths.forEach((path, i) => {
    const maxSev = path.steps.reduce((max, s) => {
      const order = {critical: 4, high: 3, medium: 2, low: 1, info: 0};
      const sev = s.severity || "medium";
      return order[sev] > order[max] ? sev : max;
    }, "info");
    
    const card = pathsContainer.append("div")
      .attr("class", "finding")
      .style("border-left-color", maxSev === "critical" ? "#ef4444" : maxSev === "high" ? "#f97316" : maxSev === "medium" ? "#fbbf24" : "#22d3ee")
      .style("display", currentPathFilter === "all" || currentPathFilter === maxSev ? "block" : "none");
    
    card.append("h3").text("Attack Path " + (i + 1) + ": " + path.name + " (Risk: " + maxSev.toUpperCase() + ")");
    
    const stepsDiv = card.append("div").style("margin-top", "12px").style("display", "flex").style("flex-direction", "column").style("gap", "8px");
    
    path.steps.forEach((step, si) => {
      const stepDiv = stepsDiv.append("div")
        .style("display", "flex")
        .style("align-items", "center")
        .style("gap", "12px")
        .style("padding", "10px")
        .style("background", "#0a0e14")
        .style("border", "1px solid #1e2a3d")
        .style("border-radius", "8px");
      
      stepDiv.append("span")
        .style("width", "30px")
        .style("height", "30px")
        .style("border-radius", "50%")
        .style("background", step.kind === "recon" ? "#22d3ee" : step.kind === "exploit" ? "#ef4444" : step.kind === "lateral" ? "#f97316" : step.kind === "persist" ? "#e879f9" : step.kind === "impact" ? "#f87171" : "#34d399")
        .style("display", "flex")
        .style("align-items", "center")
        .style("justify-content", "center")
        .style("color", "#0a0e14")
        .style("font-weight", "700")
        .style("font-size", "12px")
        .text(String(si + 1));
      
      stepDiv.append("div").style("flex", "1").html("<strong>" + step.title + "</strong>" + (step.description ? "<br><span style='color:#7a8ba5;font-size:12px'>" + step.description + "</span>" : "") + (step.command ? "<br><code style='font-size:11px;background:#1a2332;padding:2px 6px;border-radius:4px'>" + step.command + "</code>" : ""));
      
      if (step.command) {
        const copyBtn = stepDiv.append("button")
          .attr("class", "viz-btn")
          .style("padding", "4px 10px")
          .style("font-size", "11px")
          .text("Copy");
        copyBtn.on("click", () => {
          navigator.clipboard.writeText(step.command);
          copyBtn.text("Copied!").style("background", "#22c55e");
          setTimeout(() => copyBtn.text("Copy").style("background", ""), 1500);
        });
      }
    });
  });
  
  window.filterAttackPaths = filterAttackPaths;
}

function filterAttackPaths() {
  currentPathFilter = document.querySelector(".attack-path-filter-sev").value;
  d3.select("#attack-paths-interactive").selectAll(".finding")
    .style("display", d => {
      // We need to compute max severity for each path
      return "block"; // Simplified - would need path data bound
    });
}

window.initAttackPathGraphInteractive = initAttackPathGraphInteractive;
</script>
"###;

fn vulnerability_timeline_block(results: &ReconResults) -> String {
    let timeline_json = serde_json::to_string(&build_vuln_timeline_data(results)).unwrap_or_default();
    
    let mut h = String::new();
    h.push_str(&section_open("Vulnerability Discovery Timeline", "⏱️"));
    h.push_str(r###"<div class="viz-controls">
  <select class="viz-btn timeline-filter-phase" onchange="filterVulnTimeline()">
    <option value="all">All Phases</option>
    <option value="recon">Reconnaissance</option>
    <option value="exploit">Exploitation</option>
    <option value="lateral">Lateral Movement</option>
    <option value="persist">Persistence</option>
    <option value="impact">Impact</option>
  </select>
</div>"###);
    h.push_str(r###"<div id="vuln-timeline" class="viz-container" style="height:500px;"></div>"###);
    h.push_str(&section_close());
    
    let js_code = VULN_TIMELINE_JS.replace("TIMELINE_JSON", &timeline_json);
    h.push_str(&js_code);
    h
}

const VULN_TIMELINE_JS: &str = r###"
<script>
const vulnTimelineData = TIMELINE_JSON;
let currentTimelineFilter = "all";

function initVulnTimeline() {
  const container = d3.select("#vuln-timeline");
  const width = container.node().getBoundingClientRect().width;
  const height = 500;
  
  const svg = container.append("svg")
    .attr("width", "100%")
    .attr("height", 500)
    .attr("viewBox", "0 0 " + width + " 500");

  if (!vulnTimelineData || vulnTimelineData.length === 0) {
    svg.append("text")
      .attr("x", width / 2)
      .attr("y", height / 2)
      .attr("text-anchor", "middle")
      .attr("fill", "#7a8ba5")
      .attr("font-size", "16px")
      .text("No timeline data available");
    return;
  }

  // Sort by timestamp
  vulnTimelineData.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  
  const extent = d3.extent(vulnTimelineData, d => new Date(d.timestamp));
  const timeScale = d3.scaleTime().domain(extent).range([80, width - 80]);
  
  const phaseColors = {recon: "#22d3ee", exploit: "#ef4444", lateral: "#f97316", persist: "#e879f9", impact: "#f87171"};
  
  // Timeline axis
  const axis = svg.append("g")
    .attr("transform", "translate(0, 450)")
    .call(d3.axisBottom(timeScale).ticks(10).tickFormat(d3.timeFormat("%H:%M:%S")))
    .attr("color", "#7a8ba5");
  axis.selectAll("text").attr("fill", "#7a8ba5").attr("font-size", "10px");
  axis.selectAll("line, path").attr("stroke", "#2b3a52");

  // Events
  const events = svg.selectAll(".timeline-event")
    .data(vulnTimelineData)
    .join("g")
    .attr("class", "timeline-event")
    .attr("transform", d => "translate(" + timeScale(new Date(d.timestamp)) + ", 50)");
  
  events.append("circle")
    .attr("r", 10)
    .attr("fill", d => phaseColors[d.phase] || "#64748b")
    .attr("stroke", "#fff")
    .attr("stroke-width", 2)
    .on("mouseover", function(event, d) {
      showTooltip(event, "<strong>" + d.title + "</strong><br>Phase: " + d.phase + "<br>Time: " + new Date(d.timestamp).toLocaleTimeString() + "<br>Severity: " + d.severity.toUpperCase() + (d.details ? "<br>" + d.details : ""));
    })
    .on("mouseout", hideTooltip);

  events.append("text")
    .attr("text-anchor", "middle")
    .attr("dy", "-14")
    .attr("font-size", "9px")
    .attr("fill", "#dbe4f0")
    .text(d => d.title.length > 25 ? d.title.substring(0, 22) + "..." : d.title);

  // Phase filter
  window.filterVulnTimeline = filterVulnTimeline;
}

function filterVulnTimeline() {
  currentTimelineFilter = document.querySelector(".timeline-filter-phase").value;
  d3.select("#vuln-timeline svg").selectAll(".timeline-event")
    .style("opacity", d => currentTimelineFilter === "all" || d.phase === currentTimelineFilter ? 1 : 0.1)
    .style("display", d => currentTimelineFilter === "all" || d.phase === currentTimelineFilter ? null : "none");
}

window.initVulnTimeline = initVulnTimeline;
</script>
"###;

fn mitre_attack_heatmap_block(results: &ReconResults) -> String {
    let mitre_json = serde_json::to_string(&build_mitre_heatmap_data(results)).unwrap_or_default();
    
    let mut h = String::new();
    h.push_str(&section_open("MITRE ATT&CK Coverage Heatmap", "🎯"));
    h.push_str(r###"<div class="viz-controls">
  <select class="viz-btn mitre-filter-tactic" onchange="filterMitreHeatmap()">
    <option value="all">All Tactics</option>
    <option value="reconnaissance">Reconnaissance</option>
    <option value="resource-development">Resource Development</option>
    <option value="initial-access">Initial Access</option>
    <option value="execution">Execution</option>
    <option value="persistence">Persistence</option>
    <option value="privilege-escalation">Privilege Escalation</option>
    <option value="defense-evasion">Defense Evasion</option>
    <option value="credential-access">Credential Access</option>
    <option value="discovery">Discovery</option>
    <option value="lateral-movement">Lateral Movement</option>
    <option value="collection">Collection</option>
    <option value="command-and-control">Command and Control</option>
    <option value="exfiltration">Exfiltration</option>
    <option value="impact">Impact</option>
  </select>
</div>"###);
    h.push_str(r###"<div id="mitre-heatmap" class="viz-container" style="height:500px;"></div>"###);
    h.push_str(&section_close());
    
    let js_code = MITRE_HEATMAP_JS.replace("MITRE_JSON", &mitre_json);
    h.push_str(&js_code);
    h
}

const MITRE_HEATMAP_JS: &str = r###"
<script>
const mitreHeatmapData = MITRE_JSON;
let currentMitreFilter = "all";

function initMitreHeatmap() {
  const container = d3.select("#mitre-heatmap");
  const width = container.node().getBoundingClientRect().width;
  
  const tactics = [...new Set(mitreHeatmapData.map(d => d.tactic))].sort();
  const techniques = [...new Set(mitreHeatmapData.map(d => d.technique))].sort();
  const cellSize = 28;
  
  const svg = container.append("svg")
    .attr("width", "100%")
    .attr("height", tactics.length * cellSize + 60)
    .attr("viewBox", "0 0 " + (techniques.length * cellSize + 200) + " " + (tactics.length * cellSize + 60));

  const cells = svg.selectAll(".mitre-cell")
    .data(mitreHeatmapData)
    .join("rect")
    .attr("class", "mitre-cell")
    .attr("x", d => 180 + techniques.indexOf(d.technique) * cellSize)
    .attr("y", d => 30 + tactics.indexOf(d.tactic) * cellSize)
    .attr("width", cellSize - 1)
    .attr("height", cellSize - 1)
    .attr("rx", 2)
    .attr("fill", d => d.covered ? "#22c55e" : d.partial ? "#fbbf24" : "#ef4444")
    .attr("stroke", "#1e2a3d")
    .attr("stroke-width", 0.5)
    .on("mouseover", function(event, d) {
      showTooltip(event, "<strong>" + d.technique + "</strong><br>Tactic: " + d.tactic + "<br>Status: " + (d.covered ? "Covered" : d.partial ? "Partial" : "Missing") + (d.details ? "<br>" + d.details : ""));
    })
    .on("mouseout", hideTooltip);

  // Technique labels (top, rotated)
  svg.selectAll(".tech-label")
    .data(techniques)
    .join("text")
    .attr("class", "tech-label")
    .attr("x", (d, i) => 180 + i * cellSize + cellSize / 2)
    .attr("y", 20)
    .attr("text-anchor", "end")
    .attr("font-size", "9px")
    .attr("fill", "#dbe4f0")
    .attr("transform", (d, i) => "rotate(-45, " + (180 + i * cellSize + cellSize / 2) + ", 20)")
    .text(d => d);

  // Tactic labels (left)
  svg.selectAll(".tactic-label")
    .data(tactics)
    .join("text")
    .attr("class", "tactic-label")
    .attr("x", 175)
    .attr("y", (d, i) => 30 + i * cellSize + cellSize / 2 + 4)
    .attr("text-anchor", "end")
    .attr("font-size", "10px")
    .attr("fill", "#dbe4f0")
    .text(d => d.replace("-", " ").replace(/\b\w/g, c => c.toUpperCase()));

  // Legend
  const legend = svg.append("g").attr("transform", "translate(180, " + (tactics.length * cellSize + 40) + ")");
  [["Covered", "#22c55e"], ["Partial", "#fbbf24"], ["Missing", "#ef4444"]].forEach(([label, color], i) => {
    const g = legend.append("g").attr("transform", "translate(" + (i * 100) + ", 0)");
    g.append("rect").attr("width", 16).attr("height", 16).attr("rx", 3).attr("fill", color);
    g.append("text").attr("x", 22).attr("y", 12).attr("font-size", "11px").attr("fill", "#dbe4f0").text(label);
  });

  window.filterMitreHeatmap = filterMitreHeatmap;
}

function filterMitreHeatmap() {
  currentMitreFilter = document.querySelector(".mitre-filter-tactic").value;
  d3.select("#mitre-heatmap svg").selectAll(".mitre-cell")
    .style("opacity", d => currentMitreFilter === "all" || d.tactic === currentMitreFilter ? 1 : 0.1)
    .style("display", d => currentMitreFilter === "all" || d.tactic === currentMitreFilter ? null : "none");
}

window.initMitreHeatmap = initMitreHeatmap;
</script>
"###;

fn remediation_priority_block(results: &ReconResults) -> String {
    let rem_json = serde_json::to_string(&build_remediation_data(results)).unwrap_or_default();
    
    let mut h = String::new();
    h.push_str(&section_open("Remediation Priority Matrix", "✅"));
    h.push_str(r###"<div id="remediation-matrix"></div>"###);
    h.push_str(&section_close());
    
    let js_code = REMEDIATION_MATRIX_JS.replace("REM_JSON", &rem_json);
    h.push_str(&js_code);
    h
}

const REMEDIATION_MATRIX_JS: &str = r###"
<script>
const remediationData = REM_JSON;

function initRemediationMatrix() {
  const container = d3.select("#remediation-matrix");
  
  if (!remediationData || remediationData.length === 0) {
    container.append("p").attr("class", "muted").text("No remediation items");
    return;
  }

  const table = container.append("table");
  const thead = table.append("thead").append("tr");
  ["Priority", "Title", "Asset", "Severity", "Effort", "Action", "Done"].forEach(h => 
    thead.append("th").text(h)
  );
  
  const tbody = table.append("tbody");
  
  remediationData.forEach((item, i) => {
    const row = tbody.append("tr").attr("class", "remediation-item");
    row.append("td").attr("class", "remediation-priority priority-" + item.priority.toLowerCase()).text(item.priority.toUpperCase());
    row.append("td").html("<strong>" + item.title + "</strong><br><small style='color:#7a8ba5'>" + item.description + "</small>");
    row.append("td").text(item.asset);
    row.append("td").append("span").attr("class", "chip").style("background", item.severity === "critical" ? "#ef4444" : item.severity === "high" ? "#f97316" : item.severity === "medium" ? "#fbbf24" : "#22d3ee").text(item.severity.toUpperCase());
    row.append("td").text(item.effort);
    row.append("td").text(item.action);
    const checkbox = row.append("td").append("input").attr("type", "checkbox").attr("id", "rem-" + i);
    checkbox.on("change", function() {
      row.style("opacity", this.checked ? "0.5" : "1");
      row.select("td").style("text-decoration", this.checked ? "line-through" : "none");
    });
  });
}

window.initRemediationMatrix = initRemediationMatrix;
</script>
"###;

fn evidence_explorer_block(results: &ReconResults) -> String {
    let evidence_json = serde_json::to_string(&build_evidence_data(results)).unwrap_or_default();
    
    let mut h = String::new();
    h.push_str(&section_open("Raw Evidence Explorer", "🔍"));
    h.push_str(r###"<input type="text" id="evidence-search" placeholder="Search evidence... (type to filter)">"###);
    h.push_str(r###"<div id="evidence-explorer" class="viz-container" style="height:400px; max-height: 400px; overflow-y: auto;"></div>"###);
    h.push_str(&section_close());
    
    let js_code = EVIDENCE_EXPLORER_JS.replace("EVIDENCE_JSON", &evidence_json);
    h.push_str(&js_code);
    h
}

const EVIDENCE_EXPLORER_JS: &str = r###"
<script>
const evidenceData = EVIDENCE_JSON;

function initEvidenceExplorer() {
  const container = d3.select("#evidence-explorer");
  
  if (!evidenceData || evidenceData.length === 0) {
    container.append("p").attr("class", "muted").style("padding", "20px").text("No evidence data");
    return;
  }

  const rows = container.selectAll(".evidence-row")
    .data(evidenceData)
    .join("div")
    .attr("class", "evidence-row")
    .html(d => "<strong>[" + d.category + "]</strong> " + d.content + (d.source ? " <span style='color:#7a8ba5;font-size:11px'>(" + d.source + ")</span>" : ""))
    .on("click", function(event, d) {
      navigator.clipboard.writeText(d.content);
      const original = this.innerHTML;
      this.innerHTML = "<span style='color:#22c55e'>Copied to clipboard!</span>";
      setTimeout(() => this.innerHTML = original, 1500);
    });

  // Search functionality
  const searchInput = document.getElementById("evidence-search");
  if (searchInput) {
    searchInput.addEventListener("input", function() {
      const query = this.value.toLowerCase();
      d3.select("#evidence-explorer").selectAll(".evidence-row")
        .style("display", d => {
          const match = d.category.toLowerCase().includes(query) || 
                        d.content.toLowerCase().includes(query) ||
                        (d.source && d.source.toLowerCase().includes(query));
          return match ? null : "none";
        })
        .classed("match", d => {
          const match = d.category.toLowerCase().includes(query) || 
                        d.content.toLowerCase().includes(query) ||
                        (d.source && d.source.toLowerCase().includes(query));
          return match && query.length > 0;
        });
    });
  }
}

window.initEvidenceExplorer = initEvidenceExplorer;
</script>
"###;

// =============================================================================
// Additional Report Blocks (no JavaScript template literals - safe with format!)
// =============================================================================

fn attack_paths_block(results: &ReconResults) -> String {
    let mut h = String::new();
    h.push_str(&section_open("Attack Paths (Detailed)", "🛤️"));
    
    if results.attack_paths.is_empty() {
        h.push_str("<p class='muted'>No attack paths generated.</p>");
    } else {
        for (i, path) in results.attack_paths.iter().enumerate() {
            h.push_str(&format!("<div class='finding'><h3>Path {}: {}</h3>", i + 1, html_escape(&path.name)));
            h.push_str(&format!("<div class='meta'>Severity: {:?} | Steps: {}</div>", path.severity, path.steps.len()));
            h.push_str("<ol style='margin-top: 10px; padding-left: 20px;'>");
            for step in &path.steps {
                h.push_str(&format!("<li><b>{}</b> — {}</li>", html_escape(&step.title), html_escape(&step.description)));
                if let Some(cmd) = &step.command {
                    h.push_str(&format!("<pre>{}</pre>", html_escape(cmd)));
                }
            }
            h.push_str("</ol></div>");
        }
    }
    h.push_str(&section_close());
    h
}

fn exploitation_recommendations_block(results: &ReconResults) -> String {
    let mut h = String::new();
    h.push_str(&section_open("Exploitation Recommendations", "💥"));
    
    if results.exploitation_recommendations.is_empty() {
        h.push_str("<p class='muted'>No exploitation recommendations.</p>");
    } else {
        for rec in &results.exploitation_recommendations {
            h.push_str(&format!("<div class='finding'><h3>{}</h3>", html_escape(&rec.title)));
            h.push_str(&format!("<div class='meta'>Priority: {} | Risk: {}</div>", rec.priority, html_escape(&rec.risk)));
            h.push_str(&format!("<p>{}</p>", html_escape(&rec.description)));
            h.push_str(&format!("<p><b>Tool:</b> {}</p>", html_escape(&rec.tool)));
            h.push_str(&format!("<pre>{}</pre>", html_escape(&rec.command)));
            h.push_str(&format!("<p><b>Validates:</b> {}</p>", html_escape(&rec.validates)));
            if !rec.evidence.is_empty() {
                h.push_str("<p><b>Evidence:</b></p><ul>");
                for ev in &rec.evidence {
                    h.push_str(&format!("<li>{}</li>", html_escape(ev)));
                }
                h.push_str("</ul>");
            }
            h.push_str("</div>");
        }
    }
    h.push_str(&section_close());
    h
}

fn api_endpoints_block(results: &ReconResults) -> String {
    let mut h = String::new();
    h.push_str(&section_open("API Endpoints Discovered", "🔌"));
    
    if results.api_endpoints.is_empty() {
        h.push_str("<p class='muted'>No API endpoints discovered.</p>");
    } else {
        h.push_str("<table><thead><tr><th>Method</th><th>Path</th><th>Type</th><th>Auth Required</th><th>Parameters</th></tr></thead><tbody>");
        for ep in &results.api_endpoints {
            h.push_str(&format!("<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&ep.method),
                html_escape(&ep.path),
                api_type_label(&ep.api_type),
                if ep.auth_required { "Yes" } else { "No" },
                ep.parameters.iter().map(|p| html_escape(&p.name)).collect::<Vec<_>>().join(", ")
            ));
        }
        h.push_str("</tbody></table>");
    }
    h.push_str(&section_close());
    h
}

fn findings_block(results: &ReconResults) -> String {
    let mut h = String::new();
    h.push_str(&section_open("All Findings", "📋"));
    
    if results.vulns.is_empty() {
        h.push_str("<p class='muted'>No vulnerabilities found.</p>");
    } else {
        h.push_str("<table><thead><tr><th>Severity</th><th>Title</th><th>Affected</th><th>CVE</th><th>Confidence</th><th>Description</th></tr></thead><tbody>");
        for v in &results.vulns {
            h.push_str(&format!("<tr><td><span class='chip' style='background:{}'>{}</span></td><td><b>{}</b></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                sev_color(&v.severity),
                sev_label(&v.severity),
                html_escape(&v.title),
                html_escape(&v.affected),
                v.cve.as_deref().unwrap_or("-"),
                v.confidence,
                html_escape(&v.description)
            ));
        }
        h.push_str("</tbody></table>");
    }
    h.push_str(&section_close());
    h
}

fn cve_references_block(results: &ReconResults) -> String {
    let mut h = String::new();
    h.push_str(&section_open("CVE / Exploit References", "📚"));
    
    if results.cves.is_empty() && results.cve_refs.is_empty() {
        h.push_str("<p class='muted'>No CVE references.</p>");
    } else {
        if !results.cves.is_empty() {
            h.push_str("<h3>CVEs Identified</h3><ul>");
            for cve in &results.cves {
                h.push_str(&format!("<li><code>{}</code> — {}</li>", html_escape(&cve.id), html_escape(&cve.description)));
            }
            h.push_str("</ul>");
        }
        if !results.cve_refs.is_empty() {
            h.push_str("<h3>Exploit References</h3><ul>");
            for r in &results.cve_refs {
                h.push_str(&format!("<li><b>Query:</b> {} — <b>Engine:</b> {}</li>", html_escape(&r.query), html_escape(&r.engine)));
            }
            h.push_str("</ul>");
        }
    }
    h.push_str(&section_close());
    h
}

fn ai_decisions_block(results: &ReconResults) -> String {
    let mut h = String::new();
    h.push_str(&section_open("AI Agent Decisions", "🧠"));
    
    if results.ai_decisions.is_empty() {
        h.push_str("<p class='muted'>No AI decisions recorded (agent offline).</p>");
    } else {
        h.push_str("<ol style='padding-left: 20px;'>");
        for d in &results.ai_decisions {
            h.push_str(&format!("<li style='margin-bottom: 12px;'><b>{}</b> — {}</li>", html_escape(&d.decision), html_escape(&d.rationale)));
            h.push_str(&format!("<div class='meta'>Stage: {}</div>", html_escape(&d.stage)));
        }
        h.push_str("</ol>");
    }
    h.push_str(&section_close());
    h
}

fn pivot_log_block(results: &ReconResults) -> String {
    let mut h = String::new();
    h.push_str(&section_open("Pivot Log", "🔄"));
    
    if results.pivots.is_empty() {
        h.push_str("<p class='muted'>No pivots performed.</p>");
    } else {
        h.push_str("<ol style='padding-left: 20px;'>");
        for p in &results.pivots {
            h.push_str(&format!("<li style='margin-bottom: 8px;'><b>Pivot to:</b> {} (Domain)</li>", html_escape(&p.domain)));
            if let Some(dns) = &p.dns {
                h.push_str(&format!("<div class='meta'>DNS records: {}</div>", dns.records.len()));
            }
            if !p.dorks.is_empty() {
                h.push_str(&format!("<div class='meta'>Dorks: {}</div>", p.dorks.len()));
            }
        }
        h.push_str("</ol>");
    }
    h.push_str(&section_close());
    h
}

fn methodology_block() -> String {
    let mut h = String::new();
    h.push_str(&section_open("Methodology", "📖"));
    h.push_str(r###"
<p>This report was generated by <b>NightCrawler</b>, an autonomous adversary simulation agent that simulates the complete cyber kill chain:</p>
<ol style="padding-left: 20px; margin: 12px 0;">
<li><b>Reconnaissance</b> — Passive/active intelligence gathering, attack surface mapping</li>
<li><b>Initial Access</b> — Exploit validation, credential testing, supply chain analysis</li>
<li><b>Privilege Escalation</b> — Local/remote escalation paths, token abuse</li>
<li><b>Lateral Movement</b> — Pass-the-hash/ticket, application-layer pivoting</li>
<li><b>Persistence</b> — Implant simulation, scheduled tasks, WMI, cloud backdoors</li>
<li><b>Impact</b> — Data staging/exfil simulation, ransomware encryption simulation</li>
</ol>
<p>All findings are evidence-based with confidence ratings. Exploitation is simulated (read-only, proof-of-concept only).</p>
"###);
    h.push_str(&section_close());
    h
}

fn limitations_block() -> String {
    let mut h = String::new();
    h.push_str(&section_open("Limitations", "⚠️"));
    h.push_str(r###"
<ul style="padding-left: 20px;">
<li>Simulation only — no actual exploitation or data exfiltration performed</li>
<li>Passive/active reconnaissance limited to authorized scope</li>
<li>Credential attacks simulated via evidence correlation, not brute force</li>
<li>Cloud/container assessment requires appropriate permissions</li>
<li>Zero-day vulnerabilities not covered (signature-based detection only)</li>
<li>Encrypted traffic analysis limited to certificate metadata</li>
<li>Results represent point-in-time assessment</li>
</ul>
"###);
    h.push_str(&section_close());
    h
}

// =============================================================================
// Data Builder Functions
// =============================================================================

fn compute_risk_score(results: &ReconResults) -> u32 {
    let mut score = 0u32;
    for v in &results.vulns {
        score += match v.severity {
            Severity::Critical => 25,
            Severity::High => 15,
            Severity::Medium => 8,
            Severity::Low => 3,
            Severity::Info => 1,
        };
    }
    // Cap at 100
    score.min(100)
}

#[derive(Serialize)]
struct AttackSurfaceNode {
    id: String,
    label: String,
    kind: String,
    label_full: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cve: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    affected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    degree: usize,
}

#[derive(Serialize)]
struct AttackSurfaceLink {
    source: String,
    target: String,
    #[serde(rename = "type")]
    link_type: String,
}

fn build_attack_surface_nodes(results: &ReconResults) -> Vec<AttackSurfaceNode> {
    let mut nodes = Vec::new();
    
    // Target node
    nodes.push(AttackSurfaceNode {
        id: "target".to_string(),
        label: results.target.input.clone(),
        kind: "target".to_string(),
        label_full: results.target.input.clone(),
        port: None,
        service: None,
        severity: None,
        cve: None,
        affected: None,
        confidence: None,
        description: None,
        evidence: None,
        method: None,
        path: None,
        api_type: None,
        auth_required: None,
        url: None,
        degree: 0,
    });
    
    // Subdomains
    for (i, sub) in results.subdomains.iter().enumerate() {
        nodes.push(AttackSurfaceNode {
            id: format!("sub-{}", i),
            label: sub.name.clone(),
            kind: "subdomain".to_string(),
            label_full: sub.name.clone(),
            port: None,
            service: None,
            severity: None,
            cve: None,
            affected: None,
            confidence: None,
            description: Some(format!("Source: {}", sub.source)),
            evidence: None,
            method: None,
            path: None,
            api_type: None,
            auth_required: None,
            url: Some(format!("http://{}", sub.name)),
            degree: 0,
        });
    }
    
    // Open ports / services
    for p in &results.ports {
        if p.open {
            let kind = match p.port {
                80 | 443 | 8080 | 8443 | 3000 | 5000 | 8000 | 8081 => "web",
                21 | 22 | 23 | 25 | 110 | 143 | 993 | 995 | 465 | 587 => "infra",
                3306 | 5432 | 1433 | 27017 | 6379 | 11211 => "db",
                389 | 636 | 3268 => "ldap",
                445 | 139 => "smb",
                161 | 162 => "snmp",
                22 | 3389 | 5900 | 5901 => "remote",
                _ => "service",
            };
            
            nodes.push(AttackSurfaceNode {
                id: format!("port-{}", p.port),
                label: format!("{}/{}", p.port, p.service),
                kind: kind.to_string(),
                label_full: format!("{} ({}:{})", p.service, p.product.as_deref().unwrap_or("?"), p.version.as_deref().unwrap_or("?")),
                port: Some(p.port),
                service: Some(p.service.clone()),
                severity: None,
                cve: None,
                affected: None,
                confidence: None,
                description: None,
                evidence: None,
                method: None,
                path: None,
                api_type: None,
                auth_required: None,
                url: None,
                degree: 0,
            });
        }
    }
    
    // Vulnerabilities
    for (i, v) in results.vulns.iter().enumerate() {
        nodes.push(AttackSurfaceNode {
            id: format!("vuln-{}", i),
            label: if v.title.len() > 25 { v.title[..22].to_string() + "..." } else { v.title.clone() },
            kind: "vuln".to_string(),
            label_full: v.title.clone(),
            port: None,
            service: None,
            severity: Some(format!("{:?}", v.severity)),
            cve: v.cve.clone(),
            affected: Some(v.affected.clone()),
            confidence: Some(v.confidence.parse().unwrap_or(0)),
            description: Some(v.description.clone()),
            evidence: Some(v.evidence.clone()),
            method: None,
            path: None,
            api_type: None,
            auth_required: None,
            url: None,
            degree: 0,
        });
    }
    
    // API endpoints
    for (i, ep) in results.api_endpoints.iter().enumerate() {
        nodes.push(AttackSurfaceNode {
            id: format!("api-{}", i),
            label: format!("{} {}", ep.method, ep.path),
            kind: "api".to_string(),
            label_full: format!("{} {} ({})", ep.method, ep.path, api_type_label(&ep.api_type)),
            port: None,
            service: None,
            severity: None,
            cve: None,
            affected: None,
            confidence: None,
            description: None,
            evidence: None,
            method: Some(ep.method.clone()),
            path: Some(ep.path.clone()),
            api_type: Some(api_type_label(&ep.api_type).to_string()),
            auth_required: Some(ep.auth_required),
            url: None,
            degree: 0,
        });
    }
    
    nodes
}

fn build_attack_surface_links(results: &ReconResults) -> Vec<AttackSurfaceLink> {
    let mut links = Vec::new();
    
    // Target -> Subdomains
    for i in 0..results.subdomains.len() {
        links.push(AttackSurfaceLink {
            source: "target".to_string(),
            target: format!("sub-{}", i),
            link_type: "recon".to_string(),
        });
    }
    
    // Vulnerabilities -> Affected services
    for (i, v) in results.vulns.iter().enumerate() {
        for p in &results.ports {
            if p.open && v.affected.contains(&p.port.to_string()) {
                links.push(AttackSurfaceLink {
                    source: format!("port-{}", p.port),
                    target: format!("vuln-{}", i),
                    link_type: "exploit".to_string(),
                });
            }
        }
    }
    
    links
}

#[derive(Serialize)]
struct KillChainPhase {
    id: String,
    status: String,
    details: String,
}

fn build_kill_chain_phases(results: &ReconResults) -> Vec<KillChainPhase> {
    let mut phases = Vec::new();
    
    let has_recon = !results.subdomains.is_empty() || !results.ports.is_empty();
    let has_initial = results.vulns.iter().any(|v| matches!(v.severity, Severity::Critical | Severity::High));
    let has_priv = results.attack_paths.iter().any(|p| p.steps.iter().any(|s| s.tool.as_deref().unwrap_or("").to_lowercase().contains("priv") || s.title.to_lowercase().contains("privilege")));
    let has_lateral = results.attack_paths.iter().any(|p| p.steps.iter().any(|s| s.tool.as_deref().unwrap_or("").to_lowercase().contains("lateral") || s.title.to_lowercase().contains("lateral")));
    let has_persist = results.attack_paths.iter().any(|p| p.steps.iter().any(|s| s.tool.as_deref().unwrap_or("").to_lowercase().contains("persist") || s.title.to_lowercase().contains("persist")));
    let has_impact = results.exploitation_recommendations.iter().any(|r| r.title.to_lowercase().contains("impact") || r.title.to_lowercase().contains("data") || r.title.to_lowercase().contains("ransom"));
    
    phases.push(KillChainPhase { id: "recon".to_string(), status: if has_recon { "completed" } else { "pending" }.to_string(), details: format!("{} subdomains, {} open ports", results.subdomains.len(), results.ports.iter().filter(|p| p.open).count()) });
    phases.push(KillChainPhase { id: "initial".to_string(), status: if has_initial { "completed" } else { "pending" }.to_string(), details: format!("{} critical/high vulns", results.vulns.iter().filter(|v| matches!(v.severity, Severity::Critical | Severity::High)).count()) });
    phases.push(KillChainPhase { id: "privilege".to_string(), status: if has_priv { "completed" } else { "pending" }.to_string(), details: "Privilege escalation paths identified".to_string() });
    phases.push(KillChainPhase { id: "lateral".to_string(), status: if has_lateral { "completed" } else { "pending" }.to_string(), details: "Lateral movement paths identified".to_string() });
    phases.push(KillChainPhase { id: "persist".to_string(), status: if has_persist { "completed" } else { "pending" }.to_string(), details: "Persistence mechanisms identified".to_string() });
    phases.push(KillChainPhase { id: "impact".to_string(), status: if has_impact { "completed" } else { "pending" }.to_string(), details: "Impact scenarios simulated".to_string() });
    
    phases
}

#[derive(Serialize)]
struct VulnHeatmapItem {
    asset: String,
    #[serde(rename = "type")]
    vuln_type: String,
    severity: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cve: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<String>,
    count: usize,
}

fn build_vuln_heatmap_data(results: &ReconResults) -> Vec<VulnHeatmapItem> {
    let mut items = Vec::new();
    
    for v in &results.vulns {
        let vuln_type = categorize_vuln(v);
        items.push(VulnHeatmapItem {
            asset: v.affected.clone(),
            vuln_type,
            severity: format!("{:?}", v.severity).to_lowercase(),
            title: v.title.clone(),
            cve: v.cve.clone(),
            evidence: Some(v.evidence.clone()),
            count: 1,
        });
    }
    
    items
}

fn categorize_vuln(v: &VulnFinding) -> String {
    let title = v.title.to_lowercase();
    let desc = v.description.to_lowercase();
    
    if title.contains("sql") || title.contains("sqli") || desc.contains("sql injection") {
        "web".to_string()
    } else if title.contains("xss") || title.contains("cross-site") {
        "web".to_string()
    } else if title.contains("api") || title.contains("rest") || title.contains("graphql") {
        "api".to_string()
    } else if title.contains("ssh") || title.contains("rdp") || title.contains("smb") {
        "infra".to_string()
    } else if title.contains("cred") || title.contains("password") || title.contains("token") || title.contains("key") {
        "credential".to_string()
    } else if title.contains("config") || title.contains("misconfig") || title.contains("exposed") || title.contains("default") {
        "config".to_string()
    } else {
        "web".to_string()
    }
}

#[derive(Serialize)]
struct CredentialMapItem {
    id: String,
    #[serde(rename = "type")]
    cred_type: String,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reused_on: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<String>,
}

fn build_credential_map_data(_results: &ReconResults) -> Vec<CredentialMapItem> {
    // No credentials field in ReconResults
    Vec::new()
}

#[derive(Serialize)]
struct NetworkTopologyData {
    nodes: Vec<NetworkNode>,
    links: Vec<NetworkLink>,
}

#[derive(Serialize)]
struct NetworkNode {
    id: String,
    label: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ports: Option<Vec<String>>,
}

#[derive(Serialize)]
struct NetworkLink {
    source: String,
    target: String,
}

fn build_network_topology_data(results: &ReconResults) -> NetworkTopologyData {
    let mut nodes = Vec::new();
    let mut links = Vec::new();
    
    // Target
    nodes.push(NetworkNode {
        id: "target".to_string(),
        label: results.target.input.clone(),
        kind: "target".to_string(),
        ip: results.target.ip.as_ref().map(|ip| ip.to_string()),
        ports: None,
    });
    
    // Subdomains
    for (i, sub) in results.subdomains.iter().enumerate() {
        let id = format!("sub-{}", i);
        nodes.push(NetworkNode {
            id: id.clone(),
            label: sub.name.clone(),
            kind: "subdomain".to_string(),
            ip: sub.ips.first().cloned(),
            ports: None,
        });
        links.push(NetworkLink { source: "target".to_string(), target: id });
    }
    
    // Services
    for p in &results.ports {
        if p.open {
            let id = format!("svc-{}", p.port);
            nodes.push(NetworkNode {
                id: id.clone(),
                label: format!("{}:{}", p.service, p.port),
                kind: "service".to_string(),
                ip: None,
                ports: Some(vec![p.port.to_string()]),
            });
            if !results.subdomains.is_empty() {
                links.push(NetworkLink { source: "sub-0".to_string(), target: id });
            } else {
                links.push(NetworkLink { source: "target".to_string(), target: id });
            }
        }
    }
    
    NetworkTopologyData { nodes, links }
}

#[derive(Serialize)]
struct CredentialHeatmapItem {
    asset: String,
    #[serde(rename = "type")]
    cred_type: String,
    count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

fn build_credential_heatmap_data(_results: &ReconResults) -> Vec<CredentialHeatmapItem> {
    // No credentials field in ReconResults
    Vec::new()
}

#[derive(Serialize)]
struct VulnTimelineItem {
    timestamp: String,
    title: String,
    phase: String,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

fn build_vuln_timeline_data(results: &ReconResults) -> Vec<VulnTimelineItem> {
    let mut items = Vec::new();
    // Parse started_at as base time
    let base_time = chrono::DateTime::parse_from_rfc3339(&results.meta.started_at).unwrap_or_else(|_| chrono::Utc::now().into());
    
    for (i, v) in results.vulns.iter().enumerate() {
        let phase = match categorize_vuln(v).as_str() {
            "web" | "api" => "recon",
            "credential" => "credential-access",
            "config" => "recon",
            _ => "exploit",
        };
        
        items.push(VulnTimelineItem {
            timestamp: (base_time + chrono::Duration::seconds(i as i64 * 30)).to_rfc3339(),
            title: v.title.clone(),
            phase: phase.to_string(),
            severity: format!("{:?}", v.severity).to_lowercase(),
            details: Some(v.description.clone()),
        });
    }
    
    // Add attack path steps
    for (pi, path) in results.attack_paths.iter().enumerate() {
        for (si, step) in path.steps.iter().enumerate() {
            items.push(VulnTimelineItem {
                timestamp: (base_time + chrono::Duration::seconds((results.vulns.len() * 30 + pi * 10 + si) as i64)).to_rfc3339(),
                title: format!("Path {}: {}", pi + 1, step.title),
                phase: step.tool.as_deref().unwrap_or("exploit").to_string(),
                severity: "medium".to_string(),
                details: Some(step.description.clone()),
            });
        }
    }
    
    items
}

#[derive(Serialize)]
struct MitreHeatmapItem {
    tactic: String,
    technique: String,
    covered: bool,
    partial: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

fn build_mitre_heatmap_data(results: &ReconResults) -> Vec<MitreHeatmapItem> {
    let mut items = Vec::new();
    
    let techniques = vec![
        ("reconnaissance", "T1590", "Active Scanning", results.ports.iter().any(|p| p.open)),
        ("reconnaissance", "T1598", "Phishing for Information", false),
        ("initial-access", "T1190", "Exploit Public-Facing Application", results.vulns.iter().any(|v| matches!(v.severity, Severity::Critical | Severity::High))),
        ("initial-access", "T1078", "Valid Accounts", false), // No credentials field
        ("execution", "T1059", "Command and Scripting Interpreter", results.vulns.iter().any(|v| v.title.to_lowercase().contains("rce") || v.title.to_lowercase().contains("command"))),
        ("persistence", "T1505", "Server Software Component", false),
        ("privilege-escalation", "T1068", "Exploitation for Privilege Escalation", results.attack_paths.iter().any(|p| p.steps.iter().any(|s| s.tool.as_deref().unwrap_or("").to_lowercase().contains("priv") || s.title.to_lowercase().contains("privilege")))),
        ("defense-evasion", "T1070", "Indicator Removal", false),
        ("credential-access", "T1003", "OS Credential Dumping", false), // No credentials field
        ("discovery", "T1087", "Account Discovery", !results.subdomains.is_empty()),
        ("lateral-movement", "T1021", "Remote Services", results.attack_paths.iter().any(|p| p.steps.iter().any(|s| s.tool.as_deref().unwrap_or("").to_lowercase().contains("lateral") || s.title.to_lowercase().contains("lateral")))),
        ("collection", "T1005", "Data from Local System", false),
        ("command-and-control", "T1071", "Application Layer Protocol", !results.api_endpoints.is_empty()),
        ("exfiltration", "T1041", "Exfiltration Over C2 Channel", false),
        ("impact", "T1486", "Data Encrypted for Impact", results.exploitation_recommendations.iter().any(|r| r.title.to_lowercase().contains("ransom"))),
    ];
    
    for (tactic, technique_id, technique_name, covered) in techniques {
        items.push(MitreHeatmapItem {
            tactic: tactic.to_string(),
            technique: format!("{} - {}", technique_id, technique_name),
            covered,
            partial: false,
            details: None,
        });
    }
    
    items
}

#[derive(Serialize)]
struct RemediationItem {
    priority: String,
    title: String,
    asset: String,
    severity: String,
    effort: String,
    action: String,
    description: String,
}

fn build_remediation_data(results: &ReconResults) -> Vec<RemediationItem> {
    let mut items = Vec::new();
    
    // Critical vulns first
    for v in results.vulns.iter().filter(|v| matches!(v.severity, Severity::Critical)) {
        items.push(RemediationItem {
            priority: "critical".to_string(),
            title: v.title.clone(),
            asset: v.affected.clone(),
            severity: "critical".to_string(),
            effort: "High".to_string(),
            action: "Patch immediately / apply workaround".to_string(),
            description: v.description.clone(),
        });
    }
    
    // High vulns
    for v in results.vulns.iter().filter(|v| matches!(v.severity, Severity::High)) {
        items.push(RemediationItem {
            priority: "high".to_string(),
            title: v.title.clone(),
            asset: v.affected.clone(),
            severity: "high".to_string(),
            effort: "Medium".to_string(),
            action: "Patch within 7 days".to_string(),
            description: v.description.clone(),
        });
    }
    
    // Medium vulns
    for v in results.vulns.iter().filter(|v| matches!(v.severity, Severity::Medium)).take(10) {
        items.push(RemediationItem {
            priority: "medium".to_string(),
            title: v.title.clone(),
            asset: v.affected.clone(),
            severity: "medium".to_string(),
            effort: "Medium".to_string(),
            action: "Patch within 30 days".to_string(),
            description: v.description.clone(),
        });
    }
    
    // Misconfigurations
    for v in results.vulns.iter().filter(|v| matches!(v.severity, Severity::Low | Severity::Info) && categorize_vuln(v) == "config").take(5) {
        items.push(RemediationItem {
            priority: "low".to_string(),
            title: v.title.clone(),
            asset: v.affected.clone(),
            severity: "low".to_string(),
            effort: "Low".to_string(),
            action: "Harden configuration".to_string(),
            description: v.description.clone(),
        });
    }
    
    items
}

#[derive(Serialize)]
struct EvidenceItem {
    category: String,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
}

fn build_evidence_data(results: &ReconResults) -> Vec<EvidenceItem> {
    let mut items = Vec::new();
    
    // Port evidence
    for p in &results.ports {
        if p.open {
            items.push(EvidenceItem {
                category: "Port".to_string(),
                content: format!("{}/{} - {} {} {}", p.port, p.service, p.product.as_deref().unwrap_or(""), p.version.as_deref().unwrap_or(""), p.notes.first().map(|s| s.as_str()).unwrap_or("")),
                source: Some("port_scan".to_string()),
            });
        }
    }
    
    // Subdomain evidence
    for s in &results.subdomains {
        items.push(EvidenceItem {
            category: "Subdomain".to_string(),
            content: format!("{} (source: {})", s.name, s.source),
            source: Some("subdomain_enum".to_string()),
        });
    }
    
    // Vulnerability evidence
    for v in &results.vulns {
        items.push(EvidenceItem {
            category: "Vulnerability".to_string(),
            content: format!("{}: {}", v.title, v.evidence),
            source: Some("vuln_scan".to_string()),
        });
    }
    
    // Directory evidence
    for d in &results.subdirs {
        items.push(EvidenceItem {
            category: "Directory".to_string(),
            content: format!("{} (status: {})", d.url, d.status),
            source: Some("dir_enum".to_string()),
        });
    }
    
    // API endpoint evidence
    for ep in &results.api_endpoints {
        items.push(EvidenceItem {
            category: "API".to_string(),
            content: format!("{} {} ({})", ep.method, ep.path, api_type_label(&ep.api_type)),
            source: Some("api_discovery".to_string()),
        });
    }
    
    // AI decisions
    for d in &results.ai_decisions {
        items.push(EvidenceItem {
            category: "AI Decision".to_string(),
            content: format!("{}: {}", d.decision, d.rationale),
            source: Some("ai_agent".to_string()),
        });
    }
    
    items
}

// =============================================================================
// Markdown to HTML (simplified)
// =============================================================================

fn md_to_html(md: &str) -> String {
    let mut html = String::new();
    let mut in_code = false;
    let mut code_buffer = String::new();
    
    for line in md.lines() {
        if line.starts_with("```") {
            if in_code {
                html.push_str(&format!("<pre><code>{}</code></pre>", html_escape(&code_buffer)));
                code_buffer.clear();
                in_code = false;
            } else {
                in_code = true;
            }
        } else if in_code {
            code_buffer.push_str(line);
            code_buffer.push_str("\n");
        } else if line.starts_with("# ") {
            html.push_str(&format!("<h1>{}</h1>", html_escape(&line[2..])));
        } else if line.starts_with("## ") {
            html.push_str(&format!("<h2>{}</h2>", html_escape(&line[3..])));
        } else if line.starts_with("### ") {
            html.push_str(&format!("<h3>{}</h3>", html_escape(&line[4..])));
        } else if line.starts_with("- ") || line.starts_with("* ") {
            html.push_str(&format!("<li>{}</li>", html_escape(&line[2..])));
        } else if line.trim().is_empty() {
            html.push_str("<br>");
        } else {
            html.push_str(&format!("<p>{}</p>", html_escape(line)));
        }
    }
    
    if in_code {
        html.push_str(&format!("<pre><code>{}</code></pre>", html_escape(&code_buffer)));
    }
    
    html
}
