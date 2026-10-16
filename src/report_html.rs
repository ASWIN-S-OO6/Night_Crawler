//! Self-contained graphical HTML report generator.
//!
//! Produces `report.html`: dark-themed, zero external dependencies
//! (inline CSS + hand-rolled SVG charts + SVG entity graph), so the file
//! renders offline in any browser.

use crate::types::{GraphData, ReconResults, Severity};

pub fn html_escape(s: &str) -> String {
    // entity strings are built from char arrays so no raw HTML entities
    // appear in this source file
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

/// Build the complete HTML dashboard for a finished scan.
pub fn build_html(results: &ReconResults) -> String {
    let mut h = String::with_capacity(96 * 1024);
    h.push_str(&header_block(results));
    h.push_str(&stats_block(results));
    h.push_str(&charts_block(results));

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

    // Findings
    h.push_str(&findings_block(results));

    // CVE / exploit references from the CSE
    h.push_str(&cve_block(results));

    // Ports & services
    h.push_str(&ports_block(results));

    // Web + enumeration sections
    h.push_str(&web_block(results));
    h.push_str(&enum_block(results));
    h.push_str(&dns_block(results));
    h.push_str(&osint_block(results));

    // Entity graph
    h.push_str(&section_open("Link Analysis — Entity Graph", "🕸"));
    h.push_str(&svg_graph(&results.graph));
    h.push_str(&section_close());

    // AI decision timeline
    h.push_str(&timeline_block(results));

    h.push_str(&footer_block(results));
    wrap_document(results, h)
}

// ---------------------------------------------------------------------------
// document scaffolding
// ---------------------------------------------------------------------------

fn wrap_document(results: &ReconResults, body: String) -> String {
    let target = html_escape(&results.target.input);
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NightCrawler — {target}</title>
<style>
:root {{
  --bg:#0a0e14; --panel:#111827; --panel2:#0f1520; --border:#1f2b3d;
  --text:#e2e8f0; --muted:#8b9bb4; --accent:#d946ef; --cyan:#22d3ee;
  --green:#34d399; --red:#f87171; --yellow:#fbbf24;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text);
  font:15px/1.55 'Segoe UI',system-ui,-apple-system,sans-serif; }}
.wrap {{ max-width:1180px; margin:0 auto; padding:24px 20px 60px; }}
a {{ color:var(--cyan); text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
.banner {{ background:linear-gradient(120deg,#1b0b23 0%,#0a1a2e 60%,#0a0e14 100%);
  border:1px solid #2c1f3d; border-radius:14px; padding:26px 28px; margin-bottom:22px;
  position:relative; overflow:hidden; }}
.banner h1 {{ margin:0 0 6px; font-size:26px; letter-spacing:.5px;
  background:linear-gradient(90deg,#e879f9,#22d3ee); -webkit-background-clip:text;
  background-clip:text; color:transparent; }}
.banner .sub {{ color:var(--muted); font-size:14px; }}
.banner .meta {{ display:flex; gap:18px; flex-wrap:wrap; margin-top:14px; font-size:13px;
  color:#b7c3d7; }}
.banner .meta b {{ color:#fff; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:22px; }}
.card {{ background:var(--panel); border:1px solid var(--border); border-radius:12px;
  padding:14px 16px; }}
.card .num {{ font-size:26px; font-weight:700; }}
.card .lbl {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:1px; }}
.section {{ background:var(--panel2); border:1px solid var(--border); border-radius:14px;
  padding:20px 22px; margin-bottom:18px; }}
.section>h2 {{ margin:0 0 12px; font-size:18px; color:#cbd5e1;
  border-bottom:1px solid var(--border); padding-bottom:10px; }}
table {{ width:100%; border-collapse:collapse; font-size:13.5px; margin:8px 0; }}
th {{ text-align:left; color:#93a6c1; font-weight:600; padding:8px 10px;
  border-bottom:2px solid var(--border); font-size:12.5px; text-transform:uppercase; letter-spacing:.5px; }}
td {{ padding:7px 10px; border-bottom:1px solid #17202e; vertical-align:top; }}
tr:hover td {{ background:#0d1420; }}
.chip {{ display:inline-block; padding:2px 8px; border-radius:20px; font-size:11px;
  font-weight:700; color:#0a0e14; letter-spacing:.5px; }}
.muted {{ color:var(--muted); }}
.finding {{ background:var(--panel); border:1px solid var(--border); border-left:4px solid #333;
  border-radius:10px; padding:14px 16px; margin:10px 0; }}
.finding h3 {{ margin:0 0 8px; font-size:15.5px; }}
.finding .meta {{ color:var(--muted); font-size:12.5px; margin-bottom:6px; }}
.finding pre {{ background:#0a0e14; border:1px solid #17202e; padding:10px;
  border-radius:8px; overflow-x:auto; font-size:12.5px; }}
code {{ background:#1a2332; padding:1px 5px; border-radius:5px; font-size:12.5px; color:#a5f3fc; }}
details {{ margin:10px 0; }}
details summary {{ cursor:pointer; color:#cbd5e1; font-weight:600; padding:6px 0; }}
.donut-legend span {{ margin-right:14px; font-size:13px; }}
.flex {{ display:flex; gap:26px; flex-wrap:wrap; align-items:center; }}
.bars {{ margin-top:10px; }}
.bar-row {{ display:flex; align-items:center; gap:10px; margin:5px 0; }}
.bar-lbl {{ width:110px; color:var(--muted); font-size:12.5px; text-align:right; }}
.bar-track {{ flex:1; background:#0a0e14; border-radius:6px; height:16px; overflow:hidden; }}
.bar-fill {{ height:100%; border-radius:6px; }}
.foot {{ color:var(--muted); font-size:12px; text-align:center; margin-top:26px; }}
h3.sub {{ color:#e879f9; margin:18px 0 8px; }}
@media (max-width:760px) {{ .banner .meta {{ gap:10px; }} }}
</style>
</head>
<body><div class="wrap">
{body}
</div></body></html>"##,
        target = target,
        body = body
    )
}

fn header_block(results: &ReconResults) -> String {
    let model = results
        .ai_model
        .as_deref()
        .unwrap_or("offline (tools-only)");
    format!(
        r#"<div class="banner">
<h1>🕷 NightCrawler — Reconnaissance Assessment</h1>
<div class="sub">Autonomous agent · governed by the AGENTS.md pentest doctrine</div>
<div class="meta">
  <span>Target: <b>{}</b></span>
  <span>Started: <b>{}</b></span>
  <span>Duration: <b>{}s</b></span>
  <span>Agent model: <b>{}</b></span>
</div>
</div>"#,
        html_escape(&results.target.input),
        html_escape(&results.meta.started_at),
        results.meta.duration_secs,
        html_escape(model),
    )
}

fn stats_block(results: &ReconResults) -> String {
    let open = results.ports.iter().filter(|p| p.open).count();
    let crit = results.vulns.iter().filter(|v| v.severity == Severity::Critical).count();
    let high = results.vulns.iter().filter(|v| v.severity == Severity::High).count();
    let med = results.vulns.iter().filter(|v| v.severity == Severity::Medium).count();
    let cve_refs: usize = results.cve_refs.iter().map(|r| r.results.len()).sum();
    let card = |num: String, lbl: &str, color: &str| {
        format!(
            r#"<div class="card"><div class="num" style="color:{}">{}</div><div class="lbl">{}</div></div>"#,
            color, num, lbl
        )
    };
    format!(
        "{}{}{}{}{}{}{}{}",
        card(open.to_string(), "open ports", "#22d3ee"),
        card(results.subdomains.len().to_string(), "subdomains", "#34d399"),
        card(results.subdirs.len().to_string(), "web paths", "#34d399"),
        card(crit.to_string(), "critical", "#ef4444"),
        card(high.to_string(), "high", "#f97316"),
        card(med.to_string(), "medium", "#fbbf24"),
        card(cve_refs.to_string(), "cve refs (CSE)", "#d946ef"),
        card(results.graph.nodes.len().to_string(), "graph entities", "#8b9bb4"),
    )
}

// ---------------------------------------------------------------------------
// charts
// ---------------------------------------------------------------------------

fn charts_block(results: &ReconResults) -> String {
    let mut crit = 0;
    let mut high = 0;
    let mut med = 0;
    let mut low = 0;
    let mut info = 0;
    for v in &results.vulns {
        match v.severity {
            Severity::Critical => crit += 1,
            Severity::High => high += 1,
            Severity::Medium => med += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }
    let segs = [
        ("Critical", crit, "#ef4444"),
        ("High", high, "#f97316"),
        ("Medium", med, "#fbbf24"),
        ("Low", low, "#22d3ee"),
        ("Info", info, "#475569"),
    ];
    let total: usize = segs.iter().map(|s| s.1).sum();
    let (donut_svg, legend) = svg_donut(&segs, total);

    // category bar chart from the phase/findings mix
    let mut cats: Vec<(String, usize)> = Vec::new();
    for v in &results.vulns {
        let k = v.title.split('—').next().unwrap_or(&v.title).trim().to_string();
        let key = if k.len() > 22 { format!("{}…", k.chars().take(21).collect::<String>()) } else { k };
        if let Some(e) = cats.iter_mut().find(|(k2, _)| *k2 == key) {
            e.1 += 1;
        } else {
            cats.push((key, 1));
        }
    }
    cats.sort_by(|a, b| b.1.cmp(&a.1));
    cats.truncate(8);
    let maxc = cats.iter().map(|c| c.1).max().unwrap_or(1);
    let mut bars = String::new();
    for (name, n) in &cats {
        bars += &format!(
            r##"<div class="bar-row"><div class="bar-lbl">{}</div><div class="bar-track"><div class="bar-fill" style="width:{}%;background:linear-gradient(90deg,#d946ef,#8b5cf6)"></div></div><div class="muted">{}</div></div>"##,
            html_escape(name),
            (n * 100 / maxc),
            n
        );
    }

    format!(
        r#"<div class="section"><h2>📊 Findings Overview</h2>
<div class="flex">
  <div>{}</div>
  <div class="donut-legend">{}</div>
  <div style="flex:1;min-width:280px"><h3 class="sub">Top finding areas</h3><div class="bars">{}</div></div>
</div></div>"#,
        donut_svg, legend, bars
    )
}

fn svg_donut(segs: &[(&str, usize, &str)], total: usize) -> (String, String) {
    let r = 70f64;
    let c = 2.0 * std::f64::consts::PI * r;
    let mut offset = 0.0;
    let mut svg = format!(
        r#"<svg width="190" height="190" viewBox="0 0 190 190"><g transform="translate(95,95) rotate(-90)">"#
    );
    if total == 0 {
        svg += &format!(
            r##"<circle r="{}" fill="none" stroke="#1f2b3d" stroke-width="26"/>"##,
            r
        );
    }
    for (name, n, color) in segs {
        if *n == 0 {
            continue;
        }
        let len = c * (*n as f64) / total as f64;
        svg += &format!(
            r#"<circle r="{r}" fill="none" stroke="{color}" stroke-width="26" stroke-dasharray="{len:.1} {rest:.1}" stroke-dashoffset="-{offset:.1}"><title>{name}: {n}</title></circle>"#,
            r = r,
            color = color,
            len = len,
            rest = c - len,
            offset = offset,
            name = name,
            n = n
        );
        offset += len;
    }
    svg += &format!(
        r##"</g><text x="95" y="90" text-anchor="middle" fill="#e2e8f0" font-size="26" font-weight="700">{}</text><text x="95" y="110" text-anchor="middle" fill="#8b9bb4" font-size="11">VULN FINDINGS</text></svg>"##,
        total
    );
    let legend: String = segs
        .iter()
        .map(|(name, n, color)| {
            format!(
                r#"<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:{};margin-right:5px"></span>{} ({})</span>"#,
                color, name, n
            )
        })
        .collect();
    (svg, legend)
}

// ---------------------------------------------------------------------------
// entity graph (layered SVG)
// ---------------------------------------------------------------------------

fn svg_graph(graph: &GraphData) -> String {
    let kind_col = |k: &str| match k {
        "domain" | "subdomain" => 0,
        "org" | "email" | "user" | "host" => 1,
        "ip" => 2,
        "service" => 3,
        _ => 4,
    };
    let node_color = |k: &str| match k {
        "domain" | "subdomain" => "#4c6ef5",
        "org" => "#9c36b5",
        "email" => "#d6336c",
        "ip" => "#12b886",
        "service" => "#e8590c",
        "user" | "host" => "#f59f00",
        _ => "#3b5bdb",
    };

    // cap
    let max_nodes = 80usize;
    let nodes: Vec<&crate::types::GNode> = if graph.nodes.len() > max_nodes {
        // keep highest-degree nodes
        let mut deg: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
        for e in &graph.edges {
            *deg.entry(e.from).or_insert(0) += 1;
            *deg.entry(e.to).or_insert(0) += 1;
        }
        let mut ranked: Vec<&crate::types::GNode> = graph.nodes.iter().collect();
        ranked.sort_by_key(|n| std::cmp::Reverse(deg.get(&n.id).copied().unwrap_or(0)));
        ranked.into_iter().take(max_nodes).collect()
    } else {
        graph.nodes.iter().collect()
    };
    let keep: std::collections::HashSet<usize> = nodes.iter().map(|n| n.id).collect();

    // column layout
    let col_w = 250.0;
    let node_h = 30.0;
    let gap_y = 14.0;
    let mut col_counts = [0usize; 5];
    let mut pos: std::collections::HashMap<usize, (f64, f64)> = std::collections::HashMap::new();
    for n in &nodes {
        let col = kind_col(&n.kind);
        let x = 24.0 + col as f64 * col_w;
        let y = 24.0 + col_counts[col] as f64 * (node_h + gap_y);
        col_counts[col] += 1;
        pos.insert(n.id, (x, y));
    }
    let height = col_counts.iter().copied().max().unwrap_or(1) as f64 * (node_h + gap_y) + 40.0;
    let width = 5.0 * col_w + 40.0;

    let mut svg = format!(
        r##"<svg viewBox="0 0 {w} {h}" width="100%" style="max-height:{h}px;background:#0a0e14;border:1px solid #17202e;border-radius:10px">"##,
        w = width,
        h = height
    );
    // edges first
    let mut drawn = 0;
    for e in &graph.edges {
        if drawn > 200 {
            break;
        }
        if let (Some((x1, y1)), Some((x2, y2))) = (pos.get(&e.from), pos.get(&e.to)) {
            let mx = (x1 + x2) / 2.0;
            svg += &format!(
                r##"<path d="M {x1e} {y1e} C {mx} {y1e}, {mx} {y2e}, {x2e} {y2e}" fill="none" stroke="#2b3a52" stroke-width="1.3"><title>{lbl}</title></path>"##,
                x1e = x1 + 200.0,
                y1e = y1 + node_h / 2.0,
                x2e = x2,
                y2e = y2 + node_h / 2.0,
                mx = mx + 100.0,
                lbl = html_escape(&e.label)
            );
            drawn += 1;
        }
    }
    // nodes
    for n in &nodes {
        let (x, y) = pos[&n.id];
        let color = node_color(&n.kind);
        let label: String = n.label.chars().take(26).collect();
        let tx = x + 10.0;
        let ty = y + 19.0;
        svg += &format!(
            r##"<g><rect x="{x}" y="{y}" width="200" height="{nh}" rx="7" fill="#111826" stroke="{color}" stroke-width="1.4"/>
<text x="{tx}" y="{ty}" font-size="12" fill="#dbe4f0">{lbl} <tspan fill="#5b6b82" font-size="10">[{kind}]</tspan></text></g>"##,
            x = x,
            y = y,
            nh = node_h,
            color = color,
            tx = tx,
            ty = ty,
            lbl = html_escape(&label),
            kind = html_escape(&n.kind)
        );
    }
    svg += "</svg>";
    if graph.nodes.len() > max_nodes {
        svg += &format!(
            "<p class='muted'>Graph truncated to the {} most connected of {} entities.</p>",
            max_nodes,
            graph.nodes.len()
        );
    }
    svg
}

// ---------------------------------------------------------------------------
// data sections
// ---------------------------------------------------------------------------

fn section_open(title: &str, icon: &str) -> String {
    format!(
        r#"<div class="section"><h2>{} {}</h2>"#,
        icon, title
    )
}

fn section_close() -> &'static str {
    "</div>"
}

/// Collapsible appendix section (raw tool evidence).
fn appendix_open(title: &str, icon: &str, open: bool) -> String {
    format!(
        r#"<details class="section"{}><summary style="font-size:17px;color:#cbd5e1">{} {} — <span class="muted">evidence</span></summary>"#,
        if open { " open" } else { "" },
        icon,
        title
    )
}

fn appendix_close() -> &'static str {
    "</details>"
}

fn findings_block(results: &ReconResults) -> String {
    let mut h = section_open("Vulnerability Findings", "🎯");
    if results.vulns.is_empty() {
        h += "<p class='muted'>No version-matched CVEs or exposure findings from the local database.</p>";
    }
    for v in &results.vulns {
        h += &format!(
            r#"<div class="finding" style="border-left-color:{}">
<h3><span class="chip" style="background:{}">{}</span> {} {}</h3>
<div class="meta"><b>Affected:</b> {} · <b>Confidence:</b> {}</div>
<div>{}</div>
<div class="meta" style="margin-top:6px"><b>Evidence:</b> <code>{}</code></div>
{}{}</div>"#,
            sev_color(&v.severity),
            sev_color(&v.severity),
            sev_label(&v.severity),
            html_escape(&v.title),
            v.cve.as_deref().map(|c| format!("({})", c)).unwrap_or_default(),
            html_escape(&v.affected),
            html_escape(&v.confidence),
            html_escape(&v.description),
            html_escape(&v.evidence),
            v.reference
                .as_deref()
                .map(|r| format!("<div class='meta'><a href=\"{}\" target=\"_blank\">reference ↗</a></div>", html_escape(r)))
                .unwrap_or_default(),
            if v.confidence == "LIKELY" {
                "<div class='meta'>Validate before exploiting — a version match alone is not proof (doctrine §5).</div>".to_string()
            } else {
                String::new()
            }
        );
    }
    h + section_close()
}

fn cve_block(results: &ReconResults) -> String {
    if results.cves.is_empty() && results.cve_refs.is_empty() {
        return String::new();
    }
    let mut h = section_open("CVE Map — NVD database (OpenVAS-style matching)", "🧨");
    if !results.cves.is_empty() {
        h += "<p class='muted'>Product/version pairs from the scan, matched against the NVD CVE database — the same source Greenbone/OpenVAS correlates against. Sorted by CVSS.</p><table><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Product</th><th>Description</th></tr>";
        for e in results.cves.iter().take(40) {
            if e.id == "NVD-UNAVAILABLE" {
                h += &format!(
                    "<tr><td colspan='5' style='color:#ef4444'>{}</td></tr>",
                    html_escape(&e.description)
                );
                continue;
            }
            let color = if e.score >= 9.0 {
                "#ef4444"
            } else if e.score >= 7.0 {
                "#f97316"
            } else if e.score >= 4.0 {
                "#fbbf24"
            } else {
                "#22d3ee"
            };
            h += &format!(
                "<tr><td><a href=\"{}\" target=\"_blank\"><b>{}</b></a></td><td><span class='chip' style='background:{}'>{:.1}</span></td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                html_escape(&e.url),
                html_escape(&e.id),
                color,
                e.score,
                html_escape(&e.severity),
                html_escape(&e.product),
                html_escape(&e.description)
            );
        }
        h += "</table>";
    }
    if !results.cve_refs.is_empty() {
        h += "<h3 class='sub'>Exploit references (Google CSE)</h3>";
        for r in &results.cve_refs {
            if let Some(e) = &r.error {
                h += &format!(
                    "<p class='muted'>{} — <span style='color:#ef4444'>{}</span></p>",
                    html_escape(&r.query),
                    html_escape(e)
                );
            } else if r.results.is_empty() {
                h += &format!("<p class='muted'>{}</p>", html_escape(&r.query));
            } else {
                h += &format!("<p><b>{}</b></p><ul>", html_escape(&r.query.trim_start_matches("cve: ")));
                for link in r.results.iter().take(6) {
                    h += &format!(
                        "<li><a href=\"{}\" target=\"_blank\">{}</a></li>",
                        html_escape(link),
                        html_escape(link)
                    );
                }
                h += "</ul>";
            }
        }
    } else {
        h += "<p class='muted'>Set <code>GOOGLE_CSE_KEY</code> to also collect exploit-DB style references via the Programmable Search Engine (cx e724058a30fea47fa).</p>";
    }
    h + section_close()
}

fn ports_block(results: &ReconResults) -> String {
    let mut h = appendix_open("Ports & Services", "🔌", true);
    if results.ports.is_empty() {
        h += "<p class='muted'>No open TCP ports detected.</p>";
        return h + section_close();
    }
    h += "<table><tr><th>Port</th><th>Proto</th><th>Service</th><th>Product</th><th>Version</th><th>Banner</th></tr>";
    for p in &results.ports {
        h += &format!(
            "<tr><td><b>{}</b></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            p.port,
            html_escape(&p.proto),
            html_escape(&p.service),
            html_escape(p.product.as_deref().unwrap_or("—")),
            html_escape(p.version.as_deref().unwrap_or("—")),
            html_escape(p.banner.as_deref().unwrap_or("—"))
        );
    }
    h += "</table>";
    h + appendix_close()
}

fn web_block(results: &ReconResults) -> String {
    if results.http.is_empty() && results.subdirs.is_empty() {
        return String::new();
    }
    let mut h = appendix_open("Web Applications", "🌐", true);
    for info in &results.http {
        h += &format!(
            "<h3 class='sub'>{}</h3><p class='muted'>status {} · server <code>{}</code> · title <i>{}</i></p>",
            html_escape(&info.url),
            info.status,
            html_escape(info.server.as_deref().unwrap_or("—")),
            html_escape(info.title.as_deref().unwrap_or("—"))
        );
        let missing: Vec<String> = info
            .security_headers
            .iter()
            .filter(|(_, ok)| !ok)
            .map(|(k, _)| k.clone())
            .collect();
        if !missing.is_empty() {
            h += &format!(
                "<p class='muted'>missing security headers: {}</p>",
                html_escape(&missing.join(", "))
            );
        }
        if let Some(issuer) = &info.tls_issuer {
            h += &format!(
                "<p class='muted'>TLS: issuer <code>{}</code> · subject <code>{}</code> · expires {}</p>",
                html_escape(issuer),
                html_escape(info.tls_subject.as_deref().unwrap_or("—")),
                html_escape(info.tls_valid_until.as_deref().unwrap_or("—"))
            );
        }
    }
    if !results.subdirs.is_empty() {
        h += &format!("<details open><summary>Discovered web paths ({})</summary><table>", results.subdirs.len());
        h += "<tr><th>URL</th><th>Status</th><th>Length</th><th>note</th></tr>";
        for d in results.subdirs.iter().take(250) {
            h += &format!(
                "<tr><td><a href=\"{}\" target=\"_blank\">{}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&d.url),
                html_escape(&d.url),
                d.status,
                d.length,
                html_escape(&d.note)
            );
        }
        h += "</table></details>";
    }
    h + appendix_close()
}

fn enum_block(results: &ReconResults) -> String {
    let mut any = false;
    let mut h = String::new();
    if let Some(snmp) = &results.snmp {
        any = true;
        h += &format!(
            "<h3 class='sub'>SNMP</h3><p>community <code>{}</code> ({}) · sysName <b>{}</b> · vendor <i>{}</i> · {} varbinds walked</p><p class='muted'>{}</p>",
            html_escape(&snmp.community),
            html_escape(&snmp.version),
            html_escape(snmp.sysname.as_deref().unwrap_or("—")),
            html_escape(snmp.vendor_guess.as_deref().unwrap_or("—")),
            snmp.varbind_count,
            html_escape(snmp.sysdescr.as_deref().unwrap_or(""))
        );
    }
    if let Some(ldap) = &results.ldap {
        any = true;
        h += &format!(
            "<h3 class='sub'>LDAP</h3><p>{} anonymous bind · {} users · {} groups · {} computers · context <code>{}</code></p>",
            if ldap.anonymous_bind { "ALLOWED" } else { "denied" },
            ldap.users.len(),
            ldap.groups.len(),
            ldap.computers.len(),
            html_escape(ldap.naming_context.as_deref().unwrap_or("—"))
        );
        if !ldap.users.is_empty() {
            h += &format!(
                "<details><summary>users ({})</summary><p class='muted'>{}</p></details>",
                ldap.users.len(),
                html_escape(&ldap.users.join(", "))
            );
        }
    }
    if let Some(nb) = &results.netbios {
        any = true;
        h += &format!("<h3 class='sub'>NetBIOS</h3><p>MAC <code>{}</code></p><ul>", html_escape(&nb.mac_address));
        for (name, svc) in nb.names.iter().take(12) {
            h += &format!("<li><b>{}</b> — {}</li>", html_escape(name), html_escape(svc));
        }
        h += "</ul>";
    }
    if let Some(smb) = &results.smb {
        any = true;
        h += &format!(
            "<h3 class='sub'>SMB</h3><p>tools: {} · shares: {} · users: {}</p>",
            html_escape(&smb.tools_available.join(", ")),
            smb.shares.len(),
            smb.users.len()
        );
    }
    if let Some(w) = &results.whois {
        any = true;
        h += &format!(
            "<h3 class='sub'>WHOIS</h3><p class='muted'>registrar <b>{}</b> · created {} · expires {} · org <i>{}</i></p>",
            html_escape(w.registrar.as_deref().unwrap_or("—")),
            html_escape(w.created.as_deref().unwrap_or("—")),
            html_escape(w.expires.as_deref().unwrap_or("—")),
            html_escape(w.org.as_deref().unwrap_or("—"))
        );
    }
    if any {
        format!("<details class=\"section\" open><summary style=\"font-size:17px;color:#cbd5e1\">🛰 Enumeration Results — <span class=\"muted\">evidence</span></summary>{}</details>", h)
    } else {
        String::new()
    }
}

fn dns_block(results: &ReconResults) -> String {
    let dns = match &results.dns {
        Some(d) => d,
        None => return String::new(),
    };
    let mut h = appendix_open("DNS & Subdomains", "🗺", false);
    if dns.axfr_success {
        h += "<p><b style='color:var(--red)'>Zone transfer SUCCEEDED</b> — the entire zone leaked:</p><ul>";
        for r in dns.axfr_records.iter().take(40) {
            h += &format!(
                "<li>{} <b>{}</b> → {}</li>",
                html_escape(&r.rtype),
                html_escape(&r.name),
                html_escape(&r.value)
            );
        }
        h += "</ul>";
    }
    h += &format!(
        "<details><summary>DNS records ({})</summary><table><tr><th>Type</th><th>Name</th><th>Value</th></tr>",
        dns.records.len()
    );
    for r in dns.records.iter().take(120) {
        h += &format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&r.rtype),
            html_escape(&r.name),
            html_escape(&r.value)
        );
    }
    h += "</table></details>";
    if !results.subdomains.is_empty() {
        h += &format!(
            "<details><summary>Subdomains ({})</summary><table><tr><th>Subdomain</th><th>IPs</th><th>Source</th></tr>",
            results.subdomains.len()
        );
        for s in results.subdomains.iter().take(200) {
            h += &format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&s.name),
                html_escape(&s.ips.join(", ")),
                html_escape(&s.source)
            );
        }
        h += "</table></details>";
    }
    for p in &results.pivots {
        h += &format!(
            "<details><summary>Pivot domain: {}</summary><p class='muted'>DNS: {} records · dorks: {} hits</p></details>",
            html_escape(&p.domain),
            p.dns.as_ref().map(|d| d.records.len()).unwrap_or(0),
            p.dorks.iter().map(|d| d.results.len()).sum::<usize>()
        );
    }
    h + appendix_close()
}

fn osint_block(results: &ReconResults) -> String {
    if results.dorks.is_empty() {
        return String::new();
    }
    let mut h = appendix_open("OSINT Dorking", "🔎", false);
    for d in &results.dorks {
        if let Some(e) = &d.error {
            h += &format!(
                "<p class='muted'><code>{}</code> ({}) — <span style='color:var(--red)'>{}</span></p>",
                html_escape(&d.query),
                html_escape(&d.engine),
                html_escape(e)
            );
        } else if d.results.is_empty() {
            h += &format!(
                "<p class='muted'><code>{}</code> ({}) — no results</p>",
                html_escape(&d.query),
                html_escape(&d.engine)
            );
        } else {
            h += &format!(
                "<p><code>{}</code> <span class='chip' style='background:var(--green)'>{}</span></p><ul>",
                html_escape(&d.query),
                d.results.len()
            );
            for r in d.results.iter().take(6) {
                h += &format!(
                    "<li><a href=\"{}\" target=\"_blank\">{}</a></li>",
                    html_escape(r),
                    html_escape(r)
                );
            }
            h += "</ul>";
        }
    }
    h + appendix_close()
}

fn timeline_block(results: &ReconResults) -> String {
    if results.ai_decisions.is_empty() {
        return String::new();
    }
    let mut h = section_open("NightCrawler Decision Timeline", "🧭");
    h += "<table><tr><th>Stage</th><th>Decision</th><th>Rationale</th></tr>";
    for d in &results.ai_decisions {
        h += &format!(
            "<tr><td><code>{}</code></td><td><b>{}</b></td><td class='muted'>{}</td></tr>",
            html_escape(&d.stage),
            html_escape(&d.decision),
            html_escape(&d.rationale)
        );
    }
    h += "</table>";
    h + section_close()
}

fn footer_block(results: &ReconResults) -> String {
    format!(
        "<div class='foot'>Generated by Night Crawler {} · {} phases recorded · Only use against systems you are authorized to test.</div>",
        html_escape(&results.meta.version),
        results.phases.len()
    )
}

// ---------------------------------------------------------------------------
// mini markdown → HTML (for the NightCrawler-written analysis)
// ---------------------------------------------------------------------------

/// Small, dependency-free markdown renderer for the agent's report:
/// headings, bold/italic, inline code, fenced code, links, lists,
/// pipe tables, paragraphs.
pub fn md_to_html(md: &str) -> String {
    let esc = html_escape;
    let inline = |s: &str| -> String {
        let mut out = esc(s);
        // links [text](url)
        let re = regex::Regex::new(r"\[([^\]]+)\]\(([^)\s]+)\)").unwrap();
        out = re
            .replace_all(&out, "<a href=\"$2\" target=\"_blank\">$1</a>")
            .to_string();
        // bold
        let re = regex::Regex::new(r"\*\*([^*]+)\*\*").unwrap();
        out = re.replace_all(&out, "<b>$1</b>").to_string();
        // inline code
        let re = regex::Regex::new(r"`([^`]+)`").unwrap();
        out = re.replace_all(&out, "<code>$1</code>").to_string();
        out
    };

    let mut html = String::new();
    let lines: Vec<&str> = md.lines().collect();
    let mut i = 0;
    let mut list_open = false;
    while i < lines.len() {
        let line = lines[i].trim();

        // fenced code
        if line.starts_with("```") {
            let mut code = String::new();
            i += 1;
            while i < lines.len() && !lines[i].trim_start().starts_with("```") {
                code.push_str(lines[i]);
                code.push('\n');
                i += 1;
            }
            i += 1;
            html += &format!("<pre><code>{}</code></pre>", esc(&code));
            continue;
        }
        // table
        if line.starts_with('|') && i + 1 < lines.len() && lines[i + 1].trim().starts_with("|--") == false && lines[i+1].contains("--") && lines[i+1].starts_with('|') {
            // header | separator | rows
            let mut rows: Vec<String> = Vec::new();
            let hdr: Vec<String> = line.trim_matches('|').split('|').map(|c| c.trim().to_string()).collect();
            let mut j = i + 2;
            while j < lines.len() && lines[j].trim_start().starts_with('|') {
                let cells: Vec<String> = lines[j].trim().trim_matches('|').split('|').map(|c| c.trim().to_string()).collect();
                rows.push(cells.join("\u{1}")); // cell separator
                j += 1;
            }
            html += "<table><tr>";
            for hcell in &hdr {
                html += &format!("<th>{}</th>", inline(hcell));
            }
            html += "</tr>";
            for r in rows {
                html += "<tr>";
                for cell in r.split('\u{1}') {
                    html += &format!("<td>{}</td>", inline(cell));
                }
                html += "</tr>";
            }
            html += "</table>";
            i = j;
            continue;
        }
        // headings
        if let Some(rest) = line.strip_prefix("### ") {
            if list_open { html += "</ul>"; list_open = false; }
            html += &format!("<h3 class='sub'>{}</h3>", inline(rest));
            i += 1;
            continue;
        }
        if let Some(rest) = line.strip_prefix("## ") {
            if list_open { html += "</ul>"; list_open = false; }
            html += &format!("<h2 style='color:#e879f9'>{}</h2>", inline(rest));
            i += 1;
            continue;
        }
        if let Some(rest) = line.strip_prefix("# ") {
            if list_open { html += "</ul>"; list_open = false; }
            html += &format!("<h2>{}</h2>", inline(rest));
            i += 1;
            continue;
        }
        // lists
        if line.starts_with("- ") || line.starts_with("* ") {
            if !list_open {
                html += "<ul>";
                list_open = true;
            }
            html += &format!("<li>{}</li>", inline(&line[2..]));
            i += 1;
            continue;
        }
        if let Some(n) = line.chars().next() {
            if n.is_ascii_digit() && line[1..].starts_with(". ") || (line.len() > 1 && line[..2].chars().all(|c| c.is_ascii_digit()) && line[2..].starts_with(". ")) {
                if !list_open {
                    html += "<ul style='list-style:disc'>";
                    list_open = true;
                }
                let item = line.split_once(". ").map(|x| x.1).unwrap_or(line);
                html += &format!("<li>{}</li>", inline(item));
                i += 1;
                continue;
            }
        }
        // blank
        if line.is_empty() {
            if list_open {
                html += "</ul>";
                list_open = false;
            }
            i += 1;
            continue;
        }
        // paragraph
        if list_open {
            html += "</ul>";
            list_open = false;
        }
        html += &format!("<p>{}</p>", inline(line));
        i += 1;
    }
    if list_open {
        html += "</ul>";
    }
    html
}
