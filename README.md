# Night Crawler 🕷

**A fully autonomous, AI-driven reconnaissance agent** written in Rust.

Launch it, connect your NVIDIA NIM provider once, type a target — and stop
making decisions. **NightCrawler**, the embedded agent (governed by the
`AGENTS.md` pentest doctrine), thinks like an offensive-security
professional: it chooses the port strategy, selects enumeration modules,
chains follow-up tasks from combined evidence, maps CVEs, and writes a
**graphical HTML assessment report** with attack paths and concrete
exploitation recommendations.

> Only use against systems you are authorized to test.

---

## Quick start

```bash
cargo build --release
./target/release/night-crawler          # setup wizard (first run)
```

```
┌ 🕷 NIGHT CRAWLER — SETUP ───────────────────────────────┐
│      1 PROVIDER → 2 TARGET → 3 MODEL                   │
│ Step 1 — NVIDIA provider: key or config file:         │
│  > nvapi-xxxx…                                         │
│  ⠋ Connecting…                                         │
│  ✔ chat verified against z-ai/glm-5.3-flash            │
│ Step 2 — Target (IP address or domain):                │
│  > scanme.nmap.org                                     │
│  ✔ saved agent: z-ai/glm-5.3-flash                     │
│ Step 3 — pick model → Enter: start scan                │
└────────────────────────────────────────────────────────┘
```

- **First run**: provider key → target → model → the setup is **saved** to
  `~/.config/nightcrawler/provider.toml`.
- **Every later launch**: only asks for the **target**. Press `m` to pick a
  different model, `c` to re-enter the provider, or run `--setup` to redo.
- Flag-driven use also works: `night-crawler <ip|domain> --api-key …`.

## What NightCrawler does (autonomously)

| Stage | What happens |
|---|---|
| 1. Resolve | IP→domain via PTR + TLS cert SANs; domain→IP via DNS + ping |
| 2. Port strategy | **The model decides**: top / full 65535 / custom ranges, biased toward maximum coverage |
| 3. Port scan | Async TCP connect scan with live progress gauge |
| 4. Fingerprinting | Banner grabbing, product/version extraction (SSH, Apache, nginx, ProFTPD, MySQL, IIS, …) |
| 5. Vulnerability matching | Local CVE database with **CONFIRMED / LIKELY / POSSIBLE** confidence levels (doctrine §5) |
| 6. CVE mapping | **OpenVAS/Greenbone-style engine**: product→CPE identification → NVD CVE database query → client-side version-range verification → CVSS-ranked results; keyword + CIRCL fallbacks, plus Google CSE (`cx e724058a30fea47fa`) exploit references |
| 7. Planning | The model selects which modules run (SNMP/LDAP/SMB/dirs/subdomains/dorking) |
| 8. Recon modules | DNS + AXFR zone transfer, subdomains (crt.sh + brute), web directories, SNMP walk, LDAP, NetBIOS/SMB, WHOIS, dorking |
| 9. Follow-up | The model reviews **combined evidence** and chains extra tasks: `extend_dirs`, `probe_web_roots`, `pivot_domains`, `rescan_ports` — up to 3 rounds, bounded & validated |
| 10. Link analysis | Maltego-style entity graph (domains→IPs→services→URLs) |
| 11. Report | The model writes the doctrine-format assessment; rendered into a **graphical HTML dashboard** |

## The graphical HTML report

Every scan writes `./reports/nightcrawler_<target>_<timestamp>/`:

| File | Contents |
|---|---|
| **`report.html`** | Self-contained graphical dashboard: stat cards, severity donut chart, findings-by-area bars, severity-colored finding cards with confidence + evidence, ports/services table, web/enum sections, dork + CVE reference links, **SVG entity graph**, NightCrawler decision timeline, and the full AI analysis (Attack Paths, **Exploitation Recommendations**, How to Start the Attack). Zero external dependencies — opens offline in any browser. |
| `report.md` | Same content as Markdown |
| `findings.json` | Complete machine-readable results |
| `link_analysis.mmd` / `.json` | Mermaid graph + graph data |

## Connecting the providers

### NVIDIA NIM (the agent)

Accepted at setup: raw `nvapi-…` key · TOML/JSON/env-style config file (see
`nvidia.example.toml`) · `NVIDIA_API_KEY` env.

The tool **finds a model that actually works with your key**: your config's
model is tried first; if it's EOL or unavailable it auto-selects the best
working chat model from your account (preference: GLM-flash → GLM →
Gemma-4 → Nemotron → Kimi → GPT-OSS → Qwen → Llama), verified with a live
chat ping. Reasoning models (GLM/GPT-OSS `reasoning_content`) are handled
natively. Free-tier flakiness (404 function routing, hangs) is absorbed by
retry passes, and the UI shows the provider's exact error when anything
fails — the scan then degrades to evidence-based defaults instead of dying.

### Google Programmable Search Engine (dorking + CVE mapping)

Dorking and online CVE mapping run through your Programmable Search Engine:

```bash
export GOOGLE_CSE_KEY="your-google-api-key"     # free: 100 queries/day
```

- Engine ID is built in: `cx = e724058a30fea47fa` (override with
  `google_cse_cx` in `nightcrawler.toml` if you build your own).
- The CSE layer adds exploit-DB style references on top of the NVD engine —
  CVE identification itself runs against the NVD database (no key needed).
- Without a key, dorking falls back to DuckDuckGo and CVE mapping is
  skipped (noted in the report).
- Create a key at
  [developers.google.com/custom-search/v1/overview](https://developers.google.com/custom-search/v1/overview).

## How the agent thinks — `AGENTS.md`

The doctrine (embedded into every model call via `include_str!`) makes the
agent behave like a professional:

- **Authorization & scope** — only the provided target, its subdomains, and
  same-registrable-domain pivots
- **Lifecycle** — scope → recon → enumeration → vuln discovery → validation → evidence → report
- **Adaptive execution** — `ACTION → RESULT → ANALYSIS → DECISION`; never
  run modules the evidence doesn't support
- **Confidence levels** — CONFIRMED (behaviorally verified) / LIKELY
  (version-CVE match) / POSSIBLE (exposure) / UNCONFIRMED
- **Evidence discipline** — never invent ports, versions, CVEs, or results
- **Stop conditions** — finish when the evidence answers the objective
- **Reporting** — per finding: The Problem, **How to Start the Attack**
  (concrete commands), Impact, Remediation; then chained **Attack Paths**
  and an ordered **Exploitation Recommendations** action list

Every model decision returns strict JSON from a fixed action menu, is
validated before execution, and falls back to evidence-based defaults — the
model cannot hallucinate capabilities.

## CLI reference

```
night-crawler [OPTIONS] [TARGET]

  <TARGET>            IP or domain (omit → setup wizard)
  -p, --ports <SPEC>  override the AI's port strategy ("top"|"full"|"1-1024,3306")
  -k, --api-key <KEY> NVIDIA NIM key (or env NVIDIA_API_KEY)
  -m, --model <ID>    force a model (default: auto-select a verified one)
      --provider-config <FILE>  provider TOML/JSON file
      --base-url <URL>           any OpenAI-compatible endpoint
      --setup         force the full setup wizard again
      --no-ai         run tools-only, no agent
      --no-tui        plain terminal output
      --no-pivot      don't expand IP targets into domain phases
      --list-models   print the account's models and exit
  -o, --output <DIR>  report directory (default ./reports)
```

## Project layout — every file explained

```
Night Crawler/
├── AGENTS.md                 The agent's operating doctrine (auth/scope, lifecycle,
│                             confidence levels, reporting format). Embedded into
│                             every model call via include_str!.
├── nvidia.example.toml       Example provider config for the setup wizard.
├── Cargo.toml                Crate manifest (tokio, ratatui, reqwest, hickory-dns,
│                             rustls, x509-parser, ldap3, serde, clap, …).
├── src/
│   ├── main.rs               Entry point: CLI parsing, runtime setup, wizard vs flag
│   │                         mode, provider resolution, scan launch, final summary.
│   ├── lib.rs                Module tree.
│   ├── config.rs             Nightcrawler.toml + provider.toml loading, provider-input
│   │                         parsing (raw key / TOML / JSON / env-file), saved-provider
│   │                         persistence, port-spec parsing, top-port list,
│   │                         port→service map, Google CSE key/cx resolution.
│   ├── state.rs              SharedState: the live phase list (22 phases), findings
│   │                         feed, activity log, progress gauge, AI-thinking flag —
│   │                         the bridge between the scan worker and the TUI.
│   ├── types.rs              All result structs (Meta, TargetInfo, PortResult,
│   │                         VulnFinding w/ confidence, DnsResults, SubdomainResult,
│   │                         DirResult, SnmpResults, LdapResults, NbnsResults,
│   │                         SmbResults, WhoisResults, DorkResult, GraphData,
│   │                         AiDecision, PivotData, ReconResults …) + severity enum.
│   ├── util.rs               Helpers: version parsing, HTML title extraction,
│   │                         percent-decoding, timestamps, label sanitizing.
│   ├── ai.rs                 NVIDIA NIM client (OpenAI-compatible): /models listing,
│   │                         auto model selection with verified pings + retry passes
│   │                         (EOL/access/hang resilient), chat with backoff on
│   │                         429/5xx, reasoning-model message extraction
│   │                         (content + reasoning_content), NIM error decoding.
│   ├── agent.rs              The decision engine: embeds AGENTS.md, strict-JSON
│   │                         prompts for port strategy / module plan / follow-up
│   │                         tasks / final report, JSON extraction with a stricter
│   │                         retry, bounded action menus.
│   ├── orchestrator.rs       The autonomous pipeline: runs all 22 phases in order,
│   │                         gates modules on evidence, executes AI decisions,
│   │                         follow-up loop (3 rounds, validated actions, coverage
│   │                         context so the model never repeats work), CVE search
│   │                         via CSE, graph building, report writing.
│   ├── graph.rs              Maltego-style entity graph: nodes/edges, degree-ranked
│   │                         hubs, Mermaid export with per-kind shapes/colors.
│   ├── report.rs             Markdown report builder + writes the report set
│   │                         (report.md, report.html, findings.json, mermaid, graph).
│   ├── report_html.rs        The graphical HTML dashboard generator: dark theme,
│   │                         stat cards, SVG severity donut, bar charts, finding
│   │                         cards, tables, collapsible sections, SVG entity graph,
│   │                         decision timeline, mini markdown→HTML renderer.
│   ├── ui.rs                 ratatui scan dashboard: header (target, timer, counters,
│   │                         🤖 model badge), phases panel with spinners, tail-
│   │                         following findings feed, activity log, progress gauge,
│   │                         AI-thinking indicator; plus plain --no-tui renderer.
│   ├── ui_setup.rs           The setup wizard: PROVIDER → TARGET → MODEL flow, all
│   │                         network work as background jobs (never blocks),
│   │                         provider persistence, saved-provider fast path,
│   │                         m/c change keys.
│   ├── assets/               Embedded wordlists: subdomains.txt (300),
│   │                         dirs.txt (383), snmp_communities.txt (58).
│   └── modules/
│       ├── ping.rs           ICMP ping w/ TCP-connect fallback.
│       ├── portscan.rs       Async TCP connect scan (bounded concurrency).
│       ├── banner.rs         Banner grabbing, HTTP probing, product/version regex
│       │                     extraction, service refinement from products.
│       ├── tls_capture.rs    rustls no-verify client: captures the peer certificate,
│       │                     x509-parser SAN/CN/issuer/expiry → IP→domain pivots.
│       ├── cve.rs            OpenVAS-style CVE engine: product→CPE table, NVD API 2.0
│       │                     queries, client-side version-range verification, CVSS
│       │                     extraction, CIRCL mirror fallback.
│       ├── vulns.rs          Local CVE fingerprint database (vsftpd backdoor, ProFTPD
│       │                     mod_copy, regreSSHion, Heartbleed, Exim RCE, IIS 6.0
│       │                     WebDAV, Samba EternalRed, Jenkins CLI, MySQL auth bypass,
│       │                     EOL stacks …) + exposure findings, each with a
│       │                     doctrine confidence level.
│       ├── dnsrecon.rs       9 record types via hickory, wildcard detection, PTR,
│       │                     and a from-scratch DNS wire codec for AXFR zone
│       │                     transfers (TCP/53, compression-pointer parsing).
│       ├── subdomain.rs      crt.sh certificate-transparency + dictionary brute
│       │                     force with wildcard filtering.
│       ├── subdir.rs         Web directory brute force with soft-404 baselines +
│       │                     robots.txt harvesting.
│       ├── snmp.rs           Pure-Rust SNMP v1/v2c: BER codec, GET/GETBULK, community
│       │                     brute force, MIB-2 walk, vendor fingerprinting.
│       ├── netbios.rs        Raw NBNS node-status codec (UDP/137): names, service
│       │                     suffixes, group flags, MAC address.
│       ├── smb.rs            smbclient/rpcclient/enum4linux integration when installed.
│       ├── ldap.rs           ldap3: anonymous bind → RootDSE → users/groups/computers
│       │                     (AD + OpenLDAP filters).
│       ├── whois.rs          Referral-following whois client (domains + netblocks).
│       └── dork.rs           Google Programmable Search (your engine), SerpAPI,
                             DuckDuckGo fallback; dork set generation + CVE query
                             construction for online exploit mapping.
├── tests/
│   ├── e2e_wizard.py         Full pty-driven lifecycle E2E (wizard → scan → saved
│   │                         provider → second run) against the mock NVIDIA server.
│   ├── mock_nvidia.py        OpenAI-compatible mock NIM answering every decision point.
│   ├── snmp_responder.py     Minimal SNMP v2c + NBNS test responder (codec tests).
│   ├── axfr_responder.py     Minimal authoritative AXFR DNS server (codec tests).
│   ├── axfr_fixture.bin      DNS message fixture for the AXFR parser unit test.
│   ├── codecs.rs             Integration tests: SNMP BER walk, NBNS, wrong-community.
│   ├── axfr.rs               Integration tests: AXFR success + refused.
│   └── fixture/
│       └── mock_provider.toml  Provider config used by the E2E.
```

## Testing

```bash
cargo test                    # 15 unit + 6 integration tests (codecs, parsing, agents)
python3 tests/e2e_wizard.py   # full wizard lifecycle E2E (needs a pty)
```

The hand-rolled protocol codecs (SNMP BER, DNS AXFR wire, NetBIos NBNS),
provider parsing, message extraction, and model ranking are all covered by
tests; the NVIDIA/AI path is exercised end-to-end against a local mock.

## Legal

Night Crawler performs active network scanning. Running it against systems
you do not own or are not explicitly authorized to test is illegal.
# Night_Crawler
