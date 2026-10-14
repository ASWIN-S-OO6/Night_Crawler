# Night Crawler 🕷

**A fully autonomous, AI-driven reconnaissance agent** written in Rust.

Run it with no arguments: it asks for your NVIDIA NIM API key **first**,
verifies the key can actually run a chat completion, then asks for the
target, shows your models, and takes over. The onboard **NightCrawler**
agent — governed by the `AGENTS.md` doctrine — chooses the port strategy,
selects enumeration modules, chains follow-up tasks from the combined
results, and writes the assessment report. You never pick ports or tools.

> Only use against systems you are authorized to test.

## How it works

```
$ ./night-crawler

┌ 🕷 NIGHT CRAWLER — SETUP ─────────────────────────────┐
│                                                      │
│   1 PROVIDER → 2 TARGET → 3 MODEL                   │
│   Step 1 — NVIDIA provider: key or config file:      │
│  > ~/nvidia.toml▌                                    │
│  ⠋ Connecting to the NVIDIA provider…                │
│   …                                                  │
│  ✔ Provider online — chat verified                   │
│   Step 2 — Target (IP address or domain):            │
│  > scanme.nmap.org▌                                  │
│  ┌ select the model the agent will use ┐             │
│  │▶ meta/llama-3.3-70b-instruct        │             │
│  │  qwen/qwen2.5-72b-instruct           │             │
│  └─────────────────────────────────────┘             │
│   agent model: meta/llama-3.3-70b-instruct           │
│   [Enter: start scan]                                │
└──────────────────────────────────────────────────────┘
```

From there the agent takes over — the dashboard shows **the connected model
in the header**, every phase with live status, AI decisions streaming into
the findings feed, and a `🤖 AI analyzing evidence & deciding next moves…`
indicator whenever the model is thinking.

## The agent (NightCrawler)

The agent operates under `AGENTS.md` — a penetration-testing doctrine
embedded into every model call: authorized scope only, evidence-driven
decisions, CONFIRMED / LIKELY / POSSIBLE / UNCONFIRMED confidence levels,
no invented findings, and a structured report with Attack Paths that tell
you *where the problem is and how to start the attack*.

| Stage | What NightCrawler decides |
|---|---|
| 1. Port strategy | `top` / `full` / a custom range list, based on the target profile (PTR, cert SANs, role) |
| 2. Module plan | Which of snmp / ldap / netbios_smb / subdirs / deep_subdomain / dorking actually apply |
| 3. Follow-up tasks | `extend_dirs` (extra web paths), `probe_web_roots` (discovered hosts), `pivot_domains` (sibling domains → DNS + AXFR + dorks), `rescan_ports`, or `finish` — chosen from the *combined* results |
| 4. Final report | Full analysis: executive summary, attack surface, key findings with concrete next methods |

Every decision is bounded: the model picks from a fixed menu, returns strict
JSON that is validated before execution, and every stage falls back to
evidence-based defaults if the AI is slow or unavailable. All decisions are
recorded in the report's **AI Decision Timeline**.

## Recon capabilities (all automatic)

- Port scan (async TCP), banner grabbing, product/version extraction
- Local CVE fingerprint DB (regreSSHion, ProFTPD mod_copy, vsftpd backdoor, Heartbleed, Exim RCE, IIS 6.0 WebDAV, database/Docker/k8s exposure findings)
- Full DNS recon: A/AAAA/CNAME/MX/NS/TXT/SOA/SRV/CAA, wildcard detection, **raw AXFR zone transfer** (pure-Rust DNS wire codec)
- Subdomains via certificate transparency (crt.sh) + dictionary brute force
- HTTP fingerprint (headers, titles, security headers, cookies, robots.txt) + directory brute force with soft-404 baselines
- Pure-Rust SNMP v1/v2c walk (BER codec, community brute force, vendor fingerprint)
- LDAP enumeration (anonymous bind → RootDSE → users/groups/computers)
- NetBIOS node status (raw NBNS) + smbclient/rpcclient/enum4linux integration when installed
- WHOIS with referral following (domain + netblock)
- OSINT dorking (Google CSE / SerpAPI / DuckDuckGo fallback)
- Maltego-style link graph with Mermaid + JSON export
- IP ↔ domain pivoting (PTR + TLS certificate SANs)

## Setup

```bash
cargo build --release
# binary: target/release/night-crawler
```

### Connect your NVIDIA provider

The wizard accepts either:

1. **A raw key** — `nvapi-xxxx…`
2. **A provider config file** — TOML, JSON or env-style (see `nvidia.example.toml`):

```toml
[nvidia]
api_key  = "nvapi-..."
model    = "meta/llama-3.3-70b-instruct"
base_url = "https://integrate.api.nvidia.com/v1"   # optional
```

```json
{"nvidia": {"api_key": "nvapi-...", "model_id": "qwen/qwen2.5-72b-instruct"}}
```

The tool lists the account's models and **finds one that actually works**:
the model named in your config file is tried first; if it's EOL or
unavailable (e.g. `meta/llama-3.3-70b-instruct` retired Aug 2026), the
best working chat model from your account is **auto-selected** by
preference (GLM-flash > GLM > Gemma-4 > Nemotron > Kimi > Qwen > Llama…)
and verified with a live chat ping — reasoning models
(`content`/`reasoning_content` split) are handled natively. The verified
model is shown in the UI throughout the scan; you can override it in the
model picker (each pick is ping-verified before the scan starts). Failures
(bad key, org-scoped key, quota, EOL model) surface immediately with the
provider's exact error, and the scan degrades to evidence-based defaults
instead of silently skipping.

Flag-driven use still works (`--api-key`, `--model`, `--base-url`,
`--provider-config`, `NVIDIA_API_KEY` env, `nightcrawler.toml`), plus
`--no-tui` for plain output, `--no-ai` to run without the agent, and
`--list-models` to enumerate your provider's models.

## Output

Each run writes `./reports/nightcrawler_<target>_<timestamp>/`:

- `report.md` — executive summary (AI-written), ports & services, CVE findings, DNS/AXFR, subdomains, web paths, SNMP/LDAP/SMB, WHOIS, dork results, **AI decision timeline**, pivot domains, link analysis
- `findings.json` — complete machine-readable results
- `link_analysis.mmd` / `link_analysis.json` — the entity graph

## Tests

The hand-rolled protocol codecs (SNMP BER, DNS AXFR, NetBIOS NBNS) and the
provider-config parsing are covered by unit + integration tests:

```bash
cargo test
```

## Legal

Night Crawler performs active network scanning. Running it against systems you
do not own or are not explicitly authorized to test is illegal.
