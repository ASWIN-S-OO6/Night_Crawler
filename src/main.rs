use night_crawler::{ai, config, modules::recursive_agent::run_recursive_agent, orchestrator, state, types};
use anyhow::Result;
use clap::{Parser, ValueHint};
use std::path::PathBuf;
use std::sync::Arc;

fn log_verbose(verbose: bool, msg: &str) {
    if verbose {
        eprintln!("[VERBOSE] {}", msg);
    }
}

fn log_debug(verbose: bool, msg: &str) {
    if verbose {
        eprintln!("[DEBUG] {}", msg);
    }
}

fn read_wordlist(p: Option<&PathBuf>) -> Option<Vec<String>> {
    p.map(|path| {
        std::fs::read_to_string(path)
            .expect("read wordlist")
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    })
}

#[derive(Parser, Debug)]
#[command(
    name = "night-crawler",
    version,
    about = "Night Crawler — autonomous recon agent (NightCrawler)",
    long_about = "Night Crawler is a fully autonomous recon agent: connect your NVIDIA NIM provider, enter a target, and the NightCrawler agent decides the port strategy, selects enumeration modules, chains follow-up tasks from combined results, and writes the final report.\n\nOnly use against systems you are authorized to test."
)]
struct Cli {
    /// Target: IP address or domain name
    #[arg(value_hint = ValueHint::Other)]
    target: Option<String>,

    /// Optional port override (NightCrawler decides when omitted)
    #[arg(short, long)]
    ports: Option<String>,

    /// TCP connect concurrency
    #[arg(short = 'c', long, default_value = "400")]
    concurrency: usize,

    /// NVIDIA NIM API key (or env NVIDIA_API_KEY)
    #[arg(short = 'k', long)]
    api_key: Option<String>,

    /// NVIDIA NIM model, e.g. meta/llama-3.3-70b-instruct
    #[arg(short = 'm', long)]
    model: Option<String>,

    /// NVIDIA-compatible base URL (default https://integrate.api.nvidia.com/v1)
    #[arg(long)]
    base_url: Option<String>,

    /// Provider config file (TOML/JSON/env-style) with api_key/model/base_url
    #[arg(long)]
    provider_config: Option<PathBuf>,

    /// Disable the NightCrawler agent (run tools-only)
    #[arg(long)]
    no_ai: bool,

    /// Enable verbose debug logging
    #[arg(long)]
    verbose: bool,

    /// Don't expand an IP target into domain-based phases via PTR/cert pivots
    #[arg(long)]
    no_pivot: bool,

    /// Custom subdomain wordlist file
    #[arg(long)]
    subdomains_list: Option<PathBuf>,

    /// Custom directory wordlist file
    #[arg(long)]
    dirs_list: Option<PathBuf>,

    /// Custom SNMP communities file
    #[arg(long)]
    snmp_communities: Option<PathBuf>,

    /// Reports output directory (default ./reports)
    #[arg(short = 'o', long, default_value = "./reports")]
    output: PathBuf,

    /// Explicit config file path
    #[arg(long)]
    config: Option<PathBuf>,

    /// List models available for the given API key and exit
    #[arg(long)]
    list_models: bool,

    /// Force the setup wizard: re-enter the provider key and model
    #[arg(long)]
    setup: bool,

    /// Use the recursive adaptive AI agent (OODA loop) instead of fixed phases
    #[arg(long)]
    recursive: bool,
}

async fn build_cli_ai(cli: &Cli, cfg: &config::Config, verbose: bool) -> Option<ai::NvClient> {
    if cli.no_ai {
        log_verbose(verbose, "AI disabled via --no-ai flag");
        return None;
    }
    // provider-config file > --api-key flag > env > saved provider.toml > config file
    log_verbose(verbose, "Resolving NVIDIA API key and provider config...");
    let setup: Option<config::ProviderSetup> = if let Some(path) = &cli.provider_config {
        log_verbose(verbose, &format!("Loading provider config from file: {}", path.display()));
        match config::resolve_provider_input(&path.to_string_lossy()) {
            Ok(s) => {
                log_verbose(verbose, "Provider config loaded successfully from file");
                Some(s)
            }
            Err(e) => {
                eprintln!("\x1b[33mprovider config error: {}\x1b[0m", e);
                None
            }
        }
    } else {
        log_verbose(verbose, "Checking CLI --api-key flag...");
        let key = config::resolve_nvidia_key(cli.api_key.as_deref(), cfg);
        if key.is_some() {
            log_verbose(verbose, "Found API key from CLI flag");
        } else {
            log_verbose(verbose, "No CLI key, checking environment variables...");
        }
        key.map(|key| config::ProviderSetup {
            api_key: key,
            base_url: cli
                .base_url
                .clone()
                .or_else(|| cfg.nvidia.base_url.clone())
                .unwrap_or_else(config::default_base_url),
            model: cli.model.clone().or_else(|| cfg.nvidia.model.clone()),
        })
        .or_else(|| {
            log_verbose(verbose, "Checking saved provider config (~/.config/nightcrawler/provider.toml)...");
            config::load_saved_provider()
        })
    };

    let setup = match setup {
        Some(s) => {
            log_verbose(verbose, &format!("Provider setup resolved: base_url={}, model={:?}", s.base_url, s.model));
            s
        }
        None => {
            log_verbose(verbose, "No provider setup found - continuing without AI agent");
            return None;
        }
    };
    
    let model = setup.model.clone().unwrap_or_else(config::default_model);
    log_verbose(verbose, &format!("Creating NVIDIA NIM client: base_url={}, model={}", setup.base_url, model));
    let mut client = ai::NvClient::new(&setup.base_url, &setup.api_key, &model);
    
    // find a model that actually works with this key (preferred first,
    // then auto-selected from the account's list)
    log_verbose(verbose, "Connecting to NVIDIA NIM and verifying model availability...");
    match client.connect_and_select(setup.model.clone()).await {
        Ok((_, sel)) => {
            log_verbose(verbose, &format!("Model connected and verified: {}", sel.note));
            eprintln!("\x1b[1;32m[*] {}\x1b[0m", sel.note);
            Some(client)
        }
        Err(e) => {
            log_verbose(verbose, &format!("Model connection failed: {}", e));
            eprintln!("\x1b[33m[!] NightCrawler agent unavailable: {}\x1b[0m", e);
            eprintln!("\x1b[2m    continuing without the agent (evidence-based defaults)\x1b[0m");
            None
        }
    }
}

fn list_models_mode(cli: &Cli, cfg: &config::Config) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let (key, base) = if let Some(path) = &cli.provider_config {
        let setup = config::resolve_provider_input(&path.to_string_lossy())?;
        (setup.api_key, setup.base_url)
    } else {
        let key = config::resolve_nvidia_key(cli.api_key.as_deref(), cfg)
            .ok_or_else(|| anyhow::anyhow!("no API key: pass --api-key / --provider-config, set NVIDIA_API_KEY, or configure nightcrawler.toml"))?;
        (key, cli.base_url.clone().unwrap_or_else(config::default_base_url))
    };
    let client = ai::NvClient::new(&base, &key, "");
    let models = rt.block_on(client.list_models())?;
    println!("Available models ({}):", models.len());
    for m in models {
        println!("  {}", m);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // ensure a rustls crypto provider exists process-wide (ring)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let mut cfg = config::Config::load(cli.config.as_ref());
    cfg.scan.max_concurrency = cli.concurrency;

    log_verbose(cli.verbose, "Starting Night Crawler with verbose logging enabled");
    log_debug(cli.verbose, &format!("CLI args: target={:?}, no_ai={}, recursive={}, verbose={}", 
        cli.target, cli.no_ai, cli.recursive, cli.verbose));

    // --list-models mode
    if cli.list_models {
        return list_models_mode(&cli, &cfg);
    }

    // Resolve target
    let target = match &cli.target {
        Some(t) => t.clone(),
        None => {
            eprintln!("no target provided");
            eprintln!("usage: night-crawler <ip|domain>");
            return Ok(());
        }
    };

    log_verbose(cli.verbose, &format!("Target: {}", target));

    let nv = build_cli_ai(&cli, &cfg, cli.verbose).await;

    let opts = orchestrator::Opts {
        ports_spec: cli.ports.clone(),
        wordlist_subs: read_wordlist(cli.subdomains_list.as_ref()),
        wordlist_dirs: read_wordlist(cli.dirs_list.as_ref()),
        snmp_communities: read_wordlist(cli.snmp_communities.as_ref()),
        enable_ai: !cli.no_ai,
        allow_pivot: !cli.no_pivot,
        output_dir: cli.output.clone(),
    };

    let shared = state::SharedState::new(target.clone());
    let shared_scan = shared.clone();

    let use_recursive = cli.recursive && opts.enable_ai && nv.is_some();

    log_verbose(cli.verbose, &format!("Starting scan (recursive: {}, ai: {})", use_recursive, !cli.no_ai));
    
    let scan_shared = shared.clone();
    let scan_nv = nv.clone();
    let scan_target = target.clone();
    let scan_opts = orchestrator::Opts {
        ports_spec: opts.ports_spec.clone(),
        wordlist_subs: opts.wordlist_subs.clone(),
        wordlist_dirs: opts.wordlist_dirs.clone(),
        snmp_communities: opts.snmp_communities.clone(),
        enable_ai: opts.enable_ai,
        allow_pivot: opts.allow_pivot,
        output_dir: opts.output_dir.clone(),
    };
    let cfg_clone = config::Config {
        nvidia: cfg.nvidia.clone(),
        dorking: cfg.dorking.clone(),
        scan: cfg.scan.clone(),
    };

    let handle = tokio::spawn(async move {
        let scan_shared = scan_shared;
        let scan_nv = scan_nv;
        let scan_target = scan_target;
        let scan_opts = scan_opts;
        let cfg_clone = cfg_clone;
        let use_recursive = use_recursive;
        
        if use_recursive && scan_opts.enable_ai && scan_nv.is_some() {
            run_recursive_agent(&scan_target, &scan_opts, &cfg_clone, scan_shared, scan_nv).await
        } else {
            orchestrator::run_scan(&scan_target, &scan_opts, &cfg_clone, scan_shared, scan_nv).await
        }
    });

    // Wait for scan to complete with progress updates
    let mut last_phase_count = 0;
    loop {
        if handle.is_finished() {
            break;
        }
        {
            let s = shared_scan.state.lock().unwrap();
            let done_count = s.phases.iter().filter(|p| matches!(p.status, state::PhaseStatus::Done)).count();
            if done_count != last_phase_count {
                if let Some(phase) = s.phases.iter().find(|p| matches!(p.status, state::PhaseStatus::Running)) {
                    eprintln!("\x1b[1;35m[*] Phase: {} - {}\x1b[0m", phase.name, phase.summary);
                }
                last_phase_count = done_count;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    let scan_result = handle.await.unwrap_or_else(|e| {
        if e.is_panic() {
            Err(anyhow::anyhow!("scan thread panicked: {:?}", e))
        } else if e.is_cancelled() {
            Err(anyhow::anyhow!("scan cancelled"))
        } else {
            Err(anyhow::anyhow!("join error: {}", e))
        }
    });

    // Final summary
    println!();
    println!("\x1b[1;35m  ╭──────────────────────────────────────────────╮\x1b[0m");
    println!("\x1b[1;35m  │          NIGHT CRAWLER — COMPLETE           │\x1b[0m");
    println!("\x1b[1;35m  ╰──────────────────────────────────────────────╯\x1b[0m");

    {
        let s = shared_scan.state.lock().unwrap();
        let done_count = s.phases.iter().filter(|p| matches!(p.status, state::PhaseStatus::Done)).count();
        let skip_count = s.phases.iter().filter(|p| matches!(p.status, state::PhaseStatus::Skipped(_))).count();
        let fail_count = s.phases.iter().filter(|p| matches!(p.status, state::PhaseStatus::Failed(_))).count();
        println!(
            "  phases: {} done, {} skipped, {} failed",
            done_count, skip_count, fail_count
        );
        println!("  findings: {}", s.findings.len());
        if let Some(model) = &s.ai_note {
            println!("  agent:   \x1b[1;32m{}\x1b[0m", model);
        }
        if let Some(path) = &s.report_path {
            println!("  report:   \x1b[1m{}\x1b[0m (graphical dashboard)", path);
        }
        if let Some(err) = &s.error {
            println!("  \x1b[31merror: {}\x1b[0m", err);
        }
        let mut top: Vec<&state::Finding> = s.findings.iter().collect();
        top.sort_by_key(|f| f.severity.rank());
        let notable: Vec<&state::Finding> = top
            .into_iter()
            .filter(|f| {
                matches!(
                    f.severity,
                    types::Severity::Critical | types::Severity::High | types::Severity::Medium
                )
            })
            .take(8)
            .collect();
        if !notable.is_empty() {
            println!("\n  \x1b[1mTop findings:\x1b[0m");
            for f in notable {
                let color = match f.severity {
                    types::Severity::Critical => "\x1b[1;31m",
                    types::Severity::High => "\x1b[0;31m",
                    types::Severity::Medium => "\x1b[0;33m",
                    _ => "\x1b[0m",
                };
                println!("  {}  ● [{}] {}\x1b[0m", color, f.severity.label(), f.title);
            }
        }
    }

    match scan_result {
        Ok(_results) => println!("\n  \x1b[2mopen report.html in a browser · raw data in findings.json\x1b[0m\n"),
        Err(e) => {
            println!("  \x1b[31mscan error: {}\x1b[0m\n", e);
        }
    }

    Ok(())
}