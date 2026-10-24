use night_crawler::{ai, config, orchestrator, state, types, ui, ui_setup};
use anyhow::Result;
use clap::{Parser, ValueHint};
use std::io::IsTerminal;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "night-crawler",
    version,
    about = "Night Crawler — autonomous recon agent (NightCrawler)",
    long_about = "Night Crawler is a fully autonomous recon agent: connect your NVIDIA NIM provider, \
connect your NVIDIA NIM provider, enter a target, and the NightCrawler agent decides the port strategy, selects enumeration modules, chains \
follow-up tasks from combined results, and writes the final report. A ratatui setup wizard \
starts automatically when you run it with no arguments.\n\n\
Only use against systems you are authorized to test."
)]
struct Cli {
    /// Target: IP address or domain name (omit to launch the setup wizard)
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

    /// Plain log output instead of the GUI
    #[arg(long)]
    no_tui: bool,

    /// Force the terminal UI instead of the browser GUI
    #[arg(long)]
    tui: bool,

    /// GUI port (default 7655)
    #[arg(long, default_value = "7655")]
    port: u16,

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

fn main() -> Result<()> {
    // ensure a rustls crypto provider exists process-wide (ring)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let mut cfg = config::Config::load(cli.config.as_ref());
    cfg.scan.max_concurrency = cli.concurrency;

    // ------------------------------------------------------------------
    // --list-models mode
    // ------------------------------------------------------------------
    if cli.list_models {
        return list_models_mode(&cli, &cfg);
    }

    let rt = tokio::runtime::Runtime::new()?;

    // ------------------------------------------------------------------
    // Resolve target + provider. With no arguments and a real terminal,
    // launch the interactive setup wizard.
    // ------------------------------------------------------------------
    let (target, nv, provider_desc) = match (&cli.target, cli.no_tui, std::io::stdout().is_terminal()) {
        (Some(t), _, _) => {
            // classic flag-driven mode
            let nv = rt.block_on(build_cli_ai(&cli, &cfg));
            (t.clone(), nv, "flags/config".into())
        }
        (None, false, true) => {
            // interactive wizard
            let mut tui = ui::init()?;
            let outcome = ui_setup::run_setup(&mut tui.terminal, &rt, &cfg, cli.setup);
            ui::restore();
            match outcome? {
                Some(o) => (o.target, o.nv, o.provider_desc),
                None => {
                    println!("\x1b[2msetup aborted\x1b[0m");
                    return Ok(());
                }
            }
        }
        (None, true, true) => {
            // plain interactive prompts (no TUI available/requested)
            let target = prompt("Target (IP or domain): ");
            if target.trim().is_empty() {
                println!("no target given — exiting");
                return Ok(());
            }
            let provider_in = prompt("NVIDIA provider key or config file path (blank = tools-only): ");
            let nv = if provider_in.trim().is_empty() {
                None
            } else {
                match config::resolve_provider_input(&provider_in) {
                    Ok(setup) => {
                        let model = setup
                            .model
                            .clone()
                            .or_else(|| cfg.nvidia.model.clone())
                            .unwrap_or_else(config::default_model);
                        let key = setup.api_key.clone();
                        let base = setup.base_url.clone();
                        Some(ai::NvClient::new(&base, &key, &model))
                    }
                    Err(e) => {
                        eprintln!("\x1b[33mprovider setup failed: {} — continuing without the agent\x1b[0m", e);
                        None
                    }
                }
            };
            (target, nv, "prompt".into())
        }
        (None, _, false) if !cli.no_tui => {
            // GUI mode: the browser setup form supplies the target
            (String::new(), None, "gui-setup".into())
        }
        (None, _, false) => {
            // --no-tui and non-interactive: nothing to do
            eprintln!("no target provided — GUI disabled with --no-tui");
            eprintln!("usage: night-crawler <ip|domain>   — or drop --no-tui for the browser GUI");
            return Ok(());
        }
    };

    run_scan_and_finish(&rt, target, nv, provider_desc, &cli, &cfg)
}

async fn build_cli_ai(cli: &Cli, cfg: &config::Config) -> Option<ai::NvClient> {
    if cli.no_ai {
        return None;
    }
    // provider-config file > --api-key flag > env > saved provider.toml > config file
    let setup: Option<config::ProviderSetup> = if let Some(path) = &cli.provider_config {
        match config::resolve_provider_input(&path.to_string_lossy()) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("\x1b[33mprovider config error: {}\x1b[0m", e);
                None
            }
        }
    } else {
        config::resolve_nvidia_key(cli.api_key.as_deref(), cfg)
            .map(|key| config::ProviderSetup {
                api_key: key,
                base_url: cli
                    .base_url
                    .clone()
                    .or_else(|| cfg.nvidia.base_url.clone())
                    .unwrap_or_else(config::default_base_url),
                model: cli.model.clone().or_else(|| cfg.nvidia.model.clone()),
            })
            .or_else(config::load_saved_provider)
    };

    let setup = setup?;
    let mut client = ai::NvClient::new(&setup.base_url, &setup.api_key, "");
    // find a model that actually works with this key (preferred first,
    // then auto-selected from the account's list)
    match client.connect_and_select(setup.model.clone()).await {
        Ok((_, sel)) => {
            eprintln!("\x1b[1;32m[*] {}\x1b[0m", sel.note);
            Some(client)
        }
        Err(e) => {
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

fn prompt(label: &str) -> String {
    use std::io::Write;
    print!("{}", label);
    let _ = std::io::stdout().flush();
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
    buf.trim().to_string()
}

fn run_scan_and_finish(
    rt: &tokio::runtime::Runtime,
    mut target: String,
    mut nv: Option<ai::NvClient>,
    provider_desc: String,
    cli: &Cli,
    cfg: &config::Config,
) -> Result<()> {
    let opts = orchestrator::Opts {
        ports_spec: cli.ports.clone(),
        wordlist_subs: read_wordlist(cli.subdomains_list.as_ref()),
        wordlist_dirs: read_wordlist(cli.dirs_list.as_ref()),
        snmp_communities: read_wordlist(cli.snmp_communities.as_ref()),
        enable_ai: !cli.no_ai,
        allow_pivot: !cli.no_pivot,
        output_dir: cli.output.clone(),
    };

    let use_tui = cli.tui && std::io::stdout().is_terminal() && cli.target.is_some();
    let use_gui = !cli.no_tui && !use_tui;
    let _ = provider_desc;

    // Single shared state for the whole run (GUI setup + scan + report)
    let shared = state::SharedState::new(target.clone());
    let shared_ui = shared.clone();

    // ------------------------------------------------------------------
    // GUI mode: browser-first. Setup form -> live scan -> report.
    // ------------------------------------------------------------------
    if use_gui {
        night_crawler::gui::set_gui_port(cli.port);
        let gui_shared = shared.clone();
        rt.spawn(async move {
            if let Err(e) = night_crawler::gui::serve(gui_shared).await {
                eprintln!("\x1b[33mGUI unavailable: {} — falling back to plain output\x1b[0m", e);
            }
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        night_crawler::gui::open_browser(night_crawler::gui::gui_port());
        println!(
            "\x1b[1;35m🕷 Night Crawler GUI: http://127.0.0.1:{}\x1b[0m",
            night_crawler::gui::gui_port()
        );

        // no target yet: wait for the browser form to submit one
        if target.is_empty() {
            loop {
                if let Some(req) = night_crawler::gui::take_pending_start() {
                    target = req.target;
                    if !req.provider.is_empty() {
                        nv = match config::resolve_provider_input(&req.provider) {
                            Ok(setup) => {
                                let mut client = night_crawler::ai::NvClient::new(
                                    &setup.base_url, &setup.api_key, "",
                                );
                                match rt.block_on(client.connect_and_select(setup.model.clone())) {
                                    Ok((_, sel)) => {
                                        eprintln!("\x1b[1;32m[*] {}\x1b[0m", sel.note);
                                        Some(client)
                                    }
                                    Err(e) => {
                                        eprintln!("\x1b[33m[!] agent unavailable: {}\x1b[0m", e);
                                        None
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("\x1b[33m[!] provider input invalid: {}\x1b[0m", e);
                                None
                            }
                        };
                    }
                    shared.scan_started(&target);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        } else {
            shared.scan_started(&target);
        }
    }

    let shared_scan = shared.clone();
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

    let handle = rt.spawn(async move {
        let scan_target_ref = scan_target.clone();
        let scan_opts_ref = scan_opts.clone();
        let cfg_ref = cfg_clone.clone();
        orchestrator::run_scan(&scan_target_ref, &scan_opts_ref, &cfg_ref, shared_scan, scan_nv).await
    });


    let user_quit = if use_tui {
        let mut tui = ui::init()?;
        let result = tui.run(&shared_ui);
        match result {
            Ok(true) => {
                handle.abort();
                ui::restore();
                println!("\x1b[2maborted by user\x1b[0m");
                true
            }
            Ok(false) => {
                ui::restore();
                false
            }
            Err(e) => {
                ui::restore();
                println!("\x1b[31mUI error: {}\x1b[0m", e);
                false
            }
        }
    } else if use_gui {
        // the GUI server is already running (started in the browser-first
        // block above) — just hold the process so the dashboard + report
        // stay viewable; user presses Ctrl-C when done
        rt.block_on(async {
            loop {
                if shared_ui.state.lock().unwrap().done {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            }
        });
        println!(
            "\x1b[2mGUI stays live at http://127.0.0.1:{} — press Ctrl-C to exit\x1b[0m",
            night_crawler::gui::gui_port()
        );
        rt.block_on(std::future::pending::<()>());
        false
    } else {
        rt.block_on(ui::plain_watch(shared_ui.clone()));
        false
    };

    if user_quit {
        return Ok(());
    }

    let scan_result = rt.block_on(handle).unwrap_or_else(|e| {
        if e.is_panic() {
            Err(anyhow::anyhow!("scan thread panicked: {:?}", e))
        } else if e.is_cancelled() {
            Err(anyhow::anyhow!("scan cancelled"))
        } else {
            Err(anyhow::anyhow!("join error: {}", e))
        }
    });

    // final summary block
    println!();
    println!("\x1b[1;35m  ╭──────────────────────────────────────────────╮\x1b[0m");
    println!("\x1b[1;35m  │          NIGHT CRAWLER — COMPLETE           │\x1b[0m");
    println!("\x1b[1;35m  ╰──────────────────────────────────────────────╯\x1b[0m");

    {
        let s = shared.state.lock().unwrap();
        let done_count = s
            .phases
            .iter()
            .filter(|p| matches!(p.status, state::PhaseStatus::Done))
            .count();
        let skip_count = s
            .phases
            .iter()
            .filter(|p| matches!(p.status, state::PhaseStatus::Skipped(_)))
            .count();
        let fail_count = s
            .phases
            .iter()
            .filter(|p| matches!(p.status, state::PhaseStatus::Failed(_)))
            .count();
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
