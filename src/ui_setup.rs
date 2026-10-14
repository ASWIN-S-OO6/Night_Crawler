//! Interactive onboarding wizard: NVIDIA provider → target → model.
//! The API key comes FIRST (the correct flow), the tool verifies the key
//! can actually run a chat completion (not just list models), then the
//! operator enters the target and confirms the model.

use crate::ai::NvClient;
use crate::config::{resolve_provider_input, ProviderSetup, Config};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};
use tokio::task::JoinHandle;

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

#[derive(Debug, Clone, PartialEq)]
enum Stage {
    /// Step 1: provider key / config file — the correct flow starts here.
    Provider,
    /// Step 2: the target.
    Target,
    /// Step 3: model selection (after connect + chat verification).
    Models,
    /// Async connect + verify job running.
    Connecting,
}

pub struct SetupOutcome {
    pub target: String,
    pub nv: Option<NvClient>,
    pub provider_desc: String,
}

pub struct SetupState {
    stage: Stage,
    provider: String,
    provider_setup: Option<ProviderSetup>,
    connected: bool,
    target: String,
    status: String,
    error: Option<String>,
    models: Vec<String>,
    model_sel: usize,
    model: Option<String>,
    /// ping verification message from the connect job
    verify_msg: Option<String>,
    connect_job: Option<JoinHandle<anyhow::Result<(Vec<String>, String)>>>,
    base_url: String,
    quit: bool,
    done: Option<SetupOutcome>,
}

impl SetupState {
    fn new(cfg: &Config) -> Self {
        let saved_key = cfg.nvidia.api_key.clone().filter(|k| !k.is_empty());
        let status = if saved_key.is_some() {
            "A saved config key was found — press Enter to use it, or type a key/file path.".to_string()
        } else {
            "Paste your NVIDIA NIM API key, or the path to a provider config file (TOML/JSON/env).".to_string()
        };
        SetupState {
            stage: Stage::Provider,
            provider: String::new(),
            provider_setup: None,
            connected: false,
            target: String::new(),
            status,
            error: None,
            models: Vec::new(),
            model_sel: 0,
            model: None,
            verify_msg: None,
            connect_job: None,
            base_url: crate::config::default_base_url(),
            quit: false,
            done: None,
        }
    }
}

/// Run the wizard. Returns None if the user aborted (Ctrl-C / Esc at step 1).
pub fn run_setup(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    rt: &tokio::runtime::Runtime,
    cfg: &Config,
) -> anyhow::Result<Option<SetupOutcome>> {
    let mut state = SetupState::new(cfg);

    loop {
        terminal.draw(|f| draw_setup(f, &state))?;

        if crossterm::event::poll(std::time::Duration::from_millis(80))? {
            if let Event::Key(key) = crossterm::event::read()? {
                if key.kind == KeyEventKind::Press {
                    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c')
                    {
                        return Ok(None);
                    }
                    match state.stage {
                        Stage::Provider => handle_provider(&mut state, key.code, cfg, rt),
                        Stage::Connecting => {}
                        Stage::Target => handle_target(&mut state, key.code),
                        Stage::Models => handle_models(&mut state, key.code, rt),
                    }
                }
            }
        }

        // poll the connect + verify job
        if state.stage == Stage::Connecting {
            if let Some(job) = state.connect_job.take() {
                if job.is_finished() {
                    match rt.block_on(job) {
                        Ok(Ok((models, verify))) => {
                            state.models = models;
                            let want = state.provider_setup.as_ref().and_then(|p| p.model.clone());
                            if let Some(ref w) = want {
                                if let Some(i) = state.models.iter().position(|m| m == w) {
                                    state.model_sel = i;
                                }
                            }
                            state.model = state
                                .models
                                .get(state.model_sel)
                                .cloned()
                                .or(want);
                            state.verify_msg = Some(verify);
                            state.connected = true;
                            state.status = format!(
                                "✔ Provider online — {} models, chat verified",
                                state.models.len()
                            );
                            state.error = None;
                            state.stage = Stage::Target;
                        }
                        Ok(Err(e)) => {
                            state.error = Some(format!("{}", e));
                            state.stage = Stage::Provider;
                        }
                        Err(e) => {
                            state.error = Some(format!("connection task error: {}", e));
                            state.stage = Stage::Provider;
                        }
                    }
                } else {
                    state.connect_job = Some(job);
                }
            }
        }

        if state.quit {
            return Ok(None);
        }
        if let Some(out) = state.done.take() {
            return Ok(Some(out));
        }
    }
}

fn start_connect(state: &mut SetupState, cfg: &Config, rt: &tokio::runtime::Runtime) {
    let input = state.provider.trim().to_string();
    let setup = if input.is_empty() {
        cfg.nvidia
            .api_key
            .clone()
            .filter(|k| !k.is_empty())
            .map(|k| ProviderSetup {
                base_url: cfg
                    .nvidia
                    .base_url
                    .clone()
                    .unwrap_or_else(crate::config::default_base_url),
                model: cfg.nvidia.model.clone(),
                api_key: k,
            })
    } else {
        match resolve_provider_input(&input) {
            Ok(s) => Some(s),
            Err(e) => {
                state.error = Some(format!("{}", e));
                return;
            }
        }
    };

    let setup = match setup {
        Some(s) => s,
        None => {
            state.error = Some("nothing to connect: type a key or a config file path".into());
            return;
        }
    };
    state.base_url = setup.base_url.clone();
    state.model = setup.model.clone();
    state.provider_setup = Some(setup.clone());

    let mut client = NvClient::new(&setup.base_url, &setup.api_key, "");
    let preferred = setup.model.clone();
    state.connect_job = Some(rt.spawn(async move {
        // list models AND find one that actually completes a chat — the
        // provider file's model is tried first; if it's EOL/unavailable the
        // best working model from the account is auto-selected instead.
        let (models, verify) = client.connect_and_select(preferred).await?;
        Ok((models, verify))
    }));
    state.status = "Connecting to the NVIDIA provider…".into();
    state.error = None;
    state.stage = Stage::Connecting;
}

fn handle_provider(state: &mut SetupState, key: KeyCode, cfg: &Config, rt: &tokio::runtime::Runtime) {
    match key {
        KeyCode::Char(c) => {
            if !c.is_control() && state.provider.len() < 400 {
                state.provider.push(c);
                state.error = None;
            }
        }
        KeyCode::Backspace => {
            state.provider.pop();
            state.error = None;
        }
        KeyCode::Enter | KeyCode::Char('t') => start_connect(state, cfg, rt),
        KeyCode::Char('x') => {
            // run without the NightCrawler agent
            state.stage = Stage::Target;
            state.status = "Agent disabled — the scan uses evidence-based defaults.".into();
            state.connected = false;
        }
        KeyCode::Esc => state.quit = true,
        _ => {}
    }
}

fn handle_target(state: &mut SetupState, key: KeyCode) {
    match key {
        KeyCode::Char(c) => {
            if !c.is_control() && state.target.len() < 200 {
                state.target.push(c);
            }
        }
        KeyCode::Backspace => {
            state.target.pop();
        }
        KeyCode::Enter => {
            if state.target.trim().is_empty() {
                return;
            }
            if state.connected {
                state.stage = Stage::Models;
            } else {
                // no agent — start immediately
                let target = state.target.trim().to_string();
                state.done = Some(SetupOutcome {
                    target,
                    nv: None,
                    provider_desc: "NightCrawler agent disabled".into(),
                });
            }
        }
        KeyCode::Esc => state.stage = Stage::Provider,
        _ => {}
    }
}

fn handle_models(state: &mut SetupState, key: KeyCode, rt: &tokio::runtime::Runtime) {
    match key {
        KeyCode::Down | KeyCode::Char('j') => {
            if !state.models.is_empty() {
                state.model_sel = (state.model_sel + 1).min(state.models.len() - 1);
                state.model = state.models.get(state.model_sel).cloned();
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            state.model_sel = state.model_sel.saturating_sub(1);
            state.model = state.models.get(state.model_sel).cloned();
        }
        KeyCode::Enter => {
            let model = state
                .model
                .clone()
                .or_else(|| state.models.first().cloned())
                .unwrap_or_default();
            if model.is_empty() {
                state.error = Some("no model selected".into());
                return;
            }
            let setup = state.provider_setup.clone().unwrap();
            let mut client = NvClient::new(&setup.base_url, &setup.api_key, &model);
            // verify the chosen model actually responds before committing
            state.status = format!("verifying {}…", model);
            match rt.block_on(async { client.ping(&model).await }) {
                Ok(()) => {
                    client.model = model.clone();
                    let target = state.target.trim().to_string();
                    state.done = Some(SetupOutcome {
                        target,
                        nv: Some(client),
                        provider_desc: format!("{} @ {}", model, setup.base_url),
                    });
                }
                Err(e) => {
                    state.status = String::new();
                    state.error = Some(format!("{} unusable: {}", model, e));
                }
            }
        }
        KeyCode::Char('x') => {
            let target = state.target.trim().to_string();
            state.done = Some(SetupOutcome {
                target,
                nv: None,
                provider_desc: "NightCrawler agent disabled".into(),
            });
        }
        KeyCode::Esc => state.stage = Stage::Target,
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

fn draw_setup(f: &mut Frame, s: &SetupState) {
    let area = centered(f.area(), 78, if s.stage == Stage::Models { 85 } else { 64 });
    f.render_widget(Clear, area);
    let block = Block::default()
        .title(" 🕷 NIGHT CRAWLER — SETUP ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::LightMagenta))
        .style(Style::default().bg(Color::Black));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::vertical([
        Constraint::Length(2), // banner
        Constraint::Length(1), // step indicator
        Constraint::Min(0),    // content
        Constraint::Length(2), // footer hints
    ])
    .split(inner);

    let banner = Line::from(vec![
        Span::styled(
            "NIGHT CRAWLER",
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" · autonomous recon agent", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(banner).alignment(Alignment::Center), rows[0]);

    // step indicator — provider comes FIRST (the correct flow)
    let steps = [
        ("1 PROVIDER", matches!(s.stage, Stage::Provider | Stage::Connecting | Stage::Models) || s.connected),
        ("2 TARGET", !s.target.is_empty() || matches!(s.stage, Stage::Target | Stage::Models)),
        ("3 MODEL", s.stage == Stage::Models),
    ];
    let mut spans = Vec::new();
    for (i, (label, active)) in steps.iter().enumerate() {
        let style = if *active {
            Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        spans.push(Span::styled(format!(" {} ", label), style));
        if i < steps.len() - 1 {
            spans.push(Span::styled("→", Style::default().fg(Color::DarkGray)));
        }
    }
    f.render_widget(
        Paragraph::new(Line::from(spans)).alignment(Alignment::Center),
        rows[1],
    );

    match s.stage {
        Stage::Provider | Stage::Connecting => draw_provider_stage(f, s, rows[2]),
        Stage::Target => draw_target_stage(f, s, rows[2]),
        Stage::Models => draw_models_stage(f, s, rows[2]),
    }

    let hint = match s.stage {
        Stage::Provider => " Enter/t: connect · x: run WITHOUT the agent · Esc: quit",
        Stage::Connecting => " connecting…",
        Stage::Target => " type the IP or domain · Enter: continue · Esc: back",
        Stage::Models => " ↑/↓: choose model · Enter: start scan · x: no agent · Esc: back",
    };
    let footer = Line::from(vec![
        Span::styled("keys:", Style::default().fg(Color::DarkGray)),
        Span::styled(hint, Style::default().fg(Color::Cyan)),
    ]);
    f.render_widget(
        Paragraph::new(footer)
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Center),
        rows[3],
    );
}

fn draw_provider_stage(f: &mut Frame, s: &SetupState, area: Rect) {
    let connecting = s.stage == Stage::Connecting;
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(2),
        Constraint::Min(0),
    ])
    .split(area);

    let label = Paragraph::new(Line::from(Span::styled(
        " Step 1 — NVIDIA provider: API key OR provider config file (TOML/JSON/env):",
        Style::default().fg(Color::LightCyan),
    )));
    f.render_widget(label, rows[0]);

    let input_text = if connecting {
        vec![
            Span::styled("> ", Style::default().fg(Color::LightMagenta)),
            Span::styled(&s.provider, Style::default().fg(Color::Green)),
        ]
    } else {
        vec![
            Span::styled("> ", Style::default().fg(Color::LightMagenta)),
            Span::styled(
                s.provider.clone(),
                Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD),
            ),
            Span::styled("▌", Style::default().fg(Color::LightMagenta)),
        ]
    };
    let border_color = if connecting { Color::Yellow } else { Color::Magenta };
    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    f.render_widget(Paragraph::new(Line::from(input_text)).block(input_block), rows[1]);

    let status_line = if connecting {
        let frame_idx = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            / 100) as usize
            % SPINNER.len();
        Line::from(vec![
            Span::styled(SPINNER[frame_idx], Style::default().fg(Color::LightMagenta)),
            Span::styled(format!(" {}", s.status), Style::default().fg(Color::Yellow)),
        ])
    } else if let Some(err) = &s.error {
        Line::from(Span::styled(
            format!(" ✖ {}", err),
            Style::default().fg(Color::Red),
        ))
    } else {
        Line::from(Span::styled(format!(" ℹ {}", s.status), Style::default().fg(Color::DarkGray)))
    };
    f.render_widget(Paragraph::new(status_line).wrap(Wrap { trim: true }), rows[2]);

    let mut lines = vec![
        Line::from(Span::styled(
            "accepted inputs:",
            Style::default().fg(Color::Gray).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  • raw key      nvapi-xxxxxxxxxxxxxxxxxxxxxxxx",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  • config file  ./nvidia.toml   { [nvidia] api_key/model/base_url }",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  • config file  provider.json   { \"api_key\": ..., \"model\": ... }",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  • env-style    keys.env        NVIDIA_API_KEY=... / MODEL=...",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    if let Some(setup) = &s.provider_setup {
        if !connecting {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(" loaded: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!(
                        "key {}… · {} ",
                        &setup.api_key.chars().take(10).collect::<String>(),
                        setup.base_url
                    ),
                    Style::default().fg(Color::Green),
                ),
                if let Some(m) = &setup.model {
                    Span::styled(format!("· model {}", m), Style::default().fg(Color::LightCyan))
                } else {
                    Span::raw("")
                },
            ]));
        }
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), rows[3]);
}

fn draw_target_stage(f: &mut Frame, s: &SetupState, area: Rect) {
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Min(0),
    ])
    .split(area);

    let label = Paragraph::new(Line::from(Span::styled(
        " Step 2 — Target (IP address or domain):",
        Style::default().fg(Color::LightCyan),
    )));
    f.render_widget(label, rows[0]);

    let content = Line::from(vec![
        Span::styled("> ", Style::default().fg(Color::LightMagenta)),
        Span::styled(
            s.target.clone(),
            Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD),
        ),
        Span::styled("▌", Style::default().fg(Color::LightMagenta)),
    ]);
    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));
    f.render_widget(Paragraph::new(content).block(input_block), rows[1]);

    let mut lines = vec![Line::from("")];
    if s.connected {
        lines.push(Line::from(vec![
            Span::styled(" ✔ ", Style::default().fg(Color::LightGreen)),
            Span::styled(&s.status, Style::default().fg(Color::Green)),
        ]));
        if let Some(v) = &s.verify_msg {
            lines.push(Line::from(vec![
                Span::styled("   ", Style::default()),
                Span::styled(v, Style::default().fg(Color::DarkGray)),
            ]));
        }
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        "You will not be asked for ports, modules or tools.",
        Style::default().fg(Color::Gray),
    )));
    lines.push(Line::from(Span::styled(
        "NightCrawler decides the scan strategy, picks modules, chains follow-up tasks",
        Style::default().fg(Color::Gray),
    )));
    lines.push(Line::from(Span::styled(
        "from the combined evidence, and writes the assessment report.",
        Style::default().fg(Color::Gray),
    )));
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), rows[2]);
}

fn draw_models_stage(f: &mut Frame, s: &SetupState, area: Rect) {
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(2),
    ])
    .split(area);

    let label = Line::from(vec![
        Span::styled(" Step 3 — ✔ ", Style::default().fg(Color::LightGreen)),
        Span::styled(
            s.base_url.clone(),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  ({} models, chat verified)", s.models.len()),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    f.render_widget(Paragraph::new(label), rows[0]);

    let items: Vec<ListItem> = s
        .models
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let selected = i == s.model_sel;
            let style = if selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::LightMagenta)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            let prefix = if selected { "▶ " } else { "  " };
            ListItem::new(Line::from(Span::styled(format!("{}{}", prefix, m), style)))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta))
                .title(" select the model NightCrawler will run as "),
        )
        .highlight_style(Style::default().bg(Color::LightMagenta).fg(Color::Black));
    let mut ls = ListState::default();
    ls.select(Some(s.model_sel));
    f.render_stateful_widget(list, rows[1], &mut ls);

    let chosen = s
        .model
        .clone()
        .or_else(|| s.models.first().cloned())
        .unwrap_or_default();
    let line = Line::from(vec![
        Span::styled(" NightCrawler model: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            chosen,
            Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  (shown in the scan header)", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(line).alignment(Alignment::Center), rows[2]);
}

fn centered(total: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let v = Layout::vertical([Constraint::Percentage(pct_y), Constraint::Percentage(100 - pct_y)])
        .split(total);
    let h = Layout::horizontal([Constraint::Percentage(pct_x), Constraint::Percentage(100 - pct_x)])
        .split(v[0]);
    h[0]
}
