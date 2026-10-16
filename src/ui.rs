use crate::state::{AppState, PhaseStatus, SharedState};
use crate::types::Severity;
use crossterm::event::{Event, KeyCode, KeyEventKind};
use crossterm::{execute, terminal};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io::Stdout;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub struct Tui {
    pub terminal: Terminal<ratatui::backend::CrosstermBackend<Stdout>>,
    findings_scroll: usize,
    log_scroll: usize,
    focus_logs: bool,
}

pub fn init() -> anyhow::Result<Tui> {
    terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, terminal::EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(std::io::stdout());
    let terminal = Terminal::new(backend)?;
    Ok(Tui {
        terminal,
        findings_scroll: 0,
        log_scroll: 0,
        focus_logs: false,
    })
}

pub fn restore() {
    let _ = execute!(std::io::stdout(), terminal::LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();
}

impl Tui {
    /// Blocking render loop until `state.done` becomes true or user quits.
    /// Returns true if the user requested an early quit.
    pub fn run(&mut self, shared: &Arc<SharedState>) -> anyhow::Result<bool> {
        let start = std::time::Instant::now();
        loop {
            {
                let state = shared.state.lock().unwrap();
                let fs = self.findings_scroll;
                let ls = self.log_scroll;
                let fl = self.focus_logs;
                self.terminal
                    .draw(|f| draw_ui(f, &state, start, fs, ls, fl))?;
            }

            if crossterm::event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = crossterm::event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
                            KeyCode::Char('j') | KeyCode::Down => self.scroll_down(shared),
                            KeyCode::Char('k') | KeyCode::Up => self.scroll_up(shared),
                            KeyCode::Tab => self.focus_logs = !self.focus_logs,
                            KeyCode::Char('g') => {
                                self.findings_scroll = 0;
                                self.log_scroll = 0;
                            }
                            _ => {}
                        }
                    }
                }
            }

            if shared.state.lock().unwrap().done {
                return Ok(false);
            }
        }
    }

    fn scroll_down(&mut self, shared: &Arc<SharedState>) {
        let s = shared.state.lock().unwrap();
        let max = if self.focus_logs {
            s.logs.len().saturating_sub(1)
        } else {
            s.findings.len()
        };
        let cur = if self.focus_logs {
            &mut self.log_scroll
        } else {
            &mut self.findings_scroll
        };
        if *cur < max {
            *cur += 1;
        }
    }

    fn scroll_up(&mut self, _shared: &Arc<SharedState>) {
        let cur = if self.focus_logs {
            &mut self.log_scroll
        } else {
            &mut self.findings_scroll
        };
        *cur = cur.saturating_sub(1);
    }

}

fn draw_ui(f: &mut Frame, s: &AppState, start: std::time::Instant, findings_scroll: usize, log_scroll: usize, focus_logs: bool) {
    let elapsed = start.elapsed().as_secs();

    let outer = Layout::vertical([
        Constraint::Length(3), // header
        Constraint::Min(0),    // main
        Constraint::Length(3), // footer (progress + help)
    ])
    .split(f.area());

    draw_header(f, s, outer[0], elapsed);
    draw_main(f, s, outer[1], findings_scroll, log_scroll, focus_logs);
    draw_footer(f, s, outer[2]);
}

fn draw_header(f: &mut Frame, s: &AppState, area: Rect, elapsed: u64) {
        let mins = elapsed / 60;
        let secs = elapsed % 60;
        let open = s.stats.get("open_ports").copied().unwrap_or(0);
        let subs = s.stats.get("subdomain").copied().unwrap_or(0);
        let vulns = s.stats.get("vuln").copied().unwrap_or(0);
        let nodes = s.stats.get("graph_nodes").copied().unwrap_or(0);
        let ai = s.ai_note.clone().unwrap_or_else(|| "AI: off".into());

        let header = Line::from(vec![
            Span::styled(
                " NIGHT CRAWLER ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::LightMagenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled("🕷", Style::default().fg(Color::Magenta)),
            Span::raw(format!(" target: {}", trunc(&s.target_label, (area.width as usize).saturating_sub(64)))),
            Span::raw("  │  "),
            Span::styled(format!("⏱ {:02}:{:02}", mins, secs), Style::default().fg(Color::Cyan)),
            Span::raw("  │  "),
            Span::styled(format!("ports:{}", open), Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::styled(format!("subs:{}", subs), Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::styled(format!("vulns:{}", vulns), Style::default().fg(Color::Red)),
            Span::raw(" "),
            Span::styled(format!("graph:{}", nodes), Style::default().fg(Color::Blue)),
            Span::raw("  │  "),
            match &s.ai_note {
                Some(model) => Span::styled(model.clone(), Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                None => Span::styled("🕷 NightCrawler (no model)", Style::default().fg(Color::DarkGray)),
            },
        ]);

        let block = Block::default()
            .title(" NIGHT CRAWLER — autonomous recon agent ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Magenta));
        let para = Paragraph::new(header)
            .block(block)
            .style(Style::default().fg(Color::Gray));
        f.render_widget(para, area);
    }

fn draw_main(f: &mut Frame, s: &AppState, area: Rect, findings_scroll: usize, log_scroll: usize, focus_logs: bool) {
    let cols = Layout::horizontal([
        Constraint::Percentage(26), // phases
        Constraint::Percentage(36), // NightCrawler agent brain
        Constraint::Percentage(38), // findings + log
    ])
    .split(area);

    draw_phases(f, s, cols[0]);
    draw_agent(f, s, cols[1]);

    let right = Layout::vertical([
        Constraint::Percentage(62),
        Constraint::Percentage(38),
    ])
    .split(cols[2]);

    draw_findings(f, s, right[0], findings_scroll, focus_logs);
    draw_logs(f, s, right[1], log_scroll, focus_logs);
}

fn frame_now() -> usize {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        / 120) as usize
        % SPINNER.len()
}

/// The agent brain panel: identity, live state, task queue, reasoning feed.
fn draw_agent(f: &mut Frame, s: &AppState, area: Rect) {
    let block = Block::default()
        .title(" 🕷 NIGHTCRAWLER ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::LightMagenta));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::vertical([
        Constraint::Length(1), // identity + state
        Constraint::Length(1), // divider
        Constraint::Min(0),    // tasks + reasoning
    ])
    .split(inner);

    let (state_icon, state_text, state_color) = if s.ai_thinking {
        (
            SPINNER[frame_now()],
            "reasoning over the evidence…",
            Color::LightMagenta,
        )
    } else if s.done {
        ("✔", "assessment complete", Color::LightGreen)
    } else {
        ("▶", "acting", Color::LightGreen)
    };
    let identity = Line::from(vec![
        Span::styled(
            s.ai_note.clone().unwrap_or_else(|| "🕷 NightCrawler".into()),
            Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  │ ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{} {}", state_icon, state_text),
            Style::default().fg(state_color),
        ),
    ]);
    f.render_widget(Paragraph::new(identity), rows[0]);

    let div = "─".repeat(area.width.saturating_sub(2) as usize);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(div, Style::default().fg(Color::DarkGray)))),
        rows[1],
    );

    let mut lines: Vec<Line> = Vec::new();
    if !s.agent_tasks.is_empty() {
        lines.push(Line::from(Span::styled(
            " TASKS",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        for t in s.agent_tasks.iter().take(7) {
            let (icon, style) = match t.status {
                PhaseStatus::Pending => ("◌", Style::default().fg(Color::DarkGray)),
                PhaseStatus::Running => (
                    SPINNER[frame_now()],
                    Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD),
                ),
                PhaseStatus::Done => ("✔", Style::default().fg(Color::LightGreen)),
                PhaseStatus::Skipped(_) => ("–", Style::default().fg(Color::DarkGray)),
                PhaseStatus::Failed(_) => ("✖", Style::default().fg(Color::Red)),
            };
            lines.push(Line::from(vec![
                Span::styled(format!(" {} ", icon), style),
                Span::styled(t.name.clone(), style),
            ]));
        }
        lines.push(Line::from(""));
    }
    if !s.agent_reasoning.is_empty() {
        lines.push(Line::from(Span::styled(
            " REASONING",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        let start = s.agent_reasoning.len().saturating_sub(8);
        for r in s.agent_reasoning.iter().skip(start) {
            lines.push(Line::from(vec![
                Span::styled(" » ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    trunc(r, (area.width as usize).saturating_sub(4)),
                    Style::default().fg(Color::Gray),
                ),
            ]));
        }
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " the agent narrates its decisions here",
            Style::default().fg(Color::DarkGray),
        )));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), rows[2]);
}

fn draw_phases(f: &mut Frame, s: &AppState, area: Rect) {
        let block = Block::default()
            .title(" PHASES ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));
        let frame_idx = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            / 120) as usize
            % SPINNER.len();

        let mut items: Vec<ListItem> = Vec::new();
        for (i, p) in s.phases.iter().enumerate() {
            let (icon, style) = match &p.status {
                PhaseStatus::Pending => ("◌", Style::default().fg(Color::DarkGray)),
                PhaseStatus::Running => (
                    SPINNER[frame_idx],
                    Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD),
                ),
                PhaseStatus::Done => ("✔", Style::default().fg(Color::LightGreen)),
                PhaseStatus::Skipped(_) => ("–", Style::default().fg(Color::DarkGray)),
                PhaseStatus::Failed(_) => ("✖", Style::default().fg(Color::Red)),
            };
            let num = format!("{:>2}", i + 1);
            let mut spans = vec![
                Span::styled(format!("{} ", num), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{} ", icon), style),
                Span::styled(p.name.clone(), style),
            ];
            let summary = p.summary.trim();
            if !summary.is_empty() {
                spans.push(Span::styled(
                    format!("\n      {}", trunc(summary, area.width.saturating_sub(12) as usize)),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            items.push(ListItem::new(Line::from(spans)));
        }

        let list = List::new(items).block(block);
        f.render_widget(list, area);
    }

fn draw_findings(f: &mut Frame, s: &AppState, area: Rect, findings_scroll: usize, focus_logs: bool) {
        let block = Block::default()
            .title(" FINDINGS (j/k scroll) ")
            .borders(Borders::ALL)
            .border_style(if focus_logs {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::LightMagenta)
            });

        let inner_h = area.height.saturating_sub(2) as usize;
        let mut items: Vec<ListItem> = Vec::new();
        let total = s.findings.len();
        // tail-follow: scroll=0 shows the LATEST findings; scrolling down walks back in history
        let window = inner_h.max(1);
        let end_idx = total.saturating_sub(findings_scroll);
        let start_idx = end_idx.saturating_sub(window);

        for finding in s.findings.iter().take(end_idx).skip(start_idx) {
            let (sev_label, color) = match finding.severity {
                Severity::Critical => ("CRIT", Color::Red),
                Severity::High => ("HIGH", Color::LightRed),
                Severity::Medium => ("MED ", Color::Yellow),
                Severity::Low => ("LOW ", Color::LightYellow),
                Severity::Info => ("INFO", Color::DarkGray),
            };
            let cat_color = if finding.category == "nc" {
                Color::LightMagenta
            } else {
                Color::Blue
            };
            let title_color = if finding.category == "nc" {
                Color::LightCyan
            } else {
                Color::Reset
            };
            items.push(ListItem::new(Line::from(vec![
                Span::styled(" [", Style::default().fg(Color::DarkGray)),
                Span::styled(sev_label, Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Span::styled("] ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{:<10}", finding.category), Style::default().fg(cat_color)),
                Span::styled(trunc(&finding.title, (area.width as usize).saturating_sub(16)), Style::default().fg(title_color)),
            ])));
        }

        let state = ListState::default().with_selected(Some(0));
        let list = List::new(items).block(block);
        f.render_stateful_widget(list, area, &mut { state });
    }

fn draw_logs(f: &mut Frame, s: &AppState, area: Rect, log_scroll: usize, focus_logs: bool) {
        let block = Block::default()
            .title(" ACTIVITY LOG (Tab to focus) ")
            .borders(Borders::ALL)
            .border_style(if focus_logs {
                Style::default().fg(Color::LightMagenta)
            } else {
                Style::default().fg(Color::Cyan)
            });

        let inner_h = area.height.saturating_sub(2) as usize;
        let logs: Vec<&String> = if focus_logs {
            let start = log_scroll.min(s.logs.len().saturating_sub(1));
            let window = s.logs.iter().skip(start).take(inner_h).collect();
            window
        } else {
            // tail-follow when not focused
            s.logs.iter().rev().take(inner_h).rev().collect()
        };

        let mut text: Vec<Line> = Vec::new();
        for l in logs {
            text.push(Line::from(Span::styled(
                trunc(l, area.width.saturating_sub(2) as usize),
                Style::default().fg(Color::Green),
            )));
        }
        let para = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
        f.render_widget(para, area);
    }

fn draw_footer(f: &mut Frame, s: &AppState, area: Rect) {
        let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);

        // progress row
        if s.ai_thinking {
            let frame_idx = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                / 120) as usize
                % SPINNER.len();
            let line = Line::from(vec![
                Span::styled(
                    format!(" {} ", SPINNER[frame_idx]),
                    Style::default().fg(Color::LightMagenta),
                ),
                Span::styled(
                    "NightCrawler ▸ reasoning over the evidence…",
                    Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD),
                ),
            ]);
            f.render_widget(Paragraph::new(line), rows[0]);
        } else if let Some(p) = &s.progress {
            let ratio = if p.total == 0 {
                0.0
            } else {
                p.current as f64 / p.total as f64
            };
            let gauge = Gauge::default()
                .ratio(ratio.clamp(0.0, 1.0))
                .label(format!("{} {}/{}", p.label, p.current, p.total))
                .gauge_style(Style::default().fg(Color::Black).bg(Color::LightMagenta))
                .block(Block::default().borders(Borders::NONE));
            f.render_widget(gauge, rows[0]);
        } else if let Some(err) = &s.error {
            let line = Line::from(Span::styled(
                format!(" ✖ {}", err),
                Style::default().fg(Color::Red),
            ));
            f.render_widget(Paragraph::new(line), rows[0]);
        } else if s.done {
            let line = Line::from(Span::styled(
                " ✔ scan complete — see report",
                Style::default().fg(Color::LightGreen),
            ));
            f.render_widget(Paragraph::new(line), rows[0]);
        } else {
            let running: Vec<&String> = s
                .phases
                .iter()
                .filter(|p| p.status == PhaseStatus::Running)
                .map(|p| &p.name)
                .collect();
            let line = Line::from(Span::styled(
                format!(" ⏳ working: {}", running.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")),
                Style::default().fg(Color::DarkGray),
            ));
            f.render_widget(Paragraph::new(line), rows[0]);
        }

        // help row
        let help = Line::from(vec![
            Span::styled(" q", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
            Span::styled(" quit  ", Style::default().fg(Color::DarkGray)),
            Span::styled("j/k", Style::default().fg(Color::Cyan)),
            Span::styled(" scroll  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Tab", Style::default().fg(Color::Cyan)),
            Span::styled(" panel  ", Style::default().fg(Color::DarkGray)),
            Span::styled("g", Style::default().fg(Color::Cyan)),
            Span::styled(" top", Style::default().fg(Color::DarkGray)),
        ]);
        f.render_widget(Paragraph::new(help), rows[1]);
    }

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
    }
}

/// Plain-terminal mode: print phase transitions and findings as they happen.
pub async fn plain_watch(shared: Arc<SharedState>) {
    let mut last_phases: Vec<(String, PhaseStatus)> = Vec::new();
    let mut last_findings = 0usize;
    let mut last_log = 0usize;
    let mut last_rev: u64 = 0;

    loop {
        let (dirty, done) = {
            let s = shared.state.lock().unwrap();
            (
                shared.finding_rev.load(Ordering::Relaxed) != last_rev
                    || s.logs.len() != last_log
                    || s.phases.len() != last_phases.len()
                    || phase_status_changed(&s.phases, &last_phases),
                s.done,
            )
        };

        if dirty {
            let s = shared.state.lock().unwrap();
            // phase transitions
            for (i, p) in s.phases.iter().enumerate() {
                let changed = last_phases
                    .get(i)
                    .map(|(n, st)| n != &p.name || *st != p.status)
                    .unwrap_or(true);
                if changed {
                    match &p.status {
                        PhaseStatus::Running => println!("\x1b[1;35m▶ [{:02}] {}\x1b[0m", i + 1, p.name),
                        PhaseStatus::Done => println!("\x1b[1;32m✔ [{:02}] {}\x1b[0m — {}", i + 1, p.name, p.summary),
                        PhaseStatus::Skipped(r) => println!("\x1b[2m– [{:02}] {} (skipped: {})\x1b[0m", i + 1, p.name, r),
                        PhaseStatus::Failed(r) => println!("\x1b[1;31m✖ [{:02}] {} — {}\x1b[0m", i + 1, p.name, r),
                        PhaseStatus::Pending => {}
                    }
                }
            }
            last_phases = s
                .phases
                .iter()
                .map(|p| (p.name.clone(), p.status.clone()))
                .collect();

            // new findings
            while last_findings < s.findings.len() {
                let f = &s.findings[last_findings];
                let color = match f.severity {
                    Severity::Critical => "\x1b[1;31m",
                    Severity::High => "\x1b[0;31m",
                    Severity::Medium => "\x1b[0;33m",
                    Severity::Low => "\x1b[0;36m",
                    Severity::Info => "\x1b[2m",
                };
                println!(
                    "{}  └─ [{}] {}\x1b[0m",
                    color,
                    f.severity.label(),
                    f.title
                );
                last_findings += 1;
                last_rev = shared.finding_rev.load(Ordering::Relaxed);
            }

            // new logs
            let start = last_log.min(s.logs.len());
            for l in s.logs.iter().skip(start) {
                println!("\x1b[2m     · {}\x1b[0m", l);
            }
            last_log = s.logs.len();

            if let Some(p) = &s.progress {
                eprint!(
                    "\r\x1b[2K    {} {}/{}   ",
                    p.label, p.current, p.total
                );
                if p.current >= p.total {
                    eprintln!();
                }
            }
            drop(s);
        }

        if done {
            return;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

fn phase_status_changed(
    phases: &[crate::state::Phase],
    last: &[(String, PhaseStatus)],
) -> bool {
    if phases.len() != last.len() {
        return true;
    }
    phases
        .iter()
        .zip(last.iter())
        .any(|(p, (n, st))| p.name != *n || p.status != *st)
}
