//! Browser-based GUI: Night Crawler serves a live dashboard on localhost.
//! The page polls /state every 700ms and renders phases, the agent brain,
//! findings, progress and the log; when the scan finishes, /report serves
//! the graphical HTML report inline. The TUI remains available via --tui.

use crate::state::SharedState;
use std::io::Write;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

/// Pending scan launched from the GUI setup form.
pub struct StartRequest {
    pub target: String,
    pub provider: String, // raw key or config file path (may be empty)
}

static GUI_PORT: AtomicU16 = AtomicU16::new(7655);

pub fn gui_port() -> u16 {
    GUI_PORT.load(Ordering::Relaxed)
}

pub fn set_gui_port(p: u16) {
    GUI_PORT.store(p, Ordering::Relaxed);
}

/// Where the finished report.html lives (set by the scan when written).
static REPORT_PATH: Mutex<Option<String>> = Mutex::new(None);

/// Queue for scans started from the GUI (polled by main's launcher loop).
static PENDING_START: Mutex<Option<StartRequest>> = Mutex::new(None);

pub fn take_pending_start() -> Option<StartRequest> {
    PENDING_START.lock().ok().and_then(|mut g| g.take())
}

pub fn set_report_path(p: String) {
    if let Ok(mut g) = REPORT_PATH.lock() {
        *g = Some(p);
    }
}

const DASHBOARD: &str = include_str!("assets/dashboard.html");

/// Serve the GUI until the process exits. Call from a spawned task.
pub async fn serve(shared: Arc<SharedState>, ready: Option<tokio::sync::oneshot::Sender<()>>) -> anyhow::Result<()> {
    let port = gui_port();
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(_) => {
            // port busy — try the next
            GUI_PORT.fetch_add(1, Ordering::Relaxed);
            let p2 = gui_port();
            tokio::net::TcpListener::bind(("127.0.0.1", p2))
                .await
                .map_err(|e| anyhow::anyhow!("GUI bind failed on {}: {}", p2, e))?
        }
    };
    let bound = listener.local_addr()?.port();
    set_gui_port(bound);
    eprintln!("[*] GUI: http://127.0.0.1:{}", bound);

    // Signal that the server is ready
    if let Some(tx) = ready {
        let _ = tx.send(());
    }

    loop {
        let (mut sock, _) = listener.accept().await?;
        let shared = shared.clone();
        tokio::spawn(async move {
            let _ = handle_conn(&mut sock, &shared).await;
        });
    }
}

async fn handle_conn(
    sock: &mut tokio::net::TcpStream,
    shared: &Arc<SharedState>,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 4096];
    let n = sock.read(&mut buf).await.unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();

    if req.starts_with("POST /start") {
        let body_str = String::from_utf8_lossy(&buf[..n]).to_string();
        let target = extract_form_value(&body_str, "target");
        let provider = extract_form_value(&body_str, "provider");
        if target.trim().is_empty() {
            let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nno target";
            let _ = sock.write_all(resp.as_bytes()).await;
            return Ok(());
        }
        if let Ok(mut g) = PENDING_START.lock() {
            *g = Some(StartRequest {
                target: target.trim().to_string(),
                provider: provider.trim().to_string(),
            });
        }
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"ok\":true}";
        let _ = sock.write_all(resp.as_bytes()).await;
        return Ok(());
    }

    let (status, ctype, body) = match path.as_str() {
        "/" => ("200 OK", "text/html; charset=utf-8", DASHBOARD.to_string()),
        "/state" => ("200 OK", "application/json", snapshot_json(shared)),
        "/report" => match REPORT_PATH.lock().ok().and_then(|g| g.clone()) {
            Some(p) => match std::fs::read(&p) {
                Ok(bytes) => (
                    "200 OK",
                    "text/html; charset=utf-8",
                    String::from_utf8_lossy(&bytes).to_string(),
                ),
                Err(_) => ("503 Service Unavailable", "text/plain", "report not ready".into()),
            },
            None => ("503 Service Unavailable", "text/plain", "report not ready".into()),
        },
        "/health" => ("200 OK", "application/json", "{\"ok\":true}".into()),
        "/favicon.ico" => ("200 OK", "image/svg+xml", r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🕷</text></svg>"#.to_string()),
        _ => ("404 Not Found", "text/plain", "not found".into()),
    };

    let resp = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
        status,
        ctype,
        body.len(),
        body
    );
    let _ = sock.write_all(resp.as_bytes()).await;
    let _ = sock.flush();
    Ok(())
}

fn snapshot_json(shared: &Arc<SharedState>) -> String {
    let s = shared.state.lock().unwrap();
    let phases: Vec<serde_json::Value> = s
        .phases
        .iter()
        .map(|p| {
            serde_json::json!({
                "name": p.name,
                "status": match &p.status {
                    crate::state::PhaseStatus::Pending => "pending",
                    crate::state::PhaseStatus::Running => "running",
                    crate::state::PhaseStatus::Done => "done",
                    crate::state::PhaseStatus::Skipped(r) => "skipped",
                    crate::state::PhaseStatus::Failed(r) => "failed",
                },
                "summary": p.summary,
                "detail": match &p.status {
                    crate::state::PhaseStatus::Skipped(r) | crate::state::PhaseStatus::Failed(r) => r.clone(),
                    _ => String::new(),
                },
            })
        })
        .collect();
    let findings: Vec<serde_json::Value> = s
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "severity": f.severity.label().trim(),
                "category": f.category,
                "title": f.title,
            })
        })
        .collect();
    let tasks: Vec<serde_json::Value> = s
        .agent_tasks
        .iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "status": match t.status {
                    crate::state::PhaseStatus::Pending => "pending",
                    crate::state::PhaseStatus::Running => "running",
                    crate::state::PhaseStatus::Done => "done",
                    crate::state::PhaseStatus::Skipped(_) => "skipped",
                    crate::state::PhaseStatus::Failed(_) => "failed",
                },
            })
        })
        .collect();
    let reasoning: Vec<String> = s.agent_reasoning.clone();
    let logs: Vec<String> = s.logs.iter().rev().take(40).rev().cloned().collect();

    serde_json::json!({
        "scan_started": s.scan_started,
        "target": s.target_label,
        "model": s.ai_note,
        "thinking": s.ai_thinking,
        "done": s.done,
        "elapsed": (chrono::Local::now() - s.started).num_seconds(),
        "stats": s.stats,
        "progress": s.progress.as_ref().map(|p| serde_json::json!({
            "label": p.label, "current": p.current, "total": p.total,
        })),
        "phases": phases,
        "findings": findings,
        "tasks": tasks,
        "reasoning": reasoning,
        "logs": logs,
        "error": s.error,
        "geo": s.geo,
    })
    .to_string()
}

/// Extract a form-urlencoded value from a raw POST body.
fn extract_form_value(body: &str, key: &str) -> String {
    // split on both whitespace and & (form-urlencoded)
    let mut toks: Vec<&str> = Vec::new();
    for chunk in body.split_whitespace() {
        toks.extend(chunk.split('&'));
    }
    for pair in toks {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        if k == key {
            let v = it.next().unwrap_or("");
            return percent_decode(v);
        }
    }
    String::new()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Open the default browser at the GUI (best-effort, non-fatal).
pub fn open_browser(port: u16) {
    let url = format!("http://127.0.0.1:{}", port);
    let cmd: (&str, Vec<String>) = if cfg!(target_os = "windows") {
        ("cmd", vec!["/C".into(), "start".into(), url])
    } else if cfg!(target_os = "darwin") {
        ("open", vec![url])
    } else {
        ("xdg-open", vec![url])
    };
    let _ = std::process::Command::new(cmd.0)
        .args(cmd.1)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let _ = std::io::stdout().flush();
}
