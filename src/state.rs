use crate::types::Severity;
use chrono::{DateTime, Local};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq)]
pub enum PhaseStatus {
    Pending,
    Running,
    Done,
    Skipped(String),
    Failed(String),
}

impl PhaseStatus {
    pub fn short(&self) -> String {
        match self {
            PhaseStatus::Pending => "…".into(),
            PhaseStatus::Running => "▶".into(),
            PhaseStatus::Done => "✔".into(),
            PhaseStatus::Skipped(r) => format!("– ({})", truncate(r, 22)),
            PhaseStatus::Failed(r) => format!("✖ ({})", truncate(r, 22)),
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{}…", t)
    }
}

#[derive(Debug, Clone)]
pub struct Phase {
    pub name: String,
    pub status: PhaseStatus,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub title: String,
}

pub struct Progress {
    pub label: String,
    pub current: u64,
    pub total: u64,
}

pub struct AppState {
    pub target_label: String,
    pub started: DateTime<Local>,
    pub phases: Vec<Phase>,
    pub findings: Vec<Finding>,
    pub logs: Vec<String>,
    pub progress: Option<Progress>,
    pub stats: HashMap<String, u64>,
    pub done: bool,
    pub error: Option<String>,
    pub report_path: Option<String>,
    pub ai_note: Option<String>,
    pub ai_thinking: bool,
    pub next_finding_rev: u64,
}

impl AppState {
    pub fn new(target_label: String) -> Self {
        let phases = vec![
            "Resolve Target",
            "Host Liveness",
            "NightCrawler Port Strategy",
            "Port Scan",
            "Service & Version Detection",
            "Vulnerability Fingerprinting",
            "CVE Search (Google CSE)",
            "NightCrawler Planning",
            "DNS Recon",
            "Zone Transfer (AXFR)",
            "Subdomain Enumeration",
            "Web & Directory Discovery",
            "SNMP Enumeration",
            "LDAP Enumeration",
            "NetBIOS / SMB Enumeration",
            "WHOIS",
            "OSINT Dorking",
            "NightCrawler Follow-up",
            "Pivot Domains",
            "Link Analysis",
            "NightCrawler Analysis & Report",
            "Final Report",
        ]
        .into_iter()
        .map(|name| Phase {
            name: name.into(),
            status: PhaseStatus::Pending,
            summary: String::new(),
        })
        .collect();

        AppState {
            target_label,
            started: Local::now(),
            phases,
            findings: Vec::new(),
            logs: Vec::new(),
            progress: None,
            stats: HashMap::new(),
            done: false,
            error: None,
            report_path: None,
            ai_note: None,
            ai_thinking: false,
            next_finding_rev: 0,
        }
    }

    pub fn phase_idx(&self, name: &str) -> Option<usize> {
        self.phases.iter().position(|p| p.name == name)
    }
}

// Convenience handle shared between orchestrator (writer) and UI (reader).
pub struct SharedState {
    pub state: Mutex<AppState>,
    pub finding_rev: AtomicU64,
    pub ui_dirty: AtomicBool,
}

impl SharedState {
    pub fn new(target_label: String) -> Arc<Self> {
        Arc::new(SharedState {
            state: Mutex::new(AppState::new(target_label)),
            finding_rev: AtomicU64::new(0),
            ui_dirty: AtomicBool::new(true),
        })
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut AppState) -> R) -> R {
        let mut guard = self.state.lock().unwrap();
        let r = f(&mut guard);
        drop(guard);
        self.ui_dirty.store(true, Ordering::Relaxed);
        r
    }

    pub fn phase(&self, name: &str, status: PhaseStatus, summary: &str) {
        self.with(|s| {
            if let Some(i) = s.phase_idx(name) {
                s.phases[i].status = status;
                s.phases[i].summary = summary.to_string();
            }
        });
    }

    pub fn running(&self, name: &str) {
        self.phase(name, PhaseStatus::Running, "");
    }

    pub fn done(&self, name: &str, summary: &str) {
        self.phase(name, PhaseStatus::Done, summary);
    }

    pub fn skipped(&self, name: &str, reason: &str) {
        self.phase(name, PhaseStatus::Skipped(reason.to_string()), "");
    }

    pub fn failed(&self, name: &str, reason: &str) {
        self.phase(name, PhaseStatus::Failed(reason.to_string()), "");
    }

    pub fn finding(&self, severity: Severity, category: &str, title: &str) {
        self.with(|s| {
            s.findings.push(Finding {
                severity,
                category: category.into(),
                title: title.into(),
            });
            let key = category.to_string();
            *s.stats.entry(key).or_insert(0) += 1;
            *s.stats.entry("findings_total".into()).or_insert(0) += 1;
            s.next_finding_rev += 1;
        });
        self.finding_rev.fetch_add(1, Ordering::Relaxed);
    }

    pub fn log(&self, msg: impl AsRef<str>) {
        let line = msg.as_ref().to_string();
        self.with(|s| {
            s.logs.push(line);
            if s.logs.len() > 500 {
                s.logs.remove(0);
            }
        });
    }

    pub fn stat(&self, key: &str, val: u64) {
        self.with(|s| {
            s.stats.insert(key.to_string(), val);
        });
    }

    pub fn stat_add(&self, key: &str, delta: u64) {
        self.with(|s| {
            *s.stats.entry(key.to_string()).or_insert(0) += delta;
        });
    }

    pub fn progress(&self, label: &str, current: u64, total: u64) {
        self.with(|s| {
            s.progress = Some(Progress {
                label: label.to_string(),
                current,
                total,
            });
        });
    }

    pub fn clear_progress(&self) {
        self.with(|s| {
            s.progress = None;
        });
    }

    pub fn thinking(&self, on: bool) {
        self.with(|s| {
            s.ai_thinking = on;
        });
    }
}
