//! Night Crawler Tauri Backend
//! 
//! This is the Tauri backend that exposes the scanning/agent functionality
//! to the frontend via Tauri commands.

use nightcrawler_lib::{run_recursive_agent, run_scan, Config, Opts, SharedState};
use anyhow::Result;
use std::sync::Arc;
use tauri::{Manager, State};

mod commands;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::start_scan,
            commands::get_state,
            commands::submit_target,
            commands::list_models,
            commands::stop_scan,
            commands::get_report,
        ])
        .setup(|app| {
            #[cfg(debug_assertions)]
            {
                let window = app.get_webview_window("main").unwrap();
                window.open_devtools();
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[derive(Default)]
pub struct AppState {
    pub shared: std::sync::Mutex<Option<Arc<SharedState>>>,
    pub scan_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<anyhow::Result<nightcrawler_lib::ReconResults>>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            shared: std::sync::Mutex::new(None),
            scan_handle: std::sync::Mutex::new(None),
        }
    }
}

mod commands {
    use super::*;
    use crate::nightcrawler_lib::{run_recursive_agent, run_scan, Config, Opts, SharedState, types::ReconResults};
    use anyhow::Result;
    use serde::Serialize;
    use std::sync::Arc;
    use tauri::{command, State};

    #[derive(Serialize)]
    pub struct ScanStateResponse {
        scan_started: bool,
        target: String,
        model: Option<String>,
        thinking: bool,
        done: bool,
        elapsed: i64,
        stats: std::collections::HashMap<String, u64>,
        progress: Option<ProgressInfo>,
        phases: Vec<PhaseInfo>,
        findings: Vec<FindingInfo>,
        tasks: Vec<TaskInfo>,
        reasoning: Vec<String>,
        logs: Vec<String>,
        error: Option<String>,
        geo: Option<GeoInfo>,
        scan_started: bool,
    }

    #[derive(Serialize)]
    pub struct ProgressInfo {
        label: String,
        current: u64,
        total: u64,
    }

    #[derive(Serialize)]
    pub struct PhaseInfo {
        name: String,
        status: String,
        summary: String,
        detail: String,
    }

    #[derive(Serialize)]
    pub struct FindingInfo {
        severity: String,
        category: String,
        title: String,
    }

    #[derive(Serialize)]
    pub struct TaskInfo {
        name: String,
        status: String,
        note: String,
    }

    #[derive(Serialize)]
    pub struct GeoInfo {
        city: Option<String>,
        country: Option<String>,
        region: Option<String>,
        isp: Option<String>,
        org: Option<String>,
        asn: Option<String>,
        lat: Option<f64>,
        lon: Option<f64>,
        timezone: Option<String>,
        zip: Option<String>,
    }

    #[command]
    pub async fn start_scan(
        target: String,
        provider: String,
        ports: Option<String>,
        recursive: bool,
        no_ai: bool,
        no_pivot: bool,
        state: State<'_, AppState>,
    ) -> Result<(), String> {
        let opts = crate::nightcrawler_lib::Opts {
            ports_spec: ports,
            wordlist_subs: None,
            wordlist_dirs: None,
            snmp_communities: None,
            enable_ai: true,
            allow_pivot: true,
            output_dir: std::path::PathBuf::from("./reports"),
        };

        let cfg = crate::nightcrawler_lib::Config::load(None);

        // Resolve provider
        let nv = if !provider.is_empty() {
            let setup = crate::nightcrawler_lib::config::resolve_provider_input(&provider)
                .map_err(|e| format!("Provider config error: {}", e))?;
            let mut client = crate::nightcrawler_lib::ai::NvClient::new(
                &setup.base_url, &setup.api_key, "");
            match crate::nightcrawler_lib::ai::NvClient::connect_and_select(&mut client, setup.model.clone()).await {
                Ok((_, sel)) => {
                    log::info!("[*] {}", sel.note);
                    Some(client)
                }
                Err(e) => {
                    log::warn!("[!] agent unavailable: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let shared = Arc::new(crate::state::SharedState::new(target.clone()));
        let shared_clone = shared.clone();
        let scan_nv = nv.clone();
        let scan_target = target.clone();
        let scan_opts = crate::nightcrawler_lib::Opts {
            ports_spec: None,
            wordlist_subs: None,
            wordlist_dirs: None,
            snmp_communities: None,
            enable_ai: true,
            allow_pivot: true,
            output_dir: std::path::PathBuf::from("./reports"),
        };
        let cfg = crate::nightcrawler_lib::Config::load(None);

        // Store shared state
        {
            let mut guard = state.shared.lock().unwrap();
            *guard = Some(shared_clone);
        }

        // Spawn scan task
        let handle = tokio::spawn(async move {
            let scan_shared = shared.clone();
            let scan_nv = nv.clone();
            let scan_target = target.clone();
            let scan_opts = crate::nightcrawler_lib::Opts {
                ports_spec: None,
                wordlist_subs: None,
                wordlist_dirs: None,
                snmp_communities: None,
                enable_ai: true,
                allow_pivot: true,
                output_dir: std::path::PathBuf::from("./reports"),
            };
            let cfg = crate::nightcrawler_lib::Config::load(None);
            let use_recursive = true;
            let scan_nv = nv.clone();

            if true { // recursive mode
                crate::nightcrawler_lib::run_recursive_agent(
                    &scan_target,
                    &crate::nightcrawler_lib::Opts {
                        ports_spec: None,
                        wordlist_subs: None,
                        wordlist_dirs: None,
                        snmp_communities: None,
                        enable_ai: true,
                        allow_pivot: true,
                        output_dir: std::path::PathBuf::from("./reports"),
                    },
                    &cfg,
                    scan_shared,
                    scan_nv,
                ).await
            } else {
                crate::nightcrawler_lib::run_scan(
                    &scan_target,
                    &crate::nightcrawler_lib::Opts {
                        ports_spec: None,
                        wordlist_subs: None,
                        wordlist_dirs: None,
                        snmp_communities: None,
                        enable_ai: true,
                        allow_pivot: true,
                        output_dir: std::path::PathBuf::from("./reports"),
                    },
                    &cfg,
                    scan_shared,
                    scan_nv,
                ).await
            }
        });

        {
            let mut guard = state.scan_handle.lock().unwrap();
            *guard = Some(handle);
        }

        Ok(())
    }

    #[command]
    pub async fn get_state(state: State<'_, AppState>) -> Result<ScanStateResponse, String> {
        let guard = state.shared.lock().unwrap();
        if let Some(shared) = guard.as_ref() {
            let s = shared.state.lock().unwrap();
            let scan_started = s.scan_started;
            
            let phases: Vec<PhaseInfo> = s.phases.iter().map(|p| PhaseInfo {
                name: p.name.clone(),
                status: match &p.status {
                    crate::state::PhaseStatus::Pending => "pending".to_string(),
                    crate::state::PhaseStatus::Running => "running".to_string(),
                    crate::state::PhaseStatus::Done => "done",
                    crate::state::PhaseStatus::Skipped(r) => format!("skipped: {}", r),
                    crate::state::PhaseStatus::Failed(r) => format!("failed: {}", r),
                }.to_string(),
                summary: p.summary.clone(),
                detail: match &p.status {
                    crate::state::PhaseStatus::Skipped(r) | crate::state::PhaseStatus::Failed(r) => r.clone(),
                    _ => String::new(),
                },
            }).collect();

            let findings: Vec<FindingInfo> = s.findings.iter().map(|f| FindingInfo {
                severity: f.severity.label().to_string(),
                category: f.category.clone(),
                title: f.title.clone(),
            }).collect();

            let tasks: Vec<TaskInfo> = s.agent_tasks.iter().map(|t| TaskInfo {
                name: t.name.clone(),
                status: match t.status {
                    crate::state::PhaseStatus::Pending => "pending".to_string(),
                    crate::state::PhaseStatus::Running => "running".to_string(),
                    crate::state::PhaseStatus::Done => "done",
                    crate::state::PhaseStatus::Skipped(_) => "skipped",
                    crate::state::PhaseStatus::Failed(_) => "failed",
                }.to_string(),
                note: t.note.clone(),
            }).collect();

            let geo = s.geo.as_ref().map(|g| GeoInfo {
                city: g.city.clone(),
                country: g.country.clone(),
                region: g.region.clone(),
                isp: g.isp.clone(),
                org: g.org.clone(),
                asn: g.asn.clone(),
                lat: g.lat,
                lon: g.lon,
                timezone: g.timezone.clone(),
                zip: g.zip.clone(),
            });

            Ok(ScanStateResponse {
                scan_started: s.scan_started,
                target: s.target_label.clone(),
                model: s.ai_note.clone(),
                thinking: s.ai_thinking,
                done: s.done,
                elapsed: (chrono::Local::now() - s.started).num_seconds(),
                stats: s.stats.clone(),
                progress: s.progress.as_ref().map(|p| ProgressInfo {
                    label: p.label.clone(),
                    current: p.current,
                    total: p.total,
                }),
                phases,
                findings,
                tasks,
                reasoning: s.agent_reasoning.clone(),
                logs: s.logs.iter().rev().take(40).rev().cloned().collect(),
                error: s.error.clone(),
                geo,
                scan_started,
            })
        } else {
            Ok(ScanStateResponse {
                scan_started: false,
                target: String::new(),
                model: None,
                thinking: false,
                done: false,
                elapsed: 0,
                stats: std::collections::HashMap::new(),
                progress: None,
                phases: vec![],
                findings: vec![],
                tasks: vec![],
                reasoning: vec![],
                logs: vec![],
                error: None,
                geo: None,
                scan_started: false,
            })
        }
    }

    #[command]
    pub async fn submit_target(
        target: String,
        provider: String,
        state: State<'_, AppState>,
    ) -> Result<(), String> {
        if target.trim().is_empty() {
            return Err("Target cannot be empty".to_string());
        }

        let nv = if !provider.trim().is_empty() {
            let setup = crate::nightcrawler_lib::config::resolve_provider_input(&provider)
                .map_err(|e| format!("Provider config error: {}", e))?;
            let mut client = crate::nightcrawler_lib::ai::NvClient::new(
                &setup.base_url, &setup.api_key, "");
            match crate::nightcrawler_lib::ai::NvClient::connect_and_select(
                &mut client, setup.model.clone()).await {
                Ok((_, sel)) => {
                    log::info!("[*] {}", sel.note);
                    Some(client)
                }
                Err(e) => {
                    log::warn!("[!] agent unavailable: {}", e);
                    None
                }
            }
        } else {
            None
        };

        target = target.trim().to_string();
        shared.scan_started(&target);

        // Spawn scan task
        let scan_shared = shared.clone();
        let scan_nv = nv.clone();
        let scan_target = target.clone();
        let scan_opts = crate::nightcrawler_lib::Opts {
            ports_spec: None,
            wordlist_subs: None,
            wordlist_dirs: None,
            snmp_communities: None,
            enable_ai: true,
            allow_pivot: true,
            output_dir: std::path::PathBuf::from("./reports"),
        };
        let cfg_clone = crate::nightcrawler_lib::Config::load(None);
        let use_recursive = true;

        let handle = tokio::spawn(async move {
            let scan_shared = shared.clone();
            let scan_nv = nv.clone();
            let scan_target = target.clone();
            let scan_opts = crate::nightcrawler_lib::Opts {
                ports_spec: None,
                wordlist_subs: None,
                wordlist_dirs: None,
                snmp_communities: None,
                enable_ai: true,
                allow_pivot: true,
                output_dir: std::path::PathBuf::from("./reports"),
            };
            let cfg_clone = crate::nightcrawler_lib::Config::load(None);
            let use_recursive = true;
            let scan_nv = nv.clone();

            let scan_shared = shared.clone();
            let scan_nv = nv.clone();
            let scan_target = target.clone();
            let scan_opts = crate::nightcrawler_lib::Opts {
                ports_spec: None,
                wordlist_subs: None,
                wordlist_dirs: None,
                snmp_communities: None,
                enable_ai: true,
                allow_pivot: true,
                output_dir: std::path::PathBuf::from("./reports"),
            };
            let cfg_clone = crate::nightcrawler_lib::Config::load(None);
            let use_recursive = true;
            let scan_nv = nv.clone();

            if true {
                crate::nightcrawler_lib::run_recursive_agent(
                    &scan_target,
                    &crate::nightcrawler_lib::Opts {
                        ports_spec: None,
                        wordlist_subs: None,
                        wordlist_dirs: None,
                        snmp_communities: None,
                        enable_ai: true,
                        allow_pivot: true,
                        output_dir: std::path::PathBuf::from("./reports"),
                    },
                    &cfg,
                    scan_shared,
                    scan_nv,
                ).await
            } else {
                crate::nightcrawler_lib::run_scan(
                    &scan_target,
                    &crate::nightcrawler_lib::Opts {
                        ports_spec: None,
                        wordlist_subs: None,
                        wordlist_dirs: None,
                        snmp_communities: None,
                        enable_ai: true,
                        allow_pivot: true,
                        output_dir: std::path::PathBuf::from("./reports"),
                    },
                    &cfg,
                    shared,
                    scan_nv,
                ).await
            }
        });

        {
            let mut guard = state.scan_handle.lock().unwrap();
            *guard = Some(handle);
        }

        Ok(())
    }

    #[command]
    pub async fn stop_scan(state: State<'_, AppState>) -> Result<(), String> {
        let mut guard = state.scan_handle.lock().unwrap();
        if let Some(handle) = guard.take() {
            handle.abort();
        }
        Ok(())
    }

    #[command]
    pub async fn get_report(state: State<'_, AppState>) -> Result<String, String> {
        let guard = state.shared.lock().unwrap();
        if let Some(shared) = guard.as_ref() {
            let s = shared.state.lock().unwrap();
            if let Some(path) = &s.report_path {
                return Ok(path.clone());
            }
        }
        Err("Report not ready".to_string())
    }

    #[command]
    pub async fn list_models(api_key: String, base_url: Option<String>) -> Result<Vec<String>, String> {
        let client = crate::nightcrawler_lib::ai::NvClient::new(
            &base_url.unwrap_or_else(|| "https://integrate.api.nvidia.com/v1".to_string()),
            &api_key, "");
        let models = client.list_models().await
            .map_err(|e| format!("Failed to list models: {}", e))?;
        Ok(models)
    }
}