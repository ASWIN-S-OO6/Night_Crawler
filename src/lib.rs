//! Night Crawler Library
//! 
//! Core library for Night Crawler - scanning, agent, orchestration

pub mod agent;
pub mod ai;
pub mod config;
pub mod graph;
pub mod gui;
pub mod modules;
pub mod orchestrator;
pub mod report;
pub mod report_html;
pub mod state;
pub mod types;
pub mod util;

pub use crate::orchestrator::{run_scan, Opts};
pub use crate::modules::recursive_agent::run_recursive_agent;

pub use crate::types::*;
pub use crate::config::Config;
pub use crate::state::SharedState;