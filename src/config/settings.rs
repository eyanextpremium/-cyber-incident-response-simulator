use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub server: ServerSettings,
    pub database: DatabaseSettings,
    pub simulation: SimulationSettings,
    pub scoring: ScoringSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub host: String,
    pub port: u16,
    pub static_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseSettings {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationSettings {
    pub tick_interval_ms: u64,
    pub max_events_per_tick: usize,
    pub scenario_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringSettings {
    pub detection_weight: f64,
    pub investigation_weight: f64,
    pub containment_weight: f64,
    pub recovery_weight: f64,
    pub time_penalty_factor: f64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server: ServerSettings {
                host: "127.0.0.1".to_string(),
                port: 8080,
                static_dir: "fronted".to_string(),
            },
            database: DatabaseSettings {
                path: "data/simulator.db".to_string(),
            },
            simulation: SimulationSettings {
                tick_interval_ms: 1000,
                max_events_per_tick: 10,
                scenario_dir: "scenarios".to_string(),
            },
            scoring: ScoringSettings {
                detection_weight: 0.25,
                investigation_weight: 0.25,
                containment_weight: 0.25,
                recovery_weight: 0.25,
                time_penalty_factor: 0.01,
            },
        }
    }
}

impl Settings {
    pub fn from_toml(path: &PathBuf) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let settings: Settings = toml::from_str(&content)?;
        Ok(settings)
    }
}
