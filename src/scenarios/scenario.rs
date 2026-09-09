use serde::{Deserialize, Serialize};

/// A single event definition in a scenario JSON file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioEvent {
    pub offset_secs: u64,
    pub source: String,
    pub event_type: String,
    pub message: String,
    pub host: String,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub user: Option<String>,
    pub is_malicious: bool,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScenarioScoring {
    pub detect_alert_bonus: f64,
    pub investigate_bonus: f64,
    pub contain_bonus: f64,
    pub speed_bonus_threshold_secs: u64,
}

/// A complete scenario definition loaded from JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub id: String,
    pub name: String,
    pub difficulty: String,
    pub category: String,
    pub description: String,
    pub objective: String,
    pub time_limit_secs: u64,
    pub scenario_type: String,
    pub target_hosts: Vec<String>,
    pub attacker_ips: Vec<String>,
    pub events: Vec<ScenarioEvent>,
    pub expected_actions: Vec<String>,
    pub hints: Vec<String>,
    pub scoring: ScenarioScoring,
}

impl Scenario {
    pub fn difficulty_level(&self) -> crate::scenarios::Difficulty {
        crate::scenarios::Difficulty::from_str(&self.difficulty)
    }
}
