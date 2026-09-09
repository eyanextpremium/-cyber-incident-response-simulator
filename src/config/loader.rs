use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::settings::Settings;

#[derive(Debug, Deserialize)]
pub struct DetectionRulesConfig {
    pub rules: Vec<DetectionRuleEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DetectionRuleEntry {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub pattern: String,
    pub source: String,
    pub enabled: bool,
}

pub fn load_settings(base: &Path) -> Result<Settings> {
    let path = base.join("config/simulator.toml");
    if path.exists() {
        Settings::from_toml(&path).context("failed to load simulator.toml")
    } else {
        Ok(Settings::default())
    }
}

pub fn load_detection_rules(base: &Path) -> Result<Vec<DetectionRuleEntry>> {
    let path = base.join("config/detection_rules.toml");
    if !path.exists() {
        return Ok(default_detection_rules());
    }
    let content = std::fs::read_to_string(&path)?;
    let config: DetectionRulesConfig = toml::from_str(&content)?;
    Ok(config.rules)
}

pub fn load_scoring_config(base: &Path) -> Result<ScoringConfig> {
    let path = base.join("config/scoring.toml");
    if !path.exists() {
        return Ok(ScoringConfig::default());
    }
    let content = std::fs::read_to_string(&path)?;
    let config: ScoringConfig = toml::from_str(&content)?;
    Ok(config)
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScoringConfig {
    pub max_score: f64,
    pub detection_points: f64,
    pub investigation_points: f64,
    pub containment_points: f64,
    pub recovery_points: f64,
    pub false_positive_penalty: f64,
    pub missed_alert_penalty: f64,
    pub time_penalty_factor: f64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            max_score: 100.0,
            detection_points: 25.0,
            investigation_points: 25.0,
            containment_points: 25.0,
            recovery_points: 25.0,
            false_positive_penalty: 5.0,
            missed_alert_penalty: 10.0,
            time_penalty_factor: 0.005,
        }
    }
}

pub fn resolve_base_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn default_detection_rules() -> Vec<DetectionRuleEntry> {
    vec![
        DetectionRuleEntry {
            id: "brute-force".into(),
            name: "Brute Force Detection".into(),
            description: "Multiple failed authentication attempts".into(),
            severity: "high".into(),
            pattern: r"(?i)failed.*(login|auth|password)".into(),
            source: "authentication".into(),
            enabled: true,
        },
        DetectionRuleEntry {
            id: "malware-exec".into(),
            name: "Suspicious Process Execution".into(),
            description: "Known malicious process patterns".into(),
            severity: "critical".into(),
            pattern: r"(?i)(powershell.*-enc|cmd\.exe.*\/c|wscript\.exe)".into(),
            source: "endpoint".into(),
            enabled: true,
        },
        DetectionRuleEntry {
            id: "lateral-movement".into(),
            name: "Lateral Movement".into(),
            description: "Internal network scanning or SMB activity".into(),
            severity: "high".into(),
            pattern: r"(?i)(smb|psexec|wmi|rdp.*connect)".into(),
            source: "network".into(),
            enabled: true,
        },
        DetectionRuleEntry {
            id: "data-exfil".into(),
            name: "Data Exfiltration".into(),
            description: "Large outbound data transfer".into(),
            severity: "critical".into(),
            pattern: r"(?i)(upload|exfil|large.*transfer|dns.*tunnel)".into(),
            source: "firewall".into(),
            enabled: true,
        },
        DetectionRuleEntry {
            id: "phishing".into(),
            name: "Phishing Email".into(),
            description: "Suspicious email with malicious link".into(),
            severity: "medium".into(),
            pattern: r"(?i)(phish|malicious.*link|credential.*harvest)".into(),
            source: "email".into(),
            enabled: true,
        },
    ]
}
