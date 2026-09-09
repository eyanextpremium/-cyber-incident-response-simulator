use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::incident::IncidentSeverity;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    New,
    Acknowledged,
    Investigating,
    Resolved,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub session_id: String,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: IncidentSeverity,
    pub status: AlertStatus,
    pub event_ids: Vec<String>,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
}

impl Alert {
    pub fn new(
        session_id: &str,
        rule_id: &str,
        title: &str,
        severity: IncidentSeverity,
        source: &str,
    ) -> Self {
        Self {
            id: crate::utils::generate_uuid(),
            session_id: session_id.to_string(),
            rule_id: rule_id.to_string(),
            title: title.to_string(),
            description: String::new(),
            severity,
            status: AlertStatus::New,
            event_ids: Vec::new(),
            source: source.to_string(),
            created_at: Utc::now(),
            acknowledged_at: None,
            resolved_at: None,
        }
    }
}
