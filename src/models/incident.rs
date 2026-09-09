use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    New,
    Investigating,
    Contained,
    Eradicated,
    Recovered,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl IncidentSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub session_id: String,
    pub title: String,
    pub description: String,
    pub status: IncidentStatus,
    pub severity: IncidentSeverity,
    pub scenario_id: String,
    pub assigned_to: Option<String>,
    pub alert_ids: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
}

impl Incident {
    pub fn new(
        session_id: &str,
        scenario_id: &str,
        title: &str,
        severity: IncidentSeverity,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: crate::utils::generate_uuid(),
            session_id: session_id.to_string(),
            title: title.to_string(),
            description: String::new(),
            status: IncidentStatus::New,
            severity,
            scenario_id: scenario_id.to_string(),
            assigned_to: None,
            alert_ids: Vec::new(),
            created_at: now,
            updated_at: now,
            closed_at: None,
        }
    }
}
