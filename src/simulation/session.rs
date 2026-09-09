use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Status of a simulation session
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Active,
    Paused,
    Completed,
    Abandoned,
}

/// An active simulation session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimSession {
    pub id: String,
    pub scenario_id: String,
    pub analyst_name: String,
    pub status: SessionStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub score: f64,
    /// Index into scenario events — how many have been emitted so far
    pub event_cursor: usize,
}

impl SimSession {
    pub fn new(scenario_id: &str, analyst_name: &str) -> Self {
        Self {
            id: crate::utils::generate_uuid(),
            scenario_id: scenario_id.to_string(),
            analyst_name: analyst_name.to_string(),
            status: SessionStatus::Active,
            started_at: Utc::now(),
            completed_at: None,
            score: 0.0,
            event_cursor: 0,
        }
    }

    pub fn is_active(&self) -> bool {
        self.status == SessionStatus::Active
    }

    pub fn complete(&mut self, score: f64) {
        self.status = SessionStatus::Completed;
        self.completed_at = Some(Utc::now());
        self.score = score;
    }

    pub fn abandon(&mut self) {
        self.status = SessionStatus::Abandoned;
        self.completed_at = Some(Utc::now());
    }
}
