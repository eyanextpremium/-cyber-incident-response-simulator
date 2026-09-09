use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::event::EventSource;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    pub source: EventSource,
    pub level: String,
    pub message: String,
    pub raw: String,
}

impl LogEntry {
    pub fn from_event(event: &super::event::SecurityEvent) -> Self {
        Self {
            id: event.id.clone(),
            session_id: event.session_id.clone(),
            timestamp: event.timestamp,
            source: event.source.clone(),
            level: if event.is_malicious {
                "warning".to_string()
            } else {
                "info".to_string()
            },
            message: event.message.clone(),
            raw: event.raw_log.clone(),
        }
    }
}
