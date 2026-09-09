use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    Log,
    File,
    Network,
    Memory,
    Registry,
    Process,
    Email,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub session_id: String,
    pub incident_id: Option<String>,
    pub evidence_type: EvidenceType,
    pub title: String,
    pub description: String,
    pub data: String,
    pub source_host: String,
    pub collected_at: DateTime<Utc>,
    pub ioc_match: bool,
}

impl Evidence {
    pub fn new(
        session_id: &str,
        evidence_type: EvidenceType,
        title: &str,
        data: &str,
        source_host: &str,
    ) -> Self {
        Self {
            id: crate::utils::generate_uuid(),
            session_id: session_id.to_string(),
            incident_id: None,
            evidence_type,
            title: title.to_string(),
            description: String::new(),
            data: data.to_string(),
            source_host: source_host.to_string(),
            collected_at: Utc::now(),
            ioc_match: false,
        }
    }
}
