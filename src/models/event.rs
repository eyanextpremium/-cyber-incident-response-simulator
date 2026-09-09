use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Authentication,
    Firewall,
    Endpoint,
    WebServer,
    Email,
    Network,
    Dns,
    Syslog,
    Unknown,
}

impl EventSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Firewall => "firewall",
            Self::Endpoint => "endpoint",
            Self::WebServer => "web_server",
            Self::Email => "email",
            Self::Network => "network",
            Self::Dns => "dns",
            Self::Syslog => "syslog",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "authentication" | "auth" => Self::Authentication,
            "firewall" => Self::Firewall,
            "endpoint" => Self::Endpoint,
            "web_server" | "web" => Self::WebServer,
            "email" => Self::Email,
            "network" => Self::Network,
            "dns" => Self::Dns,
            "syslog" => Self::Syslog,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    pub source: EventSource,
    pub event_type: String,
    pub message: String,
    pub host: String,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub user: Option<String>,
    pub raw_log: String,
    pub mitre_technique: Option<String>,
    pub is_malicious: bool,
}

impl SecurityEvent {
    pub fn new(
        session_id: &str,
        source: EventSource,
        event_type: &str,
        message: &str,
        host: &str,
    ) -> Self {
        Self {
            id: crate::utils::generate_uuid(),
            session_id: session_id.to_string(),
            timestamp: Utc::now(),
            source,
            event_type: event_type.to_string(),
            message: message.to_string(),
            host: host.to_string(),
            source_ip: None,
            destination_ip: None,
            user: None,
            raw_log: message.to_string(),
            mitre_technique: None,
            is_malicious: false,
        }
    }
}
