use chrono::Utc;

use crate::models::{EventSource, SecurityEvent};
use crate::utils::generate_uuid;

use super::scenario::{Scenario, ScenarioEvent};

/// Converts scenario event definitions into SecurityEvent model instances
pub struct EventGenerator;

impl EventGenerator {
    /// Generate all SecurityEvents for a scenario, with timestamps offset from start_time
    pub fn generate_events(
        session_id: &str,
        scenario: &Scenario,
        start_time: chrono::DateTime<Utc>,
    ) -> Vec<SecurityEvent> {
        scenario
            .events
            .iter()
            .map(|se| Self::from_scenario_event(session_id, se, start_time))
            .collect()
    }

    /// Create a SecurityEvent from a scenario event definition
    pub fn from_scenario_event(
        session_id: &str,
        se: &ScenarioEvent,
        start_time: chrono::DateTime<Utc>,
    ) -> SecurityEvent {
        let timestamp = start_time + chrono::Duration::seconds(se.offset_secs as i64);

        SecurityEvent {
            id: generate_uuid(),
            session_id: session_id.to_string(),
            timestamp,
            source: EventSource::from_str(&se.source),
            event_type: se.event_type.clone(),
            message: se.message.clone(),
            host: se.host.clone(),
            source_ip: se.source_ip.clone(),
            destination_ip: se.destination_ip.clone(),
            user: se.user.clone(),
            raw_log: format_raw_log(se, timestamp),
            mitre_technique: se.mitre_technique.clone(),
            is_malicious: se.is_malicious,
        }
    }

    /// Generate a realistic benign "noise" event to mix in with malicious events
    pub fn noise_event(session_id: &str, host: &str) -> SecurityEvent {
        let messages = [
            (
                "authentication",
                "login_success",
                "Accepted password for svcuser from 10.0.1.2 port 22 ssh2",
            ),
            (
                "firewall",
                "connection_allow",
                "ALLOW TCP 10.0.1.15:45234 -> 10.0.1.20:80 (HTTP)",
            ),
            (
                "endpoint",
                "process_start",
                "Process started: chrome.exe by user jdoe (PID 1234)",
            ),
            (
                "web_server",
                "http_request",
                "HTTP GET /index.html from 10.0.2.5 - 200 OK",
            ),
            (
                "network",
                "dns_query",
                "DNS query: www.google.com -> 142.250.80.46",
            ),
        ];
        let idx = (Utc::now().timestamp_subsec_millis() as usize) % messages.len();
        let (source, etype, msg) = messages[idx];
        SecurityEvent {
            id: generate_uuid(),
            session_id: session_id.to_string(),
            timestamp: Utc::now(),
            source: EventSource::from_str(source),
            event_type: etype.to_string(),
            message: msg.to_string(),
            host: host.to_string(),
            source_ip: Some("10.0.1.2".to_string()),
            destination_ip: None,
            user: Some("svcuser".to_string()),
            raw_log: format!("[{}] {} {} {}", Utc::now().to_rfc3339(), host, source, msg),
            mitre_technique: None,
            is_malicious: false,
        }
    }
}

fn format_raw_log(se: &ScenarioEvent, ts: chrono::DateTime<Utc>) -> String {
    let user_str = se.user.as_deref().unwrap_or("-");
    let src_str = se.source_ip.as_deref().unwrap_or("-");
    format!(
        "[{}] host={} source={} type={} user={} src_ip={} msg={}",
        ts.to_rfc3339(),
        se.host,
        se.source,
        se.event_type,
        user_str,
        src_str,
        se.message
    )
}
