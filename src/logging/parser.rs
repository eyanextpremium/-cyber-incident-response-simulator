use chrono::{DateTime, Utc};

use crate::models::{EventSource, SecurityEvent};
use crate::utils::generate_uuid;

/// Parse raw log strings into SecurityEvent representations
pub struct LogParser;

impl LogParser {
    /// Attempt to parse a raw syslog-style line into a SecurityEvent
    pub fn parse_line(
        session_id: &str,
        line: &str,
        host: &str,
        source: EventSource,
    ) -> Option<SecurityEvent> {
        if line.trim().is_empty() {
            return None;
        }

        // Extract timestamp if present (RFC3339 format)
        let (timestamp, message) = if line.starts_with('[') {
            let end = line.find(']').unwrap_or(0);
            let ts_str = &line[1..end];
            let ts = DateTime::parse_from_rfc3339(ts_str)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);
            (ts, line[end + 1..].trim().to_string())
        } else {
            (Utc::now(), line.to_string())
        };

        // Infer event type from content
        let event_type = infer_event_type(&message);

        Some(SecurityEvent {
            id: generate_uuid(),
            session_id: session_id.to_string(),
            timestamp,
            source,
            event_type,
            message: message.clone(),
            host: host.to_string(),
            source_ip: extract_ip(&message),
            destination_ip: None,
            user: extract_user(&message),
            raw_log: line.to_string(),
            mitre_technique: None,
            is_malicious: false,
        })
    }
}

fn infer_event_type(message: &str) -> String {
    let lower = message.to_lowercase();
    if lower.contains("failed") || lower.contains("failure") {
        "login_failure".to_string()
    } else if lower.contains("accepted") || lower.contains("success") {
        "login_success".to_string()
    } else if lower.contains("process") || lower.contains("exec") {
        "process_execution".to_string()
    } else if lower.contains("connect") {
        "connection".to_string()
    } else if lower.contains("dns") {
        "dns_query".to_string()
    } else {
        "generic".to_string()
    }
}

fn extract_ip(message: &str) -> Option<String> {
    // Simple IP pattern extraction using basic string search
    let parts: Vec<&str> = message.split_whitespace().collect();
    for part in &parts {
        let clean = part.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != ':');
        if is_ip_like(clean) {
            return Some(clean.to_string());
        }
    }
    None
}

fn is_ip_like(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn extract_user(message: &str) -> Option<String> {
    let lower = message.to_lowercase();
    if let Some(pos) = lower.find("for ") {
        let rest = &message[pos + 4..];
        let user = rest.split_whitespace().next()?;
        if !user.is_empty() && user.len() < 32 {
            return Some(user.to_string());
        }
    }
    None
}
