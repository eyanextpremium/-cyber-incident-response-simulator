use crate::models::{Evidence, EvidenceType, SecurityEvent};

/// Collects and enriches evidence from events and analyst actions
pub struct EvidenceCollector;

impl EvidenceCollector {
    /// Auto-collect evidence from a malicious event
    pub fn from_event(session_id: &str, event: &SecurityEvent) -> Evidence {
        let evidence_type = infer_evidence_type(&event.event_type);
        let mut evidence = Evidence::new(
            session_id,
            evidence_type,
            &format!("Auto-collected: {}", event.event_type),
            &event.raw_log,
            &event.host,
        );
        evidence.description = format!(
            "Evidence collected from {} event on host {}. Source: {}.",
            event.event_type,
            event.host,
            event.source.as_str()
        );
        evidence.ioc_match = event.is_malicious;
        evidence
    }

    /// Create manual evidence from analyst action
    pub fn manual(
        session_id: &str,
        incident_id: &str,
        evidence_type: EvidenceType,
        title: &str,
        data: &str,
        source_host: &str,
    ) -> Evidence {
        let mut e = Evidence::new(session_id, evidence_type, title, data, source_host);
        e.incident_id = Some(incident_id.to_string());
        e
    }
}

fn infer_evidence_type(event_type: &str) -> EvidenceType {
    let lower = event_type.to_lowercase();
    if lower.contains("file") || lower.contains("registry") {
        EvidenceType::File
    } else if lower.contains("network") || lower.contains("connection") || lower.contains("smb") {
        EvidenceType::Network
    } else if lower.contains("process") || lower.contains("execution") || lower.contains("macro") {
        EvidenceType::Process
    } else if lower.contains("memory") || lower.contains("lsass") || lower.contains("dump") {
        EvidenceType::Memory
    } else if lower.contains("email") || lower.contains("phish") {
        EvidenceType::Email
    } else if lower.contains("registry") {
        EvidenceType::Registry
    } else {
        EvidenceType::Log
    }
}
