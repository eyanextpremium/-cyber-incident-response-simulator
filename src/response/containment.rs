use super::actions::{ResponseAction, ResponseActionType};

/// Containment operations — isolating and blocking threats
pub struct ContainmentOps;

impl ContainmentOps {
    pub fn isolate_host(
        session_id: &str,
        incident_id: Option<&str>,
        hostname: &str,
    ) -> ResponseAction {
        let mut action = ResponseAction::new(
            session_id,
            ResponseActionType::IsolateHost,
            hostname,
            &format!(
                "Host '{}' isolated from network — all inbound/outbound connections blocked",
                hostname
            ),
        );
        action.incident_id = incident_id.map(str::to_string);
        tracing::info!(
            action = "isolate_host",
            host = hostname,
            "Containment: host isolated"
        );
        action
    }

    pub fn block_ip(session_id: &str, incident_id: Option<&str>, ip: &str) -> ResponseAction {
        let mut action = ResponseAction::new(
            session_id,
            ResponseActionType::BlockIp,
            ip,
            &format!(
                "IP address '{}' blocked at firewall — all traffic from/to this IP denied",
                ip
            ),
        );
        action.incident_id = incident_id.map(str::to_string);
        tracing::info!(action = "block_ip", ip = ip, "Containment: IP blocked");
        action
    }

    pub fn contain_incident(session_id: &str, incident_id: &str, details: &str) -> ResponseAction {
        let mut action = ResponseAction::new(
            session_id,
            ResponseActionType::Contain,
            incident_id,
            &format!("Incident contained: {}", details),
        );
        action.incident_id = Some(incident_id.to_string());
        tracing::info!(
            action = "contain",
            incident_id = incident_id,
            "Containment applied"
        );
        action
    }
}
