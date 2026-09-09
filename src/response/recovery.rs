use super::actions::{ResponseAction, ResponseActionType};

/// Recovery operations — restoring systems to operational state
pub struct RecoveryOps;

impl RecoveryOps {
    pub fn recover_systems(session_id: &str, incident_id: &str, details: &str) -> ResponseAction {
        let mut action = ResponseAction::new(
            session_id,
            ResponseActionType::Recover,
            incident_id,
            &format!("Recovery initiated: {}", details),
        );
        action.incident_id = Some(incident_id.to_string());
        tracing::info!(
            action = "recover",
            incident_id = incident_id,
            "Recovery initiated"
        );
        action
    }

    pub fn close_incident(session_id: &str, incident_id: &str) -> ResponseAction {
        let mut action = ResponseAction::new(
            session_id,
            ResponseActionType::CloseIncident,
            incident_id,
            "Incident formally closed after recovery verification",
        );
        action.incident_id = Some(incident_id.to_string());
        tracing::info!(
            action = "close_incident",
            incident_id = incident_id,
            "Incident closed"
        );
        action
    }
}
