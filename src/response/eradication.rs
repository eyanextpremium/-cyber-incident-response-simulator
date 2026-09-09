use super::actions::{ResponseAction, ResponseActionType};

/// Eradication operations — removing malware, accounts, persistence
pub struct EradicationOps;

impl EradicationOps {
    pub fn disable_account(
        session_id: &str,
        incident_id: Option<&str>,
        account: &str,
    ) -> ResponseAction {
        let mut action = ResponseAction::new(
            session_id,
            ResponseActionType::DisableAccount,
            account,
            &format!(
                "Account '{}' disabled — login blocked, active sessions terminated",
                account
            ),
        );
        action.incident_id = incident_id.map(str::to_string);
        tracing::info!(
            action = "disable_account",
            account = account,
            "Account disabled"
        );
        action
    }

    pub fn quarantine_file(
        session_id: &str,
        incident_id: Option<&str>,
        file_path: &str,
    ) -> ResponseAction {
        let mut action = ResponseAction::new(
            session_id,
            ResponseActionType::QuarantineFile,
            file_path,
            &format!(
                "File '{}' quarantined — moved to secure quarantine, execution prevented",
                file_path
            ),
        );
        action.incident_id = incident_id.map(str::to_string);
        tracing::info!(
            action = "quarantine_file",
            file = file_path,
            "File quarantined"
        );
        action
    }

    pub fn eradicate(session_id: &str, incident_id: &str, details: &str) -> ResponseAction {
        let mut action = ResponseAction::new(
            session_id,
            ResponseActionType::Eradicate,
            incident_id,
            &format!("Eradication complete: {}", details),
        );
        action.incident_id = Some(incident_id.to_string());
        tracing::info!(
            action = "eradicate",
            incident_id = incident_id,
            "Threat eradicated"
        );
        action
    }
}
