use crate::database::Repository;
use crate::models::AlertStatus;

use super::actions::{ResponseAction, ResponseActionType};
use super::containment::ContainmentOps;
use super::eradication::EradicationOps;
use super::recovery::RecoveryOps;

/// High-level response engine accessible from the API
pub struct ResponseEngine<'a> {
    repo: &'a Repository,
}

#[derive(Debug, serde::Deserialize)]
pub struct ExecuteActionRequest {
    pub action_type: String,
    pub target: String,
    pub incident_id: Option<String>,
    pub details: Option<String>,
}

impl<'a> ResponseEngine<'a> {
    pub fn new(repo: &'a Repository) -> Self {
        Self { repo }
    }

    /// Execute an analyst-requested action and persist it
    pub fn execute(
        &self,
        session_id: &str,
        req: &ExecuteActionRequest,
    ) -> anyhow::Result<ResponseAction> {
        let action_type = ResponseActionType::from_str(&req.action_type)
            .ok_or_else(|| anyhow::anyhow!("Unknown action type: {}", req.action_type))?;

        let incident_id = req.incident_id.as_deref();
        let details = req.details.as_deref().unwrap_or("");

        let action = match action_type {
            ResponseActionType::IsolateHost => {
                ContainmentOps::isolate_host(session_id, incident_id, &req.target)
            }
            ResponseActionType::BlockIp => {
                ContainmentOps::block_ip(session_id, incident_id, &req.target)
            }
            ResponseActionType::Contain => {
                let iid = incident_id.unwrap_or(&req.target);
                ContainmentOps::contain_incident(session_id, iid, details)
            }
            ResponseActionType::DisableAccount => {
                EradicationOps::disable_account(session_id, incident_id, &req.target)
            }
            ResponseActionType::QuarantineFile => {
                EradicationOps::quarantine_file(session_id, incident_id, &req.target)
            }
            ResponseActionType::Eradicate => {
                let iid = incident_id.unwrap_or(&req.target);
                EradicationOps::eradicate(session_id, iid, details)
            }
            ResponseActionType::Recover => {
                let iid = incident_id.unwrap_or(&req.target);
                RecoveryOps::recover_systems(session_id, iid, details)
            }
            ResponseActionType::CloseIncident => {
                let iid = incident_id.unwrap_or(&req.target);
                RecoveryOps::close_incident(session_id, iid)
            }
            ResponseActionType::Acknowledge => {
                // Acknowledge an alert
                ResponseAction::new(
                    session_id,
                    ResponseActionType::Acknowledge,
                    &req.target,
                    &format!("Alert '{}' acknowledged by analyst", req.target),
                )
            }
            ResponseActionType::Investigate => ResponseAction::new(
                session_id,
                ResponseActionType::Investigate,
                &req.target,
                &format!("Investigation started on: {}", req.target),
            ),
        };

        let record = action.to_record();
        self.repo.insert_action(&record)?;
        Ok(action)
    }

    /// Acknowledge an alert and update its status
    pub fn acknowledge_alert(&self, session_id: &str, alert_id: &str) -> anyhow::Result<()> {
        let mut alert = self
            .repo
            .get_alert(alert_id)?
            .ok_or_else(|| anyhow::anyhow!("Alert not found: {}", alert_id))?;

        alert.status = AlertStatus::Acknowledged;
        alert.acknowledged_at = Some(chrono::Utc::now());
        self.repo.update_alert(&alert)?;

        let action = ResponseAction::new(
            session_id,
            ResponseActionType::Acknowledge,
            alert_id,
            &format!("Alert acknowledged: {}", alert.title),
        );
        self.repo.insert_action(&action.to_record())?;
        Ok(())
    }
}
