use crate::models::{Incident, IncidentStatus};

/// Incident lifecycle management
pub struct IncidentLifecycle;

impl IncidentLifecycle {
    /// Transition incident to a new status
    pub fn transition(
        incident: &mut Incident,
        target_status: IncidentStatus,
    ) -> Result<(), String> {
        // Validate status transitions
        let valid_transitions = match incident.status {
            IncidentStatus::New => vec![IncidentStatus::Investigating, IncidentStatus::Closed],
            IncidentStatus::Investigating => {
                vec![IncidentStatus::Contained, IncidentStatus::Closed]
            }
            IncidentStatus::Contained => vec![IncidentStatus::Eradicated, IncidentStatus::Closed],
            IncidentStatus::Eradicated => vec![IncidentStatus::Recovered, IncidentStatus::Closed],
            IncidentStatus::Recovered => vec![IncidentStatus::Closed],
            IncidentStatus::Closed => vec![], // No transitions from closed
        };

        if !valid_transitions.contains(&target_status) {
            return Err(format!(
                "Invalid transition from {:?} to {:?}",
                incident.status, target_status
            ));
        }

        incident.status = target_status.clone();
        incident.updated_at = chrono::Utc::now();

        if target_status == IncidentStatus::Closed {
            incident.closed_at = Some(chrono::Utc::now());
        }

        Ok(())
    }
}
