use crate::database::Repository;
use crate::models::{Alert, Incident, IncidentSeverity, IncidentStatus};

use super::lifecycle::IncidentLifecycle;

/// High-level incident management operations
pub struct IncidentManager<'a> {
    repo: &'a Repository,
}

impl<'a> IncidentManager<'a> {
    pub fn new(repo: &'a Repository) -> Self {
        Self { repo }
    }

    /// Open a new incident from an acknowledged alert
    pub fn open_from_alert(
        &self,
        alert: &Alert,
        session_id: &str,
        scenario_id: &str,
    ) -> anyhow::Result<Incident> {
        let mut incident = Incident::new(
            session_id,
            scenario_id,
            &format!("Incident: {}", alert.title),
            alert.severity.clone(),
        );
        incident.description = format!(
            "Incident created from alert '{}'. Source: {}.",
            alert.title, alert.source
        );
        incident.alert_ids.push(alert.id.clone());
        self.repo.insert_incident(&incident)?;
        Ok(incident)
    }

    /// Create an incident directly (without an alert)
    pub fn create(
        &self,
        session_id: &str,
        scenario_id: &str,
        title: &str,
        severity: IncidentSeverity,
        description: &str,
    ) -> anyhow::Result<Incident> {
        let mut incident = Incident::new(session_id, scenario_id, title, severity);
        incident.description = description.to_string();
        self.repo.insert_incident(&incident)?;
        Ok(incident)
    }

    /// Advance incident to the next phase
    pub fn advance(
        &self,
        session_id: &str,
        incident_id: &str,
        target_status: IncidentStatus,
    ) -> anyhow::Result<Incident> {
        let incidents = self.repo.list_incidents(session_id)?;
        let mut incident = incidents
            .into_iter()
            .find(|i| i.id == incident_id)
            .ok_or_else(|| anyhow::anyhow!("Incident not found: {}", incident_id))?;

        IncidentLifecycle::transition(&mut incident, target_status)
            .map_err(|e| anyhow::anyhow!(e))?;

        self.repo.update_incident(&incident)?;
        Ok(incident)
    }

    /// Attach an alert to an existing incident
    pub fn attach_alert(
        &self,
        session_id: &str,
        incident_id: &str,
        alert_id: &str,
    ) -> anyhow::Result<()> {
        let incidents = self.repo.list_incidents(session_id)?;
        let mut incident = incidents
            .into_iter()
            .find(|i| i.id == incident_id)
            .ok_or_else(|| anyhow::anyhow!("Incident not found: {}", incident_id))?;

        if !incident.alert_ids.contains(&alert_id.to_string()) {
            incident.alert_ids.push(alert_id.to_string());
            incident.updated_at = chrono::Utc::now();
            self.repo.update_incident(&incident)?;
        }
        Ok(())
    }

    /// Get all open incidents for a session
    pub fn open_incidents(&self, session_id: &str) -> anyhow::Result<Vec<Incident>> {
        let incidents = self.repo.list_incidents(session_id)?;
        Ok(incidents
            .into_iter()
            .filter(|i| i.status != IncidentStatus::Closed)
            .collect())
    }
}
