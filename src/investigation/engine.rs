use crate::database::Repository;
use crate::models::Evidence;

use super::evidence::EvidenceCollector;
use super::queries::InvestigationQuery;
use super::timeline::Timeline;

/// High-level investigation engine accessible via API
pub struct InvestigationEngine<'a> {
    repo: &'a Repository,
}

impl<'a> InvestigationEngine<'a> {
    pub fn new(repo: &'a Repository) -> Self {
        Self { repo }
    }

    /// Build timeline for all events in a session
    pub fn build_timeline(&self, session_id: &str) -> anyhow::Result<Timeline> {
        let events = self.repo.list_events(session_id)?;
        Ok(Timeline::from_events(&events))
    }

    /// Collect evidence automatically from malicious events in session
    pub fn auto_collect_evidence(
        &self,
        session_id: &str,
        incident_id: Option<&str>,
    ) -> anyhow::Result<Vec<Evidence>> {
        let events = self.repo.list_events(session_id)?;
        let malicious = InvestigationQuery::malicious_only(&events);
        let mut collected = Vec::new();

        for event in malicious {
            let mut evidence = EvidenceCollector::from_event(session_id, event);
            if let Some(iid) = incident_id {
                evidence.incident_id = Some(iid.to_string());
            }
            self.repo.insert_evidence(&evidence)?;
            collected.push(evidence);
        }
        Ok(collected)
    }

    /// Get a summary of investigation findings for a session
    pub fn summary(&self, session_id: &str) -> anyhow::Result<InvestigationSummary> {
        let events = self.repo.list_events(session_id)?;
        let evidence = self.repo.list_evidence(session_id)?;

        Ok(InvestigationSummary {
            total_events: events.len(),
            malicious_events: events.iter().filter(|e| e.is_malicious).count(),
            compromised_hosts: InvestigationQuery::compromised_hosts(&events),
            attacker_ips: InvestigationQuery::attacker_ips(&events),
            evidence_count: evidence.len(),
            ioc_matches: evidence.iter().filter(|e| e.ioc_match).count(),
        })
    }
}

#[derive(Debug, serde::Serialize)]
pub struct InvestigationSummary {
    pub total_events: usize,
    pub malicious_events: usize,
    pub compromised_hosts: Vec<String>,
    pub attacker_ips: Vec<String>,
    pub evidence_count: usize,
    pub ioc_matches: usize,
}
