use serde::{Deserialize, Serialize};

use crate::models::IncidentStatus;

/// Snapshot of the current simulation's incident state
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncidentState {
    pub total_incidents: usize,
    pub by_status: StatusCounts,
    pub critical_open: usize,
    pub high_open: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StatusCounts {
    pub new: usize,
    pub investigating: usize,
    pub contained: usize,
    pub eradicated: usize,
    pub recovered: usize,
    pub closed: usize,
}

impl IncidentState {
    pub fn from_incidents(incidents: &[crate::models::Incident]) -> Self {
        let mut state = Self::default();
        state.total_incidents = incidents.len();
        for inc in incidents {
            match &inc.status {
                IncidentStatus::New => state.by_status.new += 1,
                IncidentStatus::Investigating => state.by_status.investigating += 1,
                IncidentStatus::Contained => state.by_status.contained += 1,
                IncidentStatus::Eradicated => state.by_status.eradicated += 1,
                IncidentStatus::Recovered => state.by_status.recovered += 1,
                IncidentStatus::Closed => state.by_status.closed += 1,
            }
            if inc.status != IncidentStatus::Closed {
                use crate::models::IncidentSeverity;
                match &inc.severity {
                    IncidentSeverity::Critical => state.critical_open += 1,
                    IncidentSeverity::High => state.high_open += 1,
                    _ => {}
                }
            }
        }
        state
    }
}
