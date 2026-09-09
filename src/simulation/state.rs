use serde::{Deserialize, Serialize};

/// Global simulation state snapshot for the dashboard
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SimState {
    pub active_sessions: usize,
    pub total_events_generated: u64,
    pub total_alerts_fired: u64,
    pub total_incidents_opened: u64,
}

impl SimState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_events(&mut self, n: u64) {
        self.total_events_generated += n;
    }

    pub fn increment_alerts(&mut self, n: u64) {
        self.total_alerts_fired += n;
    }

    pub fn increment_incidents(&mut self, n: u64) {
        self.total_incidents_opened += n;
    }
}
