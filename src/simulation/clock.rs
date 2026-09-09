use chrono::{DateTime, Utc};

/// Simulation clock for tracking elapsed time within a session
#[derive(Debug, Clone)]
pub struct SimClock {
    pub started_at: DateTime<Utc>,
    pub paused_at: Option<DateTime<Utc>>,
    pub total_paused_secs: i64,
}

impl SimClock {
    pub fn new() -> Self {
        Self {
            started_at: Utc::now(),
            paused_at: None,
            total_paused_secs: 0,
        }
    }

    /// Elapsed active seconds (excluding paused time)
    pub fn elapsed_secs(&self) -> i64 {
        let now = self.paused_at.unwrap_or_else(Utc::now);
        (now - self.started_at).num_seconds() - self.total_paused_secs
    }

    pub fn pause(&mut self) {
        if self.paused_at.is_none() {
            self.paused_at = Some(Utc::now());
        }
    }

    pub fn resume(&mut self) {
        if let Some(paused_at) = self.paused_at.take() {
            self.total_paused_secs += (Utc::now() - paused_at).num_seconds();
        }
    }

    pub fn is_paused(&self) -> bool {
        self.paused_at.is_some()
    }
}

impl Default for SimClock {
    fn default() -> Self {
        Self::new()
    }
}
