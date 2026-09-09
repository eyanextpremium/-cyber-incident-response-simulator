use serde::{Deserialize, Serialize};

/// All scoring sub-metrics for a completed session
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScoreMetrics {
    /// Points for correctly detecting and acknowledging alerts
    pub detection_score: f64,
    /// Points for investigation depth (evidence collection, timeline)
    pub investigation_score: f64,
    /// Points for containment actions (isolate, block, contain)
    pub containment_score: f64,
    /// Points for recovery and incident closure
    pub recovery_score: f64,
    /// Penalty for time taken (higher is worse)
    pub time_penalty: f64,
    /// Penalty for false positives
    pub false_positive_penalty: f64,
    /// Total calculated score (0-100)
    pub total_score: f64,
    /// Elapsed time in seconds
    pub time_elapsed_secs: i64,
}

impl ScoreMetrics {
    pub fn calculate_total(&mut self) {
        let raw = self.detection_score
            + self.investigation_score
            + self.containment_score
            + self.recovery_score;
        let penalties = self.time_penalty + self.false_positive_penalty;
        self.total_score = (raw - penalties).clamp(0.0, 100.0);
    }
}
