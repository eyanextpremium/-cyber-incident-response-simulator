use crate::config::ScoringConfig;
use crate::database::{Repository, ScoreRecord};
use crate::utils::generate_uuid;
use chrono::Utc;

use super::metrics::ScoreMetrics;
use super::ranking::Ranking;

/// Calculates scores based on analyst actions, events, and timing
pub struct ScoringEngine {
    config: ScoringConfig,
}

impl ScoringEngine {
    pub fn new(config: ScoringConfig) -> Self {
        Self { config }
    }

    /// Calculate the score for a completed session
    pub fn calculate(
        &self,
        session_id: &str,
        repo: &Repository,
        started_at: chrono::DateTime<Utc>,
    ) -> anyhow::Result<(ScoreMetrics, Ranking)> {
        let _events = repo.list_events(session_id)?;
        let alerts = repo.list_alerts(session_id)?;
        let incidents = repo.list_incidents(session_id)?;
        let actions = repo.list_actions(session_id)?;
        let evidence = repo.list_evidence(session_id)?;

        let elapsed_secs = (Utc::now() - started_at).num_seconds().max(1);

        // Detection score: points per acknowledged/resolved alert
        let total_malicious_alerts = alerts
            .iter()
            .filter(|a| {
                use crate::models::IncidentSeverity;
                matches!(
                    a.severity,
                    IncidentSeverity::High | IncidentSeverity::Critical
                )
            })
            .count();

        let acknowledged = alerts
            .iter()
            .filter(|a| {
                use crate::models::AlertStatus;
                matches!(
                    a.status,
                    AlertStatus::Acknowledged | AlertStatus::Investigating | AlertStatus::Resolved
                )
            })
            .count();

        let detection_score = if total_malicious_alerts > 0 {
            (acknowledged as f64 / total_malicious_alerts as f64) * self.config.detection_points
        } else {
            self.config.detection_points // no alerts means perfect
        };

        // Investigation score: points for evidence collected
        let investigation_score = if evidence.is_empty() {
            0.0
        } else {
            (evidence.len().min(10) as f64 / 10.0) * self.config.investigation_points
        };

        // Containment score: points for response actions
        let containment_actions = actions
            .iter()
            .filter(|a| {
                matches!(
                    a.action_type.as_str(),
                    "isolate_host" | "block_ip" | "contain" | "disable_account" | "quarantine_file"
                )
            })
            .count();

        let containment_score = if containment_actions > 0 {
            (containment_actions.min(5) as f64 / 5.0) * self.config.containment_points
        } else {
            0.0
        };

        // Recovery score: points for incident closure
        let closed = incidents
            .iter()
            .filter(|i| {
                use crate::models::IncidentStatus;
                matches!(i.status, IncidentStatus::Closed | IncidentStatus::Recovered)
            })
            .count();

        let recovery_score = if incidents.is_empty() {
            0.0
        } else {
            (closed as f64 / incidents.len() as f64) * self.config.recovery_points
        };

        // Time penalty: increases linearly with time
        let time_penalty = (elapsed_secs as f64 * self.config.time_penalty_factor).min(20.0);

        // False positive penalty: for alerts marked as false positive
        let false_positives = alerts
            .iter()
            .filter(|a| {
                use crate::models::AlertStatus;
                matches!(a.status, AlertStatus::FalsePositive)
            })
            .count();
        let false_positive_penalty =
            (false_positives as f64 * self.config.false_positive_penalty).min(20.0);

        let mut metrics = ScoreMetrics {
            detection_score,
            investigation_score,
            containment_score,
            recovery_score,
            time_penalty,
            false_positive_penalty,
            total_score: 0.0,
            time_elapsed_secs: elapsed_secs,
        };
        metrics.calculate_total();

        let ranking = Ranking::from_score(metrics.total_score, elapsed_secs);

        // Persist score
        let score_record = ScoreRecord {
            id: generate_uuid(),
            session_id: session_id.to_string(),
            detection_score: metrics.detection_score,
            investigation_score: metrics.investigation_score,
            containment_score: metrics.containment_score,
            recovery_score: metrics.recovery_score,
            total_score: metrics.total_score,
            time_elapsed_secs: elapsed_secs,
            calculated_at: Utc::now(),
        };
        repo.upsert_score(&score_record)?;

        Ok((metrics, ranking))
    }
}
