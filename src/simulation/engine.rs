use std::sync::{Arc, Mutex};

use chrono::Utc;

use crate::config::ScoringConfig;
use crate::database::{DbPool, Repository};
use crate::detection::{DetectionEngine, DetectionRule};
use crate::scenarios::{EventGenerator, Scenario};

use super::session::SimSession;
use super::state::SimState;

/// Shared application state passed into the Axum router
#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub base_dir: std::path::PathBuf,
    pub scenario_dir: std::path::PathBuf,
    pub scoring_config: ScoringConfig,
    pub detection_rules: Vec<DetectionRule>,
    pub sim_state: Arc<Mutex<SimState>>,
    pub broadcast_tx: tokio::sync::broadcast::Sender<String>,
}

/// Core simulation engine — generates events and fires detection rules
pub struct SimulationEngine {
    pub app_state: AppState,
}

impl SimulationEngine {
    pub fn new(app_state: AppState) -> Self {
        Self { app_state }
    }

    /// Process a single simulation tick for an active session.
    /// Emits the next batch of scenario events, runs detection, persists alerts.
    pub fn tick(
        &self,
        session: &mut SimSession,
        scenario: &Scenario,
        max_events: usize,
    ) -> anyhow::Result<usize> {
        if !session.is_active() {
            return Ok(0);
        }

        let repo = Repository::new(self.app_state.db.clone());
        let elapsed = (Utc::now() - session.started_at).num_seconds();
        let session_id = &session.id;

        // Determine which scenario events are due
        let due_events: Vec<_> = scenario
            .events
            .iter()
            .enumerate()
            .skip(session.event_cursor)
            .filter(|(_, e)| e.offset_secs as i64 <= elapsed)
            .take(max_events)
            .collect();

        if due_events.is_empty() {
            return Ok(0);
        }

        // Build detection engine from configured rules
        let rules = crate::detection::rule::rules_from_config(
            &crate::config::load_detection_rules(
                &self
                    .app_state
                    .scenario_dir
                    .parent()
                    .unwrap_or(std::path::Path::new(".")),
            )
            .unwrap_or_default(),
        );
        let mut engine = DetectionEngine::new(rules);

        let mut emitted = 0;
        let last_idx = due_events
            .last()
            .map(|(i, _)| *i + 1)
            .unwrap_or(session.event_cursor);

        for (_, scenario_ev) in &due_events {
            let event =
                EventGenerator::from_scenario_event(session_id, scenario_ev, session.started_at);

            // Persist event
            if let Err(e) = repo.insert_event(&event) {
                tracing::warn!("Failed to persist event: {}", e);
                continue;
            }

            // Run detection
            let matches = engine.analyze(&event);
            for detection in &matches {
                let alert = DetectionEngine::create_alert(session_id, &event, detection);
                if let Err(e) = repo.insert_alert(&alert) {
                    tracing::warn!("Failed to persist alert: {}", e);
                } else {
                    if let Ok(mut state) = self.app_state.sim_state.lock() {
                        state.increment_alerts(1);
                    }
                    let _ = self.app_state.broadcast_tx.send(
                        serde_json::json!({
                            "type": "alert",
                            "session_id": session_id,
                            "rule_id": alert.rule_id,
                            "title": alert.title,
                            "severity": alert.severity,
                            "source": alert.source
                        })
                        .to_string(),
                    );
                    tracing::info!(
                        session = session_id,
                        rule = %detection.rule_id,
                        host = %event.host,
                        "Alert fired"
                    );
                }
            }

            emitted += 1;
        }

        session.event_cursor = last_idx;

        // Update global stats
        if let Ok(mut state) = self.app_state.sim_state.lock() {
            state.increment_events(emitted as u64);
        }

        Ok(emitted)
    }

    /// Check whether all scenario events have been emitted
    pub fn is_scenario_complete(session: &SimSession, scenario: &Scenario) -> bool {
        session.event_cursor >= scenario.events.len()
    }
}
