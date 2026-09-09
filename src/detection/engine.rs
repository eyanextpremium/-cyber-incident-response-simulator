use crate::models::{Alert, IncidentSeverity, SecurityEvent};

use super::correlation::CorrelationEngine;
use super::ioc::IocList;
use super::rule::DetectionRule;
use super::severity::Severity;

/// The main detection engine — applies rules and IOC checks to incoming events
pub struct DetectionEngine {
    pub rules: Vec<DetectionRule>,
    pub ioc_list: IocList,
    pub correlation: CorrelationEngine,
}

/// Result of running the detection engine on an event
pub struct DetectionMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub ioc_hit: bool,
}

impl DetectionEngine {
    pub fn new(rules: Vec<DetectionRule>) -> Self {
        Self {
            rules,
            ioc_list: IocList::new(),
            correlation: CorrelationEngine::new(),
        }
    }

    /// Analyze a single security event and return any matches
    pub fn analyze(&mut self, event: &SecurityEvent) -> Vec<DetectionMatch> {
        // Feed into correlation engine
        self.correlation.ingest(event);

        let mut matches = Vec::new();
        let source_str = event.source.as_str();
        let message = &event.message;

        // Rule-based matching
        for rule in &self.rules {
            if rule.matches(message, source_str) {
                matches.push(DetectionMatch {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: rule.severity.clone(),
                    ioc_hit: self.ioc_list.check_message(message),
                });
            }
        }

        // IOC-only hit (no rule matched but IOC found)
        if matches.is_empty() && self.ioc_list.check_message(message) {
            matches.push(DetectionMatch {
                rule_id: "IOC-MATCH".to_string(),
                rule_name: "IOC Match".to_string(),
                severity: Severity::High,
                ioc_hit: true,
            });
        }

        matches
    }

    /// Generate an Alert from a detection match
    pub fn create_alert(
        session_id: &str,
        event: &SecurityEvent,
        detection: &DetectionMatch,
    ) -> Alert {
        let severity = severity_to_incident(&detection.severity);
        let mut alert = Alert::new(
            session_id,
            &detection.rule_id,
            &format!(
                "[{}] {}",
                detection.severity.as_str().to_uppercase(),
                detection.rule_name
            ),
            severity,
            event.source.as_str(),
        );
        alert.description = format!(
            "Rule '{}' triggered on host '{}': {}",
            detection.rule_name,
            event.host,
            truncate(&event.message, 200)
        );
        alert.event_ids.push(event.id.clone());
        if detection.ioc_hit {
            alert.description.push_str(" [IOC MATCH]");
        }
        alert
    }
}

fn severity_to_incident(s: &Severity) -> IncidentSeverity {
    match s {
        Severity::Low => IncidentSeverity::Low,
        Severity::Medium => IncidentSeverity::Medium,
        Severity::High => IncidentSeverity::High,
        Severity::Critical => IncidentSeverity::Critical,
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
