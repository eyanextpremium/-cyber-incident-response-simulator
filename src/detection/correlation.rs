use std::collections::HashMap;

use crate::models::SecurityEvent;

/// Correlation engine — tracks event patterns across time to detect multi-event threats
#[derive(Debug, Default)]
pub struct CorrelationEngine {
    /// Count of events per source IP
    ip_event_counts: HashMap<String, u32>,
    /// Count of events per host
    host_event_counts: HashMap<String, u32>,
    /// Count of failed auth events per source IP
    auth_failure_counts: HashMap<String, u32>,
}

#[derive(Debug, Clone)]
pub struct CorrelationResult {
    pub rule_id: String,
    pub description: String,
    pub severity: super::severity::Severity,
    pub related_ips: Vec<String>,
    pub related_hosts: Vec<String>,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a new event and update internal counters
    pub fn ingest(&mut self, event: &SecurityEvent) {
        if let Some(ip) = &event.source_ip {
            *self.ip_event_counts.entry(ip.clone()).or_insert(0) += 1;

            // Track auth failures specifically
            if event.event_type.contains("failure") || event.event_type.contains("failed") {
                *self.auth_failure_counts.entry(ip.clone()).or_insert(0) += 1;
            }
        }
        *self
            .host_event_counts
            .entry(event.host.clone())
            .or_insert(0) += 1;
    }

    /// Check for correlation-level findings after ingesting events
    pub fn check_correlations(&self) -> Vec<CorrelationResult> {
        let mut results = Vec::new();

        // Brute force detection: >5 auth failures from same IP
        for (ip, count) in &self.auth_failure_counts {
            if *count >= 5 {
                results.push(CorrelationResult {
                    rule_id: "CORR-BF-01".to_string(),
                    description: format!(
                        "Brute force pattern: {} failed auth attempts from {}",
                        count, ip
                    ),
                    severity: if *count >= 20 {
                        super::severity::Severity::Critical
                    } else {
                        super::severity::Severity::High
                    },
                    related_ips: vec![ip.clone()],
                    related_hosts: Vec::new(),
                });
            }
        }

        // High event volume from single IP: possible scan
        for (ip, count) in &self.ip_event_counts {
            if *count >= 30 {
                results.push(CorrelationResult {
                    rule_id: "CORR-SCAN-01".to_string(),
                    description: format!("High-volume activity: {} events from IP {}", count, ip),
                    severity: super::severity::Severity::Medium,
                    related_ips: vec![ip.clone()],
                    related_hosts: Vec::new(),
                });
            }
        }

        results
    }

    pub fn reset(&mut self) {
        self.ip_event_counts.clear();
        self.host_event_counts.clear();
        self.auth_failure_counts.clear();
    }
}
