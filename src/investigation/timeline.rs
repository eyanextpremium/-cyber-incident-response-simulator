use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::SecurityEvent;

/// A single entry in the investigation timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub event_id: String,
    pub host: String,
    pub source: String,
    pub event_type: String,
    pub description: String,
    pub is_malicious: bool,
    pub mitre_technique: Option<String>,
}

/// Ordered timeline of events for an investigation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Timeline {
    pub entries: Vec<TimelineEntry>,
}

impl Timeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_events(events: &[SecurityEvent]) -> Self {
        let mut entries: Vec<TimelineEntry> = events
            .iter()
            .map(|e| TimelineEntry {
                timestamp: e.timestamp,
                event_id: e.id.clone(),
                host: e.host.clone(),
                source: e.source.as_str().to_string(),
                event_type: e.event_type.clone(),
                description: e.message.clone(),
                is_malicious: e.is_malicious,
                mitre_technique: e.mitre_technique.clone(),
            })
            .collect();

        // Sort chronologically
        entries.sort_by_key(|e| e.timestamp);
        Self { entries }
    }

    /// Add a single event to the timeline
    pub fn add_event(&mut self, event: &SecurityEvent) {
        self.entries.push(TimelineEntry {
            timestamp: event.timestamp,
            event_id: event.id.clone(),
            host: event.host.clone(),
            source: event.source.as_str().to_string(),
            event_type: event.event_type.clone(),
            description: event.message.clone(),
            is_malicious: event.is_malicious,
            mitre_technique: event.mitre_technique.clone(),
        });
        self.entries.sort_by_key(|e| e.timestamp);
    }

    /// Filter timeline to only malicious events
    pub fn malicious_only(&self) -> Vec<&TimelineEntry> {
        self.entries.iter().filter(|e| e.is_malicious).collect()
    }

    /// Filter timeline by host name
    pub fn for_host<'a>(&'a self, host: &str) -> Vec<&'a TimelineEntry> {
        self.entries.iter().filter(|e| e.host == host).collect()
    }

    /// Filter by MITRE technique
    pub fn for_technique<'a>(&'a self, technique: &str) -> Vec<&'a TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| {
                e.mitre_technique
                    .as_deref()
                    .map(|t| t.starts_with(technique))
                    .unwrap_or(false)
            })
            .collect()
    }
}
