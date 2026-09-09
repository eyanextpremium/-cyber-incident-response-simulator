use serde::{Deserialize, Serialize};

/// Unified severity level used across detection, alerts, and incidents
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::Medium,
        }
    }

    /// Numeric score used for sorting / display
    pub fn score(&self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    pub fn to_incident_severity(&self) -> crate::models::IncidentSeverity {
        match self {
            Self::Low => crate::models::IncidentSeverity::Low,
            Self::Medium => crate::models::IncidentSeverity::Medium,
            Self::High => crate::models::IncidentSeverity::High,
            Self::Critical => crate::models::IncidentSeverity::Critical,
        }
    }

    /// Color class for UI rendering
    pub fn color_class(&self) -> &'static str {
        match self {
            Self::Low => "severity-low",
            Self::Medium => "severity-medium",
            Self::High => "severity-high",
            Self::Critical => "severity-critical",
        }
    }
}
