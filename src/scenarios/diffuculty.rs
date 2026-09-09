use serde::{Deserialize, Serialize};

/// Difficulty levels matching the scenario directory structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Difficulty {
    Beginner,
    Intermediate,
    Advanced,
    Expert,
}

impl Difficulty {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "beginner" => Self::Beginner,
            "intermediate" => Self::Intermediate,
            "advanced" => Self::Advanced,
            "expert" => Self::Expert,
            _ => Self::Beginner,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Beginner => "beginner",
            Self::Intermediate => "intermediate",
            Self::Advanced => "advanced",
            Self::Expert => "expert",
        }
    }

    /// Score multiplier for difficulty
    pub fn multiplier(&self) -> f64 {
        match self {
            Self::Beginner => 1.0,
            Self::Intermediate => 1.25,
            Self::Advanced => 1.5,
            Self::Expert => 2.0,
        }
    }

    /// Time limit in seconds for this difficulty
    pub fn default_time_limit(&self) -> u64 {
        match self {
            Self::Beginner => 1800,
            Self::Intermediate => 2700,
            Self::Advanced => 3600,
            Self::Expert => 7200,
        }
    }
}
