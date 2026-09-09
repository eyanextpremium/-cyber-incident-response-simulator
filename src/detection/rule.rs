use regex::Regex;
use serde::{Deserialize, Serialize};

use super::severity::Severity;

/// A compiled detection rule that matches events by regex pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub pattern: String,
    pub source: String,
    pub enabled: bool,
    #[serde(skip)]
    pub compiled: Option<CompiledRule>,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub regex: Regex,
}

impl DetectionRule {
    pub fn new(
        id: &str,
        name: &str,
        description: &str,
        severity: Severity,
        pattern: &str,
        source: &str,
    ) -> Self {
        let compiled = Regex::new(pattern).ok().map(|regex| CompiledRule { regex });
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            severity,
            pattern: pattern.to_string(),
            source: source.to_string(),
            enabled: true,
            compiled,
        }
    }

    /// Compile the regex if not already done
    pub fn compile(&mut self) {
        if self.compiled.is_none() {
            if let Ok(regex) = Regex::new(&self.pattern) {
                self.compiled = Some(CompiledRule { regex });
            }
        }
    }

    /// Check whether this rule matches the given log message
    pub fn matches(&self, message: &str, source: &str) -> bool {
        if !self.enabled {
            return false;
        }
        // Source must match (or rule source is "any")
        if self.source != "any" && self.source != source {
            return false;
        }
        // Use compiled regex if available, fallback to simple contains
        if let Some(compiled) = &self.compiled {
            compiled.regex.is_match(message)
        } else {
            message
                .to_lowercase()
                .contains(&self.pattern.to_lowercase())
        }
    }
}

/// Build detection rules from config entries
pub fn rules_from_config(entries: &[crate::config::DetectionRuleEntry]) -> Vec<DetectionRule> {
    entries
        .iter()
        .map(|e| {
            DetectionRule::new(
                &e.id,
                &e.name,
                &e.description,
                Severity::from_str(&e.severity),
                &e.pattern,
                &e.source,
            )
        })
        .collect()
}
