use super::tactics::Tactic;
use super::techniques::{find_technique, Technique};

/// MITRE ATT&CK mapping helper
pub struct MitreMapper;

impl MitreMapper {
    /// Resolve technique ID string to full Technique struct
    pub fn resolve(technique_id: &str) -> Option<Technique> {
        find_technique(technique_id)
    }

    /// Get the tactic for a technique ID
    pub fn tactic_for(technique_id: &str) -> Option<Tactic> {
        Tactic::from_technique_id(technique_id)
    }

    /// Format technique ID and name for display
    pub fn display_name(technique_id: &str) -> String {
        match find_technique(technique_id) {
            Some(t) => format!("{} - {}", t.id, t.name),
            None => technique_id.to_string(),
        }
    }

    /// Check if technique ID matches a given tactic
    pub fn is_in_tactic(technique_id: &str, tactic: &Tactic) -> bool {
        Tactic::from_technique_id(technique_id)
            .as_ref()
            .map(|t| t == tactic)
            .unwrap_or(false)
    }
}
