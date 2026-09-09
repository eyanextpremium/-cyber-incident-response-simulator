use std::path::Path;

use anyhow::{Context, Result};

use super::scenario::Scenario;

/// Loads scenario definitions from the filesystem
pub struct ScenarioLoader {
    base_dir: std::path::PathBuf,
}

impl ScenarioLoader {
    pub fn new(base_dir: &Path) -> Self {
        Self {
            base_dir: base_dir.to_path_buf(),
        }
    }

    /// Load a single scenario by ID, searching all directories
    pub fn load_by_id(&self, scenario_id: &str) -> Result<Scenario> {
        for scenario in self.load_all()? {
            if scenario.id == scenario_id {
                return Ok(scenario);
            }
        }
        Err(anyhow::anyhow!("Scenario not found: {}", scenario_id))
    }

    /// Load all available scenarios (difficulty tiers + MITRE ATT&CK)
    pub fn load_all(&self) -> Result<Vec<Scenario>> {
        let mut scenarios = Vec::new();

        // Classic difficulty-based scenarios
        for difficulty in &["beginner", "intermediate", "advanced", "expert"] {
            self.collect_from_dir(&self.base_dir.join(difficulty), &mut scenarios);
        }

        // MITRE ATT&CK tactic folders under scenarios/mitre/
        let mitre_dir = self.base_dir.join("mitre");
        if mitre_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&mitre_dir) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        self.collect_from_dir(&entry.path(), &mut scenarios);
                    }
                }
            }
        }

        Ok(scenarios)
    }

    /// Load scenarios for a specific difficulty level
    pub fn load_by_difficulty(&self, difficulty: &str) -> Result<Vec<Scenario>> {
        let dir = self.base_dir.join(difficulty);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut scenarios = Vec::new();
        self.collect_from_dir(&dir, &mut scenarios);
        Ok(scenarios)
    }

    /// Load scenarios for a specific MITRE tactic category
    pub fn load_by_category(&self, category: &str) -> Result<Vec<Scenario>> {
        let dir = self.base_dir.join("mitre").join(category);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut scenarios = Vec::new();
        self.collect_from_dir(&dir, &mut scenarios);
        Ok(scenarios)
    }

    /// List all MITRE tactic categories with scenario counts
    pub fn list_mitre_categories(&self) -> Vec<(String, usize)> {
        let mut categories = Vec::new();
        let mitre_dir = self.base_dir.join("mitre");
        if !mitre_dir.exists() {
            return categories;
        }
        if let Ok(entries) = std::fs::read_dir(&mitre_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let count = std::fs::read_dir(&path)
                        .map(|entries| {
                            entries
                                .flatten()
                                .filter(|e| {
                                    e.path().extension().and_then(|ext| ext.to_str())
                                        == Some("json")
                                })
                                .count()
                        })
                        .unwrap_or(0);
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        categories.push((name.to_string(), count));
                    }
                }
            }
        }
        categories.sort_by(|a, b| a.0.cmp(&b.0));
        categories
    }

    fn collect_from_dir(&self, dir: &Path, scenarios: &mut Vec<Scenario>) {
        if !dir.exists() {
            return;
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    match self.load_file(&path) {
                        Ok(s) => scenarios.push(s),
                        Err(e) => {
                            tracing::warn!("Failed to load scenario {:?}: {}", path, e);
                        }
                    }
                }
            }
        }
    }

    fn load_file(&self, path: &Path) -> Result<Scenario> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading scenario file: {:?}", path))?;
        if content.trim().is_empty() {
            return Err(anyhow::anyhow!("Empty scenario file: {:?}", path));
        }
        serde_json::from_str(&content).with_context(|| format!("parsing scenario JSON: {:?}", path))
    }
}
