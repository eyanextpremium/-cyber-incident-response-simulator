use std::path::Path;
use std::time::Instant;

use chrono::Utc;

use crate::utils::generate_uuid;

use super::attacks::AttackSimulator;
use super::report::{AuditReport, AuditSummary};
use super::scanner::FileScanner;

/// Orchestrates full self-audit: static file scan + simulated attack probes
pub struct AuditEngine {
    base_dir: std::path::PathBuf,
    scenario_dir: std::path::PathBuf,
}

impl AuditEngine {
    pub fn new(base_dir: &Path, scenario_dir: &Path) -> Self {
        Self {
            base_dir: base_dir.to_path_buf(),
            scenario_dir: scenario_dir.to_path_buf(),
        }
    }

    /// Run a complete self-audit and return the report
    pub fn run_full_audit(&self) -> AuditReport {
        let started = Instant::now();
        let started_at = Utc::now();

        // Phase 1: Static file scan
        let scanner = FileScanner::new(&self.base_dir);
        let (mut findings, files_scanned) = scanner.scan();

        // Phase 2: Simulated attack probes
        let simulator = AttackSimulator::new(&self.base_dir, &self.scenario_dir);
        let attack_results = simulator.run_all();

        // Convert failed attack tests into findings
        for result in &attack_results {
            if !result.passed {
                findings.push(super::report::AuditFinding {
                    id: result.test_id.clone(),
                    category: "attack_simulation".to_string(),
                    severity: super::report::AuditSeverity::High,
                    title: format!("Saldırı simülasyonu başarısız: {}", result.name),
                    description: result.description.clone(),
                    file_path: None,
                    line_number: None,
                    mitre_technique: Some(result.mitre_technique.clone()),
                    recommendation: "Bu güvenlik açığını kapatmak için ilgili modülü güncelleyin."
                        .to_string(),
                    evidence: Some(result.details.clone()),
                });
            }
        }

        let completed_at = Utc::now();
        let duration_ms = started.elapsed().as_millis() as u64;

        let summary = AuditReport::compute_summary(&findings, &attack_results, files_scanned);

        AuditReport {
            audit_id: generate_uuid(),
            started_at: started_at.to_rfc3339(),
            completed_at: completed_at.to_rfc3339(),
            duration_ms,
            summary,
            findings,
            attack_results,
        }
    }

    /// Quick health check — returns summary only
    pub fn quick_check(&self) -> AuditSummary {
        let report = self.run_full_audit();
        report.summary
    }
}
