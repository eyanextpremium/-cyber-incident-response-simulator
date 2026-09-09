use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl AuditSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub id: String,
    pub category: String,
    pub severity: AuditSeverity,
    pub title: String,
    pub description: String,
    pub file_path: Option<String>,
    pub line_number: Option<u32>,
    pub mitre_technique: Option<String>,
    pub recommendation: String,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub files_scanned: usize,
    pub attack_tests_run: usize,
    pub attack_tests_passed: usize,
    pub attack_tests_failed: usize,
    pub security_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub audit_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub duration_ms: u64,
    pub summary: AuditSummary,
    pub findings: Vec<AuditFinding>,
    pub attack_results: Vec<AttackTestResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTestResult {
    pub test_id: String,
    pub name: String,
    pub description: String,
    pub mitre_technique: String,
    pub passed: bool,
    pub details: String,
}

impl AuditReport {
    pub fn compute_summary(
        findings: &[AuditFinding],
        attack_results: &[AttackTestResult],
        files_scanned: usize,
    ) -> AuditSummary {
        let critical = findings
            .iter()
            .filter(|f| f.severity == AuditSeverity::Critical)
            .count();
        let high = findings
            .iter()
            .filter(|f| f.severity == AuditSeverity::High)
            .count();
        let medium = findings
            .iter()
            .filter(|f| f.severity == AuditSeverity::Medium)
            .count();
        let low = findings
            .iter()
            .filter(|f| f.severity == AuditSeverity::Low)
            .count();
        let info = findings
            .iter()
            .filter(|f| f.severity == AuditSeverity::Info)
            .count();

        let attack_tests_run = attack_results.len();
        let attack_tests_passed = attack_results.iter().filter(|r| r.passed).count();
        let attack_tests_failed = attack_tests_run - attack_tests_passed;

        // Score: start at 100, deduct by severity weights
        let mut score: i32 = 100;
        score -= (critical as i32) * 25;
        score -= (high as i32) * 15;
        score -= (medium as i32) * 8;
        score -= (low as i32) * 3;
        score -= (attack_tests_failed as i32) * 10;
        let security_score = score.clamp(0, 100) as u8;

        AuditSummary {
            total_findings: findings.len(),
            critical,
            high,
            medium,
            low,
            info,
            files_scanned,
            attack_tests_run,
            attack_tests_passed,
            attack_tests_failed,
            security_score,
        }
    }
}
