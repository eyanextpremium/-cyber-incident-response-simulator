// Unit tests for detection system components

use cyber_incident_simulator::detection::{DetectionRule, Severity};

#[test]
fn test_detection_rule_creation() {
    let rule = DetectionRule::new(
        "test_rule",
        "Test Rule",
        "Test detection rule",
        Severity::High,
        "login_attempt",
        "authentication",
    );

    assert_eq!(rule.id, "test_rule");
    assert_eq!(rule.name, "Test Rule");
    assert_eq!(rule.severity, Severity::High);
    assert!(rule.enabled);
}

#[test]
fn test_severity_ordering() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn test_severity_to_string() {
    assert_eq!(Severity::Low.as_str(), "low");
    assert_eq!(Severity::Medium.as_str(), "medium");
    assert_eq!(Severity::High.as_str(), "high");
    assert_eq!(Severity::Critical.as_str(), "critical");
}

#[test]
fn test_rule_enablement() {
    let enabled_rule = DetectionRule::new(
        "enabled",
        "Enabled Rule",
        "Enabled",
        Severity::High,
        "login_attempt",
        "authentication",
    );

    let mut disabled_rule = DetectionRule::new(
        "disabled",
        "Disabled Rule",
        "Disabled",
        Severity::High,
        "login_attempt",
        "authentication",
    );
    disabled_rule.enabled = false;

    assert!(enabled_rule.enabled);
    assert!(!disabled_rule.enabled);
}

#[test]
fn test_mitre_technique_validation() {
    let valid_techniques = vec![
        "T1110", "T1566", "T1190", "T1204", "T1021", "T1059", "T1547", "T1068", "T1562", "T1055",
    ];

    for technique in valid_techniques {
        let rule = DetectionRule::new(
            &format!("rule_{}", technique),
            &format!("Rule for {}", technique),
            "Test rule",
            Severity::High,
            &format!("{} login_attempt", technique),
            "authentication",
        );

        assert_eq!(rule.pattern, format!("{} login_attempt", technique));
    }
}

#[test]
fn test_rule_cloning() {
    let rule = DetectionRule::new(
        "original",
        "Original Rule",
        "Original description",
        Severity::High,
        "condition1",
        "authentication",
    );

    let cloned_rule = rule.clone();

    assert_eq!(cloned_rule.id, rule.id);
    assert_eq!(cloned_rule.name, rule.name);
    assert_eq!(cloned_rule.severity, rule.severity);
    assert_eq!(cloned_rule.enabled, rule.enabled);
}
