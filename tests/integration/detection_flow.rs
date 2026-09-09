// Integration test for detection flow
// Tests the complete detection pipeline from event generation to alert creation

use cyber_incident_simulator::detection::{
    DetectionEngine, DetectionMatch, DetectionRule, Severity,
};
use cyber_incident_simulator::models::{AlertStatus, EventSource, SecurityEvent};

#[tokio::test]
async fn test_basic_detection() {
    let rules = vec![DetectionRule::new(
        "test_rule",
        "Test Rule",
        "Test detection rule",
        Severity::High,
        "login_attempt",
        "authentication",
    )];

    let mut engine = DetectionEngine::new(rules);
    let event = SecurityEvent::new(
        "test_session",
        EventSource::Authentication,
        "login_attempt",
        "Test login attempt",
        "test_host",
    );

    let detections = engine.analyze(&event);
    assert_eq!(detections.len(), 1);
}

#[tokio::test]
async fn test_multiple_events_detection() {
    let rules = vec![DetectionRule::new(
        "brute_force",
        "Brute Force Detection",
        "Detects brute force attacks",
        Severity::Critical,
        "login_attempt",
        "authentication",
    )];

    let mut engine = DetectionEngine::new(rules);

    let events = vec![
        SecurityEvent::new(
            "test_session",
            EventSource::Authentication,
            "login_attempt",
            "Failed login attempt",
            "server01",
        ),
        SecurityEvent::new(
            "test_session",
            EventSource::Authentication,
            "login_attempt",
            "Failed login attempt",
            "server01",
        ),
    ];

    let mut detection_count = 0;
    for event in &events {
        let detections = engine.analyze(event);
        detection_count += detections.len();
    }

    assert_eq!(detection_count, 2);
}

#[tokio::test]
async fn test_alert_creation() {
    let event = SecurityEvent::new(
        "test_session",
        EventSource::Authentication,
        "login_attempt",
        "Test login attempt",
        "test_host",
    );

    let detection = DetectionMatch {
        rule_id: "test_rule".to_string(),
        rule_name: "Test Rule".to_string(),
        severity: Severity::High,
        ioc_hit: false,
    };

    let alert = DetectionEngine::create_alert("test_session", &event, &detection);

    assert_eq!(alert.session_id, "test_session");
    assert_eq!(alert.rule_id, "test_rule");
    assert_eq!(alert.status, AlertStatus::New);
}

#[tokio::test]
async fn test_severity_classification() {
    let test_cases = vec![
        (Severity::Low, "low"),
        (Severity::Medium, "medium"),
        (Severity::High, "high"),
        (Severity::Critical, "critical"),
    ];

    for (severity, expected_str) in test_cases {
        let rule = DetectionRule::new(
            &format!("test_{}", expected_str),
            &format!("Test {}", expected_str),
            &format!("Test {} rule", expected_str),
            severity.clone(),
            "login_attempt",
            "authentication",
        );

        assert_eq!(rule.severity.as_str(), expected_str);
    }
}

#[tokio::test]
async fn test_mitre_mapping() {
    let rule = DetectionRule::new(
        "brute_force",
        "Brute Force Detection",
        "Detects brute force attacks",
        Severity::High,
        "login_attempt",
        "authentication",
    );

    let mut event = SecurityEvent::new(
        "test_session",
        EventSource::Authentication,
        "login_attempt",
        "Test login attempt",
        "test_host",
    );

    event.mitre_technique = Some("T1110".to_string());

    assert_eq!(event.mitre_technique, Some("T1110".to_string()));
    assert_eq!(rule.pattern, "login_attempt");
}

#[tokio::test]
async fn test_rule_enablement() {
    let mut rules = vec![
        DetectionRule::new(
            "enabled_rule",
            "Enabled Rule",
            "Enabled detection rule",
            Severity::High,
            "login_attempt",
            "authentication",
        ),
        DetectionRule::new(
            "disabled_rule",
            "Disabled Rule",
            "Disabled detection rule",
            Severity::High,
            "login_attempt",
            "authentication",
        ),
    ];

    rules[1].enabled = false;

    let mut engine = DetectionEngine::new(rules);
    let event = SecurityEvent::new(
        "test_session",
        EventSource::Authentication,
        "login_attempt",
        "Test login attempt",
        "test_host",
    );

    let detections = engine.analyze(&event);
    assert_eq!(detections.len(), 1);
    assert!(!engine.rules[1].enabled);
}
