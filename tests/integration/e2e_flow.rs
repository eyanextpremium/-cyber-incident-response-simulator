// End-to-End Integration Test: Attack -> Detection -> Incident -> Investigation -> Response -> Score

use cyber_incident_simulator::detection::{DetectionEngine, DetectionRule, Severity};
use cyber_incident_simulator::models::{
    EventSource, Evidence, EvidenceType, Incident, IncidentSeverity, IncidentStatus, SecurityEvent,
};
use cyber_incident_simulator::response::{ResponseAction, ResponseActionType};
use cyber_incident_simulator::scoring::ScoreMetrics;

#[tokio::test]
async fn test_full_attack_to_score_e2e_pipeline() {
    let session_id = "e2e_session_001";
    let scenario_id = "brute_force_dc";
    let host = "dc-server-01";

    // 1. ATTACK / EVENT INGESTION
    let attack_event = SecurityEvent::new(
        session_id,
        EventSource::Authentication,
        "login_attempt",
        "Failed password attempt for user admin from 192.168.1.50",
        host,
    );
    assert_eq!(attack_event.session_id, session_id);
    assert_eq!(attack_event.source, EventSource::Authentication);

    // 2. DETECTION ENGINE MATCHING
    let rules = vec![DetectionRule::new(
        "rule_bf_01",
        "Brute Force Attempt",
        "Detects multiple failed login attempts",
        Severity::High,
        "Failed password",
        "authentication",
    )];
    let mut detection_engine = DetectionEngine::new(rules);
    let detections = detection_engine.analyze(&attack_event);
    assert!(
        !detections.is_empty(),
        "Detection engine should match attack pattern"
    );
    assert_eq!(detections[0].rule_id, "rule_bf_01");

    // 3. INCIDENT CREATION & STATE TRANSITION
    let mut incident = Incident::new(
        session_id,
        scenario_id,
        "Brute Force Attack on DC",
        IncidentSeverity::High,
    );
    incident.description = "Multiple failed logins detected from 192.168.1.50".to_string();
    incident.alert_ids.push(detections[0].rule_id.clone());

    assert_eq!(incident.status, IncidentStatus::New);
    incident.status = IncidentStatus::Investigating;
    assert_eq!(incident.status, IncidentStatus::Investigating);
    incident.status = IncidentStatus::Contained;
    assert_eq!(incident.status, IncidentStatus::Contained);
    incident.status = IncidentStatus::Eradicated;
    incident.status = IncidentStatus::Recovered;
    incident.status = IncidentStatus::Closed;
    assert_eq!(incident.status, IncidentStatus::Closed);

    // 4. INVESTIGATION & EVIDENCE COLLECTION
    let mut evidence = Evidence::new(
        session_id,
        EvidenceType::Log,
        "Auth Failure Logs",
        r#"{"source_ip": "192.168.1.50", "failures": 25}"#,
        host,
    );
    evidence.incident_id = Some(incident.id.clone());
    evidence.ioc_match = true;
    assert!(evidence.ioc_match);
    assert_eq!(evidence.evidence_type, EvidenceType::Log);

    // 5. RESPONSE ACTION EXECUTION
    let response = ResponseAction::new(
        session_id,
        ResponseActionType::BlockIp,
        "192.168.1.50",
        "Automated firewall IP block action executed",
    );
    assert!(response.success);
    assert_eq!(response.action_type, ResponseActionType::BlockIp);

    // 6. SCORING METRICS CALCULATION
    let mut metrics = ScoreMetrics {
        detection_score: 25.0,
        investigation_score: 25.0,
        containment_score: 25.0,
        recovery_score: 25.0,
        time_penalty: 0.0,
        false_positive_penalty: 0.0,
        total_score: 0.0,
        time_elapsed_secs: 120,
    };
    metrics.calculate_total();

    assert_eq!(metrics.total_score, 100.0, "Perfect score should be 100");
}
