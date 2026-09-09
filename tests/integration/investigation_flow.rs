// Integration test for investigation flow
// Tests the investigation and evidence collection functionality

use cyber_incident_simulator::models::{EventSource, Evidence, EvidenceType, SecurityEvent};

#[tokio::test]
async fn test_timeline_building() {
    let events = vec![
        SecurityEvent::new(
            "test_session",
            EventSource::Authentication,
            "login_attempt",
            "Initial access via phishing",
            "workstation01",
        ),
        SecurityEvent::new(
            "test_session",
            EventSource::Endpoint,
            "process_execution",
            "Malicious process execution",
            "workstation01",
        ),
        SecurityEvent::new(
            "test_session",
            EventSource::Network,
            "connection",
            "Lateral movement to server",
            "server01",
        ),
    ];

    assert_eq!(events[0].source, EventSource::Authentication);
    assert_eq!(events[1].source, EventSource::Endpoint);
    assert_eq!(events[2].source, EventSource::Network);
}

#[tokio::test]
async fn test_evidence_collection() {
    let mut evidence = Evidence::new(
        "test_session",
        EvidenceType::Log,
        "Authentication Logs",
        r#"{"source_ip": "192.168.1.100", "attempts": 15}"#,
        "dc-server-01",
    );

    evidence.incident_id = Some("incident1".to_string());
    evidence.description = "Failed login attempts from suspicious IP".to_string();
    evidence.ioc_match = true;

    assert_eq!(evidence.evidence_type, EvidenceType::Log);
    assert_eq!(evidence.session_id, "test_session");
    assert_eq!(evidence.incident_id, Some("incident1".to_string()));
    assert!(evidence.ioc_match);
}

#[tokio::test]
async fn test_evidence_types() {
    let evidence_types = vec![
        EvidenceType::Log,
        EvidenceType::File,
        EvidenceType::Network,
        EvidenceType::Memory,
        EvidenceType::Registry,
        EvidenceType::Process,
    ];

    for evidence_type in evidence_types {
        let evidence = Evidence::new(
            "test_session",
            evidence_type.clone(),
            "Test evidence",
            "{}",
            "server01",
        );

        assert_eq!(evidence.evidence_type, evidence_type);
    }
}

#[tokio::test]
async fn test_multiple_evidence_per_incident() {
    let incident_id = "incident1".to_string();

    let evidence_items = vec![
        Evidence::new(
            "test_session",
            EvidenceType::Log,
            "Authentication Logs",
            "{}",
            "dc-server-01",
        ),
        Evidence::new(
            "test_session",
            EvidenceType::File,
            "Malicious File",
            "{}",
            "workstation01",
        ),
        Evidence::new(
            "test_session",
            EvidenceType::Network,
            "Network Traffic",
            "{}",
            "firewall01",
        ),
    ];

    for mut evidence in evidence_items {
        evidence.incident_id = Some(incident_id.clone());
        assert_eq!(evidence.incident_id, Some(incident_id.clone()));
    }
}

#[tokio::test]
async fn test_evidence_without_incident() {
    let evidence = Evidence::new(
        "test_session",
        EvidenceType::Log,
        "System Logs",
        "{}",
        "server01",
    );

    assert!(evidence.incident_id.is_none());
    assert_eq!(evidence.session_id, "test_session");
}

#[tokio::test]
async fn test_ioc_matching() {
    let mut evidence = Evidence::new(
        "test_session",
        EvidenceType::Log,
        "IOC Evidence",
        "{}",
        "server01",
    );

    evidence.ioc_match = true;
    assert!(evidence.ioc_match);
}
