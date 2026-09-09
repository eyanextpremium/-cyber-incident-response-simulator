// Unit tests for incident management components

use cyber_incident_simulator::models::{Incident, IncidentSeverity, IncidentStatus};

#[test]
fn test_incident_creation() {
    let mut incident = Incident::new(
        "test_session",
        "test_scenario",
        "Test Incident",
        IncidentSeverity::High,
    );
    incident.id = "test_incident".to_string();
    incident.description = "Test description".to_string();
    incident.status = IncidentStatus::Investigating;

    assert_eq!(incident.id, "test_incident");
    assert_eq!(incident.title, "Test Incident");
    assert_eq!(incident.status, IncidentStatus::Investigating);
}

#[test]
fn test_incident_status_transitions() {
    let valid_transitions = vec![
        (IncidentStatus::Investigating, IncidentStatus::Contained),
        (IncidentStatus::Contained, IncidentStatus::Eradicated),
        (IncidentStatus::Eradicated, IncidentStatus::Recovered),
        (IncidentStatus::Recovered, IncidentStatus::Closed),
    ];

    for (from, to) in valid_transitions.into_iter() {
        let mut incident = Incident::new("test", "test_scenario", "Test", IncidentSeverity::High);
        incident.status = from.clone();
        incident.status = to.clone();

        assert_eq!(incident.status, to);
    }
}

#[test]
fn test_incident_severity_levels() {
    let severities = vec![
        IncidentSeverity::Low,
        IncidentSeverity::Medium,
        IncidentSeverity::High,
        IncidentSeverity::Critical,
    ];

    for severity in severities {
        let incident = Incident::new("test", "test_scenario", "Test", severity.clone());

        assert_eq!(incident.severity, severity);
    }
}

#[test]
fn test_incident_alert_correlation() {
    let mut incident = Incident::new(
        "test_session",
        "test_scenario",
        "Test Incident",
        IncidentSeverity::High,
    );

    incident.alert_ids = vec![
        "alert1".to_string(),
        "alert2".to_string(),
        "alert3".to_string(),
    ];

    assert_eq!(incident.alert_ids.len(), 3);
    assert!(incident.alert_ids.contains(&"alert1".to_string()));
}

#[test]
fn test_incident_closure() {
    let mut incident = Incident::new(
        "test_session",
        "test_scenario",
        "Test Incident",
        IncidentSeverity::High,
    );

    incident.status = IncidentStatus::Closed;
    incident.closed_at = Some(chrono::Utc::now());

    assert_eq!(incident.status, IncidentStatus::Closed);
    assert!(incident.closed_at.is_some());
}

#[test]
fn test_incident_assignment() {
    let mut incident = Incident::new(
        "test_session",
        "test_scenario",
        "Test Incident",
        IncidentSeverity::High,
    );

    incident.assigned_to = Some("Senior Analyst".to_string());

    assert_eq!(incident.assigned_to, Some("Senior Analyst".to_string()));
}

#[test]
fn test_incident_timestamps() {
    let now = chrono::Utc::now();

    let incident = Incident::new(
        "test_session",
        "test_scenario",
        "Test Incident",
        IncidentSeverity::High,
    );
    assert!(incident.created_at <= now);
    assert!(incident.updated_at <= now);
    assert!(incident.closed_at.is_none());
}
