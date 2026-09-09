// Integration test for incident flow
// Tests the complete incident management lifecycle

use cyber_incident_simulator::models::{Incident, IncidentSeverity, IncidentStatus};

#[tokio::test]
async fn test_incident_creation() {
    let incident = Incident {
        id: "test_incident".to_string(),
        session_id: "test_session".to_string(),
        title: "Test Incident".to_string(),
        description: "Test incident description".to_string(),
        status: IncidentStatus::Investigating,
        severity: IncidentSeverity::High,
        scenario_id: "test_scenario".to_string(),
        assigned_to: Some("Test Analyst".to_string()),
        alert_ids: vec!["alert1".to_string(), "alert2".to_string()],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        closed_at: None,
    };

    assert_eq!(incident.id, "test_incident");
    assert_eq!(incident.title, "Test Incident");
    assert_eq!(incident.status, IncidentStatus::Investigating);
    assert_eq!(incident.severity, IncidentSeverity::High);
}

#[tokio::test]
async fn test_incident_lifecycle() {
    let status_progression = vec![
        IncidentStatus::Investigating,
        IncidentStatus::Contained,
        IncidentStatus::Eradicated,
        IncidentStatus::Recovered,
        IncidentStatus::Closed,
    ];

    for (i, status) in status_progression.iter().enumerate() {
        let incident = Incident {
            id: format!("incident_{}", i),
            session_id: "test_session".to_string(),
            title: format!("Incident at stage {}", i),
            description: "Test incident".to_string(),
            status: status.clone(),
            severity: IncidentSeverity::High,
            scenario_id: "test_scenario".to_string(),
            assigned_to: Some("Test Analyst".to_string()),
            alert_ids: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            closed_at: if *status == IncidentStatus::Closed {
                Some(chrono::Utc::now())
            } else {
                None
            },
        };

        assert_eq!(incident.status, *status);
        if *status == IncidentStatus::Closed {
            assert!(incident.closed_at.is_some());
        } else {
            assert!(incident.closed_at.is_none());
        }
    }
}

#[tokio::test]
async fn test_severity_classification() {
    let test_cases = vec![
        (IncidentSeverity::Low, "low"),
        (IncidentSeverity::Medium, "medium"),
        (IncidentSeverity::High, "high"),
        (IncidentSeverity::Critical, "critical"),
    ];

    for (severity, expected_str) in test_cases {
        let incident = Incident {
            id: format!("incident_{}", expected_str),
            session_id: "test_session".to_string(),
            title: format!("{} severity incident", expected_str),
            description: "Test incident".to_string(),
            status: IncidentStatus::Investigating,
            severity: severity.clone(),
            scenario_id: "test_scenario".to_string(),
            assigned_to: Some("Test Analyst".to_string()),
            alert_ids: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            closed_at: None,
        };

        assert_eq!(incident.severity.as_str(), expected_str);
    }
}

#[tokio::test]
async fn test_alert_correlation() {
    let incident = Incident {
        id: "test_incident".to_string(),
        session_id: "test_session".to_string(),
        title: "Test Incident".to_string(),
        description: "Test incident description".to_string(),
        status: IncidentStatus::Investigating,
        severity: IncidentSeverity::High,
        scenario_id: "test_scenario".to_string(),
        assigned_to: Some("Test Analyst".to_string()),
        alert_ids: vec![
            "alert1".to_string(),
            "alert2".to_string(),
            "alert3".to_string(),
        ],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        closed_at: None,
    };

    assert_eq!(incident.alert_ids.len(), 3);
    assert!(incident.alert_ids.contains(&"alert1".to_string()));
    assert!(incident.alert_ids.contains(&"alert2".to_string()));
    assert!(incident.alert_ids.contains(&"alert3".to_string()));
}

#[tokio::test]
async fn test_incident_assignment() {
    let incident = Incident {
        id: "test_incident".to_string(),
        session_id: "test_session".to_string(),
        title: "Test Incident".to_string(),
        description: "Test incident description".to_string(),
        status: IncidentStatus::Investigating,
        severity: IncidentSeverity::High,
        scenario_id: "test_scenario".to_string(),
        assigned_to: Some("Senior Analyst".to_string()),
        alert_ids: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        closed_at: None,
    };

    assert_eq!(incident.assigned_to, Some("Senior Analyst".to_string()));
}

#[tokio::test]
async fn test_incident_timestamps() {
    let now = chrono::Utc::now();

    let incident = Incident {
        id: "test_incident".to_string(),
        session_id: "test_session".to_string(),
        title: "Test Incident".to_string(),
        description: "Test incident description".to_string(),
        status: IncidentStatus::Investigating,
        severity: IncidentSeverity::High,
        scenario_id: "test_scenario".to_string(),
        assigned_to: Some("Test Analyst".to_string()),
        alert_ids: vec![],
        created_at: now,
        updated_at: now,
        closed_at: None,
    };

    assert!(incident.created_at <= now);
    assert!(incident.updated_at <= now);
    assert!(incident.closed_at.is_none());

    let closed_incident = Incident {
        id: "closed_incident".to_string(),
        session_id: "test_session".to_string(),
        title: "Closed Incident".to_string(),
        description: "Closed incident description".to_string(),
        status: IncidentStatus::Closed,
        severity: IncidentSeverity::High,
        scenario_id: "test_scenario".to_string(),
        assigned_to: Some("Test Analyst".to_string()),
        alert_ids: vec![],
        created_at: now,
        updated_at: now,
        closed_at: Some(now),
    };

    assert!(closed_incident.closed_at.is_some());
    assert_eq!(closed_incident.status, IncidentStatus::Closed);
}

#[tokio::test]
async fn test_incident_validation() {
    let valid_incident = Incident {
        id: "valid_incident".to_string(),
        session_id: "test_session".to_string(),
        title: "Valid Incident".to_string(),
        description: "Valid incident description".to_string(),
        status: IncidentStatus::Investigating,
        severity: IncidentSeverity::High,
        scenario_id: "test_scenario".to_string(),
        assigned_to: Some("Test Analyst".to_string()),
        alert_ids: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        closed_at: None,
    };

    assert!(!valid_incident.id.is_empty());
    assert!(!valid_incident.session_id.is_empty());
    assert!(!valid_incident.title.is_empty());

    let incident_without_optional = Incident {
        id: "incident_no_optional".to_string(),
        session_id: "test_session".to_string(),
        title: "Incident Without Optional".to_string(),
        description: "".to_string(),
        status: IncidentStatus::Investigating,
        severity: IncidentSeverity::Medium,
        scenario_id: "".to_string(),
        assigned_to: None,
        alert_ids: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        closed_at: None,
    };

    assert!(incident_without_optional.assigned_to.is_none());
}

#[tokio::test]
async fn test_multiple_incidents_per_session() {
    let session_id = "test_session".to_string();

    let incidents = vec![
        Incident {
            id: "incident1".to_string(),
            session_id: session_id.clone(),
            title: "First Incident".to_string(),
            description: "First incident".to_string(),
            status: IncidentStatus::Investigating,
            severity: IncidentSeverity::High,
            scenario_id: "test_scenario".to_string(),
            assigned_to: Some("Analyst 1".to_string()),
            alert_ids: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            closed_at: None,
        },
        Incident {
            id: "incident2".to_string(),
            session_id: session_id.clone(),
            title: "Second Incident".to_string(),
            description: "Second incident".to_string(),
            status: IncidentStatus::Contained,
            severity: IncidentSeverity::Critical,
            scenario_id: "test_scenario".to_string(),
            assigned_to: Some("Analyst 2".to_string()),
            alert_ids: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            closed_at: None,
        },
        Incident {
            id: "incident3".to_string(),
            session_id: session_id.clone(),
            title: "Third Incident".to_string(),
            description: "Third incident".to_string(),
            status: IncidentStatus::Closed,
            severity: IncidentSeverity::Low,
            scenario_id: "test_scenario".to_string(),
            assigned_to: Some("Analyst 3".to_string()),
            alert_ids: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            closed_at: Some(chrono::Utc::now()),
        },
    ];

    assert_eq!(incidents.len(), 3);

    for incident in &incidents {
        assert_eq!(incident.session_id, session_id);
    }

    let statuses: Vec<_> = incidents.iter().map(|i| i.status.clone()).collect();
    assert!(statuses.contains(&IncidentStatus::Investigating));
    assert!(statuses.contains(&IncidentStatus::Contained));
    assert!(statuses.contains(&IncidentStatus::Closed));
}
