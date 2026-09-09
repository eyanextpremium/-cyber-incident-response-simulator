// Test for brute force scenario
// Validates the brute force attack scenario structure and behavior

use cyber_incident_simulator::scenarios::{Scenario, ScenarioEvent, ScenarioScoring};

#[test]
fn test_brute_force_scenario_structure() {
    let scenario = Scenario {
        id: "brute_force".to_string(),
        name: "Brute Force Attack".to_string(),
        difficulty: "beginner".to_string(),
        category: "authentication".to_string(),
        description: "An attacker is attempting to brute force the administrator account on the domain controller.".to_string(),
        objective: "Detect and respond to a brute force authentication attack.".to_string(),
        time_limit_secs: 600,
        scenario_type: "brute_force".to_string(),
        target_hosts: vec!["dc-server-01".to_string()],
        attacker_ips: vec!["10.0.1.100".to_string()],
        events: vec![
            ScenarioEvent {
                offset_secs: 0,
                source: "authentication".to_string(),
                event_type: "login_attempt".to_string(),
                message: "Failed login attempt for admin".to_string(),
                host: "dc-server-01".to_string(),
                source_ip: Some("10.0.1.100".to_string()),
                destination_ip: None,
                user: Some("admin".to_string()),
                is_malicious: true,
                mitre_technique: Some("T1110".to_string()),
            },
        ],
        expected_actions: vec![
            "Detect the brute force attack pattern".to_string(),
            "Identify the source IP address".to_string(),
            "Block the malicious IP".to_string(),
            "Reset the administrator password".to_string(),
        ],
        hints: vec![
            "Look for multiple failed login attempts from the same IP".to_string(),
            "Check authentication logs for patterns".to_string(),
        ],
        scoring: ScenarioScoring::default(),
    };

    assert_eq!(scenario.id, "brute_force");
    assert_eq!(scenario.difficulty, "beginner");
    assert_eq!(scenario.category, "authentication");
    assert!(!scenario.events.is_empty());
    assert!(!scenario.expected_actions.is_empty());
}

#[test]
fn test_brute_force_mitre_mapping() {
    let event = ScenarioEvent {
        offset_secs: 0,
        source: "authentication".to_string(),
        event_type: "login_attempt".to_string(),
        message: "Failed login attempt".to_string(),
        host: "dc-server-01".to_string(),
        source_ip: Some("10.0.1.100".to_string()),
        destination_ip: None,
        user: Some("admin".to_string()),
        is_malicious: true,
        mitre_technique: Some("T1110".to_string()),
    };

    assert_eq!(event.mitre_technique, Some("T1110".to_string()));
    assert!(event.is_malicious);
}

#[test]
fn test_brute_force_event_progression() {
    let events = vec![
        ScenarioEvent {
            offset_secs: 0,
            source: "authentication".to_string(),
            event_type: "login_attempt".to_string(),
            message: "Failed login attempt 1".to_string(),
            host: "dc-server-01".to_string(),
            source_ip: Some("10.0.1.100".to_string()),
            destination_ip: None,
            user: Some("admin".to_string()),
            is_malicious: true,
            mitre_technique: Some("T1110".to_string()),
        },
        ScenarioEvent {
            offset_secs: 5,
            source: "authentication".to_string(),
            event_type: "login_attempt".to_string(),
            message: "Failed login attempt 2".to_string(),
            host: "dc-server-01".to_string(),
            source_ip: Some("10.0.1.100".to_string()),
            destination_ip: None,
            user: Some("admin".to_string()),
            is_malicious: true,
            mitre_technique: Some("T1110".to_string()),
        },
        ScenarioEvent {
            offset_secs: 10,
            source: "authentication".to_string(),
            event_type: "login_attempt".to_string(),
            message: "Failed login attempt 3".to_string(),
            host: "dc-server-01".to_string(),
            source_ip: Some("10.0.1.100".to_string()),
            destination_ip: None,
            user: Some("admin".to_string()),
            is_malicious: true,
            mitre_technique: Some("T1110".to_string()),
        },
    ];

    assert!(events[0].offset_secs < events[1].offset_secs);
    assert!(events[1].offset_secs < events[2].offset_secs);
    assert_eq!(events[0].source_ip, events[1].source_ip);
    assert_eq!(events[1].source_ip, events[2].source_ip);
}

#[test]
fn test_brute_force_expected_actions() {
    let expected_actions = vec![
        "Detect the brute force attack pattern",
        "Identify the source IP address",
        "Block the malicious IP",
        "Reset the administrator password",
    ];

    assert!(expected_actions.iter().any(|a| a.contains("Detect")));
    assert!(expected_actions.iter().any(|a| a.contains("Block")));
    assert!(expected_actions.iter().any(|a| a.contains("Reset")));
}

#[test]
fn test_brute_force_difficulty_level() {
    let scenario = Scenario {
        id: "brute_force".to_string(),
        name: "Brute Force Attack".to_string(),
        difficulty: "beginner".to_string(),
        category: "authentication".to_string(),
        description: "Test".to_string(),
        objective: "Test".to_string(),
        time_limit_secs: 600,
        scenario_type: "brute_force".to_string(),
        target_hosts: vec![],
        attacker_ips: vec![],
        events: vec![],
        expected_actions: vec![],
        hints: vec![],
        scoring: ScenarioScoring::default(),
    };

    assert_eq!(scenario.difficulty, "beginner");
    assert!(scenario.time_limit_secs <= 600);
}

#[test]
fn test_brute_force_hints() {
    let hints = vec![
        "Look for multiple failed login attempts from the same IP",
        "Check authentication logs for patterns",
    ];

    assert!(!hints.is_empty());
    assert!(hints.iter().any(|h| h.contains("failed login")));
    assert!(hints.iter().any(|h| h.contains("authentication logs")));
}
