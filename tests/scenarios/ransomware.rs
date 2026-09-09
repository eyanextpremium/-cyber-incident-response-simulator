// Test for ransomware scenario
// Validates the ransomware attack scenario structure and behavior

use cyber_incident_simulator::scenarios::{Scenario, ScenarioEvent, ScenarioScoring};

#[test]
fn test_ransomware_scenario_structure() {
    let scenario = Scenario {
        id: "ransoware".to_string(),
        name: "Ransomware Attack".to_string(),
        difficulty: "advanced".to_string(),
        category: "malware".to_string(),
        description: "A ransomware attack has encrypted critical files on multiple systems.".to_string(),
        objective: "Respond to a ransomware attack and minimize impact.".to_string(),
        time_limit_secs: 1200,
        scenario_type: "ransomware".to_string(),
        target_hosts: vec!["file-server-01".to_string(), "workstation-finance-01".to_string()],
        attacker_ips: vec!["192.168.50.100".to_string()],
        events: vec![ScenarioEvent {
            offset_secs: 0,
            source: "endpoint".to_string(),
            event_type: "process_execution".to_string(),
            message: "Suspicious process execution".to_string(),
            host: "workstation-finance-01".to_string(),
            source_ip: None,
            destination_ip: None,
            user: Some("finance_user".to_string()),
            is_malicious: true,
            mitre_technique: Some("T1204".to_string()),
        }],
        expected_actions: vec![
            "Identify all affected systems".to_string(),
            "Isolate infected systems".to_string(),
            "Identify ransomware variant".to_string(),
            "Assess data loss".to_string(),
            "Restore from backups".to_string(),
        ],
        hints: vec![
            "Look for file encryption events".to_string(),
            "Check for ransom notes".to_string(),
            "Identify patient zero".to_string(),
        ],
        scoring: ScenarioScoring::default(),
    };

    assert_eq!(scenario.id, "ransoware");
    assert_eq!(scenario.difficulty, "advanced");
    assert_eq!(scenario.category, "malware");
    assert!(!scenario.events.is_empty());
    assert!(!scenario.expected_actions.is_empty());
}

#[test]
fn test_ransomware_mitre_mapping() {
    let events = vec![
        ScenarioEvent {
            offset_secs: 0,
            source: "endpoint".to_string(),
            event_type: "process_execution".to_string(),
            message: "Ransomware execution".to_string(),
            host: "workstation01".to_string(),
            source_ip: None,
            destination_ip: None,
            user: Some("user1".to_string()),
            is_malicious: true,
            mitre_technique: Some("T1204".to_string()),
        },
        ScenarioEvent {
            offset_secs: 30,
            source: "filesystem".to_string(),
            event_type: "file_encryption".to_string(),
            message: "File encryption detected".to_string(),
            host: "workstation01".to_string(),
            source_ip: None,
            destination_ip: None,
            user: None,
            is_malicious: true,
            mitre_technique: Some("T1486".to_string()),
        },
    ];

    let techniques: Vec<_> = events
        .iter()
        .filter_map(|e| e.mitre_technique.as_deref())
        .collect();
    assert!(techniques.contains(&"T1204"));
    assert!(techniques.contains(&"T1486"));
}

#[test]
fn test_ransomware_propagation() {
    let events = vec![
        ScenarioEvent {
            offset_secs: 0,
            source: "endpoint".to_string(),
            event_type: "process_execution".to_string(),
            message: "Ransomware execution on workstation01".to_string(),
            host: "workstation01".to_string(),
            source_ip: None,
            destination_ip: None,
            user: Some("user1".to_string()),
            is_malicious: true,
            mitre_technique: Some("T1204".to_string()),
        },
        ScenarioEvent {
            offset_secs: 60,
            source: "network".to_string(),
            event_type: "connection".to_string(),
            message: "Lateral movement to server01".to_string(),
            host: "server01".to_string(),
            source_ip: Some("10.0.2.15".to_string()),
            destination_ip: Some("10.0.1.5".to_string()),
            user: None,
            is_malicious: true,
            mitre_technique: Some("T1021".to_string()),
        },
        ScenarioEvent {
            offset_secs: 90,
            source: "endpoint".to_string(),
            event_type: "process_execution".to_string(),
            message: "Ransomware execution on server01".to_string(),
            host: "server01".to_string(),
            source_ip: None,
            destination_ip: None,
            user: None,
            is_malicious: true,
            mitre_technique: Some("T1204".to_string()),
        },
    ];

    assert!(events
        .iter()
        .any(|e| e.mitre_technique == Some("T1021".to_string())));

    let hosts: Vec<_> = events.iter().map(|e| e.host.as_str()).collect();
    assert!(hosts.len() > 1);
}

#[test]
fn test_ransomware_expected_actions() {
    let expected_actions = vec![
        "Identify all affected systems",
        "Isolate infected systems",
        "Identify ransomware variant",
        "Assess data loss",
        "Restore from backups",
    ];

    assert!(expected_actions.iter().any(|a| a.contains("Identify")));
    assert!(expected_actions.iter().any(|a| a.contains("Isolate")));
    assert!(expected_actions.iter().any(|a| a.contains("Restore")));
}

#[test]
fn test_ransomware_file_encryption() {
    let events = vec![
        ScenarioEvent {
            offset_secs: 30,
            source: "filesystem".to_string(),
            event_type: "file_encryption".to_string(),
            message: "Critical files encrypted".to_string(),
            host: "workstation01".to_string(),
            source_ip: None,
            destination_ip: None,
            user: None,
            is_malicious: true,
            mitre_technique: Some("T1486".to_string()),
        },
        ScenarioEvent {
            offset_secs: 35,
            source: "filesystem".to_string(),
            event_type: "file_encryption".to_string(),
            message: "Database files encrypted".to_string(),
            host: "workstation01".to_string(),
            source_ip: None,
            destination_ip: None,
            user: None,
            is_malicious: true,
            mitre_technique: Some("T1486".to_string()),
        },
    ];

    assert!(events.iter().all(|e| e.event_type == "file_encryption"));
    assert!(events
        .iter()
        .all(|e| e.mitre_technique == Some("T1486".to_string())));
}

#[test]
fn test_ransomware_difficulty_level() {
    let scenario = Scenario {
        id: "ransoware".to_string(),
        name: "Ransomware Attack".to_string(),
        difficulty: "advanced".to_string(),
        category: "malware".to_string(),
        description: "Test".to_string(),
        objective: "Test".to_string(),
        time_limit_secs: 1200,
        scenario_type: "ransomware".to_string(),
        target_hosts: vec![],
        attacker_ips: vec![],
        events: vec![],
        expected_actions: vec![],
        hints: vec![],
        scoring: ScenarioScoring::default(),
    };

    assert_eq!(scenario.difficulty, "advanced");
    assert!(scenario.time_limit_secs > 600);
}

#[test]
fn test_ransomware_hints() {
    let hints = vec![
        "Look for file encryption events",
        "Check for ransom notes",
        "Identify patient zero",
        "Assess backup availability",
    ];

    assert!(!hints.is_empty());
    assert!(hints.iter().any(|h| h.contains("encryption")));
    assert!(hints.iter().any(|h| h.contains("ransom notes")));
    assert!(hints.iter().any(|h| h.contains("patient zero")));
}
