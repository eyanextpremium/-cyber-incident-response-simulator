// Test for scenario loader functionality
// Validates scenario loading and parsing

use cyber_incident_simulator::scenarios::{Scenario, ScenarioEvent, ScenarioLoader, ScenarioScoring};
use std::path::PathBuf;

#[test]
fn test_scenario_validation() {
    let valid_scenario = Scenario {
        id: "test_scenario".to_string(),
        name: "Test Scenario".to_string(),
        difficulty: "beginner".to_string(),
        category: "authentication".to_string(),
        description: "Test description".to_string(),
        objective: "Test objective".to_string(),
        time_limit_secs: 600,
        scenario_type: "authentication".to_string(),
        target_hosts: vec!["test_host".to_string()],
        attacker_ips: vec!["10.0.1.5".to_string()],
        events: vec![ScenarioEvent {
            offset_secs: 0,
            source: "authentication".to_string(),
            event_type: "login_attempt".to_string(),
            message: "Test event".to_string(),
            host: "test_host".to_string(),
            source_ip: Some("10.0.1.5".to_string()),
            destination_ip: None,
            user: Some("test_user".to_string()),
            is_malicious: true,
            mitre_technique: Some("T1110".to_string()),
        }],
        expected_actions: vec!["Test action".to_string()],
        hints: vec!["Test hint".to_string()],
        scoring: ScenarioScoring::default(),
    };

    assert!(!valid_scenario.id.is_empty());
    assert!(!valid_scenario.name.is_empty());
    assert!(!valid_scenario.difficulty.is_empty());
    assert!(!valid_scenario.category.is_empty());
    assert!(!valid_scenario.description.is_empty());
    assert!(!valid_scenario.objective.is_empty());
    assert!(valid_scenario.time_limit_secs > 0);
    assert!(!valid_scenario.events.is_empty());
}

#[test]
fn test_scenario_event_validation() {
    let valid_event = ScenarioEvent {
        offset_secs: 0,
        source: "authentication".to_string(),
        event_type: "login_attempt".to_string(),
        message: "Test event".to_string(),
        host: "test_host".to_string(),
        source_ip: Some("10.0.1.5".to_string()),
        destination_ip: None,
        user: Some("test_user".to_string()),
        is_malicious: true,
        mitre_technique: Some("T1110".to_string()),
    };

    assert!(!valid_event.source.is_empty());
    assert!(!valid_event.event_type.is_empty());
    assert!(!valid_event.message.is_empty());
    assert_eq!(valid_event.offset_secs, 0);
}

#[test]
fn test_difficulty_levels() {
    let valid_difficulties = vec!["beginner", "intermediate", "advanced", "expert"];

    for difficulty in valid_difficulties.iter() {
        let scenario = Scenario {
            id: format!("scenario_{}", difficulty),
            name: format!("{} Scenario", difficulty),
            difficulty: difficulty.to_string(),
            category: "authentication".to_string(),
            description: "Test".to_string(),
            objective: "Test".to_string(),
            time_limit_secs: 600,
            scenario_type: "authentication".to_string(),
            target_hosts: vec![],
            attacker_ips: vec![],
            events: vec![],
            expected_actions: vec![],
            hints: vec![],
            scoring: ScenarioScoring::default(),
        };

        assert!(valid_difficulties.contains(&scenario.difficulty.as_str()));
    }
}

#[test]
fn test_time_limit_validation() {
    let test_cases = vec![
        ("beginner", 600),
        ("intermediate", 900),
        ("advanced", 1200),
        ("expert", 1800),
    ];

    for (difficulty, expected_time) in test_cases {
        let scenario = Scenario {
            id: format!("scenario_{}", difficulty),
            name: format!("{} Scenario", difficulty),
            difficulty: difficulty.to_string(),
            category: "authentication".to_string(),
            description: "Test".to_string(),
            objective: "Test".to_string(),
            time_limit_secs: expected_time,
            scenario_type: "test".to_string(),
            target_hosts: vec![],
            attacker_ips: vec![],
            events: vec![],
            expected_actions: vec![],
            hints: vec![],
            scoring: ScenarioScoring::default(),
        };

        assert_eq!(scenario.time_limit_secs, expected_time);
    }
}

#[test]
fn test_event_chronological_order() {
    let events = vec![
        ScenarioEvent {
            offset_secs: 0,
            source: "authentication".to_string(),
            event_type: "login_attempt".to_string(),
            message: "First event".to_string(),
            host: "host1".to_string(),
            source_ip: None,
            destination_ip: None,
            user: None,
            is_malicious: true,
            mitre_technique: None,
        },
        ScenarioEvent {
            offset_secs: 30,
            source: "authentication".to_string(),
            event_type: "login_attempt".to_string(),
            message: "Second event".to_string(),
            host: "host1".to_string(),
            source_ip: None,
            destination_ip: None,
            user: None,
            is_malicious: true,
            mitre_technique: None,
        },
        ScenarioEvent {
            offset_secs: 60,
            source: "authentication".to_string(),
            event_type: "login_attempt".to_string(),
            message: "Third event".to_string(),
            host: "host1".to_string(),
            source_ip: None,
            destination_ip: None,
            user: None,
            is_malicious: true,
            mitre_technique: None,
        },
    ];

    for i in 0..events.len() - 1 {
        assert!(events[i].offset_secs <= events[i + 1].offset_secs);
    }
}

#[test]
fn test_mitre_technique_format() {
    let valid_techniques = vec![
        "T1110", "T1566", "T1190", "T1204", "T1021", "T1059", "T1547", "T1068", "T1562", "T1055",
    ];

    for technique in valid_techniques {
        assert!(technique.starts_with('T'));
        assert!(technique.len() >= 4);
        assert!(technique[1..].chars().all(|c| c.is_ascii_digit()));
    }
}

#[test]
fn test_scenario_completeness() {
    let scenario = Scenario {
        id: "complete_scenario".to_string(),
        name: "Complete Scenario".to_string(),
        difficulty: "intermediate".to_string(),
        category: "network".to_string(),
        description: "A complete scenario with all components".to_string(),
        objective: "Test all scenario components".to_string(),
        time_limit_secs: 900,
        scenario_type: "network".to_string(),
        target_hosts: vec!["server01".to_string()],
        attacker_ips: vec!["10.0.1.5".to_string()],
        events: vec![ScenarioEvent {
            offset_secs: 0,
            source: "network".to_string(),
            event_type: "connection".to_string(),
            message: "Test event".to_string(),
            host: "server01".to_string(),
            source_ip: Some("10.0.1.5".to_string()),
            destination_ip: Some("10.0.1.10".to_string()),
            user: None,
            is_malicious: true,
            mitre_technique: Some("T1021".to_string()),
        }],
        expected_actions: vec![
            "Detect the attack".to_string(),
            "Contain the threat".to_string(),
            "Investigate the source".to_string(),
        ],
        hints: vec![
            "Check network logs".to_string(),
            "Analyze connection patterns".to_string(),
        ],
        scoring: ScenarioScoring::default(),
    };

    assert!(!scenario.id.is_empty());
    assert!(!scenario.name.is_empty());
    assert!(!scenario.difficulty.is_empty());
    assert!(!scenario.category.is_empty());
    assert!(!scenario.description.is_empty());
    assert!(!scenario.objective.is_empty());
    assert!(scenario.time_limit_secs > 0);
    assert!(!scenario.events.is_empty());
    assert!(!scenario.expected_actions.is_empty());
    assert!(!scenario.hints.is_empty());
}

#[test]
fn test_event_source_validation() {
    let valid_sources = vec![
        "authentication",
        "firewall",
        "endpoint",
        "web_server",
        "network",
        "email",
        "dns",
        "filesystem",
    ];

    for source in valid_sources {
        let event = ScenarioEvent {
            offset_secs: 0,
            source: source.to_string(),
            event_type: "test".to_string(),
            message: "Test event".to_string(),
            host: "test_host".to_string(),
            source_ip: None,
            destination_ip: None,
            user: None,
            is_malicious: false,
            mitre_technique: None,
        };

        assert!(event.source.len() > 0);
    }
}

#[test]
fn test_scenario_id_uniqueness() {
    let scenarios = vec![
        Scenario {
            id: "scenario1".to_string(),
            name: "Scenario 1".to_string(),
            difficulty: "beginner".to_string(),
            category: "authentication".to_string(),
            description: "Test".to_string(),
            objective: "Test".to_string(),
            time_limit_secs: 600,
            scenario_type: "test".to_string(),
            target_hosts: vec![],
            attacker_ips: vec![],
            events: vec![],
            expected_actions: vec![],
            hints: vec![],
            scoring: ScenarioScoring::default(),
        },
        Scenario {
            id: "scenario2".to_string(),
            name: "Scenario 2".to_string(),
            difficulty: "beginner".to_string(),
            category: "authentication".to_string(),
            description: "Test".to_string(),
            objective: "Test".to_string(),
            time_limit_secs: 600,
            scenario_type: "test".to_string(),
            target_hosts: vec![],
            attacker_ips: vec![],
            events: vec![],
            expected_actions: vec![],
            hints: vec![],
            scoring: ScenarioScoring::default(),
        },
    ];

    let ids: Vec<_> = scenarios.iter().map(|s| s.id.clone()).collect();
    let unique_ids: std::collections::HashSet<_> = ids.iter().collect();

    assert_eq!(ids.len(), unique_ids.len());
}

#[test]
fn test_scenario_loader_on_disk() {
    let loader = ScenarioLoader::new(&PathBuf::from("scenarios"));
    let scenarios = loader.load_all();
    assert!(scenarios.is_ok());
    let list = scenarios.unwrap();
    assert!(!list.is_empty(), "Scenarios folder should load scenarios");
}
