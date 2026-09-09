// Test for phishing scenario
// Validates the phishing attack scenario structure and behavior

use cyber_incident_simulator::scenarios::{Scenario, ScenarioEvent, ScenarioScoring};

#[test]
fn test_phishing_scenario_structure() {
    let scenario = Scenario {
        id: "phishing".to_string(),
        name: "Phishing Campaign".to_string(),
        difficulty: "beginner".to_string(),
        category: "authentication".to_string(),
        description: "A phishing campaign is targeting employees with fake login pages.".to_string(),
        objective: "Detect and respond to a phishing campaign.".to_string(),
        time_limit_secs: 600,
        scenario_type: "phishing".to_string(),
        target_hosts: vec!["mail-server-01".to_string()],
        attacker_ips: vec!["192.168.1.50".to_string()],
        events: vec![ScenarioEvent {
            offset_secs: 0,
            source: "email".to_string(),
            event_type: "email_received".to_string(),
            message: "Phishing email received".to_string(),
            host: "mail-server-01".to_string(),
            source_ip: Some("192.168.1.50".to_string()),
            destination_ip: None,
            user: Some("user1".to_string()),
            is_malicious: true,
            mitre_technique: Some("T1566".to_string()),
        }],
        expected_actions: vec![
            "Identify the phishing emails".to_string(),
            "Identify affected users".to_string(),
            "Block the phishing domain".to_string(),
            "Reset compromised credentials".to_string(),
        ],
        hints: vec![
            "Look for emails with suspicious links".to_string(),
            "Check for successful logins from unusual locations".to_string(),
        ],
        scoring: ScenarioScoring::default(),
    };

    assert_eq!(scenario.id, "phishing");
    assert_eq!(scenario.difficulty, "beginner");
    assert_eq!(scenario.category, "authentication");
    assert!(!scenario.events.is_empty());
    assert!(!scenario.expected_actions.is_empty());
}

#[test]
fn test_phishing_mitre_mapping() {
    let event = ScenarioEvent {
        offset_secs: 0,
        source: "email".to_string(),
        event_type: "email_received".to_string(),
        message: "Phishing email received".to_string(),
        host: "mail-server-01".to_string(),
        source_ip: Some("192.168.1.50".to_string()),
        destination_ip: None,
        user: Some("user1".to_string()),
        is_malicious: true,
        mitre_technique: Some("T1566".to_string()),
    };

    assert_eq!(event.mitre_technique, Some("T1566".to_string()));
    assert!(event.is_malicious);
}

#[test]
fn test_phishing_email_patterns() {
    let events = vec![
        ScenarioEvent {
            offset_secs: 0,
            source: "email".to_string(),
            event_type: "email_received".to_string(),
            message: "Phishing email with suspicious link".to_string(),
            host: "mail-server-01".to_string(),
            source_ip: Some("192.168.1.50".to_string()),
            destination_ip: None,
            user: Some("user1".to_string()),
            is_malicious: true,
            mitre_technique: Some("T1566".to_string()),
        },
        ScenarioEvent {
            offset_secs: 30,
            source: "authentication".to_string(),
            event_type: "login_attempt".to_string(),
            message: "Successful login after clicking phishing link".to_string(),
            host: "web-server-01".to_string(),
            source_ip: Some("192.168.1.100".to_string()),
            destination_ip: None,
            user: Some("user1".to_string()),
            is_malicious: true,
            mitre_technique: Some("T1110".to_string()),
        },
    ];

    assert!(events.iter().any(|e| e.source == "email"));
    assert!(events.iter().any(|e| e.source == "authentication"));
}

#[test]
fn test_phishing_expected_actions() {
    let expected_actions = vec![
        "Identify the phishing emails",
        "Identify affected users",
        "Block the phishing domain",
        "Reset compromised credentials",
    ];

    assert!(expected_actions.iter().any(|a| a.contains("Identify")));
    assert!(expected_actions.iter().any(|a| a.contains("Block")));
    assert!(expected_actions.iter().any(|a| a.contains("Reset")));
}

#[test]
fn test_phishing_multiple_targets() {
    let events = vec![
        ScenarioEvent {
            offset_secs: 0,
            source: "email".to_string(),
            event_type: "email_received".to_string(),
            message: "Phishing email sent to user1".to_string(),
            host: "mail-server-01".to_string(),
            source_ip: Some("192.168.1.50".to_string()),
            destination_ip: None,
            user: Some("user1".to_string()),
            is_malicious: true,
            mitre_technique: Some("T1566".to_string()),
        },
        ScenarioEvent {
            offset_secs: 5,
            source: "email".to_string(),
            event_type: "email_received".to_string(),
            message: "Phishing email sent to user2".to_string(),
            host: "mail-server-01".to_string(),
            source_ip: Some("192.168.1.50".to_string()),
            destination_ip: None,
            user: Some("user2".to_string()),
            is_malicious: true,
            mitre_technique: Some("T1566".to_string()),
        },
        ScenarioEvent {
            offset_secs: 10,
            source: "email".to_string(),
            event_type: "email_received".to_string(),
            message: "Phishing email sent to user3".to_string(),
            host: "mail-server-01".to_string(),
            source_ip: Some("192.168.1.50".to_string()),
            destination_ip: None,
            user: Some("user3".to_string()),
            is_malicious: true,
            mitre_technique: Some("T1566".to_string()),
        },
    ];

    let users: Vec<_> = events.iter().filter_map(|e| e.user.as_deref()).collect();
    assert_eq!(users.len(), 3);
    assert!(users.contains(&"user1"));
    assert!(users.contains(&"user2"));
    assert!(users.contains(&"user3"));
}

#[test]
fn test_phishing_hints() {
    let hints = vec![
        "Look for emails with suspicious links",
        "Check for successful logins from unusual locations",
        "Analyze email headers for signs of spoofing",
    ];

    assert!(!hints.is_empty());
    assert!(hints.iter().any(|h| h.contains("suspicious links")));
    assert!(hints.iter().any(|h| h.contains("unusual locations")));
}
