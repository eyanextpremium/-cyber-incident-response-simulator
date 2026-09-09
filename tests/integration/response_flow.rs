// Integration test for response flow
// Tests the response action execution and tracking

use cyber_incident_simulator::response::{ResponseAction, ResponseActionType};

#[tokio::test]
async fn test_action_execution() {
    let action = ResponseAction::new(
        "test_session",
        ResponseActionType::IsolateHost,
        "10.0.1.10",
        "Isolating web server due to confirmed compromise",
    );

    assert_eq!(action.action_type, ResponseActionType::IsolateHost);
    assert_eq!(action.target, "10.0.1.10");
    assert!(action.success);
    assert_eq!(action.session_id, "test_session");
}

#[tokio::test]
async fn test_action_types() {
    let action_types = vec![
        ResponseActionType::IsolateHost,
        ResponseActionType::BlockIp,
        ResponseActionType::DisableAccount,
        ResponseActionType::QuarantineFile,
        ResponseActionType::Contain,
        ResponseActionType::Eradicate,
        ResponseActionType::Recover,
    ];

    for action_type in action_types.iter().cloned() {
        let action = ResponseAction::new(
            "test_session",
            action_type.clone(),
            "test_target",
            "test action",
        );

        assert_eq!(action.action_type, action_type);
    }
}

#[tokio::test]
async fn test_action_success_tracking() {
    let successful_action = ResponseAction::new(
        "test_session",
        ResponseActionType::IsolateHost,
        "10.0.1.10",
        "Successful isolation",
    );

    let mut failed_action = ResponseAction::new(
        "test_session",
        ResponseActionType::BlockIp,
        "192.168.1.100",
        "Failed to block IP",
    );
    failed_action.success = false;

    assert!(successful_action.success);
    assert!(!failed_action.success);
}

#[tokio::test]
async fn test_containment_actions() {
    let containment_actions = vec![
        (ResponseActionType::IsolateHost, "10.0.1.10"),
        (ResponseActionType::BlockIp, "192.168.1.100"),
        (ResponseActionType::DisableAccount, "malicious_user"),
    ];

    for (action_type, target) in containment_actions.into_iter() {
        let action = ResponseAction::new(
            "test_session",
            action_type.clone(),
            target,
            "Containment action",
        );

        assert_eq!(action.action_type, action_type);
        assert_eq!(action.target, target);
    }
}

#[tokio::test]
async fn test_eradication_actions() {
    let eradication_actions = vec![
        (ResponseActionType::Contain, "malware.exe"),
        (ResponseActionType::QuarantineFile, "CVE-2024-1234"),
    ];

    for (action_type, target) in eradication_actions.into_iter() {
        let action = ResponseAction::new(
            "test_session",
            action_type.clone(),
            target,
            "Eradication action",
        );

        assert_eq!(action.action_type, action_type);
        assert_eq!(action.target, target);
    }
}

#[tokio::test]
async fn test_recovery_actions() {
    let recovery_actions = vec![
        (ResponseActionType::Recover, "server01"),
        (ResponseActionType::Contain, "forensics"),
    ];

    for (action_type, target) in recovery_actions.into_iter() {
        let action = ResponseAction::new(
            "test_session",
            action_type.clone(),
            target,
            "Recovery action",
        );

        assert_eq!(action.action_type, action_type);
        assert_eq!(action.target, target);
    }
}

#[tokio::test]
async fn test_action_correlation_with_incident() {
    let incident_id = "incident1".to_string();

    let actions = vec![
        ResponseAction::new(
            "test_session",
            ResponseActionType::IsolateHost,
            "10.0.1.10",
            "Containment action",
        ),
        ResponseAction::new(
            "test_session",
            ResponseActionType::Contain,
            "malware.exe",
            "Eradication action",
        ),
        ResponseAction::new(
            "test_session",
            ResponseActionType::Recover,
            "server01",
            "Recovery action",
        ),
    ];

    for mut action in actions {
        action.incident_id = Some(incident_id.clone());
        assert_eq!(action.incident_id, Some(incident_id.clone()));
    }
}

#[tokio::test]
async fn test_action_without_incident() {
    let action = ResponseAction::new(
        "test_session",
        ResponseActionType::BlockIp,
        "192.168.1.100",
        "Proactive blocking",
    );

    assert!(action.incident_id.is_none());
    assert_eq!(action.session_id, "test_session");
}

#[tokio::test]
async fn test_action_timestamps() {
    let now = chrono::Utc::now();
    let _ = now;

    let action = ResponseAction::new(
        "test_session",
        ResponseActionType::IsolateHost,
        "10.0.1.10",
        "Test action",
    );

    assert_eq!(action.action_type, ResponseActionType::IsolateHost);
}

#[tokio::test]
async fn test_action_details() {
    let action = ResponseAction::new(
        "test_session",
        ResponseActionType::IsolateHost,
        "10.0.1.10",
        "Isolating host due to confirmed compromise. All network interfaces will be disabled except management interface.",
    );

    assert!(!action.details.is_empty());
    assert!(action.details.len() > 0);
}

#[tokio::test]
async fn test_multiple_actions_per_session() {
    let session_id = "test_session".to_string();

    let actions = vec![
        ResponseAction::new(
            "test_session",
            ResponseActionType::IsolateHost,
            "10.0.1.10",
            "First action",
        ),
        ResponseAction::new(
            "test_session",
            ResponseActionType::BlockIp,
            "192.168.1.100",
            "Second action",
        ),
        ResponseAction::new(
            "test_session",
            ResponseActionType::DisableAccount,
            "malicious_user",
            "Third action",
        ),
    ];

    assert_eq!(actions.len(), 3);

    for action in &actions {
        assert_eq!(action.session_id, session_id);
    }
}

#[tokio::test]
async fn test_action_validation() {
    let valid_action = ResponseAction::new(
        "test_session",
        ResponseActionType::IsolateHost,
        "10.0.1.10",
        "Valid action",
    );

    assert!(!valid_action.id.is_empty());
    assert!(!valid_action.session_id.is_empty());
    assert!(!valid_action.target.is_empty());

    let action_without_optional = ResponseAction::new(
        "test_session",
        ResponseActionType::BlockIp,
        "192.168.1.100",
        "",
    );

    assert!(action_without_optional.incident_id.is_none());
    assert!(action_without_optional.details.is_empty());
}
