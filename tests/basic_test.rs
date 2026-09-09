// Basic integration test for the simulator

#[tokio::test]
async fn test_basic() {
    // Basic smoke test to ensure the project compiles and tests can run
    assert_eq!(1 + 1, 2);
}

#[tokio::test]
async fn test_imports() {
    // Test that main modules can be imported
    use cyber_incident_simulator::utils::generate_uuid;

    let uuid = generate_uuid();
    assert!(!uuid.is_empty());
    assert_eq!(uuid.len(), 36); // UUID format length
}

#[tokio::test]
async fn test_security_functions() {
    // Test security utility functions
    use cyber_incident_simulator::utils::{generate_salt, hash_password, verify_password};

    let salt = generate_salt();
    let password = "test_password_123";
    let hash = hash_password(password, &salt);

    assert!(!hash.is_empty());
    assert!(verify_password(password, &salt, &hash));
    assert!(!verify_password("wrong_password", &salt, &hash));
}

#[tokio::test]
async fn test_html_encoding() {
    // Test XSS prevention encoding
    use cyber_incident_simulator::utils::html_encode;

    let input = "<script>alert('xss')</script>";
    let encoded = html_encode(input);

    assert!(!encoded.contains("<script>"));
    assert!(encoded.contains("&lt;"));
    assert!(encoded.contains("&gt;"));
}

#[tokio::test]
async fn test_session_validation() {
    // Test session ID validation for path traversal prevention
    use cyber_incident_simulator::utils::validate_session_id;

    assert!(validate_session_id("valid-session-123"));
    assert!(!validate_session_id("../../../etc/passwd"));
    assert!(!validate_session_id("session/with/slashes"));
    assert!(!validate_session_id("session\\with\\backslashes"));
    assert!(!validate_session_id(""));
    assert!(!validate_session_id("a".repeat(100).as_str())); // Too long
}
