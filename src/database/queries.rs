pub const INSERT_SESSION: &str =
    "INSERT INTO sessions (id, scenario_id, analyst_name, status, started_at) VALUES (?1, ?2, ?3, ?4, ?5)";

pub const UPDATE_SESSION_STATUS: &str =
    "UPDATE sessions SET status = ?1, completed_at = ?2, score = ?3 WHERE id = ?4";

pub const GET_SESSION: &str = "SELECT id, scenario_id, analyst_name, status, started_at, completed_at, score FROM sessions WHERE id = ?1";

pub const LIST_SESSIONS: &str =
    "SELECT id, scenario_id, analyst_name, status, started_at, completed_at, score FROM sessions ORDER BY started_at DESC";

pub const INSERT_EVENT: &str = r#"
INSERT INTO events (id, session_id, timestamp, source, event_type, message, host, source_ip, destination_ip, user_name, raw_log, mitre_technique, is_malicious)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
"#;

pub const LIST_EVENTS: &str =
    "SELECT id, session_id, timestamp, source, event_type, message, host, source_ip, destination_ip, user_name, raw_log, mitre_technique, is_malicious FROM events WHERE session_id = ?1 ORDER BY timestamp ASC";

pub const INSERT_ALERT: &str = r#"
INSERT INTO alerts (id, session_id, rule_id, title, description, severity, status, event_ids, source, created_at)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
"#;

pub const UPDATE_ALERT: &str = r#"
UPDATE alerts SET status = ?1, acknowledged_at = ?2, resolved_at = ?3 WHERE id = ?4
"#;

pub const LIST_ALERTS: &str =
    "SELECT id, session_id, rule_id, title, description, severity, status, event_ids, source, created_at, acknowledged_at, resolved_at FROM alerts WHERE session_id = ?1 ORDER BY created_at ASC";

pub const GET_ALERT: &str =
    "SELECT id, session_id, rule_id, title, description, severity, status, event_ids, source, created_at, acknowledged_at, resolved_at FROM alerts WHERE id = ?1";

pub const INSERT_INCIDENT: &str = r#"
INSERT INTO incidents (id, session_id, title, description, status, severity, scenario_id, assigned_to, alert_ids, created_at, updated_at)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
"#;

pub const UPDATE_INCIDENT: &str = r#"
UPDATE incidents SET status = ?1, description = ?2, alert_ids = ?3, updated_at = ?4, closed_at = ?5 WHERE id = ?6
"#;

pub const LIST_INCIDENTS: &str =
    "SELECT id, session_id, title, description, status, severity, scenario_id, assigned_to, alert_ids, created_at, updated_at, closed_at FROM incidents WHERE session_id = ?1";

pub const INSERT_EVIDENCE: &str = r#"
INSERT INTO evidence (id, session_id, incident_id, evidence_type, title, description, data, source_host, collected_at, ioc_match)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
"#;

pub const LIST_EVIDENCE: &str =
    "SELECT id, session_id, incident_id, evidence_type, title, description, data, source_host, collected_at, ioc_match FROM evidence WHERE session_id = ?1";

pub const INSERT_ACTION: &str = r#"
INSERT INTO response_actions (id, session_id, incident_id, action_type, target, details, success, performed_at)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
"#;

pub const LIST_ACTIONS: &str =
    "SELECT id, session_id, incident_id, action_type, target, details, success, performed_at FROM response_actions WHERE session_id = ?1";

pub const UPSERT_SCORE: &str = r#"
INSERT INTO scores (id, session_id, detection_score, investigation_score, containment_score, recovery_score, total_score, time_elapsed_secs, calculated_at)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
ON CONFLICT(session_id) DO UPDATE SET
    detection_score = excluded.detection_score,
    investigation_score = excluded.investigation_score,
    containment_score = excluded.containment_score,
    recovery_score = excluded.recovery_score,
    total_score = excluded.total_score,
    time_elapsed_secs = excluded.time_elapsed_secs,
    calculated_at = excluded.calculated_at
"#;

pub const GET_SCORE: &str =
    "SELECT id, session_id, detection_score, investigation_score, containment_score, recovery_score, total_score, time_elapsed_secs, calculated_at FROM scores WHERE session_id = ?1";

pub const INSERT_ASSET: &str = r#"
INSERT OR REPLACE INTO assets (id, hostname, ip_address, asset_type, os, criticality, department, status)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
"#;

pub const LIST_ASSETS: &str =
    "SELECT id, hostname, ip_address, asset_type, os, criticality, department, status FROM assets";

pub const INSERT_USER: &str = r#"
INSERT INTO users (id, username, password_hash, salt, role, totp_secret, totp_enabled, created_at)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
"#;

pub const GET_USER_BY_USERNAME: &str =
    "SELECT id, username, password_hash, salt, role, totp_secret, totp_enabled, created_at FROM users WHERE username = ?1";

pub const LIST_USERS: &str =
    "SELECT id, username, password_hash, salt, role, totp_secret, totp_enabled, created_at FROM users";

pub const UPDATE_USER_TOTP_SECRET: &str = "UPDATE users SET totp_secret = ?1 WHERE username = ?2";

pub const UPDATE_USER_TOTP_ENABLE: &str = "UPDATE users SET totp_enabled = ?1 WHERE username = ?2";

pub const INSERT_BANNED_IP: &str = r#"
INSERT OR REPLACE INTO banned_ips (ip, reason, banned_at, expires_at)
VALUES (?1, ?2, ?3, ?4)
"#;

pub const IS_IP_BANNED: &str = "SELECT ip FROM banned_ips WHERE ip = ?1 AND expires_at > ?2";
