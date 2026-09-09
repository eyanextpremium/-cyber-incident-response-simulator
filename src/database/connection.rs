use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rusqlite::Connection;

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    analyst_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    score REAL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    host TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    user_name TEXT,
    raw_log TEXT NOT NULL,
    mitre_technique TEXT,
    is_malicious INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    event_ids TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    acknowledged_at TEXT,
    resolved_at TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'new',
    severity TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    assigned_to TEXT,
    alert_ids TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    incident_id TEXT,
    evidence_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    data TEXT NOT NULL,
    source_host TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    ioc_match INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS response_actions (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    incident_id TEXT,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    success INTEGER NOT NULL DEFAULT 1,
    performed_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS scores (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL UNIQUE,
    detection_score REAL NOT NULL DEFAULT 0.0,
    investigation_score REAL NOT NULL DEFAULT 0.0,
    containment_score REAL NOT NULL DEFAULT 0.0,
    recovery_score REAL NOT NULL DEFAULT 0.0,
    total_score REAL NOT NULL DEFAULT 0.0,
    time_elapsed_secs INTEGER NOT NULL DEFAULT 0,
    calculated_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    os TEXT NOT NULL,
    criticality TEXT NOT NULL,
    department TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS banned_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    banned_at TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_malicious ON events(is_malicious);
CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_session ON incidents(session_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id);
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(evidence_type);
CREATE INDEX IF NOT EXISTS idx_evidence_collected ON evidence(collected_at);
CREATE INDEX IF NOT EXISTS idx_actions_session ON response_actions(session_id);
CREATE INDEX IF NOT EXISTS idx_actions_type ON response_actions(action_type);
CREATE INDEX IF NOT EXISTS idx_actions_performed ON response_actions(performed_at);
CREATE INDEX IF NOT EXISTS idx_scores_session ON scores(session_id);
CREATE INDEX IF NOT EXISTS idx_scores_total ON scores(total_score);
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_banned_ips_expires ON banned_ips(expires_at);
"#;

pub type DbPool = Arc<Mutex<Connection>>;

pub fn init_database(path: &Path) -> Result<DbPool> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("failed to create database directory")?;
    }
    let conn = Connection::open(path).context("failed to open database")?;
    conn.execute_batch(SCHEMA)
        .context("failed to initialize schema")?;
    let _ = conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT", []);
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0",
        [],
    );
    Ok(Arc::new(Mutex::new(conn)))
}

pub fn init_in_memory() -> Result<DbPool> {
    let conn = Connection::open_in_memory().context("failed to open in-memory database")?;
    conn.execute_batch(SCHEMA)
        .context("failed to initialize schema")?;
    let _ = conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT", []);
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0",
        [],
    );
    Ok(Arc::new(Mutex::new(conn)))
}
