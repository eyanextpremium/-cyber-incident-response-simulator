use std::sync::MutexGuard;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};

use crate::models::{
    Alert, AlertStatus, Asset, Evidence, Incident, IncidentSeverity, IncidentStatus, SecurityEvent,
    User, UserDbRecord,
};
use crate::utils::{decrypt_field, encrypt_field, generate_salt, generate_uuid, hash_password};

use super::connection::DbPool;
use super::queries;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionRecord {
    pub id: String,
    pub scenario_id: String,
    pub analyst_name: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub score: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScoreRecord {
    pub id: String,
    pub session_id: String,
    pub detection_score: f64,
    pub investigation_score: f64,
    pub containment_score: f64,
    pub recovery_score: f64,
    pub total_score: f64,
    pub time_elapsed_secs: i64,
    pub calculated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionRecord {
    pub id: String,
    pub session_id: String,
    pub incident_id: Option<String>,
    pub action_type: String,
    pub target: String,
    pub details: String,
    pub success: bool,
    pub performed_at: DateTime<Utc>,
}

pub struct Repository {
    pool: DbPool,
}

impl Repository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    fn conn(&self) -> Result<MutexGuard<'_, Connection>> {
        self.pool
            .lock()
            .map_err(|e| anyhow::anyhow!("database lock poisoned: {e}"))
    }

    pub fn create_session(
        &self,
        id: &str,
        scenario_id: &str,
        analyst_name: &str,
    ) -> Result<SessionRecord> {
        // Validate input parameters
        if id.trim().is_empty() {
            return Err(anyhow::anyhow!("Session ID cannot be empty"));
        }
        if scenario_id.trim().is_empty() {
            return Err(anyhow::anyhow!("Scenario ID cannot be empty"));
        }
        if analyst_name.trim().is_empty() {
            return Err(anyhow::anyhow!("Analyst name cannot be empty"));
        }
        if analyst_name.len() > 100 {
            return Err(anyhow::anyhow!(
                "Analyst name too long (max 100 characters)"
            ));
        }

        let now = Utc::now();
        let conn = self.conn()?;
        conn.execute(
            queries::INSERT_SESSION,
            params![id, scenario_id, analyst_name, "active", now.to_rfc3339()],
        )?;
        Ok(SessionRecord {
            id: id.to_string(),
            scenario_id: scenario_id.to_string(),
            analyst_name: analyst_name.to_string(),
            status: "active".to_string(),
            started_at: now,
            completed_at: None,
            score: 0.0,
        })
    }

    pub fn get_session(&self, id: &str) -> Result<Option<SessionRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(queries::GET_SESSION)?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(SessionRecord {
                id: row.get(0)?,
                scenario_id: row.get(1)?,
                analyst_name: row.get(2)?,
                status: row.get(3)?,
                started_at: parse_dt(row.get::<_, String>(4)?)?,
                completed_at: row
                    .get::<_, Option<String>>(5)?
                    .map(|s| parse_dt(s))
                    .transpose()?,
                score: row.get(6)?,
            }));
        }
        Ok(None)
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(queries::LIST_SESSIONS)?;
        let rows = stmt.query_map([], |row| {
            Ok(SessionRecord {
                id: row.get(0)?,
                scenario_id: row.get(1)?,
                analyst_name: row.get(2)?,
                status: row.get(3)?,
                started_at: parse_dt(row.get::<_, String>(4)?).unwrap_or_else(|_| Utc::now()),
                completed_at: row
                    .get::<_, Option<String>>(5)?
                    .and_then(|s| parse_dt(s).ok()),
                score: row.get(6)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .context("failed to list sessions")
    }

    pub fn complete_session(&self, id: &str, score: f64) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            queries::UPDATE_SESSION_STATUS,
            params!["completed", Utc::now().to_rfc3339(), score, id],
        )?;
        Ok(())
    }

    pub fn insert_event(&self, event: &SecurityEvent) -> Result<()> {
        // Validate event data
        if event.id.trim().is_empty() {
            return Err(anyhow::anyhow!("Event ID cannot be empty"));
        }
        if event.session_id.trim().is_empty() {
            return Err(anyhow::anyhow!("Session ID cannot be empty"));
        }
        if event.source.as_str().trim().is_empty() {
            return Err(anyhow::anyhow!("Event source cannot be empty"));
        }
        if event.event_type.trim().is_empty() {
            return Err(anyhow::anyhow!("Event type cannot be empty"));
        }
        if event.message.trim().is_empty() {
            return Err(anyhow::anyhow!("Event message cannot be empty"));
        }

        let encrypted_raw_log = encrypt_field(&event.raw_log);
        let conn = self.conn()?;
        conn.execute(
            queries::INSERT_EVENT,
            params![
                event.id,
                event.session_id,
                event.timestamp.to_rfc3339(),
                event.source.as_str(),
                event.event_type,
                event.message,
                event.host,
                event.source_ip,
                event.destination_ip,
                event.user,
                encrypted_raw_log,
                event.mitre_technique,
                event.is_malicious as i32,
            ],
        )?;
        Ok(())
    }

    pub fn list_events(&self, session_id: &str) -> Result<Vec<SecurityEvent>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(queries::LIST_EVENTS)?;
        let rows = stmt.query_map(params![session_id], |row| {
            let raw_log_db: String = row.get(10)?;
            Ok(SecurityEvent {
                id: row.get(0)?,
                session_id: row.get(1)?,
                timestamp: parse_dt(row.get::<_, String>(2)?).unwrap_or_else(|_| Utc::now()),
                source: crate::models::EventSource::from_str(&row.get::<_, String>(3)?),
                event_type: row.get(4)?,
                message: row.get(5)?,
                host: row.get(6)?,
                source_ip: row.get(7)?,
                destination_ip: row.get(8)?,
                user: row.get(9)?,
                raw_log: decrypt_field(&raw_log_db),
                mitre_technique: row.get(11)?,
                is_malicious: row.get::<_, i32>(12)? != 0,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .context("failed to list events")
    }

    pub fn insert_alert(&self, alert: &Alert) -> Result<()> {
        // Validate alert data
        if alert.id.trim().is_empty() {
            return Err(anyhow::anyhow!("Alert ID cannot be empty"));
        }
        if alert.session_id.trim().is_empty() {
            return Err(anyhow::anyhow!("Session ID cannot be empty"));
        }
        if alert.rule_id.trim().is_empty() {
            return Err(anyhow::anyhow!("Rule ID cannot be empty"));
        }
        if alert.title.trim().is_empty() {
            return Err(anyhow::anyhow!("Alert title cannot be empty"));
        }

        let conn = self.conn()?;
        let event_ids = serde_json::to_string(&alert.event_ids)?;
        conn.execute(
            queries::INSERT_ALERT,
            params![
                alert.id,
                alert.session_id,
                alert.rule_id,
                alert.title,
                alert.description,
                severity_str(&alert.severity),
                alert_status_str(&alert.status),
                event_ids,
                alert.source,
                alert.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn update_alert(&self, alert: &Alert) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            queries::UPDATE_ALERT,
            params![
                alert_status_str(&alert.status),
                alert.acknowledged_at.map(|t| t.to_rfc3339()),
                alert.resolved_at.map(|t| t.to_rfc3339()),
                alert.id,
            ],
        )?;
        Ok(())
    }

    pub fn list_alerts(&self, session_id: &str) -> Result<Vec<Alert>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(queries::LIST_ALERTS)?;
        let rows = stmt.query_map(params![session_id], |row| {
            let event_ids: String = row.get(7)?;
            Ok(Alert {
                id: row.get(0)?,
                session_id: row.get(1)?,
                rule_id: row.get(2)?,
                title: row.get(3)?,
                description: row.get(4)?,
                severity: parse_severity(&row.get::<_, String>(5)?),
                status: parse_alert_status(&row.get::<_, String>(6)?),
                event_ids: serde_json::from_str(&event_ids).unwrap_or_default(),
                source: row.get(8)?,
                created_at: parse_dt(row.get::<_, String>(9)?).unwrap_or_else(|_| Utc::now()),
                acknowledged_at: row
                    .get::<_, Option<String>>(10)?
                    .and_then(|s| parse_dt(s).ok()),
                resolved_at: row
                    .get::<_, Option<String>>(11)?
                    .and_then(|s| parse_dt(s).ok()),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .context("failed to list alerts")
    }

    pub fn get_alert(&self, alert_id: &str) -> Result<Option<Alert>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(queries::GET_ALERT)?;
        let mut rows = stmt.query(params![alert_id])?;
        if let Some(row) = rows.next()? {
            let event_ids: String = row.get(7)?;
            return Ok(Some(Alert {
                id: row.get(0)?,
                session_id: row.get(1)?,
                rule_id: row.get(2)?,
                title: row.get(3)?,
                description: row.get(4)?,
                severity: parse_severity(&row.get::<_, String>(5)?),
                status: parse_alert_status(&row.get::<_, String>(6)?),
                event_ids: serde_json::from_str(&event_ids).unwrap_or_default(),
                source: row.get(8)?,
                created_at: parse_dt(row.get::<_, String>(9)?).unwrap_or_else(|_| Utc::now()),
                acknowledged_at: row
                    .get::<_, Option<String>>(10)?
                    .and_then(|s| parse_dt(s).ok()),
                resolved_at: row
                    .get::<_, Option<String>>(11)?
                    .and_then(|s| parse_dt(s).ok()),
            }));
        }
        Ok(None)
    }

    pub fn insert_incident(&self, incident: &Incident) -> Result<()> {
        let conn = self.conn()?;
        let alert_ids = serde_json::to_string(&incident.alert_ids)?;
        conn.execute(
            queries::INSERT_INCIDENT,
            params![
                incident.id,
                incident.session_id,
                incident.title,
                incident.description,
                incident_status_str(&incident.status),
                severity_str(&incident.severity),
                incident.scenario_id,
                incident.assigned_to,
                alert_ids,
                incident.created_at.to_rfc3339(),
                incident.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn update_incident(&self, incident: &Incident) -> Result<()> {
        let conn = self.conn()?;
        let alert_ids = serde_json::to_string(&incident.alert_ids)?;
        conn.execute(
            queries::UPDATE_INCIDENT,
            params![
                incident_status_str(&incident.status),
                incident.description,
                alert_ids,
                incident.updated_at.to_rfc3339(),
                incident.closed_at.map(|t| t.to_rfc3339()),
                incident.id,
            ],
        )?;
        Ok(())
    }

    pub fn list_incidents(&self, session_id: &str) -> Result<Vec<Incident>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(queries::LIST_INCIDENTS)?;
        let rows = stmt.query_map(params![session_id], |row| {
            let alert_ids: String = row.get(8)?;
            Ok(Incident {
                id: row.get(0)?,
                session_id: row.get(1)?,
                title: row.get(2)?,
                description: row.get(3)?,
                status: parse_incident_status(&row.get::<_, String>(4)?),
                severity: parse_severity(&row.get::<_, String>(5)?),
                scenario_id: row.get(6)?,
                assigned_to: row.get(7)?,
                alert_ids: serde_json::from_str(&alert_ids).unwrap_or_default(),
                created_at: parse_dt(row.get::<_, String>(9)?).unwrap_or_else(|_| Utc::now()),
                updated_at: parse_dt(row.get::<_, String>(10)?).unwrap_or_else(|_| Utc::now()),
                closed_at: row
                    .get::<_, Option<String>>(11)?
                    .and_then(|s| parse_dt(s).ok()),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .context("failed to list incidents")
    }

    pub fn insert_evidence(&self, evidence: &Evidence) -> Result<()> {
        let encrypted_data = encrypt_field(&evidence.data);
        let conn = self.conn()?;
        conn.execute(
            queries::INSERT_EVIDENCE,
            params![
                evidence.id,
                evidence.session_id,
                evidence.incident_id,
                evidence_type_str(&evidence.evidence_type),
                evidence.title,
                evidence.description,
                encrypted_data,
                evidence.source_host,
                evidence.collected_at.to_rfc3339(),
                evidence.ioc_match as i32,
            ],
        )?;
        Ok(())
    }

    pub fn list_evidence(&self, session_id: &str) -> Result<Vec<Evidence>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(queries::LIST_EVIDENCE)?;
        let rows = stmt.query_map(params![session_id], |row| {
            let data_db: String = row.get(6)?;
            Ok(Evidence {
                id: row.get(0)?,
                session_id: row.get(1)?,
                incident_id: row.get(2)?,
                evidence_type: parse_evidence_type(&row.get::<_, String>(3)?),
                title: row.get(4)?,
                description: row.get(5)?,
                data: decrypt_field(&data_db),
                source_host: row.get(7)?,
                collected_at: parse_dt(row.get::<_, String>(8)?).unwrap_or_else(|_| Utc::now()),
                ioc_match: row.get::<_, i32>(9)? != 0,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .context("failed to list evidence")
    }

    pub fn insert_action(&self, action: &ActionRecord) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            queries::INSERT_ACTION,
            params![
                action.id,
                action.session_id,
                action.incident_id,
                action.action_type,
                action.target,
                action.details,
                action.success as i32,
                action.performed_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn list_actions(&self, session_id: &str) -> Result<Vec<ActionRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(queries::LIST_ACTIONS)?;
        let rows = stmt.query_map(params![session_id], |row| {
            Ok(ActionRecord {
                id: row.get(0)?,
                session_id: row.get(1)?,
                incident_id: row.get(2)?,
                action_type: row.get(3)?,
                target: row.get(4)?,
                details: row.get(5)?,
                success: row.get::<_, i32>(6)? != 0,
                performed_at: parse_dt(row.get::<_, String>(7)?).unwrap_or_else(|_| Utc::now()),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .context("failed to list actions")
    }

    pub fn upsert_score(&self, score: &ScoreRecord) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            queries::UPSERT_SCORE,
            params![
                score.id,
                score.session_id,
                score.detection_score,
                score.investigation_score,
                score.containment_score,
                score.recovery_score,
                score.total_score,
                score.time_elapsed_secs,
                score.calculated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_score(&self, session_id: &str) -> Result<Option<ScoreRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(queries::GET_SCORE)?;
        let mut rows = stmt.query(params![session_id])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(ScoreRecord {
                id: row.get(0)?,
                session_id: row.get(1)?,
                detection_score: row.get(2)?,
                investigation_score: row.get(3)?,
                containment_score: row.get(4)?,
                recovery_score: row.get(5)?,
                total_score: row.get(6)?,
                time_elapsed_secs: row.get(7)?,
                calculated_at: parse_dt(row.get::<_, String>(8)?)?,
            }));
        }
        Ok(None)
    }

    pub fn insert_asset(&self, asset: &Asset) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            queries::INSERT_ASSET,
            params![
                asset.id,
                asset.hostname,
                asset.ip_address,
                asset.asset_type,
                asset.os,
                asset.criticality,
                asset.department,
                asset.status,
            ],
        )?;
        Ok(())
    }

    pub fn list_assets(&self) -> Result<Vec<Asset>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(queries::LIST_ASSETS)?;
        let rows = stmt.query_map([], |row| {
            Ok(Asset {
                id: row.get(0)?,
                hostname: row.get(1)?,
                ip_address: row.get(2)?,
                asset_type: row.get(3)?,
                os: row.get(4)?,
                criticality: row.get(5)?,
                department: row.get(6)?,
                status: row.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .context("failed to list assets")
    }

    pub fn ensure_admin_user_from_env(&self) -> Result<()> {
        let username = std::env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string());
        let password = std::env::var("ADMIN_PASSWORD")
            .unwrap_or_else(|_| "change_admin_password_immediately".to_string());

        if self.get_user_by_username(&username)?.is_some() {
            return Ok(());
        }

        let _ = self.create_user(&username, &password, "admin")?;
        Ok(())
    }

    pub fn create_user(&self, username: &str, password: &str, role: &str) -> Result<User> {
        let conn = self.conn()?;
        let salt = generate_salt();
        let pwd_hash = hash_password(password, &salt);
        let id = generate_uuid();
        let now = Utc::now().to_rfc3339();
        let totp_secret: Option<String> = None;
        let totp_enabled: i32 = 0;

        conn.execute(
            queries::INSERT_USER,
            params![
                id,
                username,
                pwd_hash,
                salt,
                role,
                totp_secret,
                totp_enabled,
                now
            ],
        )?;

        Ok(User {
            id,
            username: username.to_string(),
            role: role.to_string(),
            created_at: now,
        })
    }

    pub fn get_user_by_username(&self, username: &str) -> Result<Option<UserDbRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(queries::GET_USER_BY_USERNAME)?;
        let mut rows = stmt.query(params![username])?;
        if let Some(row) = rows.next()? {
            let enc_secret: Option<String> = row.get(5)?;
            let decrypted_secret = enc_secret.map(|s| decrypt_field(&s));
            return Ok(Some(UserDbRecord {
                id: row.get(0)?,
                username: row.get(1)?,
                password_hash: row.get(2)?,
                salt: row.get(3)?,
                role: row.get(4)?,
                totp_secret: decrypted_secret,
                totp_enabled: row.get::<_, i32>(6)? != 0,
                created_at: row.get(7)?,
            }));
        }
        Ok(None)
    }

    pub fn update_user_totp_secret(&self, username: &str, secret: &str) -> Result<()> {
        let conn = self.conn()?;
        let encrypted_secret = encrypt_field(secret);
        conn.execute(
            queries::UPDATE_USER_TOTP_SECRET,
            params![encrypted_secret, username],
        )?;
        Ok(())
    }

    pub fn update_user_totp_enable(&self, username: &str, enabled: bool) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            queries::UPDATE_USER_TOTP_ENABLE,
            params![enabled as i32, username],
        )?;
        Ok(())
    }

    pub fn ban_ip(&self, ip: &str, reason: &str, duration_secs: i64) -> Result<()> {
        let conn = self.conn()?;
        let now = Utc::now();
        let expires_at = now.timestamp() + duration_secs;
        conn.execute(
            queries::INSERT_BANNED_IP,
            params![ip, reason, now.to_rfc3339(), expires_at],
        )?;
        Ok(())
    }

    pub fn is_ip_banned(&self, ip: &str) -> Result<bool> {
        let conn = self.conn()?;
        let now = Utc::now().timestamp();
        let mut stmt = conn.prepare(queries::IS_IP_BANNED)?;
        let mut rows = stmt.query(params![ip, now])?;
        Ok(rows.next()?.is_some())
    }
}

fn parse_dt(s: String) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&s)
        .map(|dt| dt.with_timezone(&Utc))
        .context("invalid timestamp")
}

fn severity_str(s: &IncidentSeverity) -> &'static str {
    match s {
        IncidentSeverity::Low => "low",
        IncidentSeverity::Medium => "medium",
        IncidentSeverity::High => "high",
        IncidentSeverity::Critical => "critical",
    }
}

fn parse_severity(s: &str) -> IncidentSeverity {
    match s {
        "low" => IncidentSeverity::Low,
        "medium" => IncidentSeverity::Medium,
        "high" => IncidentSeverity::High,
        _ => IncidentSeverity::Critical,
    }
}

fn alert_status_str(s: &AlertStatus) -> &'static str {
    match s {
        AlertStatus::New => "new",
        AlertStatus::Acknowledged => "acknowledged",
        AlertStatus::Investigating => "investigating",
        AlertStatus::Resolved => "resolved",
        AlertStatus::FalsePositive => "false_positive",
    }
}

fn parse_alert_status(s: &str) -> AlertStatus {
    match s {
        "acknowledged" => AlertStatus::Acknowledged,
        "investigating" => AlertStatus::Investigating,
        "resolved" => AlertStatus::Resolved,
        "false_positive" => AlertStatus::FalsePositive,
        _ => AlertStatus::New,
    }
}

fn incident_status_str(s: &IncidentStatus) -> &'static str {
    match s {
        IncidentStatus::New => "new",
        IncidentStatus::Investigating => "investigating",
        IncidentStatus::Contained => "contained",
        IncidentStatus::Eradicated => "eradicated",
        IncidentStatus::Recovered => "recovered",
        IncidentStatus::Closed => "closed",
    }
}

fn parse_incident_status(s: &str) -> IncidentStatus {
    match s {
        "investigating" => IncidentStatus::Investigating,
        "contained" => IncidentStatus::Contained,
        "eradicated" => IncidentStatus::Eradicated,
        "recovered" => IncidentStatus::Recovered,
        "closed" => IncidentStatus::Closed,
        _ => IncidentStatus::New,
    }
}

fn evidence_type_str(t: &crate::models::EvidenceType) -> &'static str {
    match t {
        crate::models::EvidenceType::Log => "log",
        crate::models::EvidenceType::File => "file",
        crate::models::EvidenceType::Network => "network",
        crate::models::EvidenceType::Memory => "memory",
        crate::models::EvidenceType::Registry => "registry",
        crate::models::EvidenceType::Process => "process",
        crate::models::EvidenceType::Email => "email",
    }
}

fn parse_evidence_type(s: &str) -> crate::models::EvidenceType {
    match s {
        "file" => crate::models::EvidenceType::File,
        "network" => crate::models::EvidenceType::Network,
        "memory" => crate::models::EvidenceType::Memory,
        "registry" => crate::models::EvidenceType::Registry,
        "process" => crate::models::EvidenceType::Process,
        "email" => crate::models::EvidenceType::Email,
        _ => crate::models::EvidenceType::Log,
    }
}
