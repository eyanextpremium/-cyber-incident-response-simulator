use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::database::Repository;
use crate::incident::IncidentManager;
use crate::investigation::InvestigationEngine;
use crate::models::{IncidentSeverity, IncidentStatus};
use crate::response::engine::{ExecuteActionRequest, ResponseEngine};
use crate::scenarios::ScenarioLoader;
use crate::scoring::ScoringEngine;
use crate::simulation::engine::AppState;
use crate::simulation::session::SimSession;

use super::errors::{ApiError, ApiResult};

// ─── Session Handlers ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub scenario_id: String,
    pub analyst_name: String,
}

pub async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSessionRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    // Validate input parameters
    if req.scenario_id.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Scenario ID cannot be empty".to_string(),
        ));
    }
    if req.analyst_name.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Analyst name cannot be empty".to_string(),
        ));
    }
    if req.analyst_name.len() > 100 {
        return Err(ApiError::BadRequest(
            "Analyst name too long (max 100 characters)".to_string(),
        ));
    }

    // Validate scenario exists
    let loader = ScenarioLoader::new(&state.scenario_dir);
    let scenario = loader
        .load_by_id(&req.scenario_id)
        .map_err(|_| ApiError::NotFound(format!("Scenario '{}' not found", req.scenario_id)))?;

    let repo = Repository::new(state.db.clone());
    let session = SimSession::new(&req.scenario_id, &req.analyst_name);

    repo.create_session(&session.id, &req.scenario_id, &req.analyst_name)?;

    // Seed scenario events immediately (pre-generate all with correct offsets)
    let events = crate::scenarios::EventGenerator::generate_events(
        &session.id,
        &scenario,
        session.started_at,
    );
    for event in &events {
        if let Err(e) = repo.insert_event(event) {
            tracing::warn!("Seed event insert failed: {}", e);
        }
    }

    // Run detection on all seeded events to generate initial alerts
    let rules = crate::detection::rule::rules_from_config(
        &crate::config::load_detection_rules(
            &state
                .scenario_dir
                .parent()
                .unwrap_or(std::path::Path::new(".")),
        )
        .unwrap_or_default(),
    );
    let mut engine = crate::detection::DetectionEngine::new(rules);
    for event in &events {
        let matches = engine.analyze(event);
        for detection in &matches {
            let alert =
                crate::detection::DetectionEngine::create_alert(&session.id, event, detection);
            if let Err(e) = repo.insert_alert(&alert) {
                tracing::warn!("Alert insert failed: {}", e);
            }
        }
    }

    tracing::info!(
        session_id = %session.id,
        scenario = %req.scenario_id,
        analyst = %req.analyst_name,
        "Session created"
    );

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "session_id": session.id,
            "scenario_id": req.scenario_id,
            "analyst_name": req.analyst_name,
            "scenario": {
                "name": scenario.name,
                "difficulty": scenario.difficulty,
                "description": scenario.description,
                "objective": scenario.objective,
                "time_limit_secs": scenario.time_limit_secs,
                "hints": scenario.hints,
                "expected_actions": scenario.expected_actions
            },
            "started_at": session.started_at
        })),
    ))
}

pub async fn list_sessions(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let repo = Repository::new(state.db.clone());
    let sessions = repo.list_sessions()?;
    // Limit to recent sessions for performance
    let recent_sessions: Vec<_> = sessions.into_iter().take(50).collect();
    Ok(Json(
        json!({ "sessions": recent_sessions, "count": recent_sessions.len() }),
    ))
}

pub async fn get_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !crate::utils::validate_session_id(&session_id) {
        return Err(ApiError::BadRequest(
            "Invalid session ID format".to_string(),
        ));
    }

    let repo = Repository::new(state.db.clone());
    let session = repo
        .get_session(&session_id)?
        .ok_or_else(|| ApiError::NotFound(format!("Session '{}' not found", session_id)))?;
    Ok(Json(serde_json::to_value(session).unwrap_or_default()))
}

// ─── Scenario Handlers ────────────────────────────────────────────────────────

pub async fn list_scenarios(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let loader = ScenarioLoader::new(&state.scenario_dir);
    let scenarios = loader.load_all()?;
    let mitre_categories = loader.list_mitre_categories();
    let summaries: Vec<Value> = scenarios
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "name": s.name,
                "difficulty": s.difficulty,
                "category": s.category,
                "description": s.description,
                "objective": s.objective,
                "time_limit_secs": s.time_limit_secs,
                "scenario_type": s.scenario_type,
                "is_mitre": s.id.starts_with("mitre-")
            })
        })
        .collect();
    Ok(Json(json!({
        "scenarios": summaries,
        "count": summaries.len(),
        "mitre_categories": mitre_categories.iter().map(|(name, count)| {
            json!({ "category": name, "count": count })
        }).collect::<Vec<_>>(),
        "mitre_total": mitre_categories.iter().map(|(_, c)| c).sum::<usize>()
    })))
}

// ─── Event Handlers ───────────────────────────────────────────────────────────

pub async fn list_events(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !crate::utils::validate_session_id(&session_id) {
        return Err(ApiError::BadRequest(
            "Invalid session ID format".to_string(),
        ));
    }

    let repo = Repository::new(state.db.clone());
    let events = repo.list_events(&session_id)?;
    Ok(Json(json!({ "events": events, "count": events.len() })))
}

// ─── Alert Handlers ───────────────────────────────────────────────────────────

pub async fn list_alerts(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !crate::utils::validate_session_id(&session_id) {
        return Err(ApiError::BadRequest(
            "Invalid session ID format".to_string(),
        ));
    }

    let repo = Repository::new(state.db.clone());
    let alerts = repo.list_alerts(&session_id)?;
    Ok(Json(json!({ "alerts": alerts, "count": alerts.len() })))
}

pub async fn acknowledge_alert(
    State(state): State<AppState>,
    Path((session_id, alert_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let repo = Repository::new(state.db.clone());
    let engine = ResponseEngine::new(&repo);
    engine.acknowledge_alert(&session_id, &alert_id)?;
    Ok(Json(
        json!({ "success": true, "alert_id": alert_id, "status": "acknowledged" }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct UpdateAlertRequest {
    pub status: String,
}

pub async fn update_alert(
    State(state): State<AppState>,
    Path((_session_id, alert_id)): Path<(String, String)>,
    Json(req): Json<UpdateAlertRequest>,
) -> ApiResult<Json<Value>> {
    // Validate alert ID
    if alert_id.trim().is_empty() {
        return Err(ApiError::BadRequest("Alert ID cannot be empty".to_string()));
    }

    // Validate status
    if req.status.trim().is_empty() {
        return Err(ApiError::BadRequest("Status cannot be empty".to_string()));
    }

    let repo = Repository::new(state.db.clone());
    let mut alert = repo
        .get_alert(&alert_id)?
        .ok_or_else(|| ApiError::NotFound(format!("Alert '{}' not found", alert_id)))?;

    match req.status.as_str() {
        "acknowledged" => {
            alert.status = crate::models::AlertStatus::Acknowledged;
            alert.acknowledged_at = Some(Utc::now());
        }
        "investigating" => {
            alert.status = crate::models::AlertStatus::Investigating;
        }
        "resolved" => {
            alert.status = crate::models::AlertStatus::Resolved;
            alert.resolved_at = Some(Utc::now());
        }
        "false_positive" => {
            alert.status = crate::models::AlertStatus::FalsePositive;
            alert.resolved_at = Some(Utc::now());
        }
        _ => {
            return Err(ApiError::BadRequest(format!(
                "Unknown status: {}",
                req.status
            )))
        }
    }

    repo.update_alert(&alert)?;
    Ok(Json(
        json!({ "success": true, "alert_id": alert_id, "status": req.status }),
    ))
}

// ─── Incident Handlers ────────────────────────────────────────────────────────

pub async fn list_incidents(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !crate::utils::validate_session_id(&session_id) {
        return Err(ApiError::BadRequest(
            "Invalid session ID format".to_string(),
        ));
    }

    let repo = Repository::new(state.db.clone());
    let incidents = repo.list_incidents(&session_id)?;
    Ok(Json(
        json!({ "incidents": incidents, "count": incidents.len() }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct CreateIncidentRequest {
    pub title: String,
    pub severity: String,
    pub description: Option<String>,
    pub scenario_id: Option<String>,
}

pub async fn create_incident(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(req): Json<CreateIncidentRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    // Validate session ID
    if session_id.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Session ID cannot be empty".to_string(),
        ));
    }

    // Validate incident title
    if req.title.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Incident title cannot be empty".to_string(),
        ));
    }
    if req.title.len() > 200 {
        return Err(ApiError::BadRequest(
            "Incident title too long (max 200 characters)".to_string(),
        ));
    }

    // Validate severity
    if req.severity.trim().is_empty() {
        return Err(ApiError::BadRequest("Severity cannot be empty".to_string()));
    }

    let repo = Repository::new(state.db.clone());
    let severity = match req.severity.as_str() {
        "low" => IncidentSeverity::Low,
        "medium" => IncidentSeverity::Medium,
        "high" => IncidentSeverity::High,
        "critical" => IncidentSeverity::Critical,
        _ => return Err(ApiError::BadRequest("Invalid severity".into())),
    };
    let manager = IncidentManager::new(&repo);
    let scenario_id = req.scenario_id.as_deref().unwrap_or("manual");
    let description = req.description.as_deref().unwrap_or("");
    let incident = manager.create(&session_id, scenario_id, &req.title, severity, description)?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(&incident).unwrap_or_default()),
    ))
}

#[derive(Debug, Deserialize)]
pub struct UpdateIncidentRequest {
    pub status: String,
}

pub async fn update_incident(
    State(state): State<AppState>,
    Path((session_id, incident_id)): Path<(String, String)>,
    Json(req): Json<UpdateIncidentRequest>,
) -> ApiResult<Json<Value>> {
    // Validate session ID
    if session_id.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Session ID cannot be empty".to_string(),
        ));
    }

    // Validate incident ID
    if incident_id.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Incident ID cannot be empty".to_string(),
        ));
    }

    // Validate status
    if req.status.trim().is_empty() {
        return Err(ApiError::BadRequest("Status cannot be empty".to_string()));
    }

    let target = match req.status.as_str() {
        "investigating" => IncidentStatus::Investigating,
        "contained" => IncidentStatus::Contained,
        "eradicated" => IncidentStatus::Eradicated,
        "recovered" => IncidentStatus::Recovered,
        "closed" => IncidentStatus::Closed,
        _ => {
            return Err(ApiError::BadRequest(format!(
                "Unknown status: {}",
                req.status
            )))
        }
    };
    let repo = Repository::new(state.db.clone());
    let manager = IncidentManager::new(&repo);
    let incident = manager.advance(&session_id, &incident_id, target)?;
    Ok(Json(serde_json::to_value(&incident).unwrap_or_default()))
}

// ─── Investigation Handlers ───────────────────────────────────────────────────

pub async fn get_timeline(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !crate::utils::validate_session_id(&session_id) {
        return Err(ApiError::BadRequest(
            "Invalid session ID format".to_string(),
        ));
    }

    let repo = Repository::new(state.db.clone());
    let engine = InvestigationEngine::new(&repo);
    let timeline = engine.build_timeline(&session_id)?;
    Ok(Json(
        json!({ "timeline": timeline.entries, "count": timeline.entries.len() }),
    ))
}

pub async fn get_investigation_summary(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !crate::utils::validate_session_id(&session_id) {
        return Err(ApiError::BadRequest(
            "Invalid session ID format".to_string(),
        ));
    }

    let repo = Repository::new(state.db.clone());
    let engine = InvestigationEngine::new(&repo);
    let summary = engine.summary(&session_id)?;
    Ok(Json(serde_json::to_value(&summary).unwrap_or_default()))
}

pub async fn list_evidence(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !crate::utils::validate_session_id(&session_id) {
        return Err(ApiError::BadRequest(
            "Invalid session ID format".to_string(),
        ));
    }

    let repo = Repository::new(state.db.clone());
    let evidence = repo.list_evidence(&session_id)?;
    Ok(Json(
        json!({ "evidence": evidence, "count": evidence.len() }),
    ))
}

pub async fn collect_evidence(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !crate::utils::validate_session_id(&session_id) {
        return Err(ApiError::BadRequest(
            "Invalid session ID format".to_string(),
        ));
    }

    let repo = Repository::new(state.db.clone());
    let engine = InvestigationEngine::new(&repo);
    let collected = engine.auto_collect_evidence(&session_id, None)?;
    Ok(Json(
        json!({ "collected": collected.len(), "evidence": collected }),
    ))
}

// ─── Response Handlers ────────────────────────────────────────────────────────

pub async fn execute_action(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(req): Json<ExecuteActionRequest>,
) -> ApiResult<Json<Value>> {
    // Validate session ID
    if !crate::utils::validate_session_id(&session_id) {
        return Err(ApiError::BadRequest(
            "Invalid session ID format".to_string(),
        ));
    }

    // Validate action type
    if req.action_type.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Action type cannot be empty".to_string(),
        ));
    }

    // Validate target
    if req.target.trim().is_empty() {
        return Err(ApiError::BadRequest("Target cannot be empty".to_string()));
    }
    if req.target.len() > 255 {
        return Err(ApiError::BadRequest(
            "Target too long (max 255 characters)".to_string(),
        ));
    }

    let repo = Repository::new(state.db.clone());
    let engine = ResponseEngine::new(&repo);
    let action = engine.execute(&session_id, &req)?;
    Ok(Json(json!({
        "success": true,
        "action_id": action.id,
        "action_type": action.action_type,
        "target": action.target,
        "details": action.details
    })))
}

pub async fn list_actions(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !crate::utils::validate_session_id(&session_id) {
        return Err(ApiError::BadRequest(
            "Invalid session ID format".to_string(),
        ));
    }

    let repo = Repository::new(state.db.clone());
    let actions = repo.list_actions(&session_id)?;
    Ok(Json(json!({ "actions": actions, "count": actions.len() })))
}

// ─── Scoring Handlers ─────────────────────────────────────────────────────────

pub async fn get_score(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !crate::utils::validate_session_id(&session_id) {
        return Err(ApiError::BadRequest(
            "Invalid session ID format".to_string(),
        ));
    }

    let repo = Repository::new(state.db.clone());
    let score_record = repo.get_score(&session_id)?;
    match score_record {
        Some(s) => Ok(Json(serde_json::to_value(&s).unwrap_or_default())),
        None => Ok(Json(json!({ "message": "No score calculated yet" }))),
    }
}

pub async fn finalize_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !crate::utils::validate_session_id(&session_id) {
        return Err(ApiError::BadRequest(
            "Invalid session ID format".to_string(),
        ));
    }

    let repo = Repository::new(state.db.clone());

    // Get session start time
    let session_record = repo
        .get_session(&session_id)?
        .ok_or_else(|| ApiError::NotFound(format!("Session '{}' not found", session_id)))?;

    let scoring_engine = ScoringEngine::new(state.scoring_config.clone());
    let (metrics, ranking) =
        scoring_engine.calculate(&session_id, &repo, session_record.started_at)?;

    repo.complete_session(&session_id, metrics.total_score)?;

    Ok(Json(json!({
        "session_id": session_id,
        "metrics": metrics,
        "ranking": ranking
    })))
}

// ─── Asset Handlers ───────────────────────────────────────────────────────────

pub async fn list_assets(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let repo = Repository::new(state.db.clone());
    let assets = repo.list_assets()?;
    Ok(Json(json!({ "assets": assets, "count": assets.len() })))
}

// ─── Health Handler ───────────────────────────────────────────────────────────

pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "Cyber Incident Response Simulator",
        "version": "0.1.0"
    }))
}

// ─── Stats Handler ────────────────────────────────────────────────────────────

pub async fn global_stats(State(state): State<AppState>) -> Json<Value> {
    let sim_state = state.sim_state.lock().unwrap_or_else(|p| p.into_inner());
    Json(json!({
        "total_events_generated": sim_state.total_events_generated,
        "total_alerts_fired": sim_state.total_alerts_fired,
        "total_incidents_opened": sim_state.total_incidents_opened,
    }))
}

// ─── Authentication & User Handlers ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub totp_code: Option<String>,
}

pub async fn login_user(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<Value>> {
    let repo = Repository::new(state.db.clone());
    let u_lower = req.username.trim().to_lowercase();

    // Sanitize username for XSS prevention
    let sanitized_username = crate::utils::html_encode(&req.username);

    // Check existing DB user record first for 2FA requirement
    let user_record = repo.get_user_by_username(&req.username)?;

    if let Some(ref user) = user_record {
        if user.totp_enabled {
            if let Some(ref secret) = user.totp_secret {
                let code = req.totp_code.as_deref().unwrap_or("");
                if !crate::utils::verify_totp_code(secret, code) {
                    return Ok(Json(json!({
                        "success": false,
                        "requires_2fa": true,
                        "error": "2FA_REQUIRED",
                        "message": "Lütfen 6 haneli 2FA kodunuzu giriniz."
                    })));
                }
            }
        }
    }

    // Admin login using environment variables (removed hardcoded credentials)
    let admin_username = std::env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string());
    let admin_password = std::env::var("ADMIN_PASSWORD")
        .unwrap_or_else(|_| "change_admin_password_immediately".to_string());

    if u_lower == admin_username.to_lowercase() && req.password == admin_password {
        let token = crate::utils::generate_token(&admin_username, "admin");
        return Ok(Json(json!({
            "success": true,
            "token": token,
            "username": admin_username,
            "role": "admin"
        })));
    }

    let user_record = user_record.ok_or_else(|| {
        ApiError::Unauthorized("Gözden geçirin: Kullanıcı adı veya şifre hatalı.".to_string())
    })?;

    // Verify password using enhanced hash function
    if !crate::utils::verify_password(&req.password, &user_record.salt, &user_record.password_hash)
    {
        return Err(ApiError::Unauthorized(
            "Gözden geçirin: Kullanıcı adı veya şifre hatalı.".to_string(),
        ));
    }

    let token = crate::utils::generate_token(&user_record.username, &user_record.role);
    Ok(Json(json!({
        "success": true,
        "token": token,
        "username": sanitized_username,
        "role": user_record.role,
        "totp_enabled": user_record.totp_enabled
    })))
}

#[derive(Debug, Deserialize)]
pub struct Setup2FARequest {
    pub username: String,
}

pub async fn setup_2fa(
    State(state): State<AppState>,
    Json(req): Json<Setup2FARequest>,
) -> ApiResult<Json<Value>> {
    let repo = Repository::new(state.db.clone());
    let secret = crate::utils::generate_totp_secret();
    let qr_uri = format!(
        "otpauth://totp/CyberIncidentSimulator:{}?secret={}&issuer=CyberIncidentSimulator",
        req.username, secret
    );

    repo.update_user_totp_secret(&req.username, &secret)?;

    Ok(Json(json!({
        "success": true,
        "secret": secret,
        "qr_uri": qr_uri
    })))
}

#[derive(Debug, Deserialize)]
pub struct Enable2FARequest {
    pub username: String,
    pub code: String,
}

pub async fn enable_2fa(
    State(state): State<AppState>,
    Json(req): Json<Enable2FARequest>,
) -> ApiResult<Json<Value>> {
    let repo = Repository::new(state.db.clone());
    let user_record = repo
        .get_user_by_username(&req.username)?
        .ok_or_else(|| ApiError::NotFound("Kullanıcı bulunamadı.".to_string()))?;

    let secret = user_record
        .totp_secret
        .ok_or_else(|| ApiError::BadRequest("Önce 2FA kurulumu yapılmalıdır.".to_string()))?;

    if !crate::utils::verify_totp_code(&secret, &req.code) {
        return Err(ApiError::Unauthorized(
            "Geçersiz 2FA doğrulama kodu.".to_string(),
        ));
    }

    repo.update_user_totp_enable(&req.username, true)?;

    Ok(Json(json!({
        "success": true,
        "message": "2FA doğrulaması başarıyla aktifleştirildi."
    })))
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub role: Option<String>,
}

pub async fn register_user(
    State(_state): State<AppState>,
    Json(_req): Json<RegisterRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    Err(ApiError::Forbidden(
        "Registration is disabled. Only the trusted administrator may provision users.".into(),
    ))
}

// ─── Live Network Log Ingest Handler ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LogIngestRequest {
    pub session_id: Option<String>,
    pub source: String,
    pub event_type: String,
    pub message: String,
    pub host: String,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub user_name: Option<String>,
    pub raw_log: Option<String>,
    pub is_malicious: Option<bool>,
}

pub async fn ingest_network_logs(
    State(state): State<AppState>,
    Json(req): Json<LogIngestRequest>,
) -> ApiResult<Json<Value>> {
    let repo = Repository::new(state.db.clone());
    let session_id = req
        .session_id
        .unwrap_or_else(|| "live-ingest-session".to_string());

    let raw_log = req.raw_log.clone().unwrap_or_else(|| {
        format!(
            "{} [{}] {} host={} src={} dst={}",
            Utc::now().to_rfc3339(),
            req.source,
            req.message,
            req.host,
            req.source_ip.as_deref().unwrap_or("-"),
            req.destination_ip.as_deref().unwrap_or("-")
        )
    });

    let event = crate::models::SecurityEvent {
        id: crate::utils::generate_uuid(),
        session_id: session_id.clone(),
        timestamp: Utc::now(),
        source: crate::models::EventSource::from_str(&req.source),
        event_type: req.event_type,
        message: req.message,
        host: req.host,
        source_ip: req.source_ip,
        destination_ip: req.destination_ip,
        user: req.user_name,
        raw_log,
        mitre_technique: None,
        is_malicious: req.is_malicious.unwrap_or(false),
    };

    repo.insert_event(&event)?;

    // Run Detection Engine
    let rules = crate::detection::rule::rules_from_config(
        &crate::config::load_detection_rules(
            &state
                .scenario_dir
                .parent()
                .unwrap_or(std::path::Path::new(".")),
        )
        .unwrap_or_default(),
    );
    let mut engine = crate::detection::DetectionEngine::new(rules);
    let matches = engine.analyze(&event);

    let mut alerts_fired = 0;
    for detection in &matches {
        let alert = crate::detection::DetectionEngine::create_alert(&session_id, &event, detection);
        if let Ok(_) = repo.insert_alert(&alert) {
            alerts_fired += 1;
            let _ = state.broadcast_tx.send(
                serde_json::json!({
                    "type": "alert",
                    "session_id": session_id,
                    "rule_id": alert.rule_id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "source": alert.source
                })
                .to_string(),
            );
        }
    }

    Ok(Json(json!({
        "success": true,
        "event_id": event.id,
        "alerts_fired": alerts_fired
    })))
}

// ─── Custom Scenario Handlers ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateCustomScenarioRequest {
    pub id: String,
    pub name: String,
    pub difficulty: String,
    pub category: String,
    pub description: String,
    pub objective: String,
    pub time_limit_secs: u64,
}

pub async fn create_custom_scenario(
    State(state): State<AppState>,
    Json(req): Json<CreateCustomScenarioRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    if req.id.trim().is_empty() || req.name.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Scenario ID and Name are required".into(),
        ));
    }

    let difficulty_dir = match req.difficulty.as_str() {
        "beginner" => "beginner",
        "intermediate" => "intermediate",
        "advanced" => "advanced",
        _ => "expert",
    };

    let target_dir = state.scenario_dir.join(difficulty_dir);
    std::fs::create_dir_all(&target_dir)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to create scenario dir: {}", e)))?;

    let file_path = target_dir.join(format!("{}.json", req.id));

    let scenario_json = json!({
        "id": req.id,
        "name": req.name,
        "difficulty": req.difficulty,
        "category": req.category,
        "description": req.description,
        "objective": req.objective,
        "time_limit_secs": req.time_limit_secs,
        "events": [],
        "hints": ["Examine system logs", "Check suspicious IP connections"],
        "expected_actions": ["isolate_host", "block_ip"]
    });

    std::fs::write(
        &file_path,
        serde_json::to_string_pretty(&scenario_json).unwrap_or_default(),
    )
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to write scenario file: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(
            json!({ "success": true, "scenario_id": req.id, "path": file_path.to_string_lossy() }),
        ),
    ))
}

// ─── Self-Audit Handlers ──────────────────────────────────────────────────────

/// Run a full self-audit: static file scan + simulated attack probes
pub async fn run_self_audit(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let engine = crate::audit::AuditEngine::new(&state.base_dir, &state.scenario_dir);
    let report = engine.run_full_audit();

    tracing::info!(
        audit_id = %report.audit_id,
        findings = %report.summary.total_findings,
        score = %report.summary.security_score,
        "Self-audit completed"
    );

    Ok(Json(serde_json::to_value(&report).unwrap_or_default()))
}

/// Quick security health check — returns summary only
pub async fn audit_quick_check(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let engine = crate::audit::AuditEngine::new(&state.base_dir, &state.scenario_dir);
    let summary = engine.quick_check();
    Ok(Json(serde_json::to_value(&summary).unwrap_or_default()))
}

/// List MITRE ATT&CK categories and scenario counts
pub async fn list_mitre_categories(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let loader = ScenarioLoader::new(&state.scenario_dir);
    let categories = loader.list_mitre_categories();
    let total: usize = categories.iter().map(|(_, c)| c).sum();
    Ok(Json(json!({
        "categories": categories.iter().map(|(name, count)| {
            json!({ "category": name, "count": count })
        }).collect::<Vec<_>>(),
        "total_scenarios": total,
        "expected": 56
    })))
}
