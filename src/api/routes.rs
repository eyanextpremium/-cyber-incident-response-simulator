use axum::http::HeaderValue;
use axum::{
    middleware,
    routing::{get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use crate::simulation::engine::AppState;

use super::handlers::*;
use super::middleware::{
    auth_middleware, ip_lockdown_middleware, request_logger, security_headers_middleware,
};
use super::ws::{sse_handler, ws_handler};

/// Build the full Axum application router with enterprise defense layers
pub fn build_router(state: AppState, static_dir: &str) -> Router {
    let allowed_origin = std::env::var("ALLOWED_ORIGIN")
        .or_else(|_| std::env::var("CORS_ORIGIN"))
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

    let origin = HeaderValue::from_str(allowed_origin.trim())
        .unwrap_or_else(|_| HeaderValue::from_static("http://127.0.0.1:8080"));

    let cors = CorsLayer::new()
        .allow_origin(origin)
        .allow_methods(Any)
        .allow_headers(Any);

    let api = Router::new()
        // Health & Public Info
        .route("/health", get(health))
        .route("/stats", get(global_stats))
        // Authentication & RBAC
        .route("/auth/login", post(login_user))
        .route("/auth/register", post(register_user))
        .route("/auth/2fa/setup", post(setup_2fa))
        .route("/auth/2fa/enable", post(enable_2fa))
        // Live Network Ingestion
        .route("/ingest/logs", post(ingest_network_logs))
        // Real-Time Streaming
        .route("/ws", get(ws_handler))
        .route("/events/sse", get(sse_handler))
        // Scenarios
        .route("/scenarios", get(list_scenarios))
        .route("/scenarios/custom", post(create_custom_scenario))
        .route("/scenarios/mitre", get(list_mitre_categories))
        // Self-Audit
        .route("/audit/run", post(run_self_audit))
        .route("/audit/quick", get(audit_quick_check))
        // Sessions
        .route("/sessions", post(create_session))
        .route("/sessions", get(list_sessions))
        .route("/sessions/:session_id", get(get_session))
        .route("/sessions/:session_id/finalize", post(finalize_session))
        .route("/sessions/:session_id/score", get(get_score))
        // Events
        .route("/sessions/:session_id/events", get(list_events))
        // Alerts
        .route("/sessions/:session_id/alerts", get(list_alerts))
        .route(
            "/sessions/:session_id/alerts/:alert_id/acknowledge",
            post(acknowledge_alert),
        )
        .route("/sessions/:session_id/alerts/:alert_id", put(update_alert))
        // Incidents
        .route("/sessions/:session_id/incidents", get(list_incidents))
        .route("/sessions/:session_id/incidents", post(create_incident))
        .route(
            "/sessions/:session_id/incidents/:incident_id",
            put(update_incident),
        )
        // Investigation
        .route("/sessions/:session_id/timeline", get(get_timeline))
        .route(
            "/sessions/:session_id/investigation/summary",
            get(get_investigation_summary),
        )
        .route("/sessions/:session_id/evidence", get(list_evidence))
        .route(
            "/sessions/:session_id/evidence/collect",
            post(collect_evidence),
        )
        // Response
        .route("/sessions/:session_id/actions", post(execute_action))
        .route("/sessions/:session_id/actions", get(list_actions))
        // Assets
        .route("/assets", get(list_assets))
        .with_state(state.clone())
        // Defense-in-depth middleware pipeline:
        // Outermost to innermost: cors -> security_headers -> request_logger -> ip_lockdown -> auth -> handlers
        .layer(middleware::from_fn(auth_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            ip_lockdown_middleware,
        ))
        .layer(middleware::from_fn(request_logger))
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(cors.clone());

    Router::new()
        .nest("/api", api)
        .fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(true))
        .layer(cors)
}
