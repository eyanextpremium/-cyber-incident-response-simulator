use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::database::Repository;
use crate::simulation::engine::AppState;
use crate::utils::parse_token;

static RATE_LIMIT_BUCKETS: OnceLock<Mutex<HashMap<String, VecDeque<Instant>>>> = OnceLock::new();

fn rate_limit_store() -> &'static Mutex<HashMap<String, VecDeque<Instant>>> {
    RATE_LIMIT_BUCKETS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Extracts the real client IP, honoring X-Forwarded-For (first hop) with a safe fallback.
fn client_ip(req: &Request<Body>) -> String {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .map(|ip| ip.split(',').next().unwrap_or(ip).trim().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

/// Request logging middleware — logs method, path, status, and elapsed time.
/// Placed so it wraps every response, including ones rejected by auth/ip-lockdown.
pub async fn request_logger(req: Request<Body>, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let start = Instant::now();

    let response = next.run(req).await;

    let elapsed = start.elapsed();
    tracing::info!(
        method = %method,
        path = %path,
        status = %response.status().as_u16(),
        elapsed_ms = %elapsed.as_millis(),
        "HTTP request"
    );

    response
}

/// Security Headers middleware — injects enterprise defense headers into all responses.
/// Placed so it wraps every response, including ones rejected by auth/ip-lockdown.
pub async fn security_headers_middleware(req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_XSS_PROTECTION,
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self';",
        ),
    );

    response
}

/// IP Ban / Lockdown Middleware — auto-blocks banned IPs
pub async fn ip_lockdown_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = client_ip(&req);

    let repo = Repository::new(state.db.clone());
    if let Ok(true) = repo.is_ip_banned(&ip) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Forbidden: Your IP has been locked down due to security violations."
            })),
        )
            .into_response();
    }

    next.run(req).await
}

fn check_rate_limit(ip: &str) -> bool {
    let now = Instant::now();
    let store = rate_limit_store();
    let mut buckets = store.lock().expect("rate limiter map poisoned");
    let window = buckets.entry(ip.to_string()).or_insert_with(VecDeque::new);

    while let Some(first) = window.front() {
        if now.duration_since(*first) > Duration::from_secs(60) {
            window.pop_front();
        } else {
            break;
        }
    }

    if window.len() >= 60 {
        false
    } else {
        window.push_back(now);
        true
    }
}

/// High-Level Authentication & RBAC Middleware for protected `/api/*` endpoints
pub async fn auth_middleware(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path();

    // Public endpoints that do not require authentication token
    if path == "/api/health"
        || path == "/api/auth/login"
        || path == "/api/auth/register"
        || path == "/api/ws"
        || path == "/api/events/sse"
        || !path.starts_with("/api/")
    {
        return next.run(req).await;
    }

    // Manual IP-based rate limiter: max 60 requests/minute per IP.
    let ip = client_ip(&req);
    if !check_rate_limit(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "Too Many Requests: per-IP minute limit exceeded."
            })),
        )
            .into_response();
    }

    // Extract Authorization header or x-api-key header
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| req.headers().get("x-api-key").and_then(|h| h.to_str().ok()));

    let token_str = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Unauthorized: Access token or API key required."
                })),
            )
                .into_response();
        }
    };

    // Validate token
    if parse_token(token_str).is_some() {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized: Invalid or expired security token."
            })),
        )
            .into_response()
    }
}
