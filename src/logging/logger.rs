use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the tracing/logging subscriber for the application
pub struct SimLogger;

impl SimLogger {
    pub fn init() {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("cyber_incident_simulator=info,tower_http=info"));

        fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_thread_ids(false)
            .compact()
            .init();
    }
}
