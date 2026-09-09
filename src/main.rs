use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;

use cyber_incident_simulator::api::build_router;
use cyber_incident_simulator::config::{
    load_detection_rules, load_scoring_config, load_settings, resolve_base_dir,
};
use cyber_incident_simulator::database::init_database;
use cyber_incident_simulator::database::Repository;
use cyber_incident_simulator::detection::rule::rules_from_config;
use cyber_incident_simulator::logging::SimLogger;
use cyber_incident_simulator::models::Asset;
use cyber_incident_simulator::scenarios::ScenarioLoader;
use cyber_incident_simulator::simulation::{
    engine::AppState, engine::SimulationEngine, session::SimSession, state::SimState,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file
    dotenv::dotenv().ok();

    // Initialize structured logging
    SimLogger::init();

    let base = resolve_base_dir();
    tracing::info!(base_dir = %base.display(), "Starting Cyber Incident Response Simulator");

    // Load configuration
    let settings = load_settings(&base)?;
    tracing::info!(host = %settings.server.host, port = %settings.server.port, "Configuration loaded");

    // Initialize SQLite database
    let db_path = base.join(&settings.database.path);
    let db = init_database(&db_path)?;
    tracing::info!(db = %db_path.display(), "Database initialized");

    // Ensure a single admin account exists from the configured .env values
    let repo = Repository::new(db.clone());
    repo.ensure_admin_user_from_env()?;

    // Load detection rules and scoring config
    let rule_entries = load_detection_rules(&base).unwrap_or_default();
    let scoring_config = load_scoring_config(&base).unwrap_or_default();
    let detection_rules = rules_from_config(&rule_entries);
    tracing::info!(rules = %detection_rules.len(), "Detection rules loaded");

    // Seed default assets
    seed_assets(&db)?;

    // Shared simulation state & real-time broadcast channel
    let sim_state = Arc::new(Mutex::new(SimState::new()));
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<String>(100);

    // Build application state
    let scenario_dir = base.join(&settings.simulation.scenario_dir);
    let app_state = AppState {
        db: db.clone(),
        base_dir: base.clone(),
        scenario_dir: scenario_dir.clone(),
        scoring_config,
        detection_rules: detection_rules.clone(),
        sim_state,
        broadcast_tx: broadcast_tx.clone(),
    };

    // Start background UDP Syslog Listener (RFC 3164 / RFC 5424)
    let udp_repo = Arc::new(Repository::new(db.clone()));
    let udp_engine = Arc::new(Mutex::new(
        cyber_incident_simulator::detection::DetectionEngine::new(detection_rules.clone()),
    ));
    let udp_tx = broadcast_tx.clone();
    tokio::spawn(async move {
        let syslog_server = cyber_incident_simulator::logging::UdpSyslogServer::new(
            "127.0.0.1:5140",
            udp_repo,
            udp_engine,
            udp_tx,
        );
        if let Err(e) = syslog_server.start().await {
            tracing::error!("UDP Syslog Server error: {}", e);
        }
    });

    // Start background simulation tick task for gradual event emission
    let tick_app_state = app_state.clone();
    let tick_scenario_dir = scenario_dir.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(2)); // Tick every 2 seconds
        let loader = ScenarioLoader::new(&tick_scenario_dir);
        let mut active_sessions: HashMap<String, SimSession> = HashMap::new();

        loop {
            interval.tick().await;

            // Refresh active sessions from database
            let repo = Repository::new(tick_app_state.db.clone());
            if let Ok(sessions) = repo.list_sessions() {
                for session in sessions {
                    if session.status == "active" && !active_sessions.contains_key(&session.id) {
                        // Load scenario for this session
                        if let Ok(_scenario) = loader.load_by_id(&session.scenario_id) {
                            let mut sim_session =
                                SimSession::new(&session.scenario_id, &session.analyst_name);
                            sim_session.id = session.id.clone();
                            sim_session.started_at = session.started_at;
                            active_sessions.insert(session.id.clone(), sim_session);
                        }
                    }
                }

                // Remove completed sessions
                active_sessions.retain(|id, session| {
                    let should_keep = session.is_active();
                    if !should_keep {
                        tracing::info!(session_id = %id, "Session removed from tick loop");
                    }
                    should_keep
                });

                // Run tick for each active session directly within the tick interval
                for (session_id, session) in active_sessions.iter_mut() {
                    if let Ok(scenario) = loader.load_by_id(&session.scenario_id) {
                        let sim_engine = SimulationEngine::new(tick_app_state.clone());
                        if let Ok(emitted) = sim_engine.tick(session, &scenario, 1) {
                            if emitted > 0 {
                                tracing::debug!(session_id = %session_id, events = emitted, "Gradual tick emitted events");
                            }
                        }
                    }
                }
            }
        }
    });

    // Build Axum router
    let static_dir = base.join(&settings.server.static_dir);
    let static_dir_str = static_dir.to_string_lossy().to_string();
    let router = build_router(app_state, &static_dir_str);

    // Bind and serve
    let addr: SocketAddr = format!("{}:{}", settings.server.host, settings.server.port)
        .parse()
        .expect("Invalid server address");

    tracing::info!(
        address = %addr,
        dashboard = %format!("http://{}", addr),
        "SOC Dashboard ready"
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

/// Seed the database with a set of realistic network assets
fn seed_assets(db: &cyber_incident_simulator::database::DbPool) -> Result<()> {
    let repo = Repository::new(db.clone());

    // Check if assets already seeded
    if let Ok(existing) = repo.list_assets() {
        if !existing.is_empty() {
            return Ok(());
        }
    }

    let assets = vec![
        Asset {
            id: "asset-dc01".to_string(),
            hostname: "dc-server-01".to_string(),
            ip_address: "10.0.1.5".to_string(),
            asset_type: "server".to_string(),
            os: "Windows Server 2022".to_string(),
            criticality: "critical".to_string(),
            department: "IT".to_string(),
            status: "active".to_string(),
        },
        Asset {
            id: "asset-web01".to_string(),
            hostname: "web-prod-01".to_string(),
            ip_address: "10.0.1.10".to_string(),
            asset_type: "server".to_string(),
            os: "Ubuntu 22.04".to_string(),
            criticality: "high".to_string(),
            department: "Engineering".to_string(),
            status: "active".to_string(),
        },
        Asset {
            id: "asset-db01".to_string(),
            hostname: "db-server-01".to_string(),
            ip_address: "10.0.1.50".to_string(),
            asset_type: "server".to_string(),
            os: "Windows Server 2019".to_string(),
            criticality: "critical".to_string(),
            department: "Engineering".to_string(),
            status: "active".to_string(),
        },
        Asset {
            id: "asset-file01".to_string(),
            hostname: "file-server-01".to_string(),
            ip_address: "10.0.1.20".to_string(),
            asset_type: "server".to_string(),
            os: "Windows Server 2022".to_string(),
            criticality: "high".to_string(),
            department: "IT".to_string(),
            status: "active".to_string(),
        },
        Asset {
            id: "asset-mail01".to_string(),
            hostname: "mail-server-01".to_string(),
            ip_address: "10.0.1.30".to_string(),
            asset_type: "server".to_string(),
            os: "Ubuntu 22.04".to_string(),
            criticality: "high".to_string(),
            department: "IT".to_string(),
            status: "active".to_string(),
        },
        Asset {
            id: "asset-backup01".to_string(),
            hostname: "backup-server-01".to_string(),
            ip_address: "10.0.1.60".to_string(),
            asset_type: "server".to_string(),
            os: "Ubuntu 22.04".to_string(),
            criticality: "critical".to_string(),
            department: "IT".to_string(),
            status: "active".to_string(),
        },
        Asset {
            id: "asset-ws-hr01".to_string(),
            hostname: "workstation-HR-01".to_string(),
            ip_address: "10.0.2.15".to_string(),
            asset_type: "workstation".to_string(),
            os: "Windows 11".to_string(),
            criticality: "medium".to_string(),
            department: "HR".to_string(),
            status: "active".to_string(),
        },
        Asset {
            id: "asset-ws-fin01".to_string(),
            hostname: "workstation-FIN-01".to_string(),
            ip_address: "10.0.2.21".to_string(),
            asset_type: "workstation".to_string(),
            os: "Windows 11".to_string(),
            criticality: "high".to_string(),
            department: "Finance".to_string(),
            status: "active".to_string(),
        },
        Asset {
            id: "asset-ws-eng12".to_string(),
            hostname: "workstation-ENG-12".to_string(),
            ip_address: "10.0.3.22".to_string(),
            asset_type: "workstation".to_string(),
            os: "Windows 11".to_string(),
            criticality: "medium".to_string(),
            department: "Engineering".to_string(),
            status: "active".to_string(),
        },
        Asset {
            id: "asset-fw01".to_string(),
            hostname: "firewall-01".to_string(),
            ip_address: "10.0.0.1".to_string(),
            asset_type: "network".to_string(),
            os: "PfSense 2.7".to_string(),
            criticality: "critical".to_string(),
            department: "IT".to_string(),
            status: "active".to_string(),
        },
    ];

    for asset in &assets {
        if let Err(e) = repo.insert_asset(asset) {
            tracing::warn!("Failed to seed asset {}: {}", asset.hostname, e);
        }
    }

    tracing::info!(count = %assets.len(), "Assets seeded");
    Ok(())
}
