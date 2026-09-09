use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::database::Repository;
use crate::detection::DetectionEngine;
use crate::models::{EventSource, SecurityEvent};
use crate::utils::generate_uuid;

pub struct UdpSyslogServer {
    bind_addr: String,
    repo: Arc<Repository>,
    engine: Arc<Mutex<DetectionEngine>>,
    ws_tx: broadcast::Sender<String>,
}

impl UdpSyslogServer {
    pub fn new(
        bind_addr: &str,
        repo: Arc<Repository>,
        engine: Arc<Mutex<DetectionEngine>>,
        ws_tx: broadcast::Sender<String>,
    ) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            repo,
            engine,
            ws_tx,
        }
    }

    pub async fn start(self) -> anyhow::Result<()> {
        let socket = UdpSocket::bind(&self.bind_addr).await?;
        info!(
            "📡 Ham UDP Syslog Soket Dinleyicisi aktif: udp://{}",
            self.bind_addr
        );

        let mut buf = [0u8; 65535];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    let raw_msg = String::from_utf8_lossy(&buf[..len]).to_string();
                    self.process_packet(src_addr, &raw_msg);
                }
                Err(e) => {
                    warn!("UDP Syslog alma hatası: {}", e);
                }
            }
        }
    }

    fn process_packet(&self, src_addr: SocketAddr, raw_msg: &str) {
        let (pri, host, message) = parse_syslog_packet(raw_msg, &src_addr.ip().to_string());
        let is_malicious = raw_msg.to_lowercase().contains("attack")
            || raw_msg.to_lowercase().contains("malware")
            || raw_msg.to_lowercase().contains("unauthorized")
            || raw_msg.to_lowercase().contains("failed");

        let event = SecurityEvent {
            id: generate_uuid(),
            session_id: "live_system_session".to_string(),
            timestamp: chrono::Utc::now(),
            source: EventSource::Syslog,
            event_type: format!("syslog_pri_{}", pri),
            message: message.clone(),
            host,
            source_ip: Some(src_addr.ip().to_string()),
            destination_ip: Some("127.0.0.1".to_string()),
            user: None,
            raw_log: raw_msg.to_string(),
            mitre_technique: if is_malicious {
                Some("T1071".to_string())
            } else {
                None
            },
            is_malicious,
        };

        // Run detection rules
        let matches = if let Ok(mut eng) = self.engine.lock() {
            eng.analyze(&event)
        } else {
            Vec::new()
        };

        // Save event to DB
        let _ = self.repo.insert_event(&event);

        // Convert matches to alerts, save & broadcast
        for m in &matches {
            let alert = DetectionEngine::create_alert(&event.session_id, &event, m);
            let _ = self.repo.insert_alert(&alert);
            let alert_json = serde_json::to_string(&alert).unwrap_or_default();
            let _ = self.ws_tx.send(format!("ALERT:{}", alert_json));
        }

        // Broadcast to WebSocket & SSE subscribers
        let event_json = serde_json::to_string(&event).unwrap_or_default();
        let _ = self.ws_tx.send(format!("EVENT:{}", event_json));
    }
}

/// Parse RFC 3164 / RFC 5424 raw syslog string into (PRI, Host, Message)
fn parse_syslog_packet<'a>(raw: &'a str, default_ip: &'a str) -> (u32, String, String) {
    let trimmed = raw.trim();
    let mut pri = 13; // Default user.notice
    let mut rest = trimmed;

    if trimmed.starts_with('<') {
        if let Some(end_idx) = trimmed.find('>') {
            if let Ok(val) = trimmed[1..end_idx].parse::<u32>() {
                pri = val;
                rest = trimmed[end_idx + 1..].trim();
            }
        }
    }

    let parts: Vec<&str> = rest.splitn(3, ' ').collect();
    let (host, message) = if parts.len() >= 3 {
        (parts[1].to_string(), parts[2].to_string())
    } else {
        (default_ip.to_string(), rest.to_string())
    };

    (pri, host, message)
}
