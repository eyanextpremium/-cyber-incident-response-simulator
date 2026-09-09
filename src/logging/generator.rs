use chrono::Utc;
use rand::Rng;

use crate::models::{EventSource, SecurityEvent};
use crate::utils::generate_uuid;

/// Generates realistic synthetic security log entries
pub struct LogGenerator;

impl LogGenerator {
    /// Generate a realistic authentication log message
    pub fn auth_log(host: &str, user: &str, src_ip: &str, success: bool) -> SecurityEvent {
        let (event_type, message) = if success {
            (
                "login_success",
                format!(
                    "Accepted password for {} from {} port {} ssh2",
                    user,
                    src_ip,
                    rand_port()
                ),
            )
        } else {
            (
                "login_failure",
                format!(
                    "Failed password for {} from {} port {} ssh2",
                    user,
                    src_ip,
                    rand_port()
                ),
            )
        };

        build_event(
            host,
            EventSource::Authentication,
            &event_type,
            &message,
            Some(src_ip),
            Some(user),
        )
    }

    /// Generate a firewall log entry
    pub fn firewall_log(src_ip: &str, dst_ip: &str, dst_port: u16, action: &str) -> SecurityEvent {
        let proto = if dst_port == 443 || dst_port == 80 {
            "TCP"
        } else {
            "TCP"
        };
        let message = format!(
            "{} {} {}:{} -> {}:{} ({})",
            action.to_uppercase(),
            proto,
            src_ip,
            rand_port(),
            dst_ip,
            dst_port,
            port_service(dst_port)
        );
        build_event(
            "firewall-01",
            EventSource::Firewall,
            "fw_rule_match",
            &message,
            Some(src_ip),
            None,
        )
    }

    /// Generate an endpoint process execution log
    pub fn process_log(host: &str, user: &str, process: &str, args: &str) -> SecurityEvent {
        let message = format!(
            "Process created: {} {} (user: {}, PID: {})",
            process,
            args,
            user,
            rand_pid()
        );
        build_event(
            host,
            EventSource::Endpoint,
            "process_execution",
            &message,
            None,
            Some(user),
        )
    }

    /// Generate a network connection log
    pub fn network_log(host: &str, src_ip: &str, dst_ip: &str, dst_port: u16) -> SecurityEvent {
        let message = format!(
            "TCP connection {} -> {}:{} ({})",
            src_ip,
            dst_ip,
            dst_port,
            port_service(dst_port)
        );
        build_event(
            host,
            EventSource::Network,
            "tcp_connection",
            &message,
            Some(src_ip),
            None,
        )
    }

    /// Generate a DNS query log
    pub fn dns_log(host: &str, query: &str, answer: &str) -> SecurityEvent {
        let message = format!("DNS query: {} -> {}", query, answer);
        build_event(host, EventSource::Dns, "dns_query", &message, None, None)
    }
}

fn build_event(
    host: &str,
    source: EventSource,
    event_type: &str,
    message: &str,
    src_ip: Option<&str>,
    user: Option<&str>,
) -> SecurityEvent {
    SecurityEvent {
        id: generate_uuid(),
        session_id: String::new(), // caller sets this
        timestamp: Utc::now(),
        source,
        event_type: event_type.to_string(),
        message: message.to_string(),
        host: host.to_string(),
        source_ip: src_ip.map(str::to_string),
        destination_ip: None,
        user: user.map(str::to_string),
        raw_log: message.to_string(),
        mitre_technique: None,
        is_malicious: false,
    }
}

fn rand_port() -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(1024..65535)
}

fn rand_pid() -> u32 {
    let mut rng = rand::thread_rng();
    rng.gen_range(100..65535)
}

fn port_service(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        80 => "HTTP",
        443 => "HTTPS",
        445 => "SMB",
        3389 => "RDP",
        1433 => "MSSQL",
        3306 => "MySQL",
        _ => "Unknown",
    }
}
