use chrono::{DateTime, Utc};

/// Format a raw log line in different log formats
pub struct LogFormatter;

impl LogFormatter {
    /// Syslog RFC 3164 style format
    pub fn syslog(timestamp: &DateTime<Utc>, host: &str, program: &str, message: &str) -> String {
        format!(
            "{} {} {}[{}]: {}",
            timestamp.format("%b %e %H:%M:%S"),
            host,
            program,
            std::process::id(),
            message
        )
    }

    /// CEF (Common Event Format) for SIEM ingestion
    pub fn cef(
        vendor: &str,
        product: &str,
        version: &str,
        event_class: &str,
        name: &str,
        severity: u8,
        extensions: &[(&str, &str)],
    ) -> String {
        let ext: String = extensions
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|{}",
            vendor, product, version, event_class, name, severity, ext
        )
    }

    /// JSON log line
    pub fn json(timestamp: &DateTime<Utc>, level: &str, host: &str, message: &str) -> String {
        format!(
            r#"{{"timestamp":"{}","level":"{}","host":"{}","message":"{}"}}"#,
            timestamp.to_rfc3339(),
            level,
            host,
            message.replace('"', "\\\"")
        )
    }

    /// Windows Event Log style
    pub fn windows_event(
        timestamp: &DateTime<Utc>,
        event_id: u32,
        source: &str,
        message: &str,
    ) -> String {
        format!(
            "EventID={} Source={} Time={} Message={}",
            event_id,
            source,
            timestamp.format("%Y-%m-%dT%H:%M:%S"),
            message
        )
    }
}
