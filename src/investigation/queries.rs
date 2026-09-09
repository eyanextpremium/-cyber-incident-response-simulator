use crate::models::SecurityEvent;

/// Query helpers for investigation — find related events
pub struct InvestigationQuery;

impl InvestigationQuery {
    /// Find all events related to a specific source IP
    pub fn by_source_ip<'a>(events: &'a [SecurityEvent], ip: &str) -> Vec<&'a SecurityEvent> {
        events
            .iter()
            .filter(|e| e.source_ip.as_deref() == Some(ip))
            .collect()
    }

    /// Find all events on a specific host
    pub fn by_host<'a>(events: &'a [SecurityEvent], host: &str) -> Vec<&'a SecurityEvent> {
        events.iter().filter(|e| e.host == host).collect()
    }

    /// Find all events for a specific user
    pub fn by_user<'a>(events: &'a [SecurityEvent], user: &str) -> Vec<&'a SecurityEvent> {
        events
            .iter()
            .filter(|e| e.user.as_deref() == Some(user))
            .collect()
    }

    /// Find all events with a specific MITRE technique
    pub fn by_technique<'a>(
        events: &'a [SecurityEvent],
        technique: &str,
    ) -> Vec<&'a SecurityEvent> {
        events
            .iter()
            .filter(|e| {
                e.mitre_technique
                    .as_deref()
                    .map(|t| t.starts_with(technique))
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Find all malicious events
    pub fn malicious_only(events: &[SecurityEvent]) -> Vec<&SecurityEvent> {
        events.iter().filter(|e| e.is_malicious).collect()
    }

    /// Collect unique hosts involved in malicious activity
    pub fn compromised_hosts(events: &[SecurityEvent]) -> Vec<String> {
        let mut hosts: Vec<String> = events
            .iter()
            .filter(|e| e.is_malicious)
            .map(|e| e.host.clone())
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// Collect unique attacker IPs seen in events
    pub fn attacker_ips(events: &[SecurityEvent]) -> Vec<String> {
        let mut ips: Vec<String> = events
            .iter()
            .filter(|e| e.is_malicious)
            .filter_map(|e| e.source_ip.clone())
            .collect();
        ips.sort();
        ips.dedup();
        ips
    }
}
