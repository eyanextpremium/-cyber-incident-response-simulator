use std::collections::HashSet;

/// A set of known Indicators of Compromise (IOCs) used for enrichment
#[derive(Debug, Clone, Default)]
pub struct IocList {
    pub malicious_ips: HashSet<String>,
    pub malicious_domains: HashSet<String>,
    pub malicious_hashes: HashSet<String>,
    pub malicious_filenames: HashSet<String>,
}

impl IocList {
    pub fn new() -> Self {
        let mut list = Self::default();
        list.populate_defaults();
        list
    }

    fn populate_defaults(&mut self) {
        // Known bad IPs used in simulator scenarios
        for ip in &[
            "185.234.218.42",
            "45.142.212.100",
            "198.51.100.22",
            "203.0.113.50",
            "45.33.32.156",
            "192.168.50.100",
            "198.51.100.77",
            "203.0.113.88",
            "45.142.212.200",
            "203.0.113.100",
            "104.18.22.200",
        ] {
            self.malicious_ips.insert(ip.to_string());
        }

        // Known bad domains
        for domain in &[
            "exfil.attacker-c2.com",
            "evil.com",
            "attacker-c2.com",
            "company-update.net",
            "company-corp.net",
            "malware-host.ru",
        ] {
            self.malicious_domains.insert(domain.to_string());
        }

        // Known bad file hashes (MD5)
        for hash in &[
            "4d41f4f4f3f3a1b2c3d4e5f6a7b8c9d0",
            "aabbccddeeff00112233445566778899",
            "deadbeefcafebabedeadbeefcafebabe",
        ] {
            self.malicious_hashes.insert(hash.to_string());
        }

        // Known bad filenames
        for name in &[
            "mimikatz.exe",
            "encrypt.exe",
            "svchost32.exe",
            "image_2024.php",
            "upd_helper.exe",
            "psexec.exe",
        ] {
            self.malicious_filenames.insert(name.to_string());
        }
    }

    pub fn is_malicious_ip(&self, ip: &str) -> bool {
        self.malicious_ips.contains(ip)
    }

    pub fn is_malicious_domain(&self, domain: &str) -> bool {
        self.malicious_domains
            .iter()
            .any(|d| domain.to_lowercase().contains(d.as_str()))
    }

    pub fn is_malicious_hash(&self, hash: &str) -> bool {
        self.malicious_hashes.contains(&hash.to_lowercase())
    }

    pub fn is_malicious_filename(&self, filename: &str) -> bool {
        let lower = filename.to_lowercase();
        self.malicious_filenames
            .iter()
            .any(|f| lower.contains(f.as_str()))
    }

    /// Check the raw message/log for any known IOC
    pub fn check_message(&self, message: &str) -> bool {
        let lower = message.to_lowercase();
        self.malicious_ips
            .iter()
            .any(|ip| lower.contains(ip.as_str()))
            || self
                .malicious_domains
                .iter()
                .any(|d| lower.contains(d.as_str()))
            || self
                .malicious_hashes
                .iter()
                .any(|h| lower.contains(h.as_str()))
            || self
                .malicious_filenames
                .iter()
                .any(|f| lower.contains(f.as_str()))
    }
}
