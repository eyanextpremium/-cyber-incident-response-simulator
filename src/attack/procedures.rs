use serde::{Deserialize, Serialize};

/// An attack procedure — a concrete sequence of steps that implements a technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackProcedure {
    pub id: String,
    pub name: String,
    pub technique_id: String,
    pub steps: Vec<String>,
    pub tools: Vec<String>,
}

impl AttackProcedure {
    pub fn new(id: &str, name: &str, technique_id: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            technique_id: technique_id.to_string(),
            steps: Vec::new(),
            tools: Vec::new(),
        }
    }

    pub fn with_steps(mut self, steps: Vec<&str>) -> Self {
        self.steps = steps.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_tools(mut self, tools: Vec<&str>) -> Self {
        self.tools = tools.iter().map(|s| s.to_string()).collect();
        self
    }
}

pub fn brute_force_procedure() -> AttackProcedure {
    AttackProcedure::new("proc-bf-01", "SSH Brute Force", "T1110.001")
        .with_steps(vec![
            "Gather target host and service information",
            "Select wordlist for password guessing",
            "Launch automated login attempts against SSH service",
            "Monitor for successful authentication",
            "Establish session upon success",
        ])
        .with_tools(vec!["Hydra", "Medusa", "Ncrack"])
}

pub fn phishing_procedure() -> AttackProcedure {
    AttackProcedure::new("proc-ph-01", "Spearphishing Email", "T1566.001")
        .with_steps(vec![
            "Research target organization and individuals",
            "Craft convincing email lure mimicking trusted sender",
            "Attach malicious document with macro payload",
            "Send targeted email to selected recipients",
            "Harvest credentials from phishing page or execute macro",
        ])
        .with_tools(vec!["GoPhish", "SET", "Custom emailer"])
}

pub fn credential_dump_procedure() -> AttackProcedure {
    AttackProcedure::new("proc-cd-01", "LSASS Credential Dump", "T1003.001")
        .with_steps(vec![
            "Establish foothold with initial access",
            "Elevate privileges to SYSTEM",
            "Access LSASS process memory using tool or API",
            "Extract NTLM hashes and clear-text credentials",
            "Use credentials for lateral movement",
        ])
        .with_tools(vec!["Mimikatz", "Procdump", "Task Manager"])
}

pub fn lateral_movement_procedure() -> AttackProcedure {
    AttackProcedure::new("proc-lm-01", "SMB Lateral Movement", "T1021.002")
        .with_steps(vec![
            "Obtain valid credentials or hashes",
            "Scan internal network for SMB-accessible hosts",
            "Mount admin shares using credentials",
            "Copy tools to remote host via share",
            "Execute remote process using WMI or PSExec",
        ])
        .with_tools(vec!["PSExec", "WMIExec", "CrackMapExec", "Impacket"])
}

pub fn ransomware_procedure() -> AttackProcedure {
    AttackProcedure::new("proc-rw-01", "Ransomware Deployment", "T1486")
        .with_steps(vec![
            "Establish domain admin access",
            "Delete volume shadow copies to prevent recovery",
            "Deploy ransomware binary via GPO or SMB",
            "Execute ransomware on all reachable systems",
            "Drop ransom note demanding payment",
        ])
        .with_tools(vec!["Custom ransomware", "Cobalt Strike", "PsExec"])
}

pub fn data_exfil_procedure() -> AttackProcedure {
    AttackProcedure::new("proc-exf-01", "DNS Tunnel Exfiltration", "T1048.003")
        .with_steps(vec![
            "Identify target data (databases, files, credentials)",
            "Compress and encode data for transmission",
            "Establish DNS tunnel to attacker-controlled DNS server",
            "Transmit encoded data as DNS TXT record queries",
            "Verify receipt on attacker infrastructure",
        ])
        .with_tools(vec!["DNScat2", "Iodine", "Custom DNS client"])
}
