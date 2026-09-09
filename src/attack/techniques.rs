use serde::{Deserialize, Serialize};

use super::tactics::Tactic;

/// A MITRE ATT&CK technique entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tactic: Tactic,
    pub detection_hint: String,
}

impl Technique {
    pub fn new(
        id: &str,
        name: &str,
        description: &str,
        tactic: Tactic,
        detection_hint: &str,
    ) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            tactic,
            detection_hint: detection_hint.to_string(),
        }
    }
}

/// Returns the standard technique registry used by the simulator
pub fn technique_registry() -> Vec<Technique> {
    vec![
        Technique::new(
            "T1566.001",
            "Spearphishing Attachment",
            "Adversaries send spearphishing emails with malicious attachments",
            Tactic::InitialAccess,
            "Monitor for suspicious email attachments, especially Office documents with macros",
        ),
        Technique::new(
            "T1059.001",
            "PowerShell",
            "Adversaries use PowerShell commands and scripts for execution",
            Tactic::Execution,
            "Monitor PowerShell process creation with suspicious parameters like -enc, -nop, -w hidden",
        ),
        Technique::new(
            "T1059.004",
            "Unix Shell",
            "Adversaries use Unix shell commands for execution",
            Tactic::Execution,
            "Monitor for shell processes spawned by web server processes",
        ),
        Technique::new(
            "T1110.001",
            "Password Guessing",
            "Adversaries try commonly used passwords against many accounts",
            Tactic::CredentialAccess,
            "Monitor for multiple failed login attempts from the same source IP",
        ),
        Technique::new(
            "T1003.001",
            "LSASS Memory",
            "Adversaries dump credentials from LSASS memory",
            Tactic::CredentialAccess,
            "Monitor for processes accessing lsass.exe memory",
        ),
        Technique::new(
            "T1550.002",
            "Pass the Hash",
            "Adversaries use stolen NTLM hashes to authenticate without the actual password",
            Tactic::LateralMovement,
            "Look for NTLM authentication without interactive login from unexpected sources",
        ),
        Technique::new(
            "T1021.002",
            "SMB/Windows Admin Shares",
            "Adversaries use Valid Accounts to interact with a remote network share using Server Message Block (SMB)",
            Tactic::LateralMovement,
            "Monitor for unusual SMB connections to administrative shares (ADMIN$, C$)",
        ),
        Technique::new(
            "T1047",
            "Windows Management Instrumentation",
            "Adversaries use WMI to execute malicious code on remote systems",
            Tactic::Execution,
            "Monitor for WMI process creation involving cmd.exe or PowerShell on remote hosts",
        ),
        Technique::new(
            "T1547.001",
            "Registry Run Keys",
            "Adversaries achieve persistence by adding programs to registry run keys",
            Tactic::Persistence,
            "Monitor for modifications to Run and RunOnce registry keys",
        ),
        Technique::new(
            "T1053.005",
            "Scheduled Task",
            "Adversaries use the Windows Task Scheduler to execute programs at boot or on a schedule",
            Tactic::Persistence,
            "Monitor for new scheduled task creation, especially by non-admin processes",
        ),
        Technique::new(
            "T1486",
            "Data Encrypted for Impact",
            "Adversaries encrypt data on target systems to interrupt availability",
            Tactic::Impact,
            "Monitor for rapid bulk file modification/rename operations",
        ),
        Technique::new(
            "T1490",
            "Inhibit System Recovery",
            "Adversaries delete shadow copies and backups to prevent recovery",
            Tactic::Impact,
            "Monitor for vssadmin.exe or wmic calls to delete shadow copies",
        ),
        Technique::new(
            "T1048",
            "Exfiltration Over Alternative Protocol",
            "Adversaries exfiltrate data over a different protocol (DNS, ICMP)",
            Tactic::Exfiltration,
            "Monitor for unusual outbound traffic volumes or protocols (DNS TXT records, ICMP)",
        ),
        Technique::new(
            "T1048.003",
            "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
            "Adversaries use DNS tunneling for exfiltration",
            Tactic::Exfiltration,
            "Monitor for abnormally large DNS TXT record queries",
        ),
        Technique::new(
            "T1071.001",
            "Web Protocols",
            "Adversaries use HTTP/HTTPS for C2 communications",
            Tactic::CommandAndControl,
            "Monitor for periodic outbound HTTPS connections to unknown external IPs",
        ),
        Technique::new(
            "T1190",
            "Exploit Public-Facing Application",
            "Adversaries exploit weaknesses in web applications",
            Tactic::InitialAccess,
            "Monitor web application logs for SQL injection, XSS, or directory traversal patterns",
        ),
        Technique::new(
            "T1505.003",
            "Web Shell",
            "Adversaries install web shells to maintain persistent access to web servers",
            Tactic::Persistence,
            "Monitor web server file systems for newly created executable scripts",
        ),
        Technique::new(
            "T1046",
            "Network Service Scanning",
            "Adversaries perform port scanning of internal hosts",
            Tactic::Discovery,
            "Monitor for sequential port scan activity from internal hosts",
        ),
        Technique::new(
            "T1068",
            "Exploitation for Privilege Escalation",
            "Adversaries exploit vulnerabilities to gain elevated privileges",
            Tactic::PrivilegeEscalation,
            "Monitor for processes gaining higher privileges than their parents",
        ),
        Technique::new(
            "T1134.001",
            "Token Impersonation/Theft",
            "Adversaries impersonate existing process tokens to escalate privileges",
            Tactic::PrivilegeEscalation,
            "Monitor for SeImpersonatePrivilege usage by non-service processes",
        ),
    ]
}

/// Look up a technique by its ID
pub fn find_technique(id: &str) -> Option<Technique> {
    technique_registry().into_iter().find(|t| t.id == id)
}
