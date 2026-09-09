use serde::{Deserialize, Serialize};

/// MITRE ATT&CK Tactics (the "why" — adversary goals)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl Tactic {
    pub fn id(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "TA0043",
            Self::ResourceDevelopment => "TA0042",
            Self::InitialAccess => "TA0001",
            Self::Execution => "TA0002",
            Self::Persistence => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion => "TA0005",
            Self::CredentialAccess => "TA0006",
            Self::Discovery => "TA0007",
            Self::LateralMovement => "TA0008",
            Self::Collection => "TA0009",
            Self::CommandAndControl => "TA0011",
            Self::Exfiltration => "TA0010",
            Self::Impact => "TA0040",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::ResourceDevelopment => "Resource Development",
            Self::InitialAccess => "Initial Access",
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::DefenseEvasion => "Defense Evasion",
            Self::CredentialAccess => "Credential Access",
            Self::Discovery => "Discovery",
            Self::LateralMovement => "Lateral Movement",
            Self::Collection => "Collection",
            Self::CommandAndControl => "Command and Control",
            Self::Exfiltration => "Exfiltration",
            Self::Impact => "Impact",
        }
    }

    pub fn from_technique_id(tid: &str) -> Option<Self> {
        // Map common technique prefixes to tactics
        match tid {
            t if t.starts_with("T1566") => Some(Self::InitialAccess),
            t if t.starts_with("T1059") => Some(Self::Execution),
            t if t.starts_with("T1547") || t.starts_with("T1053") => Some(Self::Persistence),
            t if t.starts_with("T1068") || t.starts_with("T1134") => {
                Some(Self::PrivilegeEscalation)
            }
            t if t.starts_with("T1003") || t.starts_with("T1110") => Some(Self::CredentialAccess),
            t if t.starts_with("T1021") || t.starts_with("T1550") => Some(Self::LateralMovement),
            t if t.starts_with("T1048") || t.starts_with("T1041") => Some(Self::Exfiltration),
            t if t.starts_with("T1486") || t.starts_with("T1490") => Some(Self::Impact),
            t if t.starts_with("T1071") || t.starts_with("T1095") => Some(Self::CommandAndControl),
            t if t.starts_with("T1046") || t.starts_with("T1069") => Some(Self::Discovery),
            _ => None,
        }
    }
}
