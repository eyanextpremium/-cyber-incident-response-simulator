use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::database::ActionRecord;
use crate::utils::generate_uuid;

/// All supported response action types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionType {
    Acknowledge,
    Investigate,
    IsolateHost,
    BlockIp,
    DisableAccount,
    QuarantineFile,
    Contain,
    Eradicate,
    Recover,
    CloseIncident,
}

impl ResponseActionType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "acknowledge" => Some(Self::Acknowledge),
            "investigate" => Some(Self::Investigate),
            "isolate_host" => Some(Self::IsolateHost),
            "block_ip" => Some(Self::BlockIp),
            "disable_account" => Some(Self::DisableAccount),
            "quarantine_file" => Some(Self::QuarantineFile),
            "contain" => Some(Self::Contain),
            "eradicate" => Some(Self::Eradicate),
            "recover" => Some(Self::Recover),
            "close_incident" => Some(Self::CloseIncident),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Acknowledge => "acknowledge",
            Self::Investigate => "investigate",
            Self::IsolateHost => "isolate_host",
            Self::BlockIp => "block_ip",
            Self::DisableAccount => "disable_account",
            Self::QuarantineFile => "quarantine_file",
            Self::Contain => "contain",
            Self::Eradicate => "eradicate",
            Self::Recover => "recover",
            Self::CloseIncident => "close_incident",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Acknowledge => "Acknowledge Alert",
            Self::Investigate => "Investigate",
            Self::IsolateHost => "Isolate Host",
            Self::BlockIp => "Block IP Address",
            Self::DisableAccount => "Disable User Account",
            Self::QuarantineFile => "Quarantine File",
            Self::Contain => "Contain Incident",
            Self::Eradicate => "Eradicate Threat",
            Self::Recover => "Recover Systems",
            Self::CloseIncident => "Close Incident",
        }
    }
}

/// A response action taken by the analyst
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub id: String,
    pub session_id: String,
    pub incident_id: Option<String>,
    pub action_type: ResponseActionType,
    pub target: String,
    pub details: String,
    pub success: bool,
}

impl ResponseAction {
    pub fn new(
        session_id: &str,
        action_type: ResponseActionType,
        target: &str,
        details: &str,
    ) -> Self {
        Self {
            id: generate_uuid(),
            session_id: session_id.to_string(),
            incident_id: None,
            action_type,
            target: target.to_string(),
            details: details.to_string(),
            success: true,
        }
    }

    pub fn to_record(&self) -> ActionRecord {
        ActionRecord {
            id: self.id.clone(),
            session_id: self.session_id.clone(),
            incident_id: self.incident_id.clone(),
            action_type: self.action_type.as_str().to_string(),
            target: self.target.clone(),
            details: self.details.clone(),
            success: self.success,
            performed_at: Utc::now(),
        }
    }
}
