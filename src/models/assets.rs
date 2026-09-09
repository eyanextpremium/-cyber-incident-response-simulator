use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    pub hostname: String,
    pub ip_address: String,
    pub asset_type: String,
    pub os: String,
    pub criticality: String,
    pub department: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub hostname: String,
    pub ip_address: String,
    pub mac_address: String,
    pub os: String,
    pub role: String,
    pub zone: String,
}
