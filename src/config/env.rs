use std::path::Path;
use std::sync::OnceLock;

static INIT: OnceLock<()> = OnceLock::new();

/// Load `.env` from project root (once).
pub fn load_env(base: &Path) {
    INIT.get_or_init(|| {
        let _ = dotenvy::from_path(base.join(".env"));
        let _ = dotenvy::dotenv();
    });
}

fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

pub fn admin_username() -> String {
    env_var("ADMIN_USERNAME").unwrap_or_else(|| "admin".to_string())
}

pub fn admin_password() -> String {
    env_var("ADMIN_PASSWORD").expect("ADMIN_PASSWORD must be set in .env")
}

pub fn api_key() -> String {
    env_var("API_KEY").expect("API_KEY must be set in .env")
}

pub fn token_secret() -> String {
    env_var("TOKEN_SECRET").expect("TOKEN_SECRET must be set in .env")
}

/// Constant-time string comparison for secrets.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
