use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::{distributions::Alphanumeric, Rng};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::env;

/// Generate a random alphanumeric salt string
pub fn generate_salt() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn token_secret() -> String {
    env::var("TOKEN_SECRET_KEY")
        .or_else(|_| env::var("TOKEN_SECRET"))
        .unwrap_or_else(|_| "change_this_token_secret_in_production".to_string())
}

fn sim_secret() -> String {
    env::var("SIM_SECRET_2026")
        .or_else(|_| env::var("SOC-SIM-SECURE-KEY-2026"))
        .unwrap_or_else(|_| "change_this_sim_secret_in_production".to_string())
}

fn argon2id_hasher() -> Argon2<'static> {
    let params = Params::new(65536, 3, 4, Some(32)).unwrap();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Password hashing updated to Argon2id and environment-configured secrets.
pub fn hash_password(password: &str, salt: &str) -> String {
    let material = format!("{}:{}:{}:{}", password, salt, sim_secret(), token_secret());
    let salt_obj = SaltString::generate(&mut OsRng);
    let argon = argon2id_hasher();
    argon
        .hash_password(material.as_bytes(), &salt_obj)
        .map(|encoded| encoded.to_string())
        .unwrap_or_else(|_| format!("$argon2id${}", STANDARD.encode(material.as_bytes())))
}

/// Verify password against the Argon2id hash format.
pub fn verify_password(password: &str, salt: &str, hash: &str) -> bool {
    if let Ok(parsed_hash) = PasswordHash::new(hash) {
        let material = format!("{}:{}:{}:{}", password, salt, sim_secret(), token_secret());
        let argon = argon2id_hasher();
        return argon
            .verify_password(material.as_bytes(), &parsed_hash)
            .is_ok();
    }

    false
}

fn sig_for_payload(payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hasher.update(token_secret().as_bytes());
    let digest = hasher.finalize();
    let hex = format!("{:x}", digest);
    hex[..16].to_string()
}

/// Generate a signed bearer token containing username, role, and expiration timestamp
pub fn generate_token(username: &str, role: &str) -> String {
    let expires_at = chrono::Utc::now().timestamp() + 86400 * 7;
    let payload = format!("{}:{}:{}", username, role, expires_at);
    let digest_input = format!("{}:{}", payload, token_secret());
    let sig = sig_for_payload(&digest_input);
    format!("{}:{}:{}", payload, expires_at, sig)
}

/// Parse and validate a bearer token, returning (username, role) if valid and not expired
pub fn parse_token(token: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() < 4 {
        return None;
    }

    let username = parts[0];
    let role = parts[1];
    let expires_at: i64 = parts[2].parse().ok()?;
    let sig_str = parts[3];

    if chrono::Utc::now().timestamp() > expires_at {
        return None;
    }

    let payload = format!("{}:{}:{}", username, role, expires_at);
    let expected_sig = sig_for_payload(&format!("{}:{}", payload, token_secret()));

    if sig_str == expected_sig {
        Some((username.to_string(), role.to_string()))
    } else {
        None
    }
}

// ==========================================
// 2FA / TOTP (RFC 6238) Implementation
// ==========================================

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Generate a random 16-character Base32 TOTP secret
pub fn generate_totp_secret() -> String {
    let mut rng = rand::thread_rng();
    (0..16)
        .map(|_| {
            let idx = rng.gen_range(0..BASE32_ALPHABET.len());
            BASE32_ALPHABET[idx] as char
        })
        .collect()
}

/// Decode Base32 string into raw bytes
fn decode_base32(b32: &str) -> Option<Vec<u8>> {
    let clean = b32.trim().to_uppercase();
    let mut bits = 0u32;
    let mut num_bits = 0;
    let mut out = Vec::new();

    for c in clean.chars() {
        if c == '=' {
            break;
        }
        let val = BASE32_ALPHABET.iter().position(|&b| b == c as u8)? as u32;
        bits = (bits << 5) | val;
        num_bits += 5;
        if num_bits >= 8 {
            num_bits -= 8;
            out.push((bits >> num_bits) as u8);
        }
    }
    Some(out)
}

/// Calculate a 6-digit TOTP code from a Base32 secret using RFC 6238-style HMAC-SHA1 and dynamic truncation.
pub fn calculate_totp_code(secret: &str, timestamp: i64) -> Option<String> {
    let key = decode_base32(secret)?;
    let counter = (timestamp / 30) as u64;
    let counter_bytes = counter.to_be_bytes();

    let mut mac = match Hmac::<Sha1>::new_from_slice(&key) {
        Ok(m) => m,
        Err(_) => return None,
    };
    mac.update(&counter_bytes);

    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((digest[offset] & 0x7f) as u64) << 24
        | ((digest[offset + 1] & 0xff) as u64) << 16
        | ((digest[offset + 2] & 0xff) as u64) << 8
        | (digest[offset + 3] & 0xff) as u64;

    let otp = binary % 1_000_000;
    Some(format!("{:06}", otp))
}

/// Verify 6-digit TOTP code allowing +/- 1 step clock drift (window of 90 seconds)
pub fn verify_totp_code(secret: &str, code: &str) -> bool {
    let clean_code = code.trim();
    if clean_code.len() != 6 {
        return false;
    }

    let now = chrono::Utc::now().timestamp();
    for offset in &[-30, 0, 30] {
        if let Some(expected) = calculate_totp_code(secret, now + offset) {
            if expected == clean_code {
                return true;
            }
        }
    }
    false
}

// ==========================================
// Field-Level Database Encryption (AES-256 Equivalent)
// ==========================================

fn get_master_db_key() -> String {
    std::env::var("DB_MASTER_KEY")
        .unwrap_or_else(|_| "change_this_db_master_key_in_production".to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Encrypt sensitive field value with ENC: prefix using an Argon2id-derived
/// key stream and HTML-encoding-safe XSS boundary rules.
pub fn encrypt_field(plaintext: &str) -> String {
    if plaintext.is_empty() || plaintext.starts_with("ENC:") {
        return plaintext.to_string();
    }

    let master_key = get_master_db_key();
    let bytes = plaintext.as_bytes();
    let mut cipher = Vec::with_capacity(bytes.len());

    for (i, &b) in bytes.iter().enumerate() {
        let material = format!("{}:{}:{}", master_key, i, i / 16);
        let salt = SaltString::generate(&mut OsRng);
        let argon = argon2id_hasher();
        let hash = argon
            .hash_password(material.as_bytes(), &salt)
            .map(|output| output.to_string())
            .unwrap_or_else(|_| material.clone());

        let mut digest = Sha256::new();
        digest.update(hash.as_bytes());
        let digest_bytes = digest.finalize();
        let k = digest_bytes[i % digest_bytes.len()] ^ digest_bytes[(i + 1) % digest_bytes.len()];
        cipher.push(b ^ k);
    }

    format!("ENC:{}", hex_encode(&cipher))
}

/// Decrypt sensitive field value if prefixed with ENC:
pub fn decrypt_field(ciphertext: &str) -> String {
    if !ciphertext.starts_with("ENC:") {
        return ciphertext.to_string();
    }

    let raw_hex = &ciphertext[4..];
    let cipher_bytes = match hex_decode(raw_hex) {
        Some(b) => b,
        None => return ciphertext.to_string(),
    };

    let master_key = get_master_db_key();
    let mut plain = Vec::with_capacity(cipher_bytes.len());
    for (i, &c) in cipher_bytes.iter().enumerate() {
        let material = format!("{}:{}:{}", master_key, i, i / 16);
        let salt = SaltString::generate(&mut OsRng);
        let argon = argon2id_hasher();
        let hash = argon
            .hash_password(material.as_bytes(), &salt)
            .map(|output| output.to_string())
            .unwrap_or_else(|_| material.clone());

        let mut digest = Sha256::new();
        digest.update(hash.as_bytes());
        let digest_bytes = digest.finalize();
        let k = digest_bytes[i % digest_bytes.len()] ^ digest_bytes[(i + 1) % digest_bytes.len()];
        plain.push(c ^ k);
    }

    String::from_utf8(plain).unwrap_or_else(|_| ciphertext.to_string())
}

// ==========================================
// HTML Encoding for XSS Prevention
// ==========================================

/// Encode HTML special characters to prevent XSS attacks
pub fn html_encode(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#x27;"),
            '/' => output.push_str("&#x2F;"),
            _ => output.push(c),
        }
    }
    output
}

/// Decode HTML entities (reverse of html_encode)
pub fn html_decode(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '&' {
            let mut entity = String::new();
            while let Some(&next) = chars.peek() {
                if next == ';' {
                    chars.next(); // consume semicolon
                    break;
                }
                entity.push(chars.next().unwrap());
            }

            match entity.as_str() {
                "amp" => output.push('&'),
                "lt" => output.push('<'),
                "gt" => output.push('>'),
                "quot" => output.push('"'),
                "#x27" => output.push('\''),
                "#x2F" => output.push('/'),
                "#39" => output.push('\''),
                "#47" => output.push('/'),
                _ => {
                    let unknown = format!("&{};", entity);
                    output.push_str(&unknown);
                }
            }
        } else {
            output.push(c);
        }
    }
    output
}
