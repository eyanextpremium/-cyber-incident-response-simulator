pub fn is_non_empty(s: &str) -> bool {
    !s.trim().is_empty()
}

pub fn validate_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && !id.contains("..")
        && !id.contains("/")
        && !id.contains("\\")
        && !id.contains("\0")
}

pub fn validate_action(action: &str) -> bool {
    matches!(
        action,
        "acknowledge"
            | "investigate"
            | "contain"
            | "isolate_host"
            | "block_ip"
            | "disable_account"
            | "quarantine_file"
            | "eradicate"
            | "recover"
            | "close_incident"
    )
}

pub fn sanitize_input(input: &str, max_len: usize) -> String {
    crate::utils::security::html_encode(input)
        .chars()
        .take(max_len)
        .collect()
}
