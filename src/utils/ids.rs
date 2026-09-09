use uuid::Uuid;

pub fn generate_uuid() -> String {
    Uuid::new_v4().to_string()
}

pub fn short_id() -> String {
    Uuid::new_v4()
        .to_string()
        .split('-')
        .next()
        .unwrap_or("00000000")
        .to_string()
}
