use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;

/// Decode a JWT token payload
pub fn decode_jwt_payload(token: &str) -> Result<Value, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err("Invalid JWT token format".to_string());
    }

    // Convert URL-safe base64 to standard base64
    let base64_str = parts[1].replace('-', "+").replace('_', "/");

    // Add padding
    let padding = (4 - base64_str.len() % 4) % 4;
    let padded = format!("{}{}", base64_str, "=".repeat(padding));

    let decoded = STANDARD
        .decode(&padded)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    let json_str =
        String::from_utf8(decoded).map_err(|e| format!("UTF-8 decode error: {}", e))?;

    serde_json::from_str(&json_str).map_err(|e| format!("JSON parse error: {}", e))
}

/// Extract username from a JWT token
pub fn get_user_name_from_token(token: &str) -> String {
    match decode_jwt_payload(token) {
        Ok(payload) => {
            payload
                .get("name")
                .or_else(|| payload.get("upn"))
                .or_else(|| payload.get("unique_name"))
                .or_else(|| payload.get("preferred_username"))
                .or_else(|| payload.get("email"))
                .and_then(|v| v.as_str())
                .unwrap_or("Azure User")
                .to_string()
        }
        Err(_) => "Azure User".to_string(),
    }
}

/// Extract tenant ID from a JWT token
pub fn get_tenant_id_from_token(token: &str) -> Option<String> {
    match decode_jwt_payload(token) {
        Ok(payload) => payload.get("tid").and_then(|v| v.as_str()).map(String::from),
        Err(_) => None,
    }
}
