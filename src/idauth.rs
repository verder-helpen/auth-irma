use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub attributes: Vec<String>,
    pub continuation: String,
    pub attr_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartAuthResponse {
    pub client_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResult {
    pub status: String,
    pub attributes: Option<String>,
}
