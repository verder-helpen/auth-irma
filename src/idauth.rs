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
pub enum AuthStatus {
    #[serde(rename = "succes")]
    Succes(),
    #[serde(rename = "failed")]
    Failed(),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResult {
    pub status: AuthStatus,
    pub attributes: Option<String>,
}
