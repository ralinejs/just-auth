//! https://wikinew.open.qq.com/index.html#/iwiki/901251864
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    scope: Option<Vec<String>>,
    display: Option<QQDisplayStyle>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QQDisplayStyle {
    PC,
    Mobile,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCallback {
    code: String,
    state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetTokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
    fmt: Option<ResponseFormat>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ResponseFormat {
    #[serde(rename = "x-www-form-urlencoded")]
    UrlEncoded,
    #[serde(rename = "json")]
    Json,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    refresh_token: String,
    fmt: Option<ResponseFormat>,
}
