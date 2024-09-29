//! https://open.weibo.com/wiki/授权机制说明
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCallback {
    code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetTokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
}
