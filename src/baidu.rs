//! https://openauth.baidu.com/doc/doc.html
use serde::{Deserialize, Serialize};
use serde_with::{formats::SpaceSeparator, serde_as, StringWithSeparator};

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    #[serde_as(as = "StringWithSeparator::<SpaceSeparator, String>")]
    scope: Vec<String>,
    state: Option<String>,
    display: Option<DisplayStyle>,
    // other
}

/// https://openauth.baidu.com/doc/appendix.html#_2-display参数说明
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DisplayStyle {
    Page,
    Popup,
    Dialog,
    Mobile,
    Pad,
    Tv,
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    refresh_token: String,
}
