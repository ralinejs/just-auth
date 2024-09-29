//! https://openauth.baidu.com/doc/doc.html
use crate::error::Result;
use crate::{AuthConfig, AuthUrlProvider};
use serde::{Deserialize, Serialize};
use serde_with::{formats::SpaceSeparator, serde_as, StringWithSeparator};

pub struct AuthorizationServer {
    config: AuthConfig,
}

impl AuthUrlProvider for AuthorizationServer {
    type AuthRequest = AuthRequest;
    type AuthCallback = AuthCallback;
    type AuthToken = AccessToken;

    fn authorize(request: AuthRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://openapi.baidu.com/oauth/2.0/authorize?response_type=CODE&{query}"
        ))
    }

    fn access_token_url(callback: AuthCallback) -> Result<String> {
        let query = serde_urlencoded::to_string(callback)?;
        Ok(format!(
            "https://openapi.baidu.com/oauth/2.0/token?grant_type=authorization_code&{query}"
        ))
    }

    fn user_info_url(token: AccessToken) -> Result<String> {
        let query = serde_urlencoded::to_string(token)?;
        Ok(format!(
            "https://openapi.baidu.com/rest/2.0/passport/users/getInfo?{query}"
        ))
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
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
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
}

#[derive(Debug, Serialize)]
pub struct AccessToken {
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
