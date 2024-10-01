//! https://wikinew.open.qq.com/index.html#/iwiki/901251864
use crate::{AuthConfig, AuthUrlProvider};
use serde::{Deserialize, Serialize};

pub struct AuthorizationServer {
    config: AuthConfig,
}

impl AuthUrlProvider for AuthorizationServer {
    type AuthRequest = AuthRequest;
    type TokenRequest = GetTokenRequest;
    type UserInfoRequest = GetUserInfoRequest;

    fn authorize(request: Self::AuthRequest) -> crate::error::Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://graph.qq.com/oauth2.0/authorize?response_type=token&{query}"
        ))
    }

    fn access_token_url(request: Self::TokenRequest) -> crate::error::Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://graph.qq.com/oauth2.0/token?grant_type=authorization_code&{query}"
        ))
    }

    fn user_info_url(request: Self::UserInfoRequest) -> crate::error::Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!("https://graph.qq.com/user/get_user_info?{query}"))
    }
}

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

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    access_token: String,
    expires_in: i32,
    refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserInfoRequest {
    access_token: String,
    oauth_consumer_key: String,
    openid: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfoResponse {
    pub ret: i64,
    pub msg: String,
    pub nickname: String,
    pub figureurl: String,
    #[serde(rename = "figureurl_1")]
    pub figureurl_1: String,
    #[serde(rename = "figureurl_2")]
    pub figureurl_2: String,
    #[serde(rename = "figureurl_qq_1")]
    pub figureurl_qq_1: String,
    #[serde(rename = "figureurl_qq_2")]
    pub figureurl_qq_2: String,
    pub gender: String,
}
