//! https://docs.github.com/zh/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
use crate::error::Result;
use crate::{AuthConfig, AuthUrlProvider};
use serde::{Deserialize, Serialize};
use serde_with::{formats::SpaceSeparator, serde_as, StringWithSeparator};

pub struct AuthorizationServer {
    config: AuthConfig,
}

impl AuthUrlProvider for AuthorizationServer {
    type AuthRequest = AuthRequest;
    type TokenRequest = GetTokenRequest;
    type UserInfoRequest = GetUserInfoRequest;

    fn authorize(request: Self::AuthRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!("https://github.com/login/oauth/authorize?{query}"))
    }

    fn access_token_url(request: Self::TokenRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://github.com/login/oauth/access_token?token_type=bearer&{query}"
        ))
    }

    fn user_info_url(request: Self::UserInfoRequest) -> Result<String> {
        Ok(format!("https://api.github.com/user"))
    }
}

#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthRequest {
    client_id: String,
    redirect_uri: String,
    login: Option<String>,
    #[serde_as(as = "StringWithSeparator::<SpaceSeparator, String>")]
    scope: Vec<String>,
    state: String,
    allow_signup: Option<String>,
    prompt: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCallback {
    code: String,
    state: String,
}

#[derive(Debug, Serialize)]
pub struct GetTokenRequest {
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub scope: String,
    pub token_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserInfoRequest {}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub openid: String,
    pub unionid: String,
    pub userid: Option<u32>,
    pub securemobile: Option<u32>,
    pub username: Option<String>,
    pub portrait: Option<String>,
    pub userdetail: Option<String>,
    pub birthday: Option<String>,
    pub marriage: Option<String>,
    pub sex: Option<String>,
    pub blood: Option<String>,
    pub is_bind_mobile: Option<String>,
    pub is_realname: Option<String>,
}
