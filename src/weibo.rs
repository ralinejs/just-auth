//! https://open.weibo.com/wiki/授权机制说明
use crate::{AuthConfig, AuthUrlProvider};
use serde::{Deserialize, Serialize};

pub struct AuthorizationServer {
    config: AuthConfig,
}

impl AuthUrlProvider for AuthorizationServer {
    type AuthRequest = AuthRequest;

    type TokenRequest = GetTokenRequest;

    type UserInfoRequest = GetUserInfoRequest;

    fn authorize_url(request: Self::AuthRequest) -> crate::error::Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://api.weibo.com/oauth2/authorize?response_type=code&{query}"
        ))
    }

    fn access_token_url(request: Self::TokenRequest) -> crate::error::Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://api.weibo.com/oauth2/access_token?grant_type=authorization_code&{query}"
        ))
    }

    fn user_info_url(request: Self::UserInfoRequest) -> crate::error::Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://api.weibo.com/2/eps/user/info.json?{query}"
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    display: Option<String>,
    forcelogin: Option<bool>,
    language: Option<String>,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserInfoRequest {
    access_token: String,
    uid: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub subscribe: i64,
    pub uid: String,
    pub nickname: String,
    pub sex: i64,
    pub language: String,
    pub city: String,
    pub province: String,
    pub country: String,
    pub headimgurl: String,
    pub headimgurl_large: String,
    pub headimgurl_hd: String,
    pub follow: String,
    pub subscribe_time: i64,
}
