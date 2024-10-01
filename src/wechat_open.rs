//! 微信开放平台
//! https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
use crate::{AuthConfig, AuthUrlProvider};
use serde::{Deserialize, Serialize};
use serde_with::{formats::CommaSeparator, serde_as, StringWithSeparator};

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
            "https://open.weixin.qq.com/connect/qrconnect?response_type=code&{query}"
        ))
    }

    fn access_token_url(request: Self::TokenRequest) -> crate::error::Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://api.weixin.qq.com/sns/oauth2/access_token?grant_type=authorization_code&{query}"
        ))
    }

    fn user_info_url(request: Self::UserInfoRequest) -> crate::error::Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!("https://api.weixin.qq.com/sns/userinfo?{query}"))
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    response_type: String,
    appid: String,
    redirect_uri: String,
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, String>")]
    scope: Vec<String>,
    state: Option<String>,
    lang: Option<Lang>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    En,
    Cn,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCallback {
    code: String,
    state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetTokenRequest {
    grant_type: String,
    appid: String,
    secret: String,
    code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    grant_type: String,
    appid: String,
    refresh_token: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub openid: String,
    pub scope: String,
    pub unionid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserInfoRequest {
    access_token: String,
    openid: String,
    lang: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub openid: String,
    pub nickname: String,
    pub sex: i64,
    pub province: String,
    pub city: String,
    pub country: String,
    pub headimgurl: String,
    pub privilege: Vec<String>,
    pub unionid: String,
}
