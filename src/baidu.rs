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
    type TokenRequest = GetTokenRequest;
    type UserInfoRequest = GetUserInfoRequest;

    fn authorize_url(request: Self::AuthRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://openapi.baidu.com/oauth/2.0/authorize?response_type=CODE&{query}"
        ))
    }

    fn access_token_url(request: Self::TokenRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://openapi.baidu.com/oauth/2.0/token?grant_type=authorization_code&{query}"
        ))
    }

    fn user_info_url(request: Self::UserInfoRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://openapi.baidu.com/rest/2.0/passport/users/getInfo?{query}"
        ))
    }
}

#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthRequest {
    client_id: String,
    redirect_uri: String,
    #[serde_as(as = "StringWithSeparator::<SpaceSeparator, String>")]
    scope: Vec<String>,
    state: Option<String>,
    display: Option<DisplayStyle>,
    force_login: Option<i8>,
    confirm_login: Option<i8>,
    login_type: Option<String>,
    qrext_clientid: Option<String>,
    bgurl: Option<String>,
    #[serde(rename = "qrcodeW")]
    qrcode_width: Option<u32>,
    #[serde(rename = "qrcodeH")]
    qrcode_height: Option<u32>,
    qrcode: Option<i8>,
    qrloginfrom: Option<String>,
    #[serde(rename = "userReg")]
    user_reg: Option<i8>,
    #[serde(rename = "appTip")]
    app_tip: Option<String>,
    #[serde(rename = "appName")]
    app_name: Option<String>,
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

#[derive(Debug, Serialize)]
pub struct GetTokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub scope: String,
    pub session_key: String,
    pub session_secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserInfoRequest {
    access_token: String,
    get_unionid: Option<i8>,
}

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
