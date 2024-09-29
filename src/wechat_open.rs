//! 微信开放平台
//! https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
use serde::{Deserialize, Serialize};
use serde_with::{formats::CommaSeparator, serde_as, StringWithSeparator};

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
