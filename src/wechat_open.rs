//! 微信开放平台
//! https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
use crate::{
    auth_server_builder, error::Result, AuthAction, AuthConfig, AuthUrlProvider, AuthUser,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{formats::CommaSeparator, serde_as, StringWithSeparator};
use std::collections::HashMap;

pub struct AuthorizationServer {
    config: AuthConfig,
}

auth_server_builder!();

impl AuthUrlProvider for AuthorizationServer {
    type AuthRequest = AuthRequest;

    type TokenRequest = GetTokenRequest;

    type UserInfoRequest = GetUserInfoRequest;

    fn authorize_url(request: Self::AuthRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://open.weixin.qq.com/connect/qrconnect?response_type=code&{query}"
        ))
    }

    fn access_token_url(request: Self::TokenRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://api.weixin.qq.com/sns/oauth2/access_token?grant_type=authorization_code&{query}"
        ))
    }

    fn user_info_url(request: Self::UserInfoRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!("https://api.weixin.qq.com/sns/userinfo?{query}"))
    }
}

#[async_trait]
impl AuthAction for AuthorizationServer {
    type AuthCallback = AuthCallback;
    type AuthToken = TokenResponse;
    type AuthUser = UserInfoResponse;

    async fn authorize<S: Into<String> + Send>(&self, state: S) -> Result<String> {
        let AuthConfig {
            client_id,
            redirect_uri,
            scope,
            ..
        } = &self.config;
        Self::authorize_url(AuthRequest {
            appid: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            state: Some(state.into()),
            scope: scope
                .clone()
                .or_else(|| {
                    Some(vec![
                        "snsapi_base".into(),
                        "snsapi_login".into(),
                        "snsapi_userinfo".into(),
                    ])
                })
                .expect("scope is empty"),
            ..Default::default()
        })
    }

    async fn login(&self, callback: Self::AuthCallback) -> Result<AuthUser> {
        let token = self.get_access_token(callback).await?;
        let user = self.get_user_info(token.clone()).await?;
        Ok(AuthUser {
            user_id: user.unionid,
            name: user.nickname,
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            expires_in: token.expires_in,
            extra: user.extra,
        })
    }

    async fn get_access_token(&self, callback: Self::AuthCallback) -> Result<Self::AuthToken> {
        let AuthConfig {
            client_id,
            client_secret,
            ..
        } = &self.config;
        let access_token_url = Self::access_token_url(GetTokenRequest {
            appid: client_id.to_string(),
            secret: client_secret.clone().expect("client_secret is empty"),
            code: callback.code,
        })?;
        Ok(reqwest::get(access_token_url).await?.json().await?)
    }

    async fn get_user_info(&self, token: Self::AuthToken) -> Result<Self::AuthUser> {
        let user_info_url = Self::user_info_url(GetUserInfoRequest {
            openid: token.unionid,
            access_token: token.access_token,
            ..Default::default()
        })?;
        Ok(reqwest::get(user_info_url).await?.json().await?)
    }
}

#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthRequest {
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

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GetUserInfoRequest {
    access_token: String,
    openid: String,
    lang: Option<String>,
}

/// https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Authorized_Interface_Calling_UnionID.html
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub unionid: String,
    pub nickname: String,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}
