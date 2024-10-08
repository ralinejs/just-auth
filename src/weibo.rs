//! https://open.weibo.com/wiki/授权机制说明
use crate::{auth_server_builder, AuthUser, GenericAuthAction};
use crate::{error::Result, AuthAction, AuthConfig, AuthUrlProvider};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::DisplayFromStr;
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
            "https://api.weibo.com/oauth2/authorize?response_type=code&{query}"
        ))
    }

    fn access_token_url(request: Self::TokenRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://api.weibo.com/oauth2/access_token?grant_type=authorization_code&{query}"
        ))
    }

    fn user_info_url(request: Self::UserInfoRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://api.weibo.com/2/eps/user/info.json?{query}"
        ))
    }
}

#[async_trait]
impl AuthAction for AuthorizationServer {
    type AuthCallback = AuthCallback;
    type AuthToken = TokenResponse;
    type AuthUser = UserInfoResponse;

    async fn get_access_token(&self, callback: Self::AuthCallback) -> Result<Self::AuthToken> {
        let AuthConfig {
            client_id,
            client_secret,
            redirect_uri,
            ..
        } = &self.config;
        let access_token_url = Self::access_token_url(GetTokenRequest {
            client_id: client_id.to_string(),
            client_secret: client_secret.clone().expect("client_secret is empty"),
            code: callback.code,
            redirect_uri: redirect_uri.to_string(),
        })?;
        Ok(reqwest::get(access_token_url).await?.json().await?)
    }

    async fn get_user_info(&self, token: Self::AuthToken) -> Result<Self::AuthUser> {
        let user_info_url = Self::user_info_url(GetUserInfoRequest {
            access_token: token.access_token,
            uid: token.uid,
        })?;
        Ok(reqwest::get(user_info_url).await?.json().await?)
    }
}

#[async_trait]
impl GenericAuthAction for AuthorizationServer {
    async fn authorize<S: Into<String> + Send>(&self, state: S) -> Result<String> {
        let AuthConfig {
            client_id,
            redirect_uri,
            scope,
            ..
        } = &self.config;
        Self::authorize_url(AuthRequest {
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            state: Some(state.into()),
            scope: scope
                .clone()
                .or_else(|| Some(vec!["email".into()]))
                .expect("scope is empty"),
            ..Default::default()
        })
    }

    async fn login<S: Into<String> + Send>(&self, callback: S) -> Result<AuthUser> {
        let callback: AuthCallback = serde_urlencoded::from_str(&callback.into())?;
        let token = self.get_access_token(callback).await?;
        let user = self.get_user_info(token.clone()).await?;
        Ok(AuthUser {
            user_id: user.uid,
            name: user.nickname,
            access_token: token.access_token,
            refresh_token: "".to_string(),
            expires_in: token.expires_in,
            extra: user.extra,
        })
    }
}

#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthRequest {
    client_id: String,
    redirect_uri: String,
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, String>")]
    scope: Vec<String>,
    state: Option<String>,
    display: Option<String>,
    forcelogin: Option<bool>,
    language: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCallback {
    code: String,
    state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetTokenRequest {
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    access_token: String,
    remind_in: i64,
    expires_in: i64,
    uid: i64,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserInfoRequest {
    access_token: String,
    #[serde_as(as = "DisplayFromStr")]
    uid: i64,
}

/// https://open.weibo.com/wiki/获取用户基本信息
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub uid: String,
    pub nickname: String,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}
