//! https://docs.github.com/zh/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
use crate::error::Result;
use crate::{auth_server_builder, AuthAction, AuthConfig, AuthUrlProvider, AuthUser};
use async_trait::async_trait;
use reqwest::header::ACCEPT;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{formats::SpaceSeparator, serde_as, StringWithSeparator};
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
        Ok(format!("https://github.com/login/oauth/authorize?{query}"))
    }

    fn access_token_url(request: Self::TokenRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://github.com/login/oauth/access_token?token_type=bearer&{query}"
        ))
    }

    fn user_info_url(_request: Self::UserInfoRequest) -> Result<String> {
        Ok(format!("https://api.github.com/user"))
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
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            state: state.into(),
            scope: scope
                .clone()
                .or_else(|| Some(vec!["read:user".into(), "user:email".into()]))
                .expect("scope is empty"),
            ..Default::default()
        })
    }

    async fn login(&self, callback: Self::AuthCallback) -> Result<AuthUser> {
        let token = self.get_access_token(callback).await?;
        let user = self.get_user_info(token.clone()).await?;
        Ok(AuthUser {
            user_id: user.id.to_string(),
            name: user.name,
            access_token: token.access_token,
            refresh_token: token.token_type,
            expires_in: i64::MAX,
            extra: user.extra,
        })
    }

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
            redirect_uri: redirect_uri.clone(),
        })?;
        Ok(reqwest::Client::default()
            .get(access_token_url)
            .header(ACCEPT, "application/json")
            .send()
            .await?
            .json()
            .await?)
    }

    async fn get_user_info(&self, token: Self::AuthToken) -> Result<Self::AuthUser> {
        let user_info_url = Self::user_info_url(GetUserInfoRequest {})?;
        Ok(reqwest::Client::default()
            .get(user_info_url)
            .bearer_auth(token.access_token)
            .send()
            .await?
            .json()
            .await?)
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

/// https://docs.github.com/en/rest/users/users
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub id: i64,
    pub name: String,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}
