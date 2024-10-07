//! https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow
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
            "https://www.facebook.com/v21.0/dialog/oauth?response_type=token&{query}"
        ))
    }

    fn access_token_url(request: Self::TokenRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://graph.facebook.com/v21.0/oauth/access_token?grant_type=authorization_code&{query}"
        ))
    }

    /// https://developers.facebook.com/docs/graph-api/overview#me
    fn user_info_url(request: Self::UserInfoRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!("https://graph.facebook.com/me?{query}"))
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
            state: Some(state.into()),
            scope: scope.clone().unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn login(&self, callback: Self::AuthCallback) -> Result<AuthUser> {
        let token = self.get_access_token(callback).await?;
        let user = self.get_user_info(token.clone()).await?;
        Ok(AuthUser {
            user_id: user.id,
            name: user.name,
            access_token: token.access_token,
            refresh_token: token.token_type,
            expires_in: token.expires_in,
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
            redirect_uri: redirect_uri.to_string(),
        })?;
        Ok(reqwest::get(access_token_url).await?.json().await?)
    }

    async fn get_user_info(&self, token: Self::AuthToken) -> Result<Self::AuthUser> {
        let user_info_url = Self::user_info_url(GetUserInfoRequest {
            access_token: token.access_token,
        })?;
        Ok(reqwest::get(user_info_url).await?.json().await?)
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
    pub token_type: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GetUserInfoRequest {
    access_token: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub id: String,
    pub name: String,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}
