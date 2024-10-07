//! https://developer.x.com/en/docs/authentication/oauth-2-0/authorization-code
//! https://developer.x.com/en/docs/authentication/oauth-2-0/user-access-token
//! https://developer.x.com/en/docs/x-api/users/lookup/api-reference/get-users-me
use crate::error::Result;
use crate::{
    auth_server_builder, AuthAction, AuthConfig, AuthUrlProvider, AuthUser, GenericAuthAction,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{
    formats::{CommaSeparator, SpaceSeparator},
    serde_as, StringWithSeparator,
};
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
            "https://twitter.com/i/oauth2/authorize?response_type=code&{query}"
        ))
    }

    fn access_token_url(request: Self::TokenRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://api.x.com/2/oauth2/token?grant_type=authorization_code&{query}"
        ))
    }

    fn user_info_url(_request: Self::UserInfoRequest) -> Result<String> {
        Ok(format!("https://api.x.com/2/users/me"))
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
            redirect_uri,
            ..
        } = &self.config;
        let access_token_url = Self::access_token_url(GetTokenRequest {
            client_id: client_id.to_string(),
            code: callback.code,
            redirect_uri: redirect_uri.to_string(),
            code_verifier: "aaa".to_string(),
        })?;
        Ok(reqwest::get(access_token_url).await?.json().await?)
    }

    async fn get_user_info(&self, token: Self::AuthToken) -> Result<Self::AuthUser> {
        let user_info_url = Self::user_info_url(GetUserInfoRequest {
            user_fields: [
                "created_at",
                "description",
                "entities",
                "id",
                "location",
                "most_recent_tweet_id",
                "name",
                "pinned_tweet_id",
                "profile_image_url",
                "protected",
                "public_metrics",
                "url",
                "username",
                "verified",
                "verified_type",
                "withheld",
            ]
            .map(|s| s.to_string())
            .to_vec(),
            ..Default::default()
        })?;
        Ok(reqwest::Client::default()
            .get(user_info_url)
            .bearer_auth(token.access_token)
            .send()
            .await?
            .json()
            .await?)
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
            state: state.into(),
            scope: scope
                .clone()
                .or_else(|| Some(vec!["tweet.read".into(), "users.read".into()]))
                .expect("scope is empty"),
            ..Default::default()
        })
    }

    async fn login<S: Into<String> + Send>(&self, callback: S) -> Result<AuthUser> {
        let callback: AuthCallback = serde_urlencoded::from_str(&callback.into())?;
        let token = self.get_access_token(callback).await?;
        let user = self.get_user_info(token.clone()).await?;
        Ok(AuthUser {
            user_id: user.id,
            name: user.name,
            access_token: token.access_token,
            refresh_token: token.token_type,
            expires_in: i64::MAX,
            extra: user.extra,
        })
    }
}

#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthRequest {
    client_id: String,
    redirect_uri: String,
    #[serde_as(as = "StringWithSeparator::<SpaceSeparator, String>")]
    scope: Vec<String>,
    state: String,
    /// https://www.oauth.com/oauth2-servers/pkce/authorization-request/
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCallback {
    code: String,
    state: String,
}

#[derive(Debug, Serialize)]
pub struct GetTokenRequest {
    client_id: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub scope: String,
    pub token_type: String,
}

#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GetUserInfoRequest {
    expansions: Option<String>,
    #[serde(rename = "tweet.fields")]
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, String>")]
    tweet_fields: Vec<String>,
    #[serde(rename = "user.fields")]
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, String>")]
    user_fields: Vec<String>,
}

/// https://developer.x.com/en/docs/x-api/users/lookup/api-reference/get-users-me
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub id: String,
    pub name: String,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}
