//! https://wikinew.open.qq.com/index.html#/iwiki/901251864
use crate::{error::Result, utils, AuthAction, AuthConfig, AuthUrlProvider};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

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
            "https://graph.qq.com/oauth2.0/authorize?response_type=token&{query}"
        ))
    }

    fn access_token_url(request: Self::TokenRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://graph.qq.com/oauth2.0/token?grant_type=authorization_code&{query}"
        ))
    }

    fn user_info_url(request: Self::UserInfoRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!("https://graph.qq.com/user/get_user_info?{query}"))
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
            scope: scope.clone().or_else(|| Some(vec!["get_user_info".into()])),
            ..Default::default()
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
            fmt: Some(ResponseFormat::Json),
        })?;
        Ok(reqwest::get(access_token_url).await?.json().await?)
    }

    async fn get_user_info(&self, token: Self::AuthToken) -> Result<Self::AuthUser> {
        let AuthConfig { client_id, .. } = &self.config;
        let access_token = token.access_token;
        let jsonp = reqwest::get(format!(
            "https://graph.qq.com/oauth2.0/me?access_token={access_token}"
        ))
        .await?
        .text()
        .await?;
        let json =
            utils::substr_between(&jsonp, "callback(", ");").expect("jsonp response is valid");
        let value: OpenIdResp = serde_json::from_str(json)?;
        let user_info_url = Self::user_info_url(GetUserInfoRequest {
            openid: value.openid,
            access_token: access_token,
            oauth_consumer_key: client_id.to_string(),
        })?;
        Ok(reqwest::get(user_info_url).await?.json().await?)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthRequest {
    client_id: String,
    redirect_uri: String,
    state: String,
    scope: Option<Vec<String>>,
    display: Option<QQDisplayStyle>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QQDisplayStyle {
    PC,
    Mobile,
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
    fmt: Option<ResponseFormat>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ResponseFormat {
    #[serde(rename = "x-www-form-urlencoded")]
    UrlEncoded,
    #[serde(rename = "json")]
    Json,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    refresh_token: String,
    fmt: Option<ResponseFormat>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    access_token: String,
    expires_in: i32,
    refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdResp {
    client_id: String,
    openid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserInfoRequest {
    access_token: String,
    oauth_consumer_key: String,
    openid: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfoResponse {
    pub ret: i64,
    pub msg: String,
    pub nickname: String,
    pub figureurl: String,
    #[serde(rename = "figureurl_1")]
    pub figureurl_1: String,
    #[serde(rename = "figureurl_2")]
    pub figureurl_2: String,
    #[serde(rename = "figureurl_qq_1")]
    pub figureurl_qq_1: String,
    #[serde(rename = "figureurl_qq_2")]
    pub figureurl_qq_2: String,
    pub gender: String,
}
