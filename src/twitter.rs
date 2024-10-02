//! https://developer.x.com/en/docs/authentication/oauth-2-0/authorization-code
//! https://developer.x.com/en/docs/authentication/oauth-2-0/user-access-token
//! https://developer.x.com/en/docs/x-api/users/lookup/api-reference/get-users-me
use crate::error::Result;
use crate::{AuthConfig, AuthUrlProvider};
use serde::{Deserialize, Serialize};
use serde_with::{
    formats::{CommaSeparator, SpaceSeparator},
    serde_as, StringWithSeparator,
};

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
            "https://twitter.com/i/oauth2/authorize?response_type=code&{query}"
        ))
    }

    fn access_token_url(request: Self::TokenRequest) -> Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://api.x.com/2/oauth2/token?grant_type=authorization_code&{query}"
        ))
    }

    fn user_info_url(request: Self::UserInfoRequest) -> Result<String> {
        Ok(format!("https://api.x.com/2/users/me"))
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
#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserInfoRequest {
    expansions: Option<String>,
    #[serde(rename = "tweet.fields")]
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, String>")]
    tweet_fields: Vec<String>,
    #[serde(rename = "user.fields")]
    #[serde_as(as = "StringWithSeparator::<CommaSeparator, String>")]
    user_fields: Vec<String>,
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
