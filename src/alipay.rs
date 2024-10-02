//! https://opendocs.alipay.com/open/01emu5?pathHash=8f9c00bc
//! https://open.alipay.com/api/detail?code=I1080300001000043162
use crate::{AuthConfig, AuthUrlProvider};
use serde::{Deserialize, Serialize};

pub struct AuthorizationServer {
    config: AuthConfig,
}

impl AuthUrlProvider for AuthorizationServer {
    type AuthRequest = AuthRequest;

    type TokenRequest = GetTokenRequest;

    type UserInfoRequest = GetUserInfoRequest;

    fn authorize_url(request: Self::AuthRequest) -> crate::error::Result<String> {
        let query = serde_urlencoded::to_string(request)?;
        Ok(format!(
            "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?app_id=商户的APPID&scope=auth_user&redirect_uri=ENCODED_URL&state=init"
        ))
    }

    fn access_token_url(request: Self::TokenRequest) -> crate::error::Result<String> {
        todo!()
    }

    fn user_info_url(request: Self::UserInfoRequest) -> crate::error::Result<String> {
        todo!()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    app_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Callback {
    app_id: String,
    source: String,
    scope: String,
    auth_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetTokenRequest {
    app_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserInfoRequest {
    app_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
}
