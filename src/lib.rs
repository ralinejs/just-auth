pub mod baidu;
pub mod error;
pub mod github;
pub mod qq;
pub mod twitter;
mod utils;
pub mod wechat_open;
pub mod weibo;

use crate::error::Result;
use async_trait::async_trait;
use derive_builder::Builder;

#[derive(Builder)]
pub struct AuthConfig {
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    scope: Option<Vec<String>>,
}

pub trait AuthUrlProvider {
    type AuthRequest;
    type TokenRequest;
    type UserInfoRequest;
    /// 返回带redirect_ui和state参数的授权url，授权回调时会带上这个state。
    /// 用户端重定向至该URL地址进行认证授权
    ///
    fn authorize_url(request: Self::AuthRequest) -> Result<String>;

    /// 返回获取accessToken的url
    ///
    fn access_token_url(request: Self::TokenRequest) -> Result<String>;

    /// 返回获取userInfo的url
    ///
    fn user_info_url(request: Self::UserInfoRequest) -> Result<String>;
}

#[async_trait]
pub trait AuthAction {
    type AuthCallback: Send;
    type AuthToken: Send;
    type AuthUser;

    async fn authorize<S: Into<String> + Send>(&self, state: S) -> Result<String>;

    async fn login(&self, callback: Self::AuthCallback) -> Result<Self::AuthUser> {
        let token = self.get_access_token(callback).await?;
        self.get_user_info(token).await
    }

    async fn get_access_token(&self, callback: Self::AuthCallback) -> Result<Self::AuthToken>;

    async fn get_user_info(&self, token: Self::AuthToken) -> Result<Self::AuthUser>;
}
