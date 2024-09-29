pub mod baidu;
pub mod error;
pub mod qq;
pub mod wechat_open;
pub mod weibo;

use crate::error::Result;
use async_trait::async_trait;
use derive_builder::Builder;

#[derive(Builder)]
pub struct AuthConfig {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

pub trait AuthUrlProvider {
    type AuthRequest;
    type AuthCallback;
    type AuthToken;
    /// 返回带redirect_ui和state参数的授权url，授权回调时会带上这个state。
    /// 用户端重定向至该URL地址进行认证授权
    ///
    fn authorize(request: Self::AuthRequest) -> Result<String>;

    /// 返回获取accessToken的url
    ///
    fn access_token_url(callback: Self::AuthCallback) -> Result<String>;

    /// 返回获取userInfo的url
    ///
    fn user_info_url(token: Self::AuthToken) -> Result<String>;
}

#[async_trait]
pub trait AuthAction<C, T, U> {
    type AuthCallback;
    type AuthToken;
    type AuthUser;

    async fn get_access_token(callback: Self::AuthCallback) -> Self::AuthToken;

    async fn get_user_info(token: Self::AuthToken) -> Self::AuthUser;
}
