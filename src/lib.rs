pub mod baidu;
pub mod qq;
pub mod wechat_open;
pub mod weibo;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub trait AuthUrlProvider {
    /// 返回带state参数的授权url，授权回调时会带上这个state
    ///
    /// - param state  验证授权流程的参数，可以防止csrf
    /// - return 返回授权地址
    fn authorize<S: Into<String>>(state: S) -> String;

    ///
    /// 返回获取accessToken的url
    ///
    /// - param code 授权码
    /// - return 返回获取accessToken的url
    ///
    fn access_token_url<S: Into<String>>(code: S) -> String;

    /// 返回获取userInfo的url
    ///
    /// - param authToken 用户授权后的token
    /// - return 返回获取userInfo的url
    ///
    fn user_info_url<S: Into<String>>(auth_token: S) -> String;
}

pub trait AuthCallback {}

pub trait AuthToken {}

pub trait AuthUser {}

#[async_trait]
pub trait AuthAction<C, T, U>
where
    C: AuthCallback,
    T: AuthToken,
    U: AuthUser,
{
    async fn get_access_token(callback: C) -> T;

    async fn get_user_info(token: T) -> U;
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AuthRenderRequest {
    QQ(qq::AuthRequest),
    Baidu(baidu::AuthRequest),
    Weibo(weibo::AuthRequest),
    WechatOpen(wechat_open::AuthRequest),
}

// #[derive(Debug, Serialize, Deserialize)]
// pub enum AuthCallback {
//     QQ(qq::AuthCallback),
//     Baidu(baidu::AuthCallback),
//     Weibo(weibo::AuthCallback),
//     WechatOpen(wechat_open::AuthCallback),
// }

#[derive(Debug, Serialize, Deserialize)]
pub enum GetTokenRequest {
    QQ(qq::GetTokenRequest),
    Baidu(baidu::GetTokenRequest),
    Weibo(weibo::GetTokenRequest),
    WechatOpen(wechat_open::GetTokenRequest),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RefreshTokenRequest {
    QQ(qq::RefreshTokenRequest),
    Baidu(baidu::RefreshTokenRequest),
    WechatOpen(wechat_open::RefreshTokenRequest),
}
