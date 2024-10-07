pub mod baidu;
pub mod error;
pub mod facebook;
pub mod github;
pub mod qq;
pub mod twitter;
pub mod wechat_open;
pub mod weibo;

mod utils;

use crate::error::Result;
use async_trait::async_trait;

pub struct AuthConfig {
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    scope: Option<Vec<String>>,
}

#[macro_export]
macro_rules! auth_server_builder {
    () => {
        #[derive(Default)]
        pub struct AuthConfigBuilder {
            client_id: Option<String>,
            client_secret: Option<String>,
            redirect_uri: Option<String>,
            scope: Option<Vec<String>>,
        }

        impl AuthorizationServer {
            pub fn builder() -> AuthConfigBuilder {
                AuthConfigBuilder::default()
            }
        }

        impl AuthConfigBuilder {
            pub fn client_id<S: Into<String>>(mut self, client_id: S) -> Self {
                self.client_id = Some(client_id.into());
                self
            }
            pub fn client_secret<S: Into<String>>(mut self, client_secret: S) -> Self {
                self.client_secret = Some(client_secret.into());
                self
            }
            pub fn redirect_uri<S: Into<String>>(mut self, redirect_uri: S) -> Self {
                self.redirect_uri = Some(redirect_uri.into());
                self
            }
            pub fn scope<S: Into<String>>(mut self, scope: S) -> Self {
                match &mut self.scope {
                    Some(vec) => vec.push(scope.into()),
                    None => self.scope = Some(vec![scope.into()]),
                }
                self
            }
            pub fn build(self) -> AuthorizationServer {
                AuthorizationServer {
                    config: AuthConfig {
                        client_id: self.client_id.unwrap_or_default(),
                        client_secret: self.client_secret,
                        redirect_uri: self.redirect_uri.unwrap_or_default(),
                        scope: self.scope,
                    },
                }
            }
        }
    };
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
