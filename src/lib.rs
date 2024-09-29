pub mod baidu;
pub mod qq;
pub mod wechat_open;
pub mod weibo;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum AuthRequest {
    QQ(qq::AuthRequest),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AuthCallback {
    QQ(qq::AuthCallback),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum GetTokenRequest {
    QQ(qq::GetTokenRequest),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RefreshTokenRequest {
    QQ(qq::RefreshTokenRequest),
}
