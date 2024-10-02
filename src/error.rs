use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error(transparent)]
    UrlEncodedSerializeErr(#[from] serde_urlencoded::ser::Error),

    #[error(transparent)]
    JsonParseErr(#[from] serde_json::Error),

    #[error(transparent)]
    ReqwestErr(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, AuthError>;
