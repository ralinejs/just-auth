use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error(transparent)]
    UrlEncodedSerializeErr(#[from] serde_urlencoded::ser::Error),
}

pub type Result<T> = std::result::Result<T, AuthError>;
