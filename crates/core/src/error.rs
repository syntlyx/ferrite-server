use thiserror::Error;

#[derive(Debug, Error)]
pub enum FeriteError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("tokio-rusqlite error: {0}")]
    TokioDatabase(#[from] tokio_rusqlite::Error),

    #[error("hickory resolver error: {0}")]
    Resolver(#[from] hickory_resolver::net::NetError),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("FST error: {0}")]
    Fst(String),

    #[error("snapshot codec error: {0}")]
    SnapshotCodec(#[from] postcard::Error),

    #[error("update error: {0}")]
    Update(String),

    // Reserved for handlers that need to surface 401 directly via ApiError.
    #[allow(dead_code)]
    #[error("unauthorized")]
    Unauthorized,

    #[error("too many requests; slow down and try again")]
    RateLimited,

    #[error("not found: {0}")]
    NotFound(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl From<fst::Error> for FeriteError {
    fn from(e: fst::Error) -> Self {
        FeriteError::Fst(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, FeriteError>;
