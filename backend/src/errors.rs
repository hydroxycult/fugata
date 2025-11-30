use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FugataError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("rate limit exceeded")]
    RateLimitExceeded,

    #[error("internal error: {0}")]
    Internal(String),

    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("kms error: {0}")]
    Kms(String),

    #[error("worker pool overload")]
    WorkerPoolOverload,

    #[error("configuration error: {0}")]
    Config(String),
}

impl FugataError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            FugataError::BadRequest(_) => StatusCode::BAD_REQUEST,
            FugataError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            FugataError::NotFound(_) => StatusCode::NOT_FOUND,
            FugataError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            FugataError::Internal(_) | FugataError::Database(_) | FugataError::Crypto(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            FugataError::ServiceUnavailable(_)
            | FugataError::Kms(_)
            | FugataError::WorkerPoolOverload => StatusCode::SERVICE_UNAVAILABLE,
            FugataError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn is_server_error(&self) -> bool {
        matches!(
            self.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR | StatusCode::SERVICE_UNAVAILABLE
        )
    }
}

impl IntoResponse for FugataError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let request_id = uuid::Uuid::new_v4().to_string();

        if self.is_server_error() {
            tracing::error!(
                error = %self,
                request_id = %request_id,
                "Server error occurred"
            );
        }

        let body = if status.is_server_error() {
            json!({
                "error": "internal server error",
                "request_id": request_id,
            })
        } else {
            json!({
                "error": self.to_string(),
                "request_id": request_id,
            })
        };

        (status, Json(body)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, FugataError>;
