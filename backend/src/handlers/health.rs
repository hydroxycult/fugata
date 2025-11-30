use crate::config::Config;
use crate::svc::service::SecretService;
use axum::{extract::State, http::StatusCode, Json};
use serde_json::json;
use std::sync::Arc;

pub async fn health_handler(
    State((service, _config)): State<(Arc<SecretService>, Arc<Config>)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match service.health_check().await {
        Ok(()) => Ok(Json(json!({
            "status": "healthy",
            "checks": {
                "database": "ok",
                "kms": "ok",
                "cache": "ok"
            }
        }))),
        Err(e) => {
            tracing::error!(error = %e, "Health check failed");

            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "unhealthy",
                    "error": e.to_string()
                })),
            ))
        }
    }
}
