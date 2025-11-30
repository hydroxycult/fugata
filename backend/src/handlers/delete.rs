use crate::config::Config;
use crate::errors::FugataError;
use crate::svc::service::SecretService;
use crate::util::ip::extract_client_ip;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use std::sync::Arc;

pub async fn delete_handler(
    State((service, config)): State<(Arc<SecretService>, Arc<Config>)>,
    Path(secret_id): Path<String>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<Json<serde_json::Value>, FugataError> {
    let request_id = uuid::Uuid::new_v4().to_string();

    let peer_ip = addr.ip();
    let client_ip = extract_client_ip(
        &headers,
        peer_ip,
        &config.trusted_proxies,
        &config.proxy_mode,
    );

    let deletion_token = headers
        .get("X-Deletion-Token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| FugataError::Unauthorized("Missing X-Deletion-Token header".into()))?;

    tracing::info!(
        request_id = %request_id,
        secret_id = %secret_id,
        client_ip = %client_ip,
        peer_ip = %peer_ip,
        "Deleting secret"
    );

    let response = service
        .delete_secret(&secret_id, deletion_token, &client_ip, &request_id)
        .await?;

    Ok(Json(serde_json::to_value(response).unwrap()))
}
