use crate::config::Config;
use crate::svc::service::SecretService;
use crate::util::ip::extract_client_ip;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use std::sync::Arc;

pub async fn get_handler(
    State((service, config)): State<(Arc<SecretService>, Arc<Config>)>,
    Path(secret_id): Path<String>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, crate::errors::FugataError> {
    let request_id = uuid::Uuid::new_v4().to_string();

    let peer_ip = addr.ip();
    let client_ip = extract_client_ip(
        &headers,
        peer_ip,
        &config.trusted_proxies,
        &config.proxy_mode,
    );

    tracing::info!(
        request_id = %request_id,
        secret_id = %secret_id,
        client_ip = %client_ip,
        peer_ip = %peer_ip,
        "Retrieving secret"
    );

    let response = service
        .get_secret(&secret_id, &client_ip, &request_id)
        .await?;

    Ok(Json(serde_json::to_value(response).unwrap()))
}
