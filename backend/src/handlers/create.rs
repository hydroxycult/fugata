use crate::config::Config;
use crate::svc::service::{CreateSecretRequest, SecretService};
use crate::util::ip::extract_client_ip;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use std::sync::Arc;

pub async fn create_handler(
    State((service, config)): State<(Arc<SecretService>, Arc<Config>)>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateSecretRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), crate::errors::FugataError> {
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
        client_ip = %client_ip,
        peer_ip = %peer_ip,
        one_time = req.one_time,
        duration = ?req.duration,
        "Creating secret"
    );

    let response = service.create_secret(req, &client_ip, &request_id).await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(response).unwrap()),
    ))
}
