use crate::config::Config;
use crate::handlers;
use crate::svc::rate_limit::RateLimiter;
use crate::svc::service::SecretService;
use crate::util::ip::extract_client_ip;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

pub fn build_app(service: Arc<SecretService>, config: Arc<Config>) -> Router {
    let rate_limiter = Arc::new(RateLimiter::new(
        config.rate_limit_rpm,
        config.rate_limit_burst,
        config.ip_hash_key,
    ));

    let middleware_state = (rate_limiter.clone(), config.clone());

    let cors = create_cors_layer(&config.allowed_origins);

    Router::new()
        .route("/secrets", post(handlers::create::create_handler))
        .route("/secrets/:id", get(handlers::get::get_handler))
        .route(
            "/secrets/:id",
            axum::routing::delete(handlers::delete::delete_handler),
        )
        .route("/healthz", get(handlers::health::health_handler))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(cors)
                .layer(middleware::from_fn_with_state(
                    middleware_state,
                    rate_limit_middleware,
                ))
                .layer(RequestBodyLimitLayer::new(
                    config.max_secret_size + 10 * 1024,
                ))
                .layer(TimeoutLayer::new(Duration::from_secs(30))),
        )
        .with_state((service, config))
}

async fn rate_limit_middleware(
    State((limiter, config)): State<(Arc<RateLimiter>, Arc<Config>)>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let peer_ip = addr.ip();
    let client_ip = extract_client_ip(
        &headers,
        peer_ip,
        &config.trusted_proxies,
        &config.proxy_mode,
    );

    let rate_info = match limiter.check_rate_limit(&client_ip) {
        Ok(info) => info,
        Err(e) => {
            tracing::error!(error = %e, "Rate limiter error");

            let body = serde_json::json!({
                "error": "rate limiter unavailable",
                "request_id": uuid::Uuid::new_v4().to_string()
            });
            return (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response();
        }
    };

    if !rate_info.allowed {
        tracing::warn!(
            client_ip = %client_ip,
            peer_ip = %peer_ip,
            limit = rate_info.limit,
            "Rate limit exceeded"
        );

        let body = serde_json::json!({
            "error": "rate limit exceeded",
            "request_id": uuid::Uuid::new_v4().to_string()
        });

        let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();

        let headers = response.headers_mut();
        headers.insert(
            "X-RateLimit-Limit",
            HeaderValue::from_str(&rate_info.limit.to_string()).unwrap(),
        );
        headers.insert("X-RateLimit-Remaining", HeaderValue::from_str("0").unwrap());
        headers.insert(
            "X-RateLimit-Reset",
            HeaderValue::from_str(&rate_info.reset_at.to_string()).unwrap(),
        );

        return response;
    }

    let mut response = next.run(request).await;

    let headers = response.headers_mut();
    headers.insert(
        "X-RateLimit-Limit",
        HeaderValue::from_str(&rate_info.limit.to_string()).unwrap(),
    );
    headers.insert(
        "X-RateLimit-Remaining",
        HeaderValue::from_str(&rate_info.remaining.to_string()).unwrap(),
    );
    headers.insert(
        "X-RateLimit-Reset",
        HeaderValue::from_str(&rate_info.reset_at.to_string()).unwrap(),
    );

    response
}

fn create_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    use axum::http::Method;

    let mut cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([axum::http::header::CONTENT_TYPE])
        .max_age(Duration::from_secs(5))
        .vary([axum::http::header::ORIGIN]);

    if allowed_origins.is_empty() {
        tracing::warn!("No CORS origins configured - all cross-origin requests will be rejected");
        return cors;
    }

    for origin in allowed_origins {
        match origin.parse::<HeaderValue>() {
            Ok(header_value) => {
                cors = cors.allow_origin(header_value);
            }
            Err(e) => {
                tracing::error!("Invalid CORS origin '{}': {}", origin, e);
            }
        }
    }

    cors
}

pub async fn serve(app: Router, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
