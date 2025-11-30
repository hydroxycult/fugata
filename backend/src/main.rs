mod config;
mod crypto;
mod errors;
mod handlers;
mod kms;
mod server;
mod svc;
mod util;

use config::{Config, KmsProvider};
use kms::Kms;
use std::sync::Arc;
use std::time::Duration;
use svc::audit::AuditLogger;
use svc::cache::{ReplayCache, SecretCache};
use svc::db::Database;
use svc::hasher::HasherPool;
use svc::service::SecretService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env().map_err(|e| {
        eprintln!("Configuration error: {}", e);
        e
    })?;

    init_logging(&config);

    tracing::info!("Starting Fugata backend");
    tracing::info!(
        environment = %config.environment,
        port = config.port,
        "Configuration loaded"
    );

    tracing::info!("Initializing KMS provider");
    let kms: Arc<dyn Kms> = match &config.kms_provider {
        KmsProvider::Local { key } => {
            tracing::info!("Using Local KMS provider");
            Arc::new(kms::local::LocalKms::new(key.clone())?)
        }
        KmsProvider::Vault {
            addr,
            token,
            mount,
            key_name,
        } => {
            tracing::info!(addr = %addr, "Using Vault KMS provider");
            Arc::new(kms::vault::VaultKms::new(
                addr.clone(),
                token.clone(),
                mount.clone(),
                key_name.clone(),
            ))
        }
        #[cfg(feature = "aws-kms")]
        KmsProvider::Aws { region, key_id } => {
            tracing::info!(region = %region, "Using AWS KMS provider");
            Arc::new(kms::aws::AwsKms::new(region.clone(), key_id.clone()).await?)
        }
    };

    if config.kms_fail_closed {
        tracing::info!("Performing KMS health check (fail-closed mode)");
        kms.health_check().await.map_err(|e| {
            tracing::error!(error = %e, "KMS health check failed in fail-closed mode");
            e
        })?;
        tracing::info!("KMS health check passed");
    }

    tracing::info!(url = %config.database_url, "Connecting to database");
    let db = Database::new(&config.database_url, config.db_max_connections).await?;

    tracing::info!("Running database migrations");
    db.migrate().await?;
    tracing::info!("Database migrations completed");

    tracing::info!(
        workers = config.hasher_worker_count,
        queue_size = config.hasher_queue_size,
        "Initializing hasher pool"
    );
    let hasher = Arc::new(HasherPool::new(
        config.hasher_worker_count,
        config.hasher_queue_size,
        config.pepper,
        config.argon2_time,
        config.argon2_memory,
        config.argon2_parallelism,
    )?);

    tracing::info!(cache_size = config.lru_cache_size, "Initializing caches");
    let secret_cache = SecretCache::new(config.lru_cache_size);
    let replay_cache = ReplayCache::new();

    let audit = AuditLogger::new(db.clone().pool.clone());

    let config_arc = Arc::new(config.clone());
    let service = Arc::new(SecretService::new(
        db.clone(),
        kms,
        hasher,
        secret_cache.clone(),
        replay_cache.clone(),
        audit,
        config_arc.clone(),
    ));

    spawn_cleanup_jobs(service.clone());

    let app = server::build_app(service.clone(), config_arc.clone());

    tracing::info!(port = config.port, "Server ready");

    server::serve(app, config.port).await?;

    Ok(())
}

fn init_logging(config: &Config) {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(false),
        )
        .init();
}

fn spawn_supervised_task<F, Fut>(
    task_name: &'static str,
    interval_secs: u64,
    service: Arc<SecretService>,
    task_fn: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn(Arc<SecretService>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut restart_count = 0;
        let task_fn = Arc::new(task_fn);

        loop {
            tracing::info!(
                task = %task_name,
                restart_count,
                "Starting supervised background task"
            );

            let service_clone = service.clone();
            let task_fn_clone = task_fn.clone();
            let result = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
                loop {
                    interval.tick().await;
                    task_fn_clone(service_clone.clone()).await;
                }
            })
            .await;

            match result {
                Err(join_err) if join_err.is_panic() => {
                    restart_count += 1;
                    tracing::error!(
                        task = %task_name,
                        restart_count,
                        "Background task panicked, restarting in 5 seconds"
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Err(_) => {
                    tracing::warn!(task = %task_name, "Background task cancelled");
                    break;
                }
                Ok(_) => {
                    tracing::warn!(task = %task_name, "Background task completed normally");
                    break;
                }
            }
        }

        tracing::info!(task = %task_name, "Supervisor stopped");
    })
}

fn spawn_cleanup_jobs(service: Arc<SecretService>) {
    spawn_supervised_task(
        "cleanup_expired_secrets",
        60,
        service.clone(),
        |svc| async move {
            match svc.cleanup_expired_secrets().await {
                Ok(count) if count > 0 => {
                    tracing::info!(count = %count, "Expired secrets cleaned up");
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to cleanup expired secrets");
                }
                _ => {}
            }
        },
    );

    spawn_supervised_task(
        "cleanup_replay_cache",
        300,
        service.clone(),
        |svc| async move {
            svc.cleanup_replay_cache();
        },
    );

    tracing::info!("Supervised background cleanup jobs started");
}
