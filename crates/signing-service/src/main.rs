//! Binary entrypoint.

use anyhow::Context;
use metrics_exporter_prometheus::PrometheusBuilder;
use signing_service::{config::AppConfig, infra::factory::build_backend, observability, AppState};
use std::sync::Arc;
use tokio::{net::TcpListener, signal};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env in dev; harmless if missing.
    let _ = dotenvy::dotenv();

    observability::init_tracing();

    let cfg = AppConfig::load().context("loading configuration")?;
    info!(?cfg.bind, ?cfg.backend, "starting signing-service");

    if let Some(metrics_addr) = cfg.metrics_bind {
        PrometheusBuilder::new()
            .with_http_listener(metrics_addr)
            .install()
            .context("installing prometheus exporter")?;
        info!(%metrics_addr, "prometheus metrics endpoint online");
    }

    let backend = build_backend(&cfg.backend)
        .await
        .context("initializing HSM")?;
    let state = AppState::new(Arc::clone(&backend));
    let app = signing_service::router(state, cfg.max_body_bytes, cfg.request_timeout());

    let listener = TcpListener::bind(cfg.bind).await?;
    info!(local_addr = %listener.local_addr()?, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");
}
