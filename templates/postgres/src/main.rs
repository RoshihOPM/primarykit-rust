use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde::Serialize;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{net::SocketAddr, time::Duration};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: env!("CARGO_PKG_NAME"),
    })
}

async fn readiness(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let result = sqlx::query_scalar::<_, i64>("SELECT 1::BIGINT")
        .fetch_one(&state.pool)
        .await;

    let (code, status) = match result {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(error) => {
            tracing::warn!(%error, "readiness check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
    };

    (
        code,
        Json(HealthResponse {
            status,
            service: env!("CARGO_PKG_NAME"),
        }),
    )
}

fn app(pool: PgPool) -> Router {
    Router::new()
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        .with_state(AppState { pool })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let database_url = std::env::var("DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await?;
    sqlx::migrate!().run(&pool).await?;

    let address = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8000".to_owned());
    let address: SocketAddr = address.parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "HTTP server listening");

    axum::serve(listener, app(pool))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn lazy_pool() -> PgPool {
        PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(250))
            .connect_lazy("postgres://test:test@127.0.0.1:1/unreachable")
            .expect("valid connection URL")
    }

    async fn get_status(router: Router, uri: &str) -> StatusCode {
        router
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response")
            .status()
    }

    #[tokio::test]
    async fn liveness_does_not_require_the_database() {
        assert_eq!(
            get_status(app(lazy_pool()), "/health/live").await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn readiness_fails_closed_when_database_is_unavailable() {
        assert_eq!(
            get_status(app(lazy_pool()), "/health/ready").await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn migrations_and_readiness_work_with_postgres() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("postgres accessible");
        sqlx::migrate!().run(&pool).await.expect("apply migrations");

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::BIGINT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'examples'",
        )
        .fetch_one(&pool)
        .await
        .expect("verify migration");
        assert_eq!(count, 1);
        assert_eq!(get_status(app(pool), "/health/ready").await, StatusCode::OK);
    }
}
