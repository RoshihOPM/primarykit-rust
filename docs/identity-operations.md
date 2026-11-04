# Identity-mail worker and ingress operations

These instructions apply only after installing the optional `auth_smtp`
module in a PostgreSQL/Axum project. They are **deployment examples**, not
automatically started infrastructure.

## 1. Secrets and configuration

Supply these secrets at runtime via your deployment secret manager (not
Dockerfile, git, a shared .env.example, or process logs):

- `SMTP_RELAY_HOST`: SMTP domain offering certificate-verified TLS on port 465
- `SMTP_USERNAME` and `SMTP_PASSWORD`: SMTP credentials, not user passwords
- `SMTP_FROM`: verified sender mailbox (for example `no-reply@example.org`)
- `IDENTITY_PUBLIC_ORIGIN`: origin such as `https://app.example.org/`
- `IDENTITY_OUTBOX_KEY_HEX`: active key, 64 hex digits representing 32 random bytes
- `IDENTITY_OUTBOX_KEY_ID`: active key identifier (defaults to `legacy` for migration)
- `IDENTITY_OUTBOX_PREVIOUS_KEYS`: optional comma-separated `ID=64hex` entries, decrypt-only
- `DATABASE_URL`: PostgreSQL DSN with least privileges

A reset/verification email links to `/reset-password` or `/verify-email`
respectively. Your frontend must implement these routes and remove URL
fragments immediately after extracting a token, then POST to the backend.

## 2. Worker process

Create a small `src/bin/identity_mail_worker.rs` in the generated project.
Replace `db_api` with the generated crate name:

```rust
use db_api::modules::{
    auth_http::identity_outbox,
    auth_smtp::{outbox_keys_from_env, SmtpConfig},
};
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use tokio::sync::watch;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&std::env::var("DATABASE_URL")?)
        .await?;
    let sender = SmtpConfig::from_env()?.delivery()?;
    let keys = outbox_keys_from_env()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let work = tokio::spawn(identity_outbox::run_worker(
        pool, keys, sender, shutdown_rx,
    ));

    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(true);
    work.await?;
    Ok(())
}
```

Provision the SMTP sender account and DNS authentication (SPF/DKIM/DMARC)
with the provider; no external mail account is created by PrimaryKit.
Do not point CLI tests at a production PostgreSQL instance.

Deploy this binary as a **separate container/service** from the API. Run at
least one replica and supervise it with your process manager. Add startup,
termination and restart policies. Keep its PostgreSQL pool small and monitor
queue latency; a duplicate delivery after a crash is possible.

## 3. Secure edge rate limiting (Nginx)

Place the following zone definition in Nginx `http` context (not inside
`server`):

```nginx
limit_req_zone $binary_remote_addr zone=identity_per_ip:10m rate=10r/m;
```

Inside the existing TLS `server` block:

```nginx
location ^~ /auth/ {
    limit_req zone=identity_per_ip burst=10 nodelay;
    limit_req_status 429;
    client_max_body_size 4k;
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Test with `nginx -t` and deploy only after validation. The example assumes
Nginx is the **public entrypoint** and directly sees the real client IP.
If behind a CDN/LB, configure `set_real_ip_from` **only for trusted proxy
CIDRs** and the correct real IP header; never trust arbitrary
`X-Forwarded-For` from internet clients. Adjust limits based on actual
shared-NAT traffic and bot load. PostgreSQL's identity limiter remains a
second defense against credential brute-forcing across IPs.

## 4. Monitoring and runbooks

Poll `identity_outbox::stats(pool)` from a secured metrics exporter
(periodically, not per HTTP request), and alert on:

- dead-letter count increasing
- oldest pending message age exceeding the expected delivery SLA
- growing pending backlog with no successful SMTP deliveries
- failed PostgreSQL connections and exhausted worker pools

For a lost key, queued encrypted tokens cannot be recovered. The outbox now
supports key-versioned messages and previous-key decryption; follow the
rollout and rollback steps in `docs/identity-key-rotation.md`.
Never discard an old key while `encrypted_pending_for_key` is nonzero. Restrict direct database read access to the outbox:
encrypted mail tokens are sensitive even though ciphertext is authenticated.

Run an independent security review before enabling public registration,
including account enumeration/timing, request limits, session storage,
CSRF/client token handling, email template UX, and reset abuse.
