# PrimaryKit Rust portable modules

Modules are copied into the target project under src/modules and registered
as public library exports. Generated projects are independent from PrimaryKit.

## Commands

    cargo run -p primarykit -- modules
    cargo run -p primarykit -- add api_errors --project ./inventory_api
    cargo run -p primarykit -- add pagination --project ./inventory_api
    cargo run -p primarykit -- add audit --project ./db_api

Dependencies are resolved automatically. Installing pagination also installs
api_errors. audit is only valid with the PostgreSQL template.

## Module inventory

| Module | Template | Dependencies | Functionality |
|---|---|---|---|
| api_errors | basic / postgres | none | Typed safe JSON HTTP error responses |
| pagination | basic / postgres | api_errors | Validated page/per_page and SQL offsets |
| audit | postgres | none | Transactional PostgreSQL audit event writer and migration |
| auth | postgres | none | Argon2id passwords, opaque revocable/rotating sessions |
| permissions | postgres | auth | Tenant-scoped deny-by-default RBAC |
| auth_http | postgres | auth | Identity API with encrypted transactional outbox |
| auth_smtp | postgres | auth_http | TLS-only SMTP delivery callback |
| owned_records | postgres | permissions | Tenant and owner-aware SQL access |

In a generated application's Rust code, import items through the library
crate's public modules, for example:

    use inventory_api::modules::pagination::Pagination;
    use inventory_api::modules::api_errors::ApiError;

The installer does not inject HTTP routes or run arbitrary module scripts.
Applications wire exported functions into their own business logic.

For the audit module, business changes and audit writes must share an SQLx
transaction. Run the SQLx migrations before using audit, and commit only
when both writes succeed. The migration includes an index for resource
history. The schema does NOT prevent privileged SQL users from updating
or deleting rows: immutable storage requires separate database privileges,
policies and retention design.

## Safety policy

- Only catalog modules may be installed; no remote template code is fetched.
- Reject incompatible templates, unknown modules, edited registration blocks,
  modified provenance schemas, and pre-existing destination files.
- Preserve user code outside the managed module-registration markers.
- Resolve dependencies before changing any files; avoid partial installs
  for standard errors.
- No arbitrary replacement of application files or migrations.
- Installation is not fully crash-atomic; if a process is interrupted during
  a write, inspect and reconcile the project before retrying.
- Generator provenance is local metadata, not a cryptographic attestation.

For production systems, security review and integration testing are required
before deploying generated modules.


## Authentication and authorization (initial modules)

    cargo run -p primarykit -- add permissions --project ./db_api

Installs both \`auth\` and \`permissions\`, their migrations and module-local
dependencies in the generated project's managed Cargo dependency block.
Old projects without this block must be migrated deliberately: the installer
refuses to edit an unmarked Cargo manifest.

The \`auth\` module supplies Argon2id password hashing/verification and 256-bit
random, opaque sessions (only SHA-256 token digests are stored). Sessions are
revocable, expire in PostgreSQL and can be rotated in a single transaction.
Password verification must run via \`tokio::task::spawn_blocking\`, with throttling
and consistent error handling on login attempts. Raw tokens are secrets: never
include them in logs, URLs or analytics.

The \`permissions\` module checks a user's ACTIVE status and explicit role
assignments in a specific tenant. A missing role or permission denies access,
and database errors must never be converted into allow decisions. The caller
must derive the tenant scope from trusted resource data and additionally
constrain business queries by tenant and object identifiers.

These are **code modules**, not a complete identity product. This release
does not supply login/register HTTP endpoints, recovery, MFA, tenant provisioning,
distributed rate limiting, cleanup workers or a full account-management UI.
Review the business flow and threat model before exposing authentication publicly.

For RBAC, `has_permission` accepts an `AuthenticatedUser` obtained from
`auth::authenticate_session`, not an arbitrary user ID. The principal's
identity field cannot be initialized from outside the auth module. After
authentication, business queries still need to enforce actual tenant and
resource ownership. Sessions must be revalidated for each incoming request.


## Optional HTTP identity flows

Install the portable Axum module in a PostgreSQL project:

    primarykit add auth_http --project ./db_api

It depends on \`auth\` and exposes an **opt-in** router. You must construct an
\`auth_http::IdentityState\` with a PostgreSQL pool and a \`TokenDelivery\`
callback, then merge \`auth_http::routes(state)\` into the app router.
No routes are exposed automatically by the generator.

Routes: POST /auth/register, /auth/verify-email, /auth/login,
/auth/logout, /auth/me, /auth/password-reset/request,
/auth/password-reset/confirm. Only verification activates a new user.
Password reset revokes all active sessions. Tokens for verification and
password reset are 256-bit opaque secrets, hashed in PostgreSQL and single-use.
No token is included in a public verification/reset-request response.
The host application's token delivery callback must construct a trusted HTTPS
URL and send email; the module does not bundle SMTP credentials or a mail worker.

The database-backed identity limiter allows five attempts per 15-minute
window per normalized email and operation. **It is not an edge/IP limiter.**
In production use TLS and additional per-IP/network limits at an ingress
or reverse proxy. Do not trust spoofable X-Forwarded-For headers without
explicit proxy trust configuration. Password hashing/verification is moved
to Tokio's blocking thread pool. Keep its concurrency bounded by operational
policy to avoid CPU and memory exhaustion.

Identity emails are committed to an encrypted PostgreSQL transactional outbox
at the same time as the one-time token. Delivery happens **after commit**, not
inside HTTP requests. The generated project's IdentityState requires an
\`outbox_key: Arc<[u8; 32]>\` loaded from a deployment secret manager. Use
independently generated random 32-byte keys (never hard-code test keys in
production); share them with all HTTP replicas and delivery workers. Keys
are not stored in PostgreSQL. Draining pending messages or implementing
dual-key decryption is necessary before rotating an existing key.

Run \`auth_http::identity_outbox::run_worker(pool, key, deliver, shutdown)\` as
a separate long-lived Tokio task/process. The callback is still provided
by the host application and must send the mail with a trusted HTTPS reset/
verify URL and bounded network timeouts. The queue uses row leases with
\`FOR UPDATE SKIP LOCKED\`, bounded exponential retries and dead-letter
states. **Delivery is at least once:** if a worker crashes after the provider
accepted an email but before acknowledgement, the email can be delivered
again. The provider integration should support idempotency where available.
After successful delivery the encrypted token payload is erased from its
outbox row; the one-time token hash remains until retention cleanup.

The worker also invokes \`cleanup_once\` to remove stale counters, expired
tokens, and old sessions in bounded batches. Monitor dead rows, lag, retry
counts, missing email deliveries, and key validity.

This module remains **not fully production-ready**: configure TLS, network
edge/IP rate limiting, email retry policies, operational alerts and a threat
model before exposing it publicly.

## Example object-level authorization

Install \`owned_records\` in a PostgreSQL service. It also installs
\`auth\` and \`permissions\`.

    primarykit add owned_records --project ./db_api

The module supplies an example \`owned_records\` table and typed Rust
functions \`get(pool, validated_principal, id)\` and
\`update(pool, validated_principal, id, body)\`.

It deliberately derives the tenant from the **stored resource**, not an
untrusted tenant header. Both actions enforce user activation, explicit
tenant RBAC grants and resource ownership in the **same SQL statement**.
Missing resources, wrong owners and denied grants all return absence or
false to avoid exposing cross-tenant existence. Integration tests exercise
legitimate access, intruders in the same tenant, missing write permission
and deactivated users.

This is a reference implementation: real applications must embed equivalent
predicates into their own domain queries and decide whether a role grants
access beyond the owner. Do not treat a separate \`has_permission\` call
followed by an unguarded resource update as safe.


### Memory and password-reset concurrency

Argon2 password operations are bounded to four concurrent blocking workers
per server process. Workers retain semaphore permits until hashing completes,
even when HTTP requests are cancelled. Deploy independent network-edge
throttling and measure queue latency before exposing login publicly.

After verifying a password, session creation rechecks the exact verified
password hash under a PostgreSQL row lock. A concurrent password reset either
revokes the newly committed session or changes the password first, preventing
issuance of a session using superseded credentials.

## Production SMTP adapter

Install `auth_smtp` into an Axum/PostgreSQL project to add an optional
TLS-only SMTP provider callback compatible with the transactional identity
outbox:

    primarykit add auth_smtp --project ./db_api

Configure `SMTP_RELAY_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
`SMTP_FROM`, `IDENTITY_PUBLIC_ORIGIN` (HTTPS origin without a path), and
`IDENTITY_OUTBOX_KEY_HEX` (a separately generated 32-byte key encoded as
64 hexadecimal characters; never commit this secret). The adapter requires
SMTP TLS via certificate-verified SMTPS on port 465. No plaintext or
opportunistic SMTP downgrade is permitted.

Call `auth_smtp::SmtpConfig::from_env()?.delivery()?` to construct the
`TokenDelivery` callback. Call `auth_smtp::outbox_key_from_env()?` to
load the encryption key. Pass both to `auth_http::IdentityState` for
HTTP routes and to `auth_http::identity_outbox::run_worker` in a **separate
long-running worker process**. Do not run the worker as part of each request.

The email contains a verification or reset link with the token in the URL
**fragment**, not the HTTP query string. Your frontend must read that fragment,
POST the token to `/auth/verify-email` or
`/auth/password-reset/confirm`, then immediately clear it from browser
history. Do not log the full URL or leak it to third-party scripts.

Run one to a few worker replicas initially; the PostgreSQL leases avoid
simultaneous claims. Delivery is at-least-once: if the SMTP server accepts a
message and the worker crashes before acknowledgement, it might be delivered
again. Test how your provider handles this and keep the mail content
idempotent.

`identity_outbox::stats(pool)` reports queued, due, dead-letter counts and
oldest pending age. Monitor them in an authenticated operations service;
alert on increasing dead letters or delivery age beyond expected latency.
`identity_outbox::cleanup_once` scrubs expired/used pending secrets and
purges old metadata in bounded batches. Pending encrypted messages must be
drained (or a dual-key reader added) **before rotating**
`IDENTITY_OUTBOX_KEY_HEX`.

See `docs/identity-operations.md` for a worker integration example and
Nginx ingress rules. SMTP provider credentials must be provisioned separately;
this adapter never registers with or configures an external provider.
