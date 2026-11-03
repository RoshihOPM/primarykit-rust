# Engineering rules for AI coding agents

This is a standalone Rust/Axum application created by PrimaryKit.
The generator is not installed at runtime. These rules apply when changing
its API handlers, database code, background tasks and dependencies.

## Clean code and architecture

- **SOLID:** give modules cohesive responsibilities, keep public contracts small,
  honor trait invariants, and introduce abstractions only for real variation
  or testability. Do not build layers or traits for every function.
- **KISS:** choose the smallest clear implementation and familiar Rust crates;
  avoid custom frameworks, an ORM replacement, or gratuitous indirection.
- **DRY:** consolidate repeated business knowledge, validation and permission
  rules. Do not couple unrelated modules merely to deduplicate a few lines.
- **YAGNI:** implement current requirements; no speculative feature flags,
  generic repositories or configuration systems.
- Prefer readable names, explicit errors, guard clauses and focused tests.
  Comment why a design exists, not what each line does.

## Rust / Axum / Tokio

- Prefer safe Rust; do not introduce `unsafe` without a documented invariant
  and dedicated review.
- Avoid `unwrap` or `expect` in user-facing, background-worker and network
  paths. Map internal errors to safe, stable HTTP responses.
- Use async I/O; do not block Tokio executor threads. Bound parallel tasks,
  timeouts, queues, request sizes and connection pools.
- Use structured tracing without secrets, tokens, passwords or personal data.
- Keep liveness separate from readiness, and fail readiness closed if required
  dependencies are unavailable. Handle graceful shutdown.

## Database / security

- Validate untrusted input; always parameterize queries.
- Keep business changes and corresponding audit writes in one transaction.
- Protect against concurrent updates, retry duplication and lost updates.
  Use idempotency where required.
- Review migrations for long locks, index costs, backfills and backwards
  compatibility. Never run destructive changes against production blindly.
- Authentication is not authorization. Deny by default, verify object/tenant
  ownership, and use established password hashing/crypto libraries.
- Do not embed production credentials in code, migrations or Docker images.

## Required checks

Before proposing a PR, run:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- `cargo build --release`

For SQLx or migration changes, test with a real PostgreSQL instance, including
rollback/error paths. Add regression tests for every bug fix. Do not claim
checks passed unless they were actually run; report limitations and risks.

Keep changes scoped, preserve generated code ownership, and never overwrite
unrelated user files or disable failing CI checks to force a merge.
