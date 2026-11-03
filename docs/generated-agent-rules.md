# AI agent instructions for this generated Axum project

This project is **independent** from PrimaryKit Rust. The source code belongs
to this application; keep changes small, explicit and reviewable.

## Required approach

- **SOLID:** separate transport, business rules and infrastructure; use
  composition and narrow traits only when they provide real value.
- **KISS:** a direct function is better than a new architecture for one case.
- **DRY:** centralize meaningful invariants; avoid abstracting incidental
  repetition. **YAGNI:** implement only demonstrated requirements.
- **Clean Code:** accurate domain names, small cohesive functions, explicit
  inputs/outputs, no implicit mutation or misleading comments.
- Prefer safe Rust, typed `Result` errors, `serde` for validated boundaries,
  and structured `tracing` without secrets. Avoid `unwrap`/`expect` in
  production request paths and never panic for expected client errors.
- Respect async execution: no blocking I/O on Tokio workers, bound concurrent
  work and pools, use timeouts for external calls, support shutdown.
- Favor parameterized SQL and transactions for business invariants; never
  rewrite an already-applied migration. Handle conflicts and retries explicitly.
- Keep HTTP handlers thin, authorize on the server, validate all untrusted
  inputs, and avoid leaking internal implementation details in API errors.
- Generated modules in `src/modules` are opt-in libraries, not automatically
  installed routes; preserve registration/provenance and user-written code.
- Do not add Kubernetes, a new ORM, or elaborate dependency injection without
  demonstrated operational need. Do not commit secrets or production fixtures.

## Before opening a PR

1. Explain the change, risks, trade-offs and backward compatibility.
2. Add tests for the happy path, invalid input, failures and concurrency
   where relevant. PostgreSQL integrations must have real database tests.
3. Run `cargo fmt --all -- --check`,
   `cargo clippy --all-targets -- -D warnings`, `cargo test`, and
   `cargo build --release`. Inspect failures, not just exit codes.
4. Update README and migrations when behavior or data contracts change.
5. Do not claim production readiness without security and operational review.
