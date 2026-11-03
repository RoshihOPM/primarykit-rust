# Agent instructions — PrimaryKit Rust

These instructions apply to the entire repository. Read them before editing.
The project's purpose is to **generate independent, maintainable Rust/Axum
services**, not to build an opaque framework or a service tied to PrimaryKit.

## Priorities (in order)

1. Correctness and security, including existing data and user-written code.
2. Backward compatibility of CLI commands and generated applications.
3. Clarity, testability, and long-term maintenance.
4. Predictable resource usage and performance, demonstrated by measurements.
5. Convenience and brevity.

## Engineering principles

- **SOLID, pragmatically:** one responsibility per module; separate I/O, domain
  decisions, persistence and transport; depend on narrow, explicit contracts.
  Introduce traits for meaningful substitutions or tests, **not** an interface
  for every struct. Prefer composition over inheritance-like abstractions.
- **KISS:** choose the smallest explicit design that satisfies the requirement.
  Prefer familiar Rust/std/Tokio/SQLx patterns to custom runtimes or frameworks.
- **DRY:** deduplicate stable domain rules and invariants, **not** every similar
  line. A little repetition is preferable to premature generic abstractions.
- **YAGNI:** do not add future-oriented layers, configuration, macros or
  dependencies without a concrete current use case.
- **Clean Code:** descriptive names, cohesive short functions, explicit inputs,
  no surprising side effects, consistent error boundaries. Comments should
  explain intent and trade-offs rather than narrate obvious code.

## Rust and async rules

- Prefer safe Rust; `unsafe` requires documented invariants and human review.
- Do not suppress errors with `unwrap`, `expect`, broad catches, or ignored
  results in request paths. Test-only `expect` is acceptable.
- Prefer typed errors and `Result`; do not leak secrets or internal SQL errors
  in public HTTP responses. Use structured, redacted `tracing`.
- Never hold a std::sync mutex guard or a database transaction across
  unrelated `.await` operations. Avoid blocking work on Tokio worker threads.
- Apply explicit timeouts, connection-pool bounds and graceful shutdown for
  externally dependent services; benchmark before tuning.
- Keep generated code idiomatic and compilable without the generator installed.

## Generator, module and database constraints

- `primarykit new` must not overwrite existing directories.
- `primarykit add` must refuse unknown/incompatible modules, path traversal,
  symlink redirection and collisions with user files. Preserve user-written
  code outside clearly marked managed regions.
- Modules must be independent, have explicit dependencies, and not secretly
  register HTTP routes, launch tasks or run database migrations.
- Do not edit already-applied SQL migrations. Add new versioned migrations.
- Keep business changes and audit/outbox writes in the same transaction when
  they must succeed atomically. Define the isolation and locking strategy for
  concurrent mutations; demonstrate idempotency where relevant.
- Assume all request data, external file contents and connector outputs are
  untrusted. Validate at boundaries; use parameterized SQL.
- Never commit credentials, access tokens or real customer data.

## Work and review process

1. Inspect current code, tests, contracts and relevant docs before editing.
2. Implement the smallest coherent change, including failure cases and tests.
3. Verify the **generator and a generated project**; for PostgreSQL modules
   verify against real PostgreSQL in CI, not only mocks.
4. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets
   --all-features -- -D warnings`, `cargo test --workspace --all-features`
   and build checks. For generated projects, run their own commands too.
5. Add a regression test for every bug fix. Document behavior, limitations and
   migration or rollout steps for any public change.
6. Use feature branch -> PR -> green CI -> `dev`; promote to protected `main`
   only after separate successful release verification. Never force push or
   claim checks passed without inspecting their results.

## Definition of done

- Compatible CLI behavior and no silent mutation of user code.
- Security and failure paths tested; generated service compiles and tests.
- Lint, format, unit and relevant integration checks green in GitHub Actions.
- README and module documentation accurate, including limitations.
- No speculative abstractions, unchecked dependencies or unfinished stubs
  advertised as production-ready.
