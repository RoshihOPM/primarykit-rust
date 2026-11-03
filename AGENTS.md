# Engineering rules for AI agents

Applies to every change in this repository and to code copied from its templates.
This file is the **source of truth** for coding-agent instructions.
Read the relevant source, tests, workflow and docs **before** editing.

## Project contract

- PrimaryKit is a **copy-based generator**, not a runtime framework.
- Generated Axum projects must build, run and deploy **without** PrimaryKit installed.
- Preserve existing behavior unless the task explicitly changes the contract.
- Do not overwrite user-owned files. Validate filenames, destinations, symlinks,
  dependencies and provenance **before** writing. Never execute untrusted scripts
  as part of module installation.
- Keep `basic` free of mandatory PostgreSQL; restrict SQLx modules to compatible templates.
- Changes to the generator must be tested against a **freshly generated project**,
  not only the CLI workspace.
- Do not claim production readiness while authentication, authorization, migration
  strategy, or security review is incomplete.

## Clean code: SOLID, KISS, DRY, YAGNI

Apply these as **decision tools**, not as quotas for abstractions.

- **S — Single responsibility:** a module/function should have one clear reason
  to change. Separate parsing, business decisions, persistence and HTTP adapters
  where this improves clarity; do not create a layer for every function.
- **O — Open/closed:** introduce extension points for a demonstrated second
  implementation or variation, not hypothetical future requirements.
- **L — Liskov substitution:** implementations of the same trait must preserve
  documented invariants, failure behavior and authorization contracts.
- **I — Interface segregation:** keep traits small and consumer-focused. Avoid
  large service traits and broad public exports.
- **D — Dependency inversion:** depend on narrowly defined contracts at
  domain/infrastructure boundaries **when** this improves testability or
  substitution. Do not blanket every struct with traits or DI containers.
- **KISS:** prefer obvious control flow, explicit types, small modules and
  existing stable Rust crates. No custom ORM, async runtime or home-grown
  dependency-injection framework.
- **DRY:** centralize repeated *business rules and sources of truth*; duplicating
  a tiny implementation can be better than coupling unrelated modules.
- **YAGNI:** implement only the requested behavior. Avoid speculative
  configuration switches, generic repositories, feature flags and indirection.
- Favor meaningful names, cohesive functions, guard clauses, explicit failure
  cases and simple data flow. Comments explain **why**, not restate **what**.
- Avoid hard-coded production credentials, hidden side effects, magical
  defaults, global mutable state and unnecessary dependencies.
- Do not refactor unrelated code in feature PRs. If the smallest safe change
  still introduces complexity, document the trade-off.

## Rust and asynchronous execution

- Prefer safe Rust; any `unsafe` requires an isolated, documented invariant
  and explicit security review.
- Do not use `unwrap()`/`expect()` on request, worker or network paths.
  Test setup may use them when a failure is intentionally fatal.
- Use typed errors and map internal failures to **non-sensitive** public HTTP
  responses. Log operational context with `tracing`, never secrets or tokens.
- Use Tokio async I/O; offload blocking/CPU-heavy operations rather than
  blocking executor threads. Bound concurrency, timeouts, retries and queues.
- Limit memory growth: avoid unbounded buffering, spawning, caches and
  connection pools. Support graceful shutdown and cancellation.
- Prefer explicit validated configuration. Separate liveness from readiness:
  readiness should fail closed on required dependency failure.
- Verify object ownership, transaction lifetimes, cancellation and rollback
  behavior instead of merely silencing borrow-checker errors with `Arc`/`Mutex`.

## PostgreSQL, data integrity and security

- Parameterize SQL and validate untrusted input. Never interpolate user data
  into SQL identifiers or statements without strict allow-list validation.
- Keep multi-step business changes and their audit records in **one** transaction.
  Design for retries, idempotency and concurrent updates, not only happy paths.
- Version and commit migrations; use expand/contract for breaking schema
  changes and explicitly assess locks, indexes, backfills and rollback plans.
- Review query plans and indexes for endpoints that read growing datasets.
  Pagination must have deterministic ordering and bounded limits.
- Enforce least privilege and deny-by-default permissions. Authentication is
  **not** authorization; check object/tenant ownership on every sensitive path.
- Use reputable password hashing/key management and constant-time comparisons
  where appropriate. Never store tokens, passwords or API keys in plaintext.
- Set safe defaults for file uploads, deserialization, webhook signatures,
  replay windows, rate limits and request body limits when those features exist.

## Module catalog and generation

- Modules are portable, opt-in and independently testable; prefer minimal
  dependencies and avoid coupling to CLI internals.
- Declare dependencies, compatibility and generated files explicitly.
- Treat provenance as metadata, **not** a cryptographic guarantee.
- Reject existing targets rather than overwriting. Verify that generated Rust
  modules are registered and compile in both supported templates as applicable.
- Document runtime and database side effects, permissions and migrations.
- Prefer idempotent behavior where possible; document operations that are not
  crash-atomic. Avoid claiming transactionality across filesystem writes.

## Testing and pull-request workflow

1. Inspect existing patterns, history, the issue/PR and relevant CI checks.
2. Plan the smallest coherent change; specify invariants and failure modes.
3. Add focused unit tests plus integration/regression tests for the affected
   contract, including invalid inputs and concurrent/transactional behavior.
4. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets
   --all-features -- -D warnings`, `cargo test --workspace --all-features`
   and `cargo build --workspace --release`.
5. **Also** generate a fresh `basic` or `postgres` app as appropriate,
   install affected modules, then run its fmt, Clippy, tests and build. Test
   PostgreSQL-specific behavior against real PostgreSQL in CI.
6. Open a focused feature PR targeting `dev`. Merge only after required checks
   succeed; promote tested code from `dev` to protected `main` through a PR.
   Do not bypass protections, force-push protected branches or rewrite history.
7. Report precisely what was changed, what actually ran, and what remains
   untested. A passing compiler alone does not prove correctness.

## Reviews and agent collaboration

- Check: correctness, behavior regressions, tenant/data isolation,
  authorization, SQL transactionality, memory bounds, failure recovery and
  observable errors before aesthetics.
- Treat code produced by other agents as untrusted until reviewed and tested.
- If another PR or agent owns a file, avoid overlapping edits and re-check
  branch heads immediately before pushing. Never silently discard others' work.
- When requirements conflict, prefer safety, backwards compatibility and
  explicit documentation over speculative cleverness.
