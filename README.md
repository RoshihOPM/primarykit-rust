# PrimaryKit Rust

Copy-based generator of independent Rust/Axum HTTP services. The generated project
has no runtime dependency on the generator.

## Quick start

    cargo run -p primarykit -- new inventory_api
    cd inventory_api
    cargo run

For a PostgreSQL-enabled service instead:

    cargo run -p primarykit -- new inventory_api --template postgres

The command creates inventory_api in the current directory. Use
--output <directory> to select a parent directory. Existing directories
are never overwritten.

Try GET /health/live or GET /health/ready on port 8000.

## Development

    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace --all-features
    cargo build --workspace --release

GitHub Actions verifies the CLI and also generates, lints, tests and compiles
a fresh Axum project. The starter provides basic liveness, readiness, tracing,
graceful shutdown, and a non-root Docker runtime.

## Project status

Early bootstrap. The optional postgres template includes PostgreSQL, SQLx
migrations, and database readiness. Authentication,
audit history, API keys, queues, module registry, and security checks are
planned but are NOT implemented yet.

## Design principles

- Copy code into independent projects; avoid hidden runtime dependencies.
- Fail closed on invalid project names, and never overwrite a target project.
- Prefer small, independently tested modules over a custom framework.
- Use CI and integration tests before claiming production readiness.
