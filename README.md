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

## Portable modules

PrimaryKit keeps the generated service independent from the generator.

    cargo run -p primarykit -- modules
    cargo run -p primarykit -- add pagination --project ./inventory_api
    cargo run -p primarykit -- add audit --project ./inventory_api
    cargo run -p primarykit -- add permissions --project ./inventory_api

The second command installs both pagination and its api_errors dependency.
The audit module requires a project created with --template postgres.
To run the PostgreSQL audit migration, execute the service's usual migration
workflow. Dependencies are resolved automatically, existing files are never
overwritten, and the generator tracks installed modules in primarykit-origin.json.

Modules are compiled as public library exports (src/modules). They are not
implicitly attached to HTTP routes: use the exports explicitly from your
business handlers. In particular, audit.record must be called using the
same SQLx transaction as the audited business operation. For details, see
[Module documentation](docs/modules.md).

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
migrations, and database readiness. The initial module catalog includes api_errors,
pagination and transaction-scoped audit events. The optional postgres
template can install `auth` (Argon2id and revocable sessions) and
`permissions` (tenant-scoped RBAC). Login endpoints, recovery, rate limiting,
API keys, queues and comprehensive security hardening are NOT implemented yet.

## Design principles

- Copy code into independent projects; avoid hidden runtime dependencies.
- Fail closed on invalid project names, and never overwrite a target project.
- Prefer small, independently tested modules over a custom framework.
- Use CI and integration tests before claiming production readiness.

## Contributing with AI agents

Coding agents must follow [AGENTS.md](AGENTS.md): SOLID, KISS, DRY and YAGNI
are practical guidelines, together with explicit Rust, security, PostgreSQL
and CI requirements. The same policy is linked from Claude and Copilot
instructions. Every change must pass tests on the generated project.
