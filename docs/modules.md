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
