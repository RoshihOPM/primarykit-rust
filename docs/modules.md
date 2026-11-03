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
