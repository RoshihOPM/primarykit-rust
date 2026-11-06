# Dependency review and reproducible builds

PrimaryKit emits **independent** Axum services. A clean generator build does
not prove that every generated application's dependencies are secure.

## Update policy

- Dependabot opens weekly Cargo and GitHub Actions update PRs **against `dev`**.
  Updates are reviewed and merged through the normal PR process; no automatic
  merges, branch-protection bypasses, or direct pushes to `main`.
- Validate changes using the two Rust CI jobs, including a freshly generated
  basic service and a PostgreSQL service with migrations.
- Inspect release notes and breaking changes, especially for SQLx, Axum,
  authentication, AMQP/TLS, cryptography, and GitHub Actions.
- The generator's `Cargo.lock` covers its workspace. Copied templates live
  outside that lockfile and have their own dependency resolution. Dependabot
  does **not** update dependencies embedded in copied template manifests or
  module catalog strings; maintainers must review those sources separately.

## Automated RustSec checks

The `.github/workflows/security.yml` workflow runs on pull requests, on
pushes to `dev`/`main`, nightly and on manual dispatch. It installs a
checksum-verified `cargo-audit` binary and executes
`scripts/audit-rust-dependencies.sh`. The script audits three **independent**
resolved dependency graphs:

1. The checked-in generator workspace `Cargo.lock`.
2. A freshly generated basic Axum project with pagination and RabbitMQ tasks.
3. A freshly generated PostgreSQL project with audit, auth, API keys, HTTP
   identity, SMTP, tenant records, webhooks and tasks.

Each generated application receives its own temporary `Cargo.lock` via
`cargo generate-lockfile` before `cargo audit --file`. The temporary
lockfiles are **not release lockfiles** for already deployed applications.
An advisory or an inability to complete an audit fails the workflow, except
for the single documented, **runtime-graph-guarded** finding described below.
Never mark a failing scan green with `continue-on-error`. Investigate and
upgrade affected dependencies, including version ranges in copied manifests
and module catalog entries. No undocumented global ignore list is permitted.

### Tracked SQLx lockfile exception — issue #44

**RUSTSEC-2023-0071** (RSA Marvin timing sidechannel, no patched release as
of 2026-11-06) appears in the PostgreSQL generated project's lockfile through
SQLx's optional `sqlx-mysql` package. The generated service explicitly enables
only PostgreSQL; its selected feature graph has **no active `rsa`** package.
Because `cargo audit` scans all resolved lockfile entries, including optional
packages, the single advisory is suppressed **only for that PostgreSQL
lockfile**, and only after `cargo tree --target all` proves no RSA is active
and `sqlx-mysql` is present. The generator and basic app have **no exception**;
any other advisory or tool failure blocks the workflow.

Owner: PrimaryKit maintainers. **Reassess by 2027-01-31**, or immediately if
SQLx/RSA changes. The exception must be removed if RSA becomes active or the
unused dependency is removed from the lockfile. Enabling MySQL or RSA in a
generated deployment invalidates this decision. Track remediation and the
proposed removal in [issue #44](https://github.com/RoshihOPM/primarykit-rust/issues/44).
This scoped exception does not constitute a fix for the RSA vulnerability.

RustSec checks known Rust crate advisories, **not** container OS packages,
secrets, infrastructure, or exploitability of application logic. Continue
scanning built images and deployed applications' committed lockfiles in their
own deployment pipelines. The security workflow is separate from the two
preexisting Rust CI jobs; add its exact check to the protected `main` ruleset
only once it is consistently green (issue #19).

## Deploying generated applications

1. Generate the service, install the required modules, then resolve and commit
   that **application's own** `Cargo.lock`.
2. Build/test with `cargo build --locked` and `cargo test --locked` (for
   example in CI and image builds) to prevent silent dependency drift.
3. Run a vulnerability review of both the generator and the generated app's
   dependency tree (for example, RustSec `cargo audit`) before release and
   after security advisories. Review and triage results; a passing compilation
   or Dependabot PR is **not** a security audit.
4. Pin base container images by digest for reproducible deployment, scan the
   final images, and publish the exact source revision and lockfile used.
   Registry signatures, image scans and provenance attestations are **not**
   currently guaranteed by PrimaryKit and must be provided by deployment CI.

Do not treat this policy as completion of production security controls.
Issue #19 tracks mandatory branch status checks; issue #4 tracks security,
benchmarking and release readiness.
