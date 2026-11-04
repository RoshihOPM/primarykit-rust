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
