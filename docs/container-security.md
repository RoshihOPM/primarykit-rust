# Generated container image security

PrimaryKit copies independent Rust/Axum projects. The generator itself is not
deployed in those services. Protect the **actual final runtime image**, not only
the source workspace or the Rust builder stage.

## Continuous verification

`.github/workflows/container-security.yml` independently generates the basic
and PostgreSQL templates, resolves each application's own Cargo.lock, builds
the corresponding Dockerfile, checks the runtime UID/GID `65532:65532`,
smoke-tests the actual container with `/health/ready` (including a temporary
PostgreSQL service for the database template), then runs Trivy against the
local **final image**. It blocks the job on
reported HIGH or CRITICAL vulnerabilities in OS packages or detectable
libraries. There are no vulnerability ignore lists and scan errors fail the
check. The workflow runs for PRs, both mainline branches, on Monday, and on
manual dispatch. It has read-only GitHub permissions; no images are pushed.

The final stage uses Debian 13 Distroless `base-nossl`, not a full
Debian userland. Its lack of a shell and package manager reduces installed
packages and attack surface. TLS trust roots are present, but applications
needing extra shared libraries, shell scripts or non-Rust TLS must explicitly
review and test their runtime dependencies. Never use the Distroless debug
variant for the production image.

The scanner does not inspect the builder-stage image or cover secrets,
runtime authorization, app-specific dependencies, ingress, DB privileges,
deployment configuration or runtime behavior. It does not prove that every
existing generated project is secure. The separate RustSec workflow covers
dependency advisories for generated projects with opt-in modules.

## Reproducible generated builds

For each generated project:

1. After adding modules, resolve `Cargo.lock` in the **generated project**,
   review it, and commit it with the project. The generator never uses its own
   lockfile for that project.
2. The template Dockerfiles copy `Cargo.toml` and `Cargo.lock` and build
   with `cargo build --locked --release`. Building without a lockfile or with
   a stale lockfile fails closed. Create or update it intentionally before
   building the container.
3. Pin the Rust builder and final runtime base images to **reviewed digests**
   in each deployed application's Dockerfile, not mutable tags. Keep digests
   updated deliberately after an image scan. The starter template's base tags
   are intentionally not presented as fully reproducible production pins.
4. Run the application's own RustSec audit, Trivy image scan and release
   tests for its precise source revision, feature set and target platform.
   Scan the deployed digest for the platform used by the cluster or VPS.
5. Deploy by immutable image digest and keep software bill of materials,
   lockfile, git revision, CI provenance and deployment log together. Sign
   images and verify signatures if the deployment environment supports it.

## Failure response

On a HIGH/CRITICAL finding, identify the package, affected image layer,
whether a patched base or direct dependency exists, and actual runtime
exposure. Prefer rebuilding against a patched base or upgrading dependencies.
For an unfixed vulnerability, keep the gate red until there is a documented
owner, review deadline and mitigation; do not silently use
`continue-on-error`, global ignore rules or disable the scanner.

See [dependency security](dependency-security.md) for RustSec advisory
handling and [roadmap issue #4](https://github.com/RoshihOPM/primarykit-rust/issues/4)
for release-hardening tasks. Enforcing the image scan as a mandatory branch
check requires a separate successful-run review and Ruleset administrator
configuration (issue #19).
