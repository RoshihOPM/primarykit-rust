## What changed and why

<!-- Describe the smallest user-visible behavior change and its trade-offs. -->

## Safety / architecture checklist

- [ ] Read and followed `AGENTS.md` (SOLID/KISS/DRY/YAGNI where applicable)
- [ ] No unrelated refactoring or speculative abstraction
- [ ] Checked failure modes, permissions, data integrity and secrets
- [ ] No user-owned files overwritten or unsafe module-install side effects
- [ ] Migration / dependency compatibility assessed (if applicable)
- [ ] Tests added or updated for behavior and regressions

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo build --workspace --release`
- [ ] Freshly generated project and affected module(s) tested
- [ ] PostgreSQL integration tested when SQLx or migrations changed

Note any unchecked boxes and why. Do not merge into `dev` or `main` with
known failing required checks.
