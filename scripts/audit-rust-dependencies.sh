#!/usr/bin/env bash
# Audit the generator and the independently resolved dependencies of copied projects.
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

for tool in cargo; do
    command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done
cargo audit --version >/dev/null

temporary_root="$(mktemp -d)"
trap 'rm -rf "$temporary_root"' EXIT

audit_lockfile() {
    local lockfile="$1"
    if [[ ! -s "$lockfile" ]]; then
        echo "missing resolved lockfile: $lockfile" >&2
        exit 1
    fi
    cargo audit --file "$lockfile"
}

echo "Verifying committed Cargo.lock against the generator manifest"
# Temporary diagnostic: print the canonical lockfile so the repository can be fixed.
cargo generate-lockfile
if ! git diff --quiet -- Cargo.lock; then
    echo "PRIMARYKIT_GENERATED_LOCK_BEGIN"
    cat Cargo.lock
    echo "PRIMARYKIT_GENERATED_LOCK_END"
    echo "The committed generator Cargo.lock must be refreshed before a locked build" >&2
    exit 1
fi

echo "Auditing PrimaryKit generator workspace"
audit_lockfile "$repository_root/Cargo.lock"

echo "Generating basic Axum service with portable HTTP and RabbitMQ modules"
cargo run --locked -p primarykit -- new audit_basic --output "$temporary_root"
cargo run --locked -p primarykit -- add pagination --project "$temporary_root/audit_basic"
cargo run --locked -p primarykit -- add tasks --project "$temporary_root/audit_basic"
cargo generate-lockfile --manifest-path "$temporary_root/audit_basic/Cargo.toml"
audit_lockfile "$temporary_root/audit_basic/Cargo.lock"

echo "Generating PostgreSQL Axum service with all security-sensitive modules"
cargo run --locked -p primarykit -- new audit_postgres --template postgres --output "$temporary_root"
for module in audit permissions api_keys auth_http auth_smtp owned_records webhooks tasks; do
    cargo run --locked -p primarykit -- add "$module" --project "$temporary_root/audit_postgres"
done
cargo generate-lockfile --manifest-path "$temporary_root/audit_postgres/Cargo.toml"
audit_lockfile "$temporary_root/audit_postgres/Cargo.lock"

echo "All three Cargo.lock audits completed without reported vulnerabilities"
