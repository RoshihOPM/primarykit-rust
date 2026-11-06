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

echo "Verifying generator lockfile is current without modifying it"
cargo metadata --locked --no-deps --format-version=1 >/dev/null

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

# SQLx resolves the unused sqlx-mysql -> rsa package in Cargo.lock even when
# the project uses only PostgreSQL. RUSTSEC-2023-0071 has no patched release.
# The narrow exception below is ONLY permitted while rsa is absent from the
# complete active feature graph for all target platforms (see issue #44).
echo "Verifying RSA is absent from the active PostgreSQL dependency graph"
active_dependencies="$(cargo tree --manifest-path "$temporary_root/audit_postgres/Cargo.toml" --target all --prefix none --format '{p}')"
if grep -Eq '^rsa v[0-9]' <<< "$active_dependencies"; then
    echo "RSA is active; refusing RUSTSEC-2023-0071 exception" >&2
    exit 1
fi

postgres_lock="$temporary_root/audit_postgres/Cargo.lock"
if grep -Fq 'name = "rsa"' "$postgres_lock"; then
    if ! grep -Fq 'name = "sqlx-mysql"' "$postgres_lock"; then
        echo "Unexpected RSA lockfile source; manual security review required" >&2
        exit 1
    fi
    echo "Applying scoped, active-graph-guarded RUSTSEC-2023-0071 exception (issue #44)"
    cargo audit --file "$postgres_lock" --ignore RUSTSEC-2023-0071
else
    audit_lockfile "$postgres_lock"
fi

echo "All three Cargo.lock audits completed without reported vulnerabilities"
