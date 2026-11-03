# GitHub Copilot repository instructions

Read and follow [AGENTS.md](../AGENTS.md) before generating or modifying code.

In brief: prefer SOLID (only useful interfaces), KISS, pragmatic DRY, YAGNI
and Clean Code. Preserve existing user code and migrations. Use safe Rust,
typed errors, parameterized SQL, bounded Tokio concurrency, explicit auth
and tests. Always test both PrimaryKit's CLI **and its generated projects**;
do not merge failed CI or claim unverified checks succeeded.

Generated applications receive their own AGENTS.md from
`docs/generated-agent-rules.md`.
