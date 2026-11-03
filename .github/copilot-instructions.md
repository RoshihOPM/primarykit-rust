# GitHub Copilot instructions

Follow [the repository engineering policy](../AGENTS.md) for every change.
It defines SOLID, KISS, DRY, YAGNI, safe Rust, SQL integrity, modular
architecture, security, CI and branch/PR requirements.

Generated projects are independent from PrimaryKit: test the generated
application and affected portable modules, not only the generator.
