# Saugra Console Contracts

Shared Rust wire contracts for Saugra Console integrations used by Saugra EDR,
Saugra WAF, server nodes, and relay nodes.

Consumers should depend on a pinned release tag or revision instead of a local
relative path:

```toml
saugra-console-contracts = { git = "https://github.com/saugra/saugra-console-contracts.git", tag = "v0.1.0" }
```

Local `path` dependencies should be reserved for workspace development only.
