# Saugra Public Roadmap

This roadmap tracks public community-edition development for Saugra.

Saugra is developed with an open-core direction: this public repository focuses
on the self-hosted WAF engine, reverse proxy, rules, local logs, CLI, local
visibility, deployment examples, and basic explain-only AI summaries. Future
enterprise and cloud capabilities may include centralized management,
organization-level controls, external integrations, and reporting. Commercial
planning and private implementation details are tracked outside this public
repository.

## Current Status

Current phase: **Phase 2 — Reverse Proxy Core**

The repository has a working Rust foundation:

- CLI scaffold
- YAML config loading and validation
- Built-in WAF rule metadata
- Regex-based attack inspection helpers
- WAF decision model
- Basic AI-style explanation helper
- Structured logging setup
- Minimal Axum health service
- Example config at `configs/saugra.example.yml`

## Verified Commands

```bash
cargo fmt --check
cargo test
cargo run -- test-config --config configs/saugra.example.yml
cargo run -- rules list
```

Current test status:

```txt
6 passed; 0 failed
```

## Community Edition Scope

The public edition should remain useful by itself:

- Reverse proxy runtime
- Request inspection
- Built-in OWASP-style rules
- Monitor and block modes
- Structured JSON security logs
- Local CLI tools
- Local dashboard or log viewer
- Nginx and Apache integration examples
- Docker/demo deployment examples
- Basic explain-only AI summaries

## Open-Core Boundary

The public edition should provide real security value without requiring a paid
or hosted service. Enterprise and cloud features should extend Saugra for larger
teams and organizations, not replace the community WAF core.

Public development should prioritize:

- Reliable local protection
- Transparent rule-based decisions
- Clear monitor and block behavior
- Safe structured logs
- Practical deployment examples
- Explainable findings

Future enterprise/cloud work may focus on:

- Centralized dashboards
- Multi-node management
- Team access controls
- External identity integrations
- Alerting and security tool integrations
- Organization-level reporting

## Next Public Development Work

- [ ] Replace the placeholder root route with a catch-all proxy route.
- [ ] Accept all HTTP methods and paths.
- [ ] Normalize request path, query, headers, user-agent, and body.
- [ ] Run built-in rules before forwarding traffic.
- [ ] Log a structured security event when rules match.
- [ ] In `monitor` mode, allow suspicious traffic after logging.
- [ ] In `block` mode, return a safe block response.
- [ ] Forward allowed traffic to the configured upstream.
- [ ] Add tests for monitor and block behavior.

## Public Built-In Rules

- `SAUGRA-SQLI-001` — basic SQL injection pattern
- `SAUGRA-XSS-001` — basic cross-site scripting pattern
- `SAUGRA-PATH-001` — path traversal pattern
- `SAUGRA-CMD-001` — command injection pattern
- `SAUGRA-BOT-001` — suspicious scanner user agent
- `SAUGRA-CT-001` — suspicious content type
- `SAUGRA-BODY-001` — suspicious body script pattern
