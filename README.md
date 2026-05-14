# Saugra WAF

Saugra is a lightweight Rust-based, AI-assisted Web Application Firewall for
modern web applications and APIs.

The MVP direction is:

```txt
Rules-first protection + rate limiting + behavior scoring + AI explanations
```

AI is used for explanations and tuning support. Blocking decisions should come
from deterministic rules, rate limits, and explicit configuration.

## Current Status

This repository now has the Phase 1 foundation:

- Rust CLI scaffold
- YAML config loading and validation
- Built-in rule metadata and basic regex inspection
- Monitor/block/off mode model
- Structured logging setup
- Minimal Axum service with `/_saugra/health`
- Example config at `configs/saugra.example.yml`

## Quick Start

Validate the example config:

```bash
cargo run -- test-config --config configs/saugra.example.yml
```

List built-in rules:

```bash
cargo run -- rules list
```

Start the service:

```bash
cargo run -- run --config configs/saugra.example.yml
```

Then check the health endpoint:

```bash
curl http://127.0.0.1:8787/_saugra/health
```

## Next Development Step

The next useful slice is the reverse proxy inspection path:

1. Accept all HTTP methods and paths.
2. Normalize request path, query, headers, user-agent, and body.
3. Run built-in rules before forwarding.
4. In `monitor` mode, log matches and forward.
5. In `block` mode, return a safe block response.
6. Forward clean requests to the configured upstream.
