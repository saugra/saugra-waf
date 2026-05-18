# Contributing to Saugra WAF

Thank you for your interest in contributing to **Saugra WAF**! We are building a lightweight, rule-based + AI-assisted Web Application Firewall that protects modern web apps and APIs against OWASP Top 10-style attacks.

As an open-core project licensed under the [AGPL-3.0 License](LICENSE), we aim to make Saugra the easiest, most developer-friendly WAF to configure, inspect, and deploy.

Please take a moment to read this guide to ensure a smooth contribution process.

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please report violations or inappropriate behavior through the repository maintainer contact channel listed in the project profile.

---

## Coding Principles

When writing code or adding rules to Saugra, please keep these primary design goals in mind:

1. **Deterministic Decisions**: Blocking decisions must come from deterministic rules, rate limits, and configuration. The AI assistant layer is **explain-only** and should never be the only blocking mechanism.
2. **Data-Driven & Upgradeable Rules**: **Avoid hard-coding security rules or OWASP mappings in the Rust source code.** Keep rules, thresholds, and policy choices in YAML rule packs or data files (e.g., standard catalogs), loaded and validated through stable interfaces.
3. **No Silently Blocked Traffic**: Every single block or monitor decision must produce a queryable, structured JSON security event in the local/external event logs.
4. **Monitor Mode First**: Always support a safe `monitor` mode alongside active `block` mode to allow operators to tune false positives without breaking live applications.
5. **No Panics in Request Handling**: Do not write code that can panic in critical request-handling paths. Always handle errors gracefully with `anyhow` or `thiserror`.

---

## Development Environment Setup

Saugra is built with Rust. You will need a modern Rust toolchain installed.

### Prerequisites

1. **Rust & Cargo**: Install via [rustup](https://rustup.rs/):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
2. **Redis**: Needed for rate limiting tests and production backend validations:
   ```bash
   # On Ubuntu/Debian:
   sudo apt-get install redis-server
   ```

### Get the Code

1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/saugra.git
   cd saugra
   ```
3. Add the upstream repository as a remote:
   ```bash
   git remote add upstream https://github.com/<upstream-owner>/saugra.git
   ```

---

## Quality & Verification Workflows

We maintain high standards of code quality. Before submitting a Pull Request, make sure your changes pass all of these steps:

### 1. Code Formatting

Format your code with the standard Rust tool:
```bash
cargo fmt --all
```
To check if formatting is correct without modifying the files:
```bash
cargo fmt --all -- --check
```

### 2. Linting (Clippy)

Run the linter to catch common bugs and performance pitfalls:
```bash
cargo clippy --all-targets -- -D warnings
```

### 3. Running Tests

Run the full integration and unit test suite:
```bash
cargo test
```
Make sure you write tests for:
* Configuration parsing & invalid YAML schemas.
* Custom rules (e.g. SQLi, XSS, Path Traversal).
* Rate limiting behavior (both in-memory and Redis).
* Structured JSON logging outputs.

### 4. Validating Rules and Configs

Always verify that Saugra compiles and can validate the example configuration and rules files:
```bash
cargo run -- test-config --config configs/saugra.example.yml
```

You can list rules configured in the rulepack files with:
```bash
cargo run -- rules list --config configs/saugra.example.yml
```

---

## Contributing Rules

Saugra rules are represented as YAML rule packs located under `configs/rules/` or dynamically loaded.

When creating a new rule, follow the standard YAML schema:

```yaml
id: SAUGRA-SQLI-001
name: Basic SQL Injection Pattern
category: sql_injection
severity: high
target: query
action: block
# Mapped to a specific regex or condition list
```

Please refer to `docs/OWASP_TOP_10_STRATEGY.md` for our layered coverage matrix.

---

## Submitting a Pull Request

1. **Create a branch**: Create a descriptive branch name from `main`:
   ```bash
   git checkout -b feature/your-awesome-feature
   # or
   git checkout -b bugfix/fix-some-leak
   ```
2. **Commit your changes**: Write clear, descriptive commit messages. Focus on *why* the change was made in addition to *what* changed.
3. **Push to your fork**:
   ```bash
   git push origin feature/your-awesome-feature
   ```
4. **Open a PR**: Open a Pull Request from your branch to the upstream repository's `main` branch. Fill out the Pull Request Template completely.
5. **Address review feedback**: The project maintainers will review your PR and suggest changes or additions if needed.

---

## Need Help?

If you have questions about the codebase or design decisions, feel free to refer to:
* [ARCHITECTURE.md](docs/ARCHITECTURE.md) for technical design details.
* [PRODUCT_SPEC.md](docs/PRODUCT_SPEC.md) for product specification.
* [PRODUCTION_DEPLOYMENT.md](docs/PRODUCTION_DEPLOYMENT.md) for deployment insights.

Alternatively, open a GitHub Discussion or issue for non-sensitive questions.
