# Contributing to Saugra WAF

Thank you for your interest in contributing to **Saugra WAF**! We are building a lightweight, rule-based + AI-assisted Web Application Firewall that protects modern web apps and APIs against OWASP Top 10-style attacks.

As an open-core project licensed under
[AGPL-3.0-only](LICENSE), we aim to make Saugra the easiest, most
developer-friendly WAF to configure, inspect, and deploy.

Please take a moment to read this guide to ensure a smooth contribution process.

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please report violations or inappropriate behavior through the repository maintainer contact channel listed in the project profile.

---

## Contributor Licensing

By submitting a contribution to Saugra Community Edition, you agree that your
contribution is licensed under AGPL-3.0-only, the same license as the project,
unless a file clearly states a different license.

You also confirm that you have the right to submit the contribution and that it
does not knowingly include code, data, rules, signatures, documentation, or
other material that is incompatible with AGPL-3.0-only.

Community Edition contributions are accepted for the AGPL-3.0-only codebase.
They are not assumed to be available for proprietary relicensing or inclusion
in separately licensed editions unless the contributor has agreed to that
separately in writing.

Do not submit confidential customer data, proprietary rules, private threat
intelligence, copied commercial signatures, leaked materials, or third-party
content unless its license clearly permits inclusion in this repository.

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
   git clone https://github.com/<your-username>/saugra-waf.git
   cd saugra-waf
   ```
3. Add the upstream repository as a remote:
   ```bash
   git remote add upstream https://github.com/saugra/saugra-waf.git
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

### 4. Coverage

GitHub Actions generates an LCOV coverage report and uploads it to Codecov when
the repository has a `CODECOV_TOKEN` Actions secret configured. Store the token
only in the CI secret manager; do not commit it to source files, examples, or
documentation.

Run the normal Rust test suite before collecting coverage. Treat coverage as a
regression signal for security-critical paths, not as a reason to add weak
tests.

### 5. Validating Rules and Configs

Always verify that Saugra compiles and can validate the example configuration and rules files:
```bash
cargo run --bin saugra-waf -- test-config --config configs/saugra-waf.example.yml
```

You can list rules configured in the rulepack files with:
```bash
cargo run --bin saugra-waf -- rules list --config configs/saugra-waf.example.yml
```

### 6. Building Documentation

Documentation is built with MkDocs and published through Read the Docs. Install
the pinned documentation dependencies in a virtual environment, then run the
strict build:

```bash
python3 -m venv .venv-docs
.venv-docs/bin/pip install --requirement docs/requirements.txt
.venv-docs/bin/mkdocs build --strict
```

The strict build must pass before documentation changes are submitted. It
checks the site configuration, navigation, and internal links.

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

See [Architecture](docs/ARCHITECTURE.md#security-model) for the layered OWASP
coverage model.

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
* [ADMIN_GUIDE.md](docs/ADMIN_GUIDE.md) for deployment and operations.
* [ROADMAP.md](ROADMAP.md) for product direction and implementation status.

Alternatively, open a GitHub Discussion or issue for non-sensitive questions.
