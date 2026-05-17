## Description

Please include a summary of the changes and the motivation or context behind them. Mention any dependencies that are required for this change.

Fixes # (issue)

## Type of Change

Please tick the options that are relevant:

- [ ] **Bug Fix** (non-breaking change which fixes an issue)
- [ ] **New Feature** (non-breaking change which adds functionality)
- [ ] **Rule Update** (adding or tuning WAF rule YAML packs)
- [ ] **Breaking Change** (fix or feature that would cause existing functionality to not work as expected)
- [ ] **Documentation Update** (clarifications, guides, example updates)

## How Has This Been Tested?

Please describe the tests that you ran to verify your changes. Provide instructions so we can reproduce.

- [ ] **Unit Tests**: `cargo test --lib` (for rule matching, config parsers, etc.)
- [ ] **Integration Tests**: `cargo test --test <name>` (for proxy routing, Redis rate limits)
- [ ] **CLI Validation**: Verified CLI commands function as expected (e.g. `cargo run -- test-config`)

## Checklist

Before submitting your PR, please verify:

- [ ] My code follows the code style of this project (`cargo fmt` passes).
- [ ] I have run the linter and verified no warnings are reported (`cargo clippy --all-targets -- -D warnings`).
- [ ] I have added tests that prove my fix is effective or that my feature works.
- [ ] New and existing unit tests pass locally with my changes (`cargo test`).
- [ ] I have commented on my code, particularly in hard-to-understand areas.
- [ ] I have updated the documentation accordingly (e.g. `README.md`, `ROADMAP.md` or files in `docs/`).
- [ ] My changes do **not** introduce any new compiler warnings or panics in the request-handling hot path.

### Security Checklist
- [ ] **No Hardcoded Security Rules**: I did not hardcode rules, OWASP/category mappings, or thresholds in Rust code. All such choices are placed in standard YAML catalogs/configs.
- [ ] **Data Masking**: I have verified that any secrets, tokens, passwords, cookies, or authorization headers are masked in JSON security logs and not printed in plain text.
- [ ] **Client IP Preservation**: If modifying proxy headers, I have ensured `X-Forwarded-For` and `X-Real-IP` are preserved correctly.
- [ ] **No Unchecked Stdin/Input**: Any input parsing (like YAML files, HTTP headers, request bodies) is bound-checked and does not cause out-of-memory or high CPU spikes.
