# CLI Reference

Run `saugra-waf --help` for the command surface installed by your release and
`saugra-waf <command> --help` for command-specific options.

## Configuration

Commands that load configuration use `--config`, `SAUGRA_WAF_CONFIG`, the
installed path, then the source-checkout example.

```bash
saugra-waf test-config
saugra-waf test-config --config /path/to/saugra-waf.yml
```

## Proxy

Start the reverse proxy:

```bash
saugra-waf run
```

## Rules and Security Coverage

```bash
saugra-waf rules list
saugra-waf owasp coverage
```

Use `rules list` to confirm which rule packs loaded. The OWASP coverage command
summarizes mapped controls and should not be interpreted as proof that the
protected application itself is compliant.

## Events and Explanations

```bash
saugra-waf logs tail --limit 20
saugra-waf logs summary --limit 200
saugra-waf explain <request-id>
```

`logs tail` shows recent security events. `logs summary` aggregates recent
actions and categories. `explain` retrieves the stored decision associated
with a request ID.

## Runtime Policy

Runtime policy commands update local policy without restarting the proxy:

```bash
saugra-waf allowlist list
saugra-waf allowlist add ip 203.0.113.10 \
  --duration 2h \
  --reason "controlled rollout"

saugra-waf allowlist block add 198.51.100.20 \
  --duration 1h \
  --reason "confirmed scanner activity"
```

Use short expirations and explicit reasons for temporary exceptions. Runtime
policy is security-sensitive state; protect its file permissions and include
changes in operational review.

See the [administration guide](../ADMIN_GUIDE.md) for incident procedures and
the [runtime allowlist design](../RUNTIME_ALLOWLIST.md) for policy semantics.

## Reports and Maintenance

Additional commands cover security summaries, external report ingestion, and
local storage cleanup. Their exact options can evolve between releases:

```bash
saugra-waf --help
saugra-waf <command> --help
```

Prefer the help output from the installed release whenever it differs from the
latest online documentation.
