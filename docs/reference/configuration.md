# Configuration Reference

Saugra reads YAML configuration from the first available source:

1. An explicit `--config <path>` argument.
2. The `SAUGRA_WAF_CONFIG` environment variable.
3. `/etc/saugra-waf/saugra-waf.yml` for installed deployments.
4. `configs/saugra-waf.example.yml` in a source checkout.

Always validate changes before restarting:

```bash
saugra-waf test-config
```

The repository ships two maintained examples:

- [`saugra-waf.example.yml`](https://github.com/saugra/saugra-waf/blob/main/configs/saugra-waf.example.yml)
  for local evaluation.
- [`saugra-waf.production.example.yml`](https://github.com/saugra/saugra-waf/blob/main/configs/saugra-waf.production.example.yml)
  for an installed monitor-first deployment.

## Major Sections

| Section | Purpose |
| --- | --- |
| `server` | Listen address, operating mode, and server behavior |
| `upstreams` | Named backend applications and their target URLs |
| `routes` | Path-based selection of named upstreams |
| `forwarded_headers` | Trusted proxy and client IP handling |
| `security` | Request inspection and body limits |
| `rate_limit` | Backend, global limits, bursts, and route limits |
| `rules` | Rule packs, exclusions, and rule-engine settings |
| `behavior` | Repeated suspicious activity scoring |
| `bot_protection` | Bot and scanner scoring policy |
| `runtime_policy` | Reloadable allowlist and blocklist behavior |
| `standards` | Security-standard catalogs and mappings |
| `logging` | Structured logs, event store, rotation, and retention |
| `ai` | Optional explanation-only AI behavior |

## Server Modes

`server.mode` controls the main WAF enforcement behavior:

| Mode | Result |
| --- | --- |
| `off` | Inspection enforcement is disabled |
| `monitor` | Suspicious traffic is forwarded and recorded |
| `block` | Configured blocking decisions are enforced and recorded |

Begin production rollout in `monitor`. Behavior and bot protection have their
own modes and should also be reviewed before enforcement.

## Upstreams and Routes

Each upstream has a unique name, expected host, and target URL:

```yaml
upstreams:
  - name: app
    host: example.com
    target: http://127.0.0.1:8000

routes:
  - path_prefix: /api
    upstream: app
```

Routes refer to upstreams by name. Validate that every route points to a
declared upstream and that the fallback routing behavior matches the intended
application layout.

## Production State

Production rate limiting should use Redis so counters survive process restarts
and work across Saugra instances:

```yaml
rate_limit:
  enabled: true
  backend: redis
  redis_url: redis://127.0.0.1:6379
```

Security events must use bounded, queryable storage. Configure the JSONL event
path, rotation size, and retained file count under `logging`.

## Forwarded Headers

Only trust client IP and protocol headers from known reverse proxies. An
overly broad trusted proxy range lets clients influence identity, rate limits,
behavior scoring, and audit records.

Review the complete discussion in
[Forwarded Header Trust](../PRODUCTION_DEPLOYMENT.md#forwarded-header-trust).

## Rules and Exclusions

Security behavior should remain data-driven through external rule packs and
documented configuration. Keep exclusions narrow: constrain them by rule,
route, parameter, or another supported target instead of globally disabling a
detection category.

Use:

```bash
saugra-waf rules list
```

to inspect the active rules after configuration loading.

!!! note

    This page is an orientation reference. The shipped production YAML remains
    the authoritative example for all currently supported fields while the
    field-by-field generated schema reference is developed.
