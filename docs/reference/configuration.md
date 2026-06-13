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
| `unknown_threats` | Monitor-only route request-shape baselines |
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

## Unknown-Threat Monitoring

`unknown_threats` learns request shapes per normalized route from clean
requests. After `minimum_observations`, it monitors unseen methods, content
types, query parameter names, and large body-size deviations. It stores only
bounded metadata, not request bodies.

Signal weights are loaded from the versioned YAML file configured by
`signal_catalog`. Use `builtin` for the catalog embedded in the binary, or an
external path when operators need to tune weights without rebuilding Saugra.
Production packages seed
`/etc/saugra-waf/intelligence/unknown-threat-signals.yml`.

```yaml
version: 1
signals:
  unseen_method:
    score: 20
  unseen_content_type:
    score: 15
  unseen_query_parameter:
    score: 10
  body_size_deviation:
    score: 15
```

Every required score must be greater than zero. Unsupported versions, missing
signals, malformed YAML, and legacy inline score fields are startup errors.

The local backend supports a single-node deployment and survives restarts;
leave unknown-threat blocking disabled in multi-instance deployments until a
shared backend is available. Review the phased safety and enforcement work in the
[public roadmap](https://github.com/saugra/saugra-waf/blob/main/ROADMAP.md#phase-9--unknown-threat-detection-and-ai-assistance).

Use the rollout modes in order:

- `monitor` records threshold candidates and never blocks.
- `shadow` computes `would_block` and enforcement gates but still forwards.
- `block` can enforce only after `shadow_review_completed: true`.

Before block mode, run:

```bash
saugra-waf unknown-threats report --limit 1000
```

Review candidate volume, single-signal and new-baseline pressure, top routes,
and the sample request IDs with `saugra-waf explain`.

Automatic blocking requires all of the following:

- the route has an explicit longest-prefix override with `high_risk: true`;
- the score reaches `block_threshold`;
- at least `minimum_independent_signals` distinct signals are present;
- the route has at least `minimum_block_observations`;
- the baseline is at least `minimum_baseline_age` old;
- the main server mode also permits blocking.

Ordinary and newly observed routes therefore remain monitor-only.

Use `retention` and `max_routes` to bound persisted baseline state. Stale routes
are pruned during request evaluation before new routes are allocated. When the
route cap is reached, Saugra continues forwarding traffic and records
`capacity_reached` in the unknown-threat outcome instead of growing the state
file.

Use `excluded_paths` for health checks and other routes that should not be
analyzed. Route overrides use longest-prefix matching and can disable learning
or change `minimum_observations` and `monitor_threshold`:

```yaml
unknown_threats:
  enabled: true
  mode: shadow
  shadow_review_completed: false
  signal_catalog: /etc/saugra-waf/intelligence/unknown-threat-signals.yml
  monitor_threshold: 20
  block_threshold: 40
  minimum_independent_signals: 2
  minimum_baseline_age: 7d
  minimum_block_observations: 1000
  promotion_observations: 3
  trusted_learning_only: false
  trusted_learning_clients: []
  max_methods_per_route: 16
  max_content_types_per_route: 32
  max_query_parameters_per_route: 256
  retention: 30d
  max_routes: 10000
  excluded_paths:
    - /_saugra-waf/health
  routes:
    - path: /uploads
      learning_enabled: false
    - path: /admin
      high_risk: true
      minimum_observations: 200
      monitor_threshold: 15
      block_threshold: 40
```

Baseline-poisoning controls include deterministic-rule filtering, quarantine of
anomalous requests, repeated-observation promotion for novel values, bounded
feature sets, bucketed body-size learning, and optional trusted-only learning.
When `trusted_learning_only` is true, `trusted_learning_clients` accepts exact
IP addresses and IPv4 CIDRs.

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
