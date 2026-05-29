# Runtime Allowlist Plan

## Purpose

Runtime allowlisting lets an operator recover from false positives without
restarting Saugra. It is especially important for bot protection and behavior
scoring, where a trusted administrator can accidentally accumulate enough score
to trigger a temporary block during production verification.

The community edition should support a local, file-backed runtime allowlist.
This is an operational safety feature for the community edition.

## Goals

- Add or remove trusted IP/CIDR entries without restarting Saugra.
- Support expiring allowlist entries for safe emergency use.
- Keep traffic observable when an allowlist entry matches.
- Avoid exposing an admin HTTP API in the community edition.
- Preserve deterministic WAF protection by default.
- Keep the implementation local-first and production-usable for one node.

## Non-Goals

- No public admin HTTP API in the community edition.
- No cloud policy sync in the community edition.
- No team/RBAC workflow in the community edition.
- No user allowlisting until trusted identity extraction is implemented safely.

## Runtime Policy File

Default path:

```txt
/var/lib/saugra-waf/runtime-policy.json
```

Example:

```json
{
  "version": 1,
  "allowlisted_ips": [
    {
      "id": "local-admin-20260521",
      "value": "203.0.113.10/32",
      "reason": "admin production verification",
      "created_by": "cli:root",
      "created_at": "2026-05-21T18:35:00Z",
      "expires_at": "2026-05-21T20:35:00Z"
    }
  ],
  "blocklisted_ips": [
    {
      "id": "deny-scanner-20260521",
      "value": "198.51.100.44/32",
      "reason": "active scanner",
      "created_by": "cli:root",
      "created_at_unix_seconds": 1779388500,
      "expires_at_unix_seconds": 1779395700
    }
  ]
}
```

The file should be owned by root or the Saugra service user, writable only by
trusted local administrators, and read by the running Saugra process.

## Configuration

Target config shape:

```yaml
runtime_policy:
  enabled: true
  path: /var/lib/saugra-waf/runtime-policy.json
  reload_interval: 5s
  default_duration: 2h
  allowlist_effect: skip_bot_and_behavior_block
```

Supported `allowlist_effect` values:

- `skip_bot_and_behavior_block`: bot and behavior threshold blocks are bypassed
  for matching IPs, but deterministic WAF rules still run.
- `monitor_all`: deterministic WAF findings, bot findings, and behavior
  findings are logged as monitor events for matching IPs.
- `allow_all`: emergency-only. Matching IPs bypass all blocking decisions.
- `block`: used by runtime blocklist entries to force a block.

## CLI

Target commands:

```bash
saugra-waf allowlist add ip 203.0.113.10 --duration 2h --reason "admin testing"
saugra-waf allowlist add cidr 203.0.113.0/24 --duration 30m --reason "office NAT"
saugra-waf allowlist block add 198.51.100.44 --duration 2h --reason "active scanner"
saugra-waf allowlist remove local-admin-20260521
saugra-waf allowlist list
saugra-waf allowlist prune
```

The CLI should write the policy atomically:

1. Read the current JSON file if it exists.
2. Validate schema, CIDRs, timestamps, and duplicate entries.
3. Write a temporary file in the same directory.
4. Flush the file to disk where supported.
5. Rename the temporary file over the policy file.

## Runtime Reload

Saugra should reload the policy without restart:

- Cache the last valid policy in memory.
- Check file metadata every `reload_interval`.
- Reload when mtime or size changes.
- If reload fails, keep the last known good policy.
- Emit an operator-visible event or warning when reload fails.

Polling is acceptable for the first implementation. A filesystem watcher can be
added later without changing the CLI or policy file format.

## Decision Flow

Runtime allowlist matching should happen after client identity extraction and
before bot or behavior blocking:

1. Extract client IP using the existing trusted proxy/header logic.
2. Match the IP against active, non-expired runtime allowlist entries.
3. Match the IP against active, non-expired runtime blocklist entries.
4. Runtime blocklist matches force a deterministic block.
5. Apply the configured allowlist effect.
6. Continue request inspection when the policy does not force allow/block.
7. Include runtime policy match metadata in the decision and security event.

Event metadata should make the bypass explainable:

```json
{
  "runtime_allowlist_match": {
    "id": "local-admin-20260521",
    "type": "ip",
    "value": "203.0.113.10/32",
    "effect": "skip_bot_and_behavior_block",
    "reason": "admin production verification",
    "expires_at": "2026-05-21T20:35:00Z"
  }
}
```

`saugra-waf explain <request-id>` should mention the allowlist match when it changes
the decision.

## State Interaction

An allowlist entry should suppress matching bot and behavior blocks while it is
active. It should not silently erase bot or behavior state by default.

Operators should have an explicit cleanup command later if needed:

```bash
saugra-waf behavior reset --client 203.0.113.10
saugra-waf bot reset --client 203.0.113.10
```

Those reset commands are separate from runtime allowlisting because deletion of
security state is higher risk and should be visible.

## Security Notes

- Runtime allowlisting must never be loaded from a world-writable path.
- Expiring entries should be encouraged in CLI help and examples.
- Operators can choose whether allowlists affect deterministic WAF rules with
  `allowlist_effect`.
- Runtime policy matches should be logged so production investigations can
  explain why a request was allowed, monitored, or blocked.
- Multi-node deployments need per-node files until a distributed policy sync
  layer exists.

## Implementation Steps

1. Add `runtime_policy` config parsing and validation.
2. Add `runtime_policy.rs` with schema, CIDR matching, expiry handling, and
   atomic write helpers.
3. Add a reloadable runtime policy handle used by the proxy request path.
4. Add `saugra-waf allowlist add/list/remove/prune`.
5. Apply IP/CIDR runtime allowlist and blocklist before final decision
   enforcement.
6. Add allowlist metadata to decisions and security events.
7. Include allowlist context in `saugra-waf explain`.
8. Add package defaults so `/var/lib/saugra-waf/runtime-policy.json` can be created
   by the CLI and read by the service user.
9. Document production use in `docs/PRODUCTION_DEPLOYMENT.md`.

## Tests Required

- Config parsing accepts runtime policy defaults and custom paths.
- Invalid reload interval, duration, or effect produces a clear config error.
- CLI add/list/remove/prune updates the JSON file atomically.
- Expired entries do not match.
- IP and CIDR matching handles exact IPs and subnet ranges.
- Runtime reload works without restarting Saugra.
- Malformed policy keeps the last known good policy.
- Allowlisted IP bypasses active bot temporary block.
- Allowlisted IP bypasses behavior threshold block.
- SQLi/XSS/path traversal rules still block under `skip_bot_and_behavior_block`.
- SQLi/XSS/path traversal rules are downgraded under `monitor_all`.
- Runtime blocklist entries block clean requests.
- Security events include runtime allowlist metadata.
- `saugra-waf explain` mentions allowlist matches.

## Future Extension

Future work can build on this same runtime policy model with an authenticated
admin API, RBAC, audit trails, dashboard workflows, and fleet-wide policy sync.
The current community edition remains local and file-backed.
