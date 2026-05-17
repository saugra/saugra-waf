---
name: 🛡️ False Positive Report
about: Report a rule that is incorrectly blocking or monitoring legitimate requests
title: "[FALSE-POSITIVE] "
labels: false-positive, rules
assignees: ""
---

## Matched Rule Information
* **Matched Rule ID**: (e.g., `SAUGRA-SQLI-001`)
* **Category**: (e.g., `sql_injection`, `cross_site_scripting`)
* **Severity**: (e.g., `high`, `medium`)

## Request Details
Please describe the request that was incorrectly flagged:
* **HTTP Method**: (e.g. `GET`, `POST`)
* **Path**: (e.g. `/api/v1/posts`)
* **Flagged Parameter/Header**: (e.g. `q`, `content`, `Cookie`)
* **Parameter Value** (mask sensitive secrets/passwords/auth tokens!):
  ```txt
  // Paste parameter value here
  ```

## JSON Security Log Event
Please paste the corresponding entry from `/var/log/saugra/saugra-events.jsonl` (ensure to mask credentials, actual session IDs, and tokens):
```json
{
  "request_id": "...",
  "action": "...",
  "matched_rules": [...],
  ...
}
```

## Expected Behavior
Why do you believe this traffic is safe and should not trigger this rule?

## Environment:
- **Saugra Version**: (e.g. `1.0.0`)
- **Paranoia Level Configured**: (e.g., `1`, `2`)

## Additional Context / Proposed Exclusions
If you have worked around this using the `rules.exclusions` configuration, feel free to share the exclusion rule here to help us refine the defaults:
```yaml
# Paste exclusions block here
```
