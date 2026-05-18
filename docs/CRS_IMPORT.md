# OWASP CRS Import

Saugra uses native YAML rule packs at runtime. OWASP CRS files are treated as an
upstream source that can be converted into Saugra YAML before deployment.

```txt
OWASP CRS .conf files
  -> saugra rules convert-crs
  -> Saugra YAML rule packs
  -> saugra test-config
  -> Saugra rule engine
```

## Supported Import Surface

The converter currently supports:

- `SecRule` statements with `@rx` regex operators.
- `SecRule` statements with `@pmFromFile` literal data-file operators.
- CRS data files referenced by relative path from the CRS rules directory.
- Request targets that map to Saugra `path`, `query`, `headers`, or `body`.
- Ordered transform actions:
  - `t:none`
  - `t:urlDecode`
  - `t:urlDecodeUni`
  - `t:lowercase`
- CRS category tags for SQLi, XSS, LFI/path traversal, RCE/command injection,
  scanner detection, protocol enforcement, and suspicious file upload rules.
- Severity normalization from CRS values into Saugra `low`, `medium`, `high`,
  and `critical`.
- Paranoia level tags such as `paranoia-level/1`.

`@pmFromFile` imports are converted into escaped literal regex alternations in
the generated Saugra YAML. Empty, commented, or missing data files are reported
as unsupported imports.

## Unsupported CRS Features

Unsupported CRS features are not silently converted. The generated YAML includes
an `unsupported_imports` section with the CRS rule ID, reason, and source
statement where possible. `saugra test-config` prints those warnings so
operators can review the gap before using a converted pack.

Currently unsupported:

- Chained CRS rules using the `chain` action.
- Libinjection and other engine-specific operators such as `@detectSQLi`.
- Operators other than `@rx` and `@pmFromFile`.
- Transform actions outside the supported list, such as `t:cmdLine`.
- Complex ModSecurity variable selectors, collection updates, `ctl` actions,
  and phase-specific side effects.
- Runtime ModSecurity semantics that require transaction collections or
  persistent variable state.

When a skipped CRS rule is important for a deployment, convert it manually into
a native Saugra YAML rule or keep the original protection at another layer until
Saugra supports the needed feature.

## Validation Workflow

After converting CRS rules, always validate the generated YAML:

```bash
saugra rules convert-crs --input /path/to/coreruleset/rules --output /etc/saugra/rules/converted-crs.yml
saugra test-config --config /etc/saugra/saugra.yml
```

Review:

- rule-pack name, version, and standards
- active rule counts
- transform pipeline counts
- rules filtered by detection paranoia level
- unsupported imports and warnings

Converted rule packs should be rolled out in `monitor` mode first. Raise
`detection_paranoia_level` before `blocking_paranoia_level` so noisier imports
can be observed before they are allowed to block traffic.
