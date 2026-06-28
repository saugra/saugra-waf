# Saugra WAF Documentation

Saugra WAF is a self-hosted Web Application Firewall for applications and APIs
that need OWASP-style request inspection, monitor-first rollout, deterministic
blocking, rate limiting, behavior and bot scoring, durable security events, and
explainable decisions.

This documentation is the public operator entry point for setup, configuration,
operations, tuning, troubleshooting, and updates. The repository
[README](https://github.com/saugra/saugra-waf#readme) remains the quick-start
and feature overview.

## Start here

- [Administration](ADMIN_GUIDE.md): installation, configuration, reverse-proxy
  deployment, AI explanations, service operations, safe rollout, upgrades,
  logs, and troubleshooting.
- [Release process](RELEASE_PROCESS.md): release verification, package
  publishing, signed APT repository handling, and maintainer release steps.
- [Architecture](ARCHITECTURE.md): request processing, security model, rule
  formats, storage, and implementation design.
- [Licensing](LICENSING.md): AGPL-3.0-only licensing and project notices.

## Production posture

Run Saugra behind Nginx, Apache, or another trusted public reverse proxy, with
Saugra and the backend application bound to private interfaces. Start new
deployments in monitor mode, review security events and explanations, then
move selected rules and protections to block mode after tuning.

AI is optional and explain-only. Blocking decisions come from deterministic
rules, rate limits, behavior scoring, bot scoring, and explicit configuration.
Saugra is an additional defense layer; it does not replace secure application
development, authorization, dependency management, TLS, patching, or host
hardening.

## Updates

Use the [Administration](ADMIN_GUIDE.md#upgrade-to-the-newest-version) upgrade
runbook for installed systems. Before replacing packages, stop and mask the
service, unhold the package only for the planned maintenance window, validate
configuration, restart deliberately, then hold the package again to prevent
unattended upgrades.
