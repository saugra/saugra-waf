# AI Explanation Providers

Saugra does not require an AI model to inspect, monitor, or block traffic.
Rules, rate limits, behavior scoring, bot scoring, unknown-threat policy, and
campaign correlation remain deterministic. AI is limited to operator-triggered
explanations and tuning assistance.

## Run Without A Model

For small servers or environments where model processing is not allowed,
disable AI providers:

```yaml
ai:
  enabled: false
  mode: explain_only
```

`saugra-waf explain <request-id>` still returns Saugra's deterministic
explanation. Ollama does not need to be installed and no event data leaves the
server.

Alternatively, keep the AI feature configured but force the deterministic
provider:

```yaml
ai:
  enabled: true
  mode: explain_only
  provider: local
```

Both configurations avoid model calls. `enabled: false` is the clearest choice
when model-backed explanations are not permitted. `provider: local` is useful
as an operational rollback because it preserves the rest of the AI audit
configuration.

## Local Ollama Resource Guide

Model file size is not the same as total runtime memory. Ollama also needs
memory for model execution and context, while the host still needs capacity for
the operating system, Saugra, Redis, Nginx or Apache, and the protected
application.

Use these as conservative starting points for a shared server:

| Host resources | Suggested configuration | Expected result |
| --- | --- | --- |
| Less than 2 GB RAM | `enabled: false` or `provider: local` | Do not run Ollama on the WAF host. |
| 2-3 GB RAM, 1-2 CPU cores | `qwen3:0.6b` | Development or occasional explanations; evaluate quality carefully. |
| 4 GB RAM, 2 CPU cores | `qwen3:1.7b` | Minimum practical local model for occasional operator explanations. |
| 8 GB RAM, 4 CPU cores | `qwen3:4b` | Recommended minimum for the default model on a shared host. |
| 12 GB or more RAM | `qwen3:8b` | Higher quality but greater latency and memory use. |

Our CPU-only development test loaded `qwen3:4b` at approximately 3.5 GB of
runtime memory and took roughly 39-55 seconds for a bounded explanation. A
4 GB host therefore does not leave safe capacity for the operating system and
production services.

For a 4 GB host:

```bash
ollama pull qwen3:1.7b
```

```yaml
ai:
  enabled: true
  mode: explain_only
  provider: ollama
  ollama_url: http://127.0.0.1:11434
  model: qwen3:1.7b
  timeout: 60s
```

Measure with `ollama ps`, system memory tools, and retained explanation
latencies before production rollout. Avoid swap as the primary capacity plan:
heavy swapping can degrade the WAF, proxy, Redis, and application sharing the
host.

## Remote Model APIs

Saugra currently supports remote services such as OpenAI, Gemini, or another
model gateway through the `command` provider. Saugra does not yet include
native provider-specific HTTP clients for those services.

The command adapter:

1. Receives one sanitized JSON object on standard input.
2. Calls the operator-selected remote API.
3. Returns Saugra's structured explanation JSON on standard output.
4. Keeps API credentials outside Saugra YAML.

Example:

```yaml
ai:
  enabled: true
  mode: explain_only
  provider: command
  command: /usr/local/bin/saugra-ai-adapter
  command_args: ["--provider", "openai"]
  model: operator-selected-model
  prompt_version: saugra-explain-v1
  timeout: 60s
  audit_log_path: /var/log/saugra-waf/saugra-waf-ai-audit.jsonl
```

The adapter should read credentials from its service environment or a
restricted secret store. Do not place API keys in `saugra-waf.yml`, command
arguments, event logs, or AI audit records.

Saugra sends route shapes, query parameter names, rule metadata, bounded
scores, baseline signals, behavior reasons, and campaign counts. It excludes
query values, request bodies, cookies, authorization data, client addresses,
and upstream credentials. Remote processing may still have legal, contractual,
residency, retention, and incident-response implications. Review the provider's
terms and your organization's data policy before enabling an adapter.

Provider failures, timeouts, malformed JSON, unsafe suggestions, and ungrounded
explanations fall back to the deterministic local explanation. Remote models
never participate in request blocking.

## Native Provider Status

| Provider | Current support |
| --- | --- |
| Deterministic local | Native |
| Local Ollama | Native |
| Operator command adapter | Native adapter interface |
| OpenAI API | Supported through command adapter; native client planned |
| Gemini API | Supported through command adapter; native client planned |
| Other HTTP model gateways | Supported through command adapter |

Native remote providers should add secret references, endpoint allowlisting,
TLS requirements, provider-specific structured-output handling, retry and
rate-limit behavior, and tests without weakening the existing sanitized-input
and deterministic-fallback boundaries.
