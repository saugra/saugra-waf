# Ollama Operations for Saugra

Saugra uses local Ollama for optional explain-only analysis. Ollama never
participates in request blocking. If Ollama is stopped, unavailable, slow, or
returns invalid output, Saugra returns its deterministic local explanation.

The default model is `qwen3:4b`. The repository also provides a versioned
Saugra model blueprint at `configs/ollama/Modelfile`.

Ollama is optional. For model-free operation, low-resource sizing, and remote
API adapter options, see [AI explanation providers](AI_PROVIDERS.md).

## Install Ollama

Use the official Ollama installation packages and keep the API bound to the
local machine.

### Ubuntu and Debian

Install Ollama:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

The official Linux installation supports a systemd service. Verify and enable
it:

```bash
ollama --version
sudo systemctl enable --now ollama
sudo systemctl status ollama --no-pager
```

Do not set `OLLAMA_HOST` to a public address. Saugra validates `ai.ollama_url`
as loopback HTTP.

### macOS

Download the Ollama application from the official Ollama download page, move it
to `Applications`, and start it once. The application installs or offers to
install the `ollama` command in the shell path.

Verify:

```bash
ollama --version
curl -s http://127.0.0.1:11434/api/version
```

### Windows

Install the official `OllamaSetup.exe`. Ollama runs in the background and makes
the CLI available to PowerShell, Command Prompt, and compatible terminals.

Verify in PowerShell:

```powershell
ollama --version
Invoke-RestMethod http://127.0.0.1:11434/api/version
```

## Pull and Verify the Default Model

Pull the base model:

```bash
ollama pull qwen3:4b
ollama list
```

Test local generation:

```bash
ollama run qwen3:4b "Reply with the word ready."
```

Verify the API without sending production traffic:

```bash
curl -s http://127.0.0.1:11434/api/generate \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen3:4b","prompt":"Reply with ready.","stream":false}'
```

## Create the Versioned Saugra Model

The repository `Modelfile` pins Saugra's system behavior and conservative
runtime parameters. It is customization, not weight training.

From a source checkout:

```bash
ollama pull qwen3:4b
ollama create saugra-explainer:v1 -f configs/ollama/Modelfile
ollama show --modelfile saugra-explainer:v1
```

From a Debian package installation:

```bash
ollama pull qwen3:4b
ollama create saugra-explainer:v1 -f /etc/saugra-waf/ollama/Modelfile
ollama show --modelfile saugra-explainer:v1
```

Configure Saugra:

```yaml
ai:
  enabled: true
  mode: explain_only
  provider: ollama
  ollama_url: http://127.0.0.1:11434
  model: saugra-explainer:v1
  prompt_version: saugra-explain-v1
  timeout: 60s
```

Validate and test:

```bash
saugra-waf test-config
saugra-waf explain <request-id>
tail -n 1 /var/log/saugra-waf/saugra-waf-ai-audit.jsonl
```

The audit record should show `provider: ollama`, the configured model, a
SHA-256 input digest, latency, output, and `fallback_used: false`. If
`fallback_used` is true, inspect Ollama and Saugra logs.

## Hardware and Model Selection

`qwen3:4b` is the default because it is small enough for many developer and
single-server environments while retaining useful instruction-following
ability. Ollama currently lists it at approximately 2.5 GB before runtime
overhead.

Practical starting points:

| Environment | Suggested model | Notes |
| --- | --- | --- |
| Less than 2 GB RAM | No model | Use `enabled: false` or `provider: local`. |
| 2-3 GB RAM, 1-2 CPU cores | `qwen3:0.6b` | Development use; explanation quality needs close review. |
| 4 GB RAM, 2 CPU cores | `qwen3:1.7b` | Minimum practical local model for occasional explanations. |
| 8 GB RAM, 4 CPU cores | `qwen3:4b` | Recommended minimum for the default model on a shared host. |
| 12 GB or more RAM | `qwen3:8b` | Better language quality with more latency and storage. |

Leave capacity for Saugra, Redis, the reverse proxy, and the application. Do
not let Ollama memory pressure degrade request forwarding. Explanation runs
from the operator CLI, outside the blocking request path.

In CPU-only development testing, `qwen3:4b` used approximately 3.5 GB of
runtime memory and bounded explanations took roughly 39-55 seconds. Do not use
that model on a 4 GB host shared with production services.

## Evaluation Before Rollout

Do not select a model because one example looks good. Evaluate a fixed,
sanitized case set before changing production configuration.

The repository and Debian package include sanitized regression fixtures:

```txt
configs/ollama/evaluation-cases.jsonl
/etc/saugra-waf/ollama/evaluation-cases.jsonl
```

For each case:

1. Submit only the `input` object to the candidate model with Saugra's system
   policy and structured-output schema.
2. Confirm every `must_include` item is represented semantically.
3. Reject output containing any `must_not_include` item.
4. Reject suggestion kinds outside `allowed_suggestion_kinds`.
5. Reject output exceeding `maximum_suggestions`.
6. Confirm valid JSON, stable latency, and no invented request details.
7. Compare against the deterministic Saugra explanation.

Add reviewed false-positive and attack cases from your environment only after
sanitization. Never place raw request bodies, query values, cookies,
authorization headers, passwords, tokens, API keys, client IP addresses, or
personal data in an evaluation file.

Record at least:

- Ollama version;
- model name and digest from `ollama list`;
- Saugra prompt version;
- evaluation case version or commit;
- pass/fail result per case;
- p50 and p95 latency;
- reviewer and review date.

Promote a candidate model only when it passes privacy, schema, hallucination,
and tuning-scope checks. Keep `provider: local` available as an immediate
rollback.

## Model Upgrade and Rollback

Never replace the active custom model tag in place. Create a new version:

```bash
ollama pull qwen3:4b
ollama create saugra-explainer:v2 -f configs/ollama/Modelfile
ollama list
```

Evaluate `v2`, then change only:

```yaml
ai:
  model: saugra-explainer:v2
```

Run `saugra-waf test-config` and explain retained sample request IDs. Roll back
by restoring `saugra-explainer:v1`, or set `provider: local` to stop model
calls entirely.

Updating Ollama and updating a model are separate operations. On Linux, the
official installer supports rerunning the install script and pinning a specific
Ollama version with `OLLAMA_VERSION`. Record the old binary and model versions
before upgrading.

## Fine-Tuning and Adapter Import

Saugra does not train models online and does not train from live request logs.
Start with prompt and `Modelfile` customization. Fine-tuning is justified only
after repeated evaluation shows a stable gap that prompts cannot solve.

If a separately reviewed training pipeline produces a supported Safetensors,
GGUF, or LoRA/QLoRA adapter, Ollama can import it through `FROM` or `ADAPTER` in
a separate `Modelfile`. Keep that build outside the Saugra service account and
outside production hosts.

Training-data requirements:

- explicit authorization to use every sample;
- irreversible removal of secrets and personal data;
- route shapes instead of raw identifiers;
- query parameter names without values;
- balanced legitimate, false-positive, and attack examples;
- separate train, validation, and holdout sets;
- provenance, retention, deletion, and reviewer records;
- no automatic collection from Saugra event or AI audit logs.

Treat imported weights and adapters as software artifacts: scan them, verify
their license, record a checksum, version them immutably, evaluate them against
the holdout set, and require human approval before production use.

## Monitoring and Troubleshooting

Linux service checks:

```bash
systemctl status ollama --no-pager
journalctl -u ollama -n 100 --no-pager
curl -s http://127.0.0.1:11434/api/version
ollama list
ollama ps
```

Saugra checks:

```bash
saugra-waf test-config
saugra-waf explain <request-id>
tail -n 20 /var/log/saugra-waf/saugra-waf-ai-audit.jsonl
```

Common failure states:

| Symptom | Action |
| --- | --- |
| `fallback=true` | Check Ollama service, URL, model name, timeout, and audit failure field. |
| Model not found | Run `ollama pull <model>` or create the configured custom tag. |
| Slow explanations | Use a smaller model, enable GPU support, or increase `ai.timeout` after measuring latency. The default is 60 seconds; Ollama output is capped at 256 tokens and one concise suggestion for CPU-only hosts. |
| Invalid JSON | Recreate the custom model, verify the base model supports instructions well, and retain deterministic fallback. |
| Out of memory | Stop larger models, choose a smaller model, and verify application memory headroom. |
| Unexpected suggestions | Reject them, retain the audit record, and tighten/evaluate the model; Saugra will not apply them. |

Ollama must remain on loopback. Do not publish port `11434` through Nginx,
Apache, a firewall, container port mapping, or a cloud security group.

## Backup and Recovery

Back up Saugra's `Modelfile`, active YAML configuration, evaluation cases, and
evaluation records. Base model blobs can normally be pulled again, so prefer
recording model names and digests over copying large caches.

For custom imported weights or adapters, maintain an access-controlled artifact
backup with checksums and license/provenance metadata. Recovery is complete
when the model tag can be recreated, `ollama list` shows it, Saugra validates,
and the evaluation suite passes.

## Official Ollama References

- [Linux installation](https://docs.ollama.com/linux)
- [macOS installation](https://docs.ollama.com/macos)
- [Windows installation](https://docs.ollama.com/windows)
- [Generate API](https://docs.ollama.com/api/generate)
- [Structured outputs](https://docs.ollama.com/capabilities/structured-outputs)
- [Modelfile reference](https://docs.ollama.com/modelfile)
- [Importing models and adapters](https://docs.ollama.com/import)
