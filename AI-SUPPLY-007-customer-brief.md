# New Arckon Detection: Hidden Backdoors in Local/Private AI Models (AI-SUPPLY-007)

## What just happened

A recent security research publication described how a time-triggered backdoor can be inserted into a local or private AI model and then silently activated by a future date. Because the weights and configuration of a locally hosted model are entirely under the deployer's control, a malicious insider or compromised supply-chain step can modify the model so that, after a certain date, it injects instructions that the agent carrying it out — for example OpenCode, Claude Code, or similar coding agents — then executes on the developer machine or production environment.

This is different from ordinary software supply-chain attacks: the malicious behavior is stored inside the model weights themselves, not in the surrounding code, so it can bypass static analysis and normal vulnerability scans.

## What Arckon now scans for

The `AI-SUPPLY-007` check in Arckon detects the exploitable configuration chain that makes this backdoor possible:

1. **A local or open-weight model is wired into an agent or IDE**
   - The scan looks for references to `localhost`/`127.0.0.1`/`:11434` (Ollama) or other self-hosted endpoints in:
     - OpenCode agent configuration files (`.config/opencode/agents/*.md`)
     - Claude Code / Claude for Desktop settings (`.claude/settings.json`, `.claude/settings.local.json`)
     - Common shell/runtime configuration files (`.bashrc`, `.zshrc`, `.*rc`, scripts, Dockerfiles, YAML manifests, etc.)
   - It recognizes compact JSON, YAML, and single-quoted model references.

2. **The agent harness can execute shell commands without per-call approval**
   - OpenCode: unscoped `Bash(*)` or similar execution permissions in agent files.
   - Claude Code: `bypassPermissions: true`, or `Bash` enabled without explicit user prompts.
   - Generic: `ollama run` / `ollama exec` patterns that expose a shell.

3. **Sleeper / time-trigger behavior**
   - Date-based activation checks in scripts or model wrapper code (`Date`, `new Date`, `datetime`, `>= 2026`, etc.) combined with the local model reference.

## Finding severity

- **CRITICAL / FAIL** — A local/open-weight model is connected to an agent that can run shell commands unattended. This is the exact chain described in the backdoor article. Immediate review is required.
- **HIGH / WARN** — The agent is configured to use a model from an unofficial Ollama publisher namespace. These images are not verified by the original model author and are a common vector for tampered weights.
- **MEDIUM / WARN** — A local model is present, but the current agent configuration requires explicit human approval before executing commands. Risk is reduced, but the model weights remain unverifiable; any local model should still be inspected.
- **PASS / SKIP** — The scan finds only hosted-API usage (OpenAI, Anthropic, Azure, AWS Bedrock, Google Vertex, etc.) and no local model wiring.

## What Arckon tells the user

When a failure or warning is found, Arckon returns a plain-English remediation block that tells the user exactly what to do:

- Remove the local model wiring from the agent configuration and switch to a hosted API or a model signed by a trusted provider.
- Disable `bypassPermissions` / unscoped `Bash(*)` execution.
- Require per-command human approval for any shell execution.
- Audit the source of the model weights (official Hugging Face repo, verified Ollama library namespace, or your own trained checkpoint) and re-pull from a known-good source.
- Review the flagged file for time/date comparisons that could act as delayed triggers.

The finding includes the specific file path, line context, the model name or endpoint detected, and the execution permission that created the risk.

## Availability

Detection `AI-SUPPLY-007` is included in the default Arckon profile beginning with agent release **v1.0.16**. It runs automatically during the standard device scan. No manual policy configuration is required.

For questions or to request a focused review, contact the Arckon team.
