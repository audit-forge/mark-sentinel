# Arckon Customer User Guide

## Purpose

Arckon identifies AI security exposure across endpoints, Docker hosts, and Kubernetes clusters. Use this guide to understand the dashboard, respond to findings, and recover agents that stop reporting.

## Daily Dashboard Review

Open **Home** in Arckon and review the summary cards first.

| Dashboard item | What it means | What to do |
| --- | --- | --- |
| Devices | Enrolled endpoints, Docker hosts, and Kubernetes clusters | Confirm expected devices are present and recently seen. |
| Critical / High | Findings needing prompt review | Open the device report and validate the evidence. |
| Medium | Findings that should be planned into normal remediation | Review during weekly security operations. |
| Low / Info | Inventory and awareness information | Track trends; remediate when appropriate. |
| Shadow AI | AI services or tools discovered outside managed inventory | Confirm business ownership and approval status. |
| MCP Servers | Model Context Protocol servers discovered on devices | Review exposed tools, permissions, and authentication. |

The Home page refreshes automatically. After **Scan All**, it refreshes at approximately 15, 30, and 60 seconds. A scan can take longer than a refresh cycle; the Profile column changes after the device uploads a completed report.

## Understanding Devices

The device table is grouped by scan type.

| Group | Meaning | Expected profile behavior |
| --- | --- | --- |
| Endpoints | Windows, macOS, and Linux user or server devices | Uses the customer Default Device Scan profile. |
| Docker | Docker host/container security inventory | Always uses the Docker security profile. |
| Kubernetes | Kubernetes cluster inventory | Always uses the Kubernetes security profile. |

Two rows with the same hostname are not automatically merged. They can be separate agents, a reinstalled agent with a new identity, or an old agent service still running. Do not remove a record until the source process has been identified and stopped.

## Selecting a Default Device Scan

1. Open **Settings**.
2. Choose **Default Device Scan**.
3. Select the profile that matches your organization.
4. Select **Save**.

The selected profile is sent to online endpoint agents. It is also used by newly enrolled endpoint agents, scheduled scans, and Scan All when no temporary override is selected.

Use the profile menu beside **Scan All** only for a one-time override. Leave it as **Customer default** for normal operation.

## Common Profiles

| Profile | Use when |
| --- | --- |
| Base Scan | General AI security inventory and baseline controls. |
| OWASP Agentic AI Top 10 | The organization builds, deploys, or uses AI agents and tool-enabled workflows. |
| ISO 42001 | The organization operates an AI management system or is preparing for ISO/IEC 42001. |
| FedRAMP / NIST 800-53 | A federal or regulated environment needs NIST control evidence. |
| CMMC 2.0 | Defense supply-chain requirements apply. |
| Healthcare or Biotech | HIPAA, FDA, GxP, clinical, or life-sciences requirements apply. |
| Financial Services | Financial-sector governance and control expectations apply. |
| Professional Services | Client-delivery and consulting organizations need governance evidence. |

## Running a Scan

### Scan every device

1. On **Home**, leave the profile selector set to **Customer default**.
2. Choose a stagger rate.
3. Select **Scan All**.

Use **Normal** unless there is a specific need to finish faster. It reduces concurrent load on endpoints and networks.

### Scan one device

1. Find the device on Home.
2. Select **Scan**.
3. Leave profile choices empty to use the saved customer default, or select a profile for a one-time scan.

### Expected timing

Agents poll for commands about every 15 seconds. The scan then runs locally and uploads its report. A device can take longer when its target has many files, the system is busy, or it is not connected to the network.

## Reading a Finding

Open a device's **Full Report** or select the device in **Findings**. Review these fields in order:

1. **Check ID and title:** identifies the control being evaluated.
2. **Severity:** prioritizes review, not automatic proof of compromise.
3. **What we found / evidence:** the concrete path, configuration, process, or network observation.
4. **Mapped controls:** shows regulatory or framework relevance.
5. **Recommended fix:** a starting remediation; validate impact before making production changes.

### Alert triage steps

1. Confirm the device and timestamp are current.
2. Confirm the evidence is reachable or still configured.
3. Determine whether the exposure is accessible to an unauthorized user, process, network, or tenant.
4. Check whether a compensating control prevents access.
5. Apply the least disruptive remediation that removes the exposure.
6. Run a targeted scan and confirm the finding clears or document an approved exception.

## Example: Claude Code Permission Finding

**Finding:** `AI-TOOL-002 — Claude Code CLI config files are world-readable`

This finding appears in **Home** under the affected device's findings, in **Findings**, and in the device **Full Report**. It is included in reports generated from **Reports**.

### Is it a real risk?

It is a real risk only when another local user can both traverse the parent directory and read the file. Claude Code files may contain session state, local settings, prompt history, or credentials.

On macOS and Linux, a file mode such as `644` does not expose the file if its parent `~/.claude` directory is mode `700`. Other users cannot enter the directory. In that case, treat the alert as a false positive and validate the parent-directory mode before changing permissions.

### Validate safely

```sh
stat -f '%Sp %N' ~/.claude ~/.claude/settings.local.json
```

Expected secure example:

```text
drwx------ ~/.claude
-rw-r--r-- ~/.claude/settings.local.json
```

### Remediate a real exposure

If `~/.claude` is traversable by other users, restrict the directory and file access:

```sh
chmod 700 ~/.claude
find ~/.claude -type f -exec chmod 600 {} +
```

Do not use `chmod -R 700 ~/.claude`: it marks every file executable unnecessarily.

## When a Device Is Not Updating

### Symptoms

- Last Seen is old.
- The profile remains unchanged after a baseline change.
- Scan All reports queued but there is no new report.
- Device commands remain pending.

### Windows

1. Confirm the device is online and can reach the Arckon server.
2. Open Services and confirm **ArckonAgent** is running.
3. Restart the service if necessary.
4. Confirm `C:\ProgramData\Arckon\agent_config.json` contains the correct server URL and token.
5. Run a single-device scan from Home and wait for the report upload.

### macOS

1. Confirm the device is online and can reach the Arckon server.
2. Confirm the service is loaded:

```sh
sudo launchctl print system/ai.mfdynamics.arckon-agent
```

3. Confirm the installed agent and active configuration are present:

```sh
sudo ls -l /opt/arckon/agent /opt/arckon/agent_config.json
```

4. Review the agent log:

```sh
sudo tail -100 /var/log/arckon-agent.log
```

5. If the launchd job references an old Python path or missing virtual environment, reinstall or upgrade the agent using the current compiled-agent installer. Do not run multiple legacy and current agent services simultaneously.

### Linux

1. Confirm network reachability to the Arckon server.
2. Check the canonical service:

```sh
sudo systemctl status arckon-agent
sudo journalctl -u arckon-agent --since '30 minutes ago'
```

3. Confirm that obsolete `sentinel-agent` services are disabled before removing old dashboard records.

## Shadow AI and MCP Review

### Shadow AI

For every discovered AI service:

1. Identify the business owner.
2. Confirm it is approved for the data it processes.
3. Confirm authentication, data handling, retention, and vendor risk review.
4. Remove unapproved tokens, integrations, or network access when there is no business justification.

### MCP Servers

For every discovered MCP server:

1. Confirm the server owner and intended users.
2. Review every exposed tool and its filesystem, shell, database, or network permissions.
3. Require authentication and least-privilege credentials.
4. Remove tools that are not necessary.
5. Re-scan after remediation.

## Escalation Guidance

Escalate immediately when a finding indicates exposed credentials, public administration interfaces, unrestricted tool execution, unknown AI services processing sensitive data, or a Critical/High finding that cannot be validated as a false positive.

Include the device name, check ID, evidence, timestamp, business owner, remediation status, and any approved exception in the escalation record.
