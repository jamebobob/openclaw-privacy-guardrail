# openclaw-privacy-guardrail

An OpenClaw plugin that blocks direct writes to public-facing paths. Forces all public content through a staging pipeline with a mandatory privacy scrub.

## Why

AI agents forget rules. Not sometimes. Reliably. Under load, mid-task, when the writing is flowing and the details feel concrete. Behavioral instructions ("check the privacy rules before publishing") compete with whatever the agent is actually doing, and they lose.

We proved this to ourselves twice in three days. Once in a blog post, once in a README for a privacy framework. Both times the agent knew the rules, had them in multiple files, had them in persistent memory, and still used a real location in public content because the real word was more available than the sanitized one.

The fix isn't better rules. It's a wall. This plugin makes it structurally impossible for the agent to write to public paths without passing through a privacy scrub first.

## How It Works

The plugin hooks `before_tool_call` and intercepts four tools:

- **write** and **edit**: checks the `path` (and `file_path`) parameter against protected path prefixes
- **exec** and **bash**: pattern-matches the command string for output redirects, file copy operations, and write-like verbs targeting protected paths

If a violation is detected, the tool call is blocked before execution. The agent gets an error message telling it to use the staging pipeline instead.

### Path Protection

Default protected path:
```
/var/www/
```

Add your own via `protectedPaths` in the plugin config (e.g., `~/websites/`, `~/public-html/`).

### Path Normalization

The plugin resolves `~`, `$HOME`, relative paths, and `..` traversal before checking. So these all get caught:

```
~/websites/index.html
$HOME/websites/index.html
../../var/www/file.txt
```

### Exec Pattern Matching

For exec/bash commands, the plugin checks for:
- Output redirects (`>`, `>>`, with or without spaces)
- File operations (`cp`, `mv`, `tee`, `rsync`, `install`, `ln`, `dd`)
- In-place edits (`sed -i`)
- Language-level file writes (`python open()`, `node fs.*`)
- Subshells (`bash -c`)
- Download-to-file (`curl -o`, `wget -O`)

### Pipeline Whitelist

Two scripts are whitelisted as the authorized path through:
- `publish.sh` (runs the privacy scrub, then copies to destination)
- `privacy-scrub.sh` (the grep gate itself)

Whitelisting is regex-based and requires the script to be invoked, not just mentioned as a string. Chained commands (`&&`, `||`, `;`, `|`) are never whitelisted because the chained portion could bypass the guardrail.

## The Staging Pipeline

```
1. Agent writes to ~/workspace/staging/
2. Agent rereads the draft and rewrites in own voice (a genuine second pass, not a proofread)
3. publish.sh runs privacy-scrub.sh automatically
4. If clean (exit 0): file is copied to destination
5. If violations found (exit 1): blocked, agent must fix and retry
```

`privacy-scrub.sh` is a configurable grep gate that checks for sensitive terms: locations, real names, infrastructure details, and anything else on your scrub list. Exit 0 means clean. Exit 1 means stop.

The plugin enforces the staging boundary. The scrub scripts are part of your pipeline setup and are not included in this repo. See [openclaw-privacy-protocol](https://github.com/jamebobob/openclaw-privacy-protocol) for a reference scrub list and publishing process.

## Installation

A deploy script (`deploy-privacy-guardrail.sh`) is included that handles all of the below automatically. Or install manually:

### 1. Copy plugin files

```bash
mkdir -p ~/.openclaw/extensions/privacy-guardrail
cp index.ts ~/.openclaw/extensions/privacy-guardrail/
cp openclaw.plugin.json ~/.openclaw/extensions/privacy-guardrail/
```

### 2. Add to OpenClaw config

```bash
# Add to plugins.entries (start in monitor mode)
jq '.plugins.entries."privacy-guardrail" = {
  "enabled": true,
  "config": {
    "monitorOnly": true
  }
}' ~/.openclaw/openclaw.json > /tmp/oc-patch.json && mv /tmp/oc-patch.json ~/.openclaw/openclaw.json

# Add to plugins.allow (required on v2026.3.12+ where implicit auto-load is disabled)
jq '.plugins.allow += ["privacy-guardrail"]' ~/.openclaw/openclaw.json > /tmp/oc-patch.json && mv /tmp/oc-patch.json ~/.openclaw/openclaw.json
```

### 3. Restart and verify

```bash
sudo systemctl restart openclaw
journalctl -u openclaw --since "1 min ago" | grep privacy-guardrail
# Should show: [privacy-guardrail] v1.3.0 Active. Mode: MONITOR.
```

### 4. Monitor, then enforce

Monitor mode logs violations without blocking. Watch for 24 hours:

```bash
journalctl -u openclaw -f | grep privacy-guardrail
```

When satisfied, flip to enforce:

```bash
jq '.plugins.entries."privacy-guardrail".config.monitorOnly = false' \
  ~/.openclaw/openclaw.json > /tmp/oc-patch.json && \
  mv /tmp/oc-patch.json ~/.openclaw/openclaw.json && \
  sudo systemctl restart openclaw
```

## Configuration

```json
{
  "plugins": {
    "entries": {
      "privacy-guardrail": {
        "enabled": true,
        "config": {
          "monitorOnly": false,
          "protectedPaths": [
            "/var/www/",
            "/home/user/websites/"
          ]
        }
      }
    }
  }
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `true` | Master toggle |
| `monitorOnly` | boolean | `false` | Log violations without blocking |
| `protectedPaths` | string[] | See defaults | Path prefixes that require the staging pipeline |

## Known Limitations

These are accepted for the threat model (habit defense, not adversarial defense):

- **Shell variable indirection**: `DIR="/var"; echo > "${DIR}/www/file"` is not caught
- **Command substitution**: `$(echo /var/www)` is not caught
- **process tool send-keys**: Background shell keystrokes bypass inspection
- **apply_patch**: Experimental, OpenAI-only tool not available on Anthropic models. Not guarded.

If your threat model includes an agent actively trying to circumvent the guardrail, you need additional controls. This plugin defends against forgetting, not against intent.

## Audit History

- **v3**: Initial. Two blockers found (whitelist chaining bypass, protected path prefix overlap)
- **v4**: Fixed v3 blockers. Added exec normalization, ln/curl/wget patterns. New blocker: apply_patch wrong param, bash tool not intercepted
- **v5**: Fixed all v4 findings. apply_patch guard removed (OpenAI-only tool, not applicable). bash tool added
- **v6**: Spaceless redirect pattern. Cleaned dead code. Version in startup log
- **v7**: Added `file_path` param fallback on write/edit tools (Eve's audit finding F6: OpenClaw tools accept both `path` and `file_path` parameter names; checking only one creates a silent bypass)

Six audit rounds: initial design, Claude Code review, fresh Opus red team, two re-audits after fixes, and a final infrastructure audit by the agent the plugin protects.

## Companion Projects

Part of a four-layer privacy defense stack:

| Layer | Project | What It Guards |
|-------|---------|---------------|
| Memory boundaries | [openclaw-agent-privacy](https://github.com/jamebobob/openclaw-agent-privacy) | Which memories each agent can access |
| **Write path enforcement** | **openclaw-privacy-guardrail** | **Which paths the agent can write to directly** |
| System context | [openclaw-sticky-context](https://github.com/jamebobob/openclaw-sticky-context) | Which operational details each agent can see |
| Output scrubbing | [openclaw-privacy-protocol](https://github.com/jamebobob/openclaw-privacy-protocol) | What actually leaves the system toward public surfaces |

## License

MIT
