// privacy-guardrail plugin for OpenClaw v1.3.0
// Blocks direct writes to protected public paths via write, edit, exec, and bash tools.
// Forces all public content through the staging pipeline (publish.sh).
//
// AUDIT HISTORY:
//   v3: Initial. Two BLOCKERs found (whitelist chaining bypass, prefix mismatch).
//   v4: Fixed v3 BLOCKERs + added exec normalization, ln/curl/wget patterns.
//       New BLOCKER found: apply_patch checks wrong param. bash tool not intercepted.
//   v5: Fixed all v4 findings. apply_patch removed (not available on Anthropic).
//       bash tool added. process send-keys documented as known limitation.
//   v6: Added spaceless redirect pattern (echo data>/path). Removed phantom
//       second protected path. Removed dead filePath fallback.
//       Startup log includes version for deploy verification.
//
// KNOWN LIMITATIONS (accepted for threat model):
//   - Shell variable indirection (DIR="/var"; echo > "${DIR}/www/file") not caught.
//   - Command substitution ($(echo /var/www)) not caught.
//   - process tool send-keys: if the agent opens a background shell via exec with
//     background:true, it can send-keys into it via the process tool. Those
//     keystrokes are not inspected by this plugin because toolName is "process",
//     not "exec". Low risk for habit-defense; the agent wouldn't deliberately open
//     a background shell to route around a guardrail.
//   - apply_patch: not guarded. It uses a single "input" param containing embedded
//     file paths (*** Add File: / *** Update File:), not a "path" param. However,
//     apply_patch is experimental, disabled by default, and OpenAI-only. If
//     apply_patch is ever enabled, this plugin needs a parser for the
//     patch format. See: https://docs.openclaw.ai/tools/apply-patch
//
// DEPLOYMENT NOTES:
//   - Requires explicit plugins.entries declaration on v2026.3.12+ (implicit
//     workspace auto-load disabled by GHSA-99qw-6mr3-36qr). Global extensions
//     dir is a separate path but may still need explicit enablement.
//   - Deploy order: copy files FIRST, then jq-patch openclaw.json, then restart.
//     Reverse order = gateway refuses to start (unknown plugin id error).
//   - Verify after deploy: journalctl -u openclaw --since "1 min ago" | grep privacy-guardrail
//     Must see "Active" line with version. If absent, plugin did not load.
//   - Hook priority 100 runs before mem0 (higher = first). Correct order.

import { homedir } from "os";

const PLUGIN_VERSION = "1.3.0";
const HOME = homedir();

// ---- CONFIGURATION ----
const ALLOWED_KEYS = new Set(["enabled", "protectedPaths", "monitorOnly"]);

const DEFAULT_PROTECTED_PATHS = [
  "/var/www/",
  // Add your own paths here, e.g.:
  // `${HOME}/websites/`,
];

// Whitelist: regex patterns that match the authorized pipeline commands.
// Must match the BEGINNING of the command or follow a path separator/space.
// This prevents bypass via embedding the string in unrelated commands
// (e.g., echo "workspace/tools/publish.sh" > /var/www/hack).
const PIPELINE_WHITELIST = [
  /(?:^|\/|\s)workspace\/tools\/publish\.sh\b/,
  /(?:^|\/|\s)workspace\/tools\/privacy-scrub\.sh\b/,
  /(?:^|\s)~\/.openclaw\/workspace\/tools\/publish\.sh\b/,
  /(?:^|\s)~\/.openclaw\/workspace\/tools\/privacy-scrub\.sh\b/,
  /(?:^|\s)\$HOME\/.openclaw\/workspace\/tools\/publish\.sh\b/,
  /(?:^|\s)\$HOME\/.openclaw\/workspace\/tools\/privacy-scrub\.sh\b/,
];

// Patterns that indicate output redirection or file copy in exec commands.
const EXEC_OUTPUT_PATTERNS = [
  /\s>/,             // redirect with space: cmd > /path
  /\s>>/,            // append with space: cmd >> /path
  />[^>]/,           // redirect without space: cmd>/path (catches echo data>/var/www)
  /\bcp\b/,          // copy
  /\bmv\b/,          // move
  /\btee\b/,         // tee
  /\brsync\b/,       // rsync
  /\binstall\b/,     // install command
  /\bsed\b.*-i/,     // sed in-place edit
  /\bpython3?\b.*open\s*\(/,  // python file write
  /\bnode\b.*fs\./,  // node fs operations
  /\bbash\s+-c\b/,   // bash -c subshell (check inner command for paths)
  /\bln\b/,          // symlink creation
  /\bcurl\b.*-[oO]/,  // curl download to file
  /\bwget\b.*-O/,    // wget download to file
];

// ---- HELPERS ----

/**
 * Check if a path starts with any protected prefix.
 * Returns the matched prefix or null.
 * Handles ~, $HOME, relative paths, and .. traversal.
 */
function matchesProtectedPath(filePath, protectedPaths) {
  if (!filePath || typeof filePath !== "string") return null;

  // Resolve ~ and $HOME to actual home directory for comparison
  let normalized = filePath
    .replace(/^~\//, `${HOME}/`)
    .replace(/^\$HOME\//, `${HOME}/`);

  // Resolve relative paths: if not absolute, treat as relative to workspace
  if (!normalized.startsWith("/")) {
    normalized = `${HOME}/.openclaw/workspace/${normalized}`;
  }

  // Collapse .. segments to prevent traversal bypass
  // e.g., /home/user/.openclaw/workspace/../../var/www -> /var/www
  const parts = normalized.split("/");
  const resolved = [];
  for (const part of parts) {
    if (part === "..") {
      resolved.pop();
    } else if (part !== "." && part !== "") {
      resolved.push(part);
    }
  }
  normalized = "/" + resolved.join("/");

  for (const prefix of protectedPaths) {
    if (normalized.startsWith(prefix)) {
      return prefix;
    }
  }
  return null;
}

/**
 * Check if an exec command is whitelisted (part of the pipeline).
 * Uses regex to ensure the whitelisted script is being INVOKED,
 * not just mentioned as a string in the command.
 * DOES NOT whitelist chained commands (&&, ||, ;, |) because
 * the chained portion could write to a protected path.
 */
function isWhitelistedCommand(command) {
  // If the command contains chaining operators, never whitelist.
  // Agents commonly chain commands with &&, and the chained part
  // could bypass the guardrail.
  if (/[;&|]{1,2}/.test(command)) {
    return false;
  }

  for (const pattern of PIPELINE_WHITELIST) {
    if (pattern.test(command)) {
      return true;
    }
  }
  return false;
}

/**
 * Check if an exec command writes to a protected path.
 * Returns { path, reason } or null.
 */
function checkExecViolation(command, protectedPaths) {
  if (isWhitelistedCommand(command)) return null;

  // Normalize ~ and $HOME in the command string before path matching
  // so that "echo x > ~/websites/file" is caught
  const normalizedCmd = command
    .replace(/~\//g, `${HOME}/`)
    .replace(/\$HOME\//g, `${HOME}/`);

  // Check if any output pattern + protected path combination exists
  for (const pattern of EXEC_OUTPUT_PATTERNS) {
    if (pattern.test(normalizedCmd)) {
      for (const prefix of protectedPaths) {
        if (normalizedCmd.includes(prefix)) {
          return { path: prefix, reason: "exec command writes to protected path" };
        }
      }
    }
  }

  // Also catch write-like verbs with protected path anywhere
  const writeVerbs = /\b(cp|mv|rsync|install|tee|dd|ln)\b/;
  if (writeVerbs.test(normalizedCmd)) {
    for (const prefix of protectedPaths) {
      if (normalizedCmd.includes(prefix)) {
        return { path: prefix, reason: "exec write-verb targets protected path" };
      }
    }
  }

  return null;
}

// ---- BLOCKED MESSAGE ----

function buildBlockMessage(toolName, targetPath, matchedPrefix) {
  return (
    `Privacy guardrail: ${toolName} targets a protected public path (${matchedPrefix}). ` +
    `Write to ~/.openclaw/workspace/staging/ first, then use ` +
    `~/.openclaw/workspace/tools/publish.sh to move the file through the privacy scrub.\n` +
    `Blocked path: ${targetPath}`
  );
}

// ---- PLUGIN REGISTRATION ----

export default function register(api) {
  const config = api.config?.plugins?.entries?.["privacy-guardrail"]?.config || {};

  // Validate config keys
  for (const key of Object.keys(config)) {
    if (!ALLOWED_KEYS.has(key)) {
      api.logger.warn(`[privacy-guardrail] Unknown config key: ${key}`);
    }
  }

  const enabled = config.enabled !== false;
  const monitorOnly = config.monitorOnly === true;
  const protectedPaths = config.protectedPaths || DEFAULT_PROTECTED_PATHS;

  if (!enabled) {
    api.logger.info(`[privacy-guardrail] v${PLUGIN_VERSION} disabled by config.`);
    return;
  }

  api.logger.info(
    `[privacy-guardrail] v${PLUGIN_VERSION} Active. ` +
    `Mode: ${monitorOnly ? "MONITOR" : "ENFORCE"}. ` +
    `Protected: ${protectedPaths.join(", ")}. ` +
    `Guarded: write, edit, exec, bash.`
  );

  // ---- BEFORE_TOOL_CALL HOOK ----
  api.on(
    "before_tool_call",
    async (event, ctx) => {
      const toolName = event.toolName;
      let violation = null;
      let targetPath = null;

      // ---- WRITE TOOL ----
      if (toolName === "write") {
        targetPath = event.params?.path || event.params?.file_path || "";
        const match = matchesProtectedPath(targetPath, protectedPaths);
        if (match) {
          violation = { path: match, reason: "write to protected path" };
        }
      }

      // ---- EDIT TOOL ----
      else if (toolName === "edit") {
        targetPath = event.params?.path || event.params?.file_path || "";
        const match = matchesProtectedPath(targetPath, protectedPaths);
        if (match) {
          violation = { path: match, reason: "edit of protected path" };
        }
      }

      // ---- EXEC / BASH TOOLS ----
      // bash is a separate tool from exec in group:runtime (exec, bash, process).
      // Both accept the same "command" parameter. Both must be guarded.
      else if (toolName === "exec" || toolName === "bash") {
        const command = event.params?.command || "";
        if (command) {
          const execResult = checkExecViolation(command, protectedPaths);
          if (execResult) {
            violation = execResult;
            targetPath = command.substring(0, 200);
          }
        }
      }

      // NOTE: apply_patch is NOT guarded. It uses a single "input" param with
      // embedded file paths, not a "path" param. It is also experimental,
      // disabled by default, and OpenAI-only. See header comment.

      // NOTE: process tool send-keys is NOT guarded. See header comment for
      // rationale. If the threat model changes to include adversarial defense,
      // this needs revisiting.

      // No violation found
      if (!violation) return;

      // ---- HANDLE VIOLATION ----
      const logMsg =
        `[privacy-guardrail] ${monitorOnly ? "MONITOR" : "BLOCKED"}: ` +
        `tool=${toolName}, path=${targetPath}, reason=${violation.reason}`;

      api.logger.warn(logMsg);

      if (monitorOnly) return;

      return {
        block: true,
        blockReason: buildBlockMessage(toolName, targetPath, violation.path),
      };
    },
    { name: "privacy-guardrail.before-tool-call", priority: 100 }
  );
}
