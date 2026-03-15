#!/bin/bash
# deploy-privacy-guardrail.sh
# Deploys the privacy-guardrail plugin to an OpenClaw instance.
#
# ORDER MATTERS:
#   1. Copy plugin files (so OpenClaw can discover the plugin id)
#   2. Patch openclaw.json (add plugins.entries with monitorOnly: true)
#   3. Restart gateway
#   4. Verify plugin loaded
#
# Reverse order = gateway refuses to start (unknown plugin id in entries).
#
# Usage: bash deploy-privacy-guardrail.sh
# Run from the directory containing the plugin files:
#   index.ts
#   openclaw.plugin.json

set -euo pipefail

PLUGIN_DIR="$HOME/.openclaw/extensions/privacy-guardrail"
CONFIG="$HOME/.openclaw/openclaw.json"
BACKUP="$HOME/.openclaw/openclaw.json.bak.privacy-guardrail"

echo "=== Privacy Guardrail Deploy ==="
echo ""

# ---- STEP 0: Pre-flight checks ----
echo "[0/4] Pre-flight checks..."

if [ ! -f "$CONFIG" ]; then
  echo "FATAL: $CONFIG not found. Is OpenClaw installed?"
  exit 1
fi

if ! command -v jq &> /dev/null; then
  echo "FATAL: jq not found. Install with: sudo apt install jq"
  exit 1
fi

# Check source files exist (look for both naming conventions)
SRC_TS=""
SRC_JSON=""

if [ -f "./index.ts" ]; then
  SRC_TS="./index.ts"
fi

if [ -f "./openclaw.plugin.json" ]; then
  SRC_JSON="./openclaw.plugin.json"
fi

if [ -z "$SRC_TS" ] || [ -z "$SRC_JSON" ]; then
  echo "FATAL: Plugin source files not found in current directory."
  echo "  Need: index.ts"
  echo "  Need: openclaw.plugin.json"
  exit 1
fi

echo "  Source TS:   $SRC_TS"
echo "  Source JSON: $SRC_JSON"
echo "  Config:      $CONFIG"
echo "  Target:      $PLUGIN_DIR"
echo ""

# ---- STEP 1: Copy plugin files ----
echo "[1/4] Copying plugin files..."

mkdir -p "$PLUGIN_DIR"
cp "$SRC_TS" "$PLUGIN_DIR/index.ts"
cp "$SRC_JSON" "$PLUGIN_DIR/openclaw.plugin.json"

echo "  Copied index.ts and openclaw.plugin.json to $PLUGIN_DIR"
echo ""

# ---- STEP 2: Backup and patch openclaw.json ----
echo "[2/4] Patching openclaw.json..."

cp "$CONFIG" "$BACKUP"
echo "  Backup: $BACKUP"

# Check if plugins.entries.privacy-guardrail already exists
if jq -e '.plugins.entries."privacy-guardrail"' "$CONFIG" > /dev/null 2>&1; then
  echo "  plugins.entries.privacy-guardrail already exists, updating config..."
  jq '.plugins.entries."privacy-guardrail".config.monitorOnly = true' \
    "$CONFIG" > /tmp/oc-patch.json && mv /tmp/oc-patch.json "$CONFIG"
else
  echo "  Adding plugins.entries.privacy-guardrail (monitorOnly: true)..."
  jq '.plugins.entries."privacy-guardrail" = {
    "enabled": true,
    "config": {
      "monitorOnly": true
    }
  }' "$CONFIG" > /tmp/oc-patch.json && mv /tmp/oc-patch.json "$CONFIG"
fi

echo "  Config patched. monitorOnly: true (monitor mode for 24h bake-in)."
echo ""

# ---- STEP 3: Restart gateway ----
echo "[3/4] Restarting OpenClaw..."

sudo systemctl restart openclaw
sleep 3
echo "  Restarted. Waiting 3s for startup..."
echo ""

# ---- STEP 4: Verify ----
echo "[4/4] Verifying..."

# Check service is running
if systemctl is-active --quiet openclaw; then
  echo "  [PASS] openclaw service is active"
else
  echo "  [FAIL] openclaw service is NOT active!"
  echo "  Check: journalctl -u openclaw --since '1 min ago' | tail -30"
  echo "  Rollback: cp $BACKUP $CONFIG && sudo systemctl restart openclaw"
  exit 1
fi

# Check plugin loaded (look for version string in logs)
sleep 2
if journalctl -u openclaw --since "30 sec ago" --no-pager 2>/dev/null | grep -q "privacy-guardrail.*v1.3.0.*Active"; then
  echo "  [PASS] privacy-guardrail v1.3.0 loaded and active"
elif journalctl -u openclaw --since "30 sec ago" --no-pager 2>/dev/null | grep -q "privacy-guardrail"; then
  echo "  [WARN] privacy-guardrail found in logs but version/status unclear"
  echo "  Check: journalctl -u openclaw --since '1 min ago' | grep privacy-guardrail"
else
  echo "  [FAIL] privacy-guardrail NOT found in startup logs!"
  echo "  The plugin may not have been discovered. Check:"
  echo "    journalctl -u openclaw --since '1 min ago' | grep -i plugin"
  echo "    journalctl -u openclaw --since '1 min ago' | grep -i privacy"
  echo "  If missing, the plugin was not loaded despite files being in place."
  echo "  Rollback: cp $BACKUP $CONFIG && sudo systemctl restart openclaw"
  exit 1
fi

echo ""
echo "=== Deploy complete ==="
echo ""
echo "Plugin is running in MONITOR mode (monitorOnly: true)."
echo "It will LOG violations but NOT block them."
echo ""
echo "Monitor for 24h with:"
echo "  journalctl -u openclaw -f | grep privacy-guardrail"
echo ""
echo "When ready to enforce, run:"
echo "  jq '.plugins.entries.\"privacy-guardrail\".config.monitorOnly = false' ~/.openclaw/openclaw.json > /tmp/oc-patch.json && mv /tmp/oc-patch.json ~/.openclaw/openclaw.json && sudo systemctl restart openclaw"
echo ""
echo "Rollback (if needed):"
echo "  cp $BACKUP $CONFIG && sudo systemctl restart openclaw"
