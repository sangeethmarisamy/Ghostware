#!/bin/bash
# response_agent.sh — reads anomaly JSON from stdin, validates the local IP
# against this machine's interfaces, then blocks the remote IP if the action
# says so.

set -euo pipefail

FIREWALL_SCRIPT="$(dirname "$0")/firewall_manager.sh"

# ── Read & parse JSON from stdin ─────────────────────────────────────────────
JSON=$(cat)

if [ -z "$JSON" ]; then
    echo "[RESPONSE AGENT] ERROR: No JSON input received on stdin."
    exit 1
fi

STATUS=$(echo "$JSON"   | jq -r '.status       // empty')
RISK=$(echo "$JSON"     | jq -r '.risk_level    // empty')
REASON=$(echo "$JSON"   | jq -r '.reason        // empty')
USERNAME=$(echo "$JSON"  | jq -r '.username      // empty')
LOCAL_IP=$(echo "$JSON"  | jq -r '.local_ip      // empty')
REMOTE_IP=$(echo "$JSON" | jq -r '.remote_ip     // empty')
ACTION=$(echo "$JSON"    | jq -r '.action        // empty')

echo "════════════════════════════════════════════════════════"
echo "  [RESPONSE AGENT] Anomaly Report"
echo "════════════════════════════════════════════════════════"
echo "  Status    : $STATUS"
echo "  Risk      : $RISK"
echo "  Reason    : $REASON"
echo "  User      : $USERNAME"
echo "  Local IP  : $LOCAL_IP"
echo "  Remote IP : $REMOTE_IP"
echo "  Action    : $ACTION"
echo "════════════════════════════════════════════════════════"

# ── Validate required fields ─────────────────────────────────────────────────
if [ -z "$LOCAL_IP" ] || [ -z "$REMOTE_IP" ] || [ -z "$ACTION" ]; then
    echo "[RESPONSE AGENT] ERROR: Missing required fields (local_ip, remote_ip, or action)."
    exit 1
fi

# ── Validate local IP belongs to this machine ────────────────────────────────
# Collect all IPv4 addresses assigned to local interfaces.
MACHINE_IPS=$(ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1)

LOCAL_IP_VALID=false
for ip_addr in $MACHINE_IPS; do
    if [ "$ip_addr" = "$LOCAL_IP" ]; then
        LOCAL_IP_VALID=true
        break
    fi
done

if [ "$LOCAL_IP_VALID" = false ]; then
    echo "[RESPONSE AGENT] WARNING: local_ip ($LOCAL_IP) does NOT match any interface on this machine."
    echo "[RESPONSE AGENT] Known IPs on this host:"
    echo "$MACHINE_IPS" | sed 's/^/    /'
    echo "[RESPONSE AGENT] Aborting — the alert may not belong to this host."
    exit 2
fi

echo "[RESPONSE AGENT] ✓ Local IP ($LOCAL_IP) verified on this machine."

# ── Execute action ───────────────────────────────────────────────────────────
case "$ACTION" in
    BLOCK_REMOTE_IP)
        echo "[RESPONSE AGENT] Blocking remote IP: $REMOTE_IP ..."

        if [ ! -x "$FIREWALL_SCRIPT" ]; then
            echo "[RESPONSE AGENT] ERROR: Firewall script not found or not executable: $FIREWALL_SCRIPT"
            exit 3
        fi

        "$FIREWALL_SCRIPT" "$REMOTE_IP"
        echo "[RESPONSE AGENT] ✓ Remote IP $REMOTE_IP has been blocked."
        ;;
    *)
        echo "[RESPONSE AGENT] No defensive action required (action=$ACTION)."
        ;;
esac
