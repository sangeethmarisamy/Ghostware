# 🛡️ Firewall Response Agent

An automated firewall response system that reads anomaly detection JSON output, validates the alert belongs to this machine, and blocks malicious remote IPs using `nftables`.

---

## 📁 Project Structure

```
firewall/
├── response_agent.sh    # Main script — parses JSON, validates, triggers block
├── firewall_manager.sh  # Low-level script — adds nftables drop rules
└── README.md
```

---

## ⚙️ Prerequisites

| Tool       | Purpose                        | Install (Debian/Ubuntu)          |
|------------|--------------------------------|----------------------------------|
| `bash`     | Shell interpreter              | Pre-installed                    |
| `jq`       | JSON parsing                   | `sudo apt install jq`            |
| `nftables` | Firewall rule management       | `sudo apt install nftables`      |
| `iproute2` | IP address detection (`ip`)    | Pre-installed                    |
| `sudo`     | Elevated privileges for `nft`  | Pre-installed                    |

---

## 🚀 Setup

```bash
# Clone or copy the project
cd firewall/

# Make scripts executable
chmod +x response_agent.sh firewall_manager.sh
```

---

## 📖 Usage

### Input Format

The script reads a JSON anomaly report from **stdin**. Expected format:

```json
{
    "status": "ANOMALY",
    "risk_level": "HIGH",
    "reason": "LOCAL_REMOTE_IP_MISMATCH",
    "username": "sangeeth",
    "local_ip": "10.143.202.209",
    "remote_ip": "10.83.235.209",
    "action": "BLOCK_REMOTE_IP"
}
```

### JSON Fields

| Field        | Description                                      | Required |
|--------------|--------------------------------------------------|----------|
| `status`     | Alert status (`ANOMALY`, `NORMAL`, etc.)         | No       |
| `risk_level` | Severity level (`HIGH`, `MEDIUM`, `LOW`)         | No       |
| `reason`     | Why the anomaly was flagged                      | No       |
| `username`   | User associated with the alert                   | No       |
| `local_ip`   | IP of the machine being protected                | **Yes**  |
| `remote_ip`  | IP of the attacker / suspicious source           | **Yes**  |
| `action`     | Action to take (`BLOCK_REMOTE_IP` to block)      | **Yes**  |

### Run the Script

**Inline JSON:**

```bash
echo '{
    "status": "ANOMALY",
    "risk_level": "HIGH",
    "reason": "LOCAL_REMOTE_IP_MISMATCH",
    "username": "sangeeth",
    "local_ip": "<YOUR_MACHINE_IP>",
    "remote_ip": "<IP_TO_BLOCK>",
    "action": "BLOCK_REMOTE_IP"
}' | ./response_agent.sh
```

**From a file:**

```bash
cat alert.json | ./response_agent.sh
```

**From another program's output:**

```bash
python3 anomaly_detector.py | ./response_agent.sh
```

### Find Your Machine's IP

```bash
ip -4 addr show | grep inet
```

Use the IP from your active interface (e.g., `wlo1`, `eth0`) as the `local_ip` value.

---

## 🔍 What the Script Does

1. **Reads** the JSON from stdin and parses all fields using `jq`
2. **Prints** a formatted anomaly report to the terminal
3. **Validates** that `local_ip`, `remote_ip`, and `action` are present
4. **Checks** that `local_ip` matches an actual IP on this machine's network interfaces — if it doesn't match, the script **aborts** (the alert may be for a different host)
5. **Blocks** the `remote_ip` using `nftables` when `action` is `BLOCK_REMOTE_IP`

### Exit Codes

| Code | Meaning                                        |
|------|------------------------------------------------|
| `0`  | Success                                        |
| `1`  | Missing JSON input or required fields          |
| `2`  | `local_ip` does not match any interface on host|
| `3`  | `firewall_manager.sh` not found / not executable|

---

## 🧪 Testing Between Two Laptops

### Setup

- **Laptop 1** (defender) — the machine running the firewall scripts
- **Laptop 2** (attacker) — the machine whose IP will be blocked
- Both laptops must be on the **same network** (same Wi-Fi / LAN)

### Step 1: Get Both IPs

On **Laptop 1** (defender):
```bash
ip -4 addr show | grep inet
# Example output: 10.143.202.209
```

On **Laptop 2** (attacker):
```bash
ip -4 addr show | grep inet
# Example output: 10.143.202.6
```

### Step 2: Verify Connectivity (Before Blocking)

On **Laptop 1**, ping Laptop 2:
```bash
ping -c 3 10.143.202.6
```
✅ You should see successful replies.

On **Laptop 2**, ping Laptop 1:
```bash
ping -c 3 10.143.202.209
```
✅ You should see successful replies.

### Step 3: Block Laptop 2

On **Laptop 1**, run:
```bash
echo '{
    "status": "ANOMALY",
    "risk_level": "HIGH",
    "reason": "LOCAL_REMOTE_IP_MISMATCH",
    "username": "sangeeth",
    "local_ip": "10.143.202.209",
    "remote_ip": "10.143.202.6",
    "action": "BLOCK_REMOTE_IP"
}' | ./response_agent.sh
```

Expected output:
```
[RESPONSE AGENT] ✓ Local IP (10.143.202.209) verified on this machine.
[RESPONSE AGENT] Blocking remote IP: 10.143.202.6 ...
[FIREWALL] Blocking IP: 10.143.202.6
[FIREWALL] IP blocked: 10.143.202.6
[RESPONSE AGENT] ✓ Remote IP 10.143.202.6 has been blocked.
```

### Step 4: Verify the Block

On **Laptop 2**, try to reach Laptop 1:
```bash
ping -c 3 10.143.202.209
```
❌ Should **timeout** — no replies (packets are being dropped).

On **Laptop 1**, verify the firewall rule exists:
```bash
sudo nft list ruleset
```
You should see:
```
table inet edgerunners {
    chain input {
        type filter hook input priority filter; policy accept;
        ip saddr 10.143.202.6 drop
    }
}
```

---

## 🔓 Unblocking an IP

### Unblock a Specific IP

```bash
# Find the rule handle number
sudo nft -a list chain inet edgerunners input

# Output example:
#   ip saddr 10.143.202.6 drop # handle 4

# Delete by handle number
sudo nft delete rule inet edgerunners input handle 4
```

**One-liner** (auto-detects the handle):

```bash
sudo nft delete rule inet edgerunners input handle $(sudo nft -a list chain inet edgerunners input | grep "10.143.202.6" | awk '{print $NF}')
```

### Flush All Rules (Nuclear Option)

```bash
sudo nft flush ruleset
```

> ⚠️ This removes **all** nftables rules, not just the ones added by this script.

### Verify Unblock

After removing the rule, test from Laptop 2:
```bash
ping -c 3 10.143.202.209
```
✅ Should work again.

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `jq: command not found` | Install jq: `sudo apt install jq` |
| `nft: command not found` | Install nftables: `sudo apt install nftables` |
| `local_ip does NOT match any interface` | Run `ip -4 addr show` and use the correct IP in your JSON |
| Script hangs at password prompt | Enter your sudo password, or run with `sudo ./response_agent.sh` |
| Block doesn't seem to work | Verify with `sudo nft list ruleset` — the rule should be listed |
| Ping still works after blocking | Make sure you blocked the correct IP; check with `sudo nft list ruleset` |

---

## 📝 License

Internal use.
