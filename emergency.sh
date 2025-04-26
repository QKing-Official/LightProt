#!/bin/bash
# emergency.sh - Ultimate Firewall and Network Rescue Script

set -e

echo "[*] Starting Emergency Firewall Flush..."

# 0. Stop custom DDoS/firewall services
kill_service() {
    local svc="$1"
    if systemctl list-units --type=service | grep -q "$svc"; then
        echo "[*] Stopping and disabling $svc..."
        systemctl stop "$svc"
        systemctl disable "$svc"
        if [ -f "/etc/systemd/system/$svc" ]; then
            echo "[*] Removing service file $svc..."
            rm -f "/etc/systemd/system/$svc"
            systemctl daemon-reload
        fi
    else
        echo "[*] Service $svc not found, skipping."
    fi
}

kill_service "ddos-protection.service"
kill_service "netfilter-persistent.service"
kill_service "firewalld.service"

# Timer function to attempt installing iptables with timeout
try_install_iptables() {
    echo "[*] Attempting to install iptables (timeout 40 seconds)..."
    if command -v timeout >/dev/null 2>&1; then
        timeout 40 bash -c "apt update && apt install iptables -y" || echo "[!] iptables install failed or timed out."
    else
        echo "[!] timeout command not available, skipping iptables install attempt."
    fi
}

# 1. Check for iptables
if command -v iptables >/dev/null 2>&1; then
    echo "[*] Flushing iptables rules..."
    iptables -F || true
    iptables -X || true
    iptables -t nat -F || true
    iptables -t nat -X || true
    iptables -t mangle -F || true
    iptables -t mangle -X || true
    iptables -P INPUT ACCEPT || true
    iptables -P FORWARD ACCEPT || true
    iptables -P OUTPUT ACCEPT || true
else
    echo "[!] iptables not found."
    try_install_iptables
    if command -v iptables >/dev/null 2>&1; then
        echo "[*] iptables installed successfully, flushing rules..."
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        iptables -t mangle -F
        iptables -t mangle -X
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
    else
        echo "[!] Still no iptables, moving to nftables and manual network recovery."
    fi
fi

# 2. Try nftables
if command -v nft >/dev/null 2>&1; then
    echo "[*] Flushing nftables rules..."
    nft flush ruleset || true
else
    echo "[!] nft not found, skipping."
fi

# 3. Try iptables-restore
if command -v iptables-restore >/dev/null 2>&1; then
    echo "[*] Applying empty iptables ruleset..."
    cat <<EOF | iptables-restore
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
EOF
else
    echo "[!] iptables-restore not found, skipping."
fi

# 4. Bring interfaces up
echo "[*] Bringing up all network interfaces..."
for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo"); do
    ip link set dev "$iface" up || true
    echo "[*] Interface $iface brought up."
done

# 5. Check default route
if ! ip route | grep -q default; then
    echo "[!] No default route detected!"
    echo "[!] You may need to manually add your gateway:"
    echo "    ip route add default via YOUR_GATEWAY_IP"
else
    echo "[*] Default route exists."
fi

echo "[*] Emergency rescue operations complete."
