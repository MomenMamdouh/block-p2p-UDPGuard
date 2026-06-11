#!/bin/bash
# ==============================================================================
# 3x-ui / Xray Multi-Layered Torrent Traffic Blocker (Corrected Path)
# Uses Xray Application Decryption + Dynamic Native IPset Firewall Ban
# ==============================================================================

if [ "$(id -u)" != "0" ]; then
   echo "[-] This script must be run as root." >&2
   exit 1
fi

# ------------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------------
IPSET_NAME="vless_torrent_block"
XRAY_LOG="/etc/x-ui/access.log"
BAN_DURATION=18000   # 5 Hours
MAX_ENTRIES=200000

# ------------------------------------------------------------------------------
# NETWORK ENVIRONMENT SETUP
# ------------------------------------------------------------------------------
SERVER_IPS=$(ip -o addr show | awk '!/^[0-9]+: lo:/ && $3 == "inet" {split($4, a, "/"); print a[1]}')

is_server_ip() {
    local ip=$1
    for server_ip in $SERVER_IPS; do
        if [ "$ip" == "$server_ip" ]; then return 0; fi
    done
    return 1
}

is_dns_ip() {
    local ip=$1
    local dns_ips=("8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1")
    for dns_ip in "${dns_ips[@]}"; do
        if [ "$ip" == "$dns_ip" ]; then return 0; fi
    done
    return 1
}

is_ignored_ip_range() {
    local ip=$1
    if [[ $ip =~ ^10\.9\.[0-3]\.[0-9]{1,3}$ ]] || [[ $ip =~ ^10\.8\.[0-3]\.[0-9]{1,3}$ ]]; then
        return 0
    fi
    return 1
}

# ------------------------------------------------------------------------------
# INITIALIZE FIREWALL LAYERS
# ------------------------------------------------------------------------------
echo "[+] Initializing ipset with native timeout rules..."
if ! ipset list -n | grep -qw "$IPSET_NAME"; then
    ipset create "$IPSET_NAME" hash:ip timeout "$BAN_DURATION" maxelem "$MAX_ENTRIES"
fi

echo "[+] Injecting blocking rules into Netfilter (iptables)..."
iptables-save | grep -v "$IPSET_NAME" | iptables-restore
iptables -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP
iptables -I FORWARD -m set --match-set "$IPSET_NAME" src -j DROP

cleanup() {
    echo -e "\n[-] Stopping monitor and cleaning firewall rules..."
    iptables-save | grep -v "$IPSET_NAME" | iptables-restore
    exit 0
}
trap cleanup SIGINT SIGTERM

# ------------------------------------------------------------------------------
# REAL-TIME PARSING ENGINE
# ------------------------------------------------------------------------------
if [ ! -f "$XRAY_LOG" ]; then
    echo "[-] Error: Xray access log file not found at $XRAY_LOG"
    exit 1
fi

echo "[+] System fully armed. Monitoring decrypted Xray streams..."
echo "[+] Matching outbound tag: [blocked]"

tail -Fn0 "$XRAY_LOG" | while read -r line; do
    if echo "$line" | grep -q "\[blocked\]"; then
        
        # التقاط أول IPv4 يظهر في السطر وتنظيفه من الـ Port
        client_ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?' | head -n 1 | cut -d':' -f1)

        if [ -n "$client_ip" ]; then
            if is_server_ip "$client_ip" || is_dns_ip "$client_ip" || is_ignored_ip_range "$client_ip"; then
                continue
            fi

            # إضافة الحظر الفوري في النواة (Kernel)
            if ! ipset test "$IPSET_NAME" "$client_ip" 2>/dev/null; then
                echo "[BAN] Torrent detected from client: $client_ip. Dropping firewall access."
                ipset add "$IPSET_NAME" "$client_ip" -exist
            fi
        fi
    fi
done
