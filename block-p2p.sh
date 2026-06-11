#!/bin/bash
# ==============================================================================
# Xray Multi-Layered Torrent Traffic Blocker (Modified for "blocked" tag)
# Uses Xray Application Decryption + Dynamic Native IPset Firewall Ban
# ==============================================================================

# Ensure the script is running as root
if [ "$(id -u)" != "0" ]; then
   echo "[-] This script must be run as root." >&2
   exit 1
fi

# ------------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------------
IPSET_NAME="vless_torrent_block"
XRAY_LOG="/var/log/xray/access.log"
BAN_DURATION=18000   # Time in seconds to ban the client IP (18000s = 5 hours)
MAX_ENTRIES=200000

# ------------------------------------------------------------------------------
# NETWORK ENVIRONMENT SETUP
# ------------------------------------------------------------------------------
# Collect all local server IPs to prevent accidental self-blocking
SERVER_IPS=$(ip -o addr show | awk '!/^[0-9]+: lo:/ && $3 == "inet" {split($4, a, "/"); print a[1]}')

is_server_ip() {
    local ip=$1
    for server_ip in $SERVER_IPS; do
        if [ "$ip" == "$server_ip" ]; then return 0; fi
    done
    return 1
}

# Whitelist common DNS servers
is_dns_ip() {
    local ip=$1
    local dns_ips=("8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1")
    for dns_ip in "${dns_ips[@]}"; do
        if [ "$ip" == "$dns_ip" ]; then return 0; fi
    done
    return 1
}

# Whitelist infrastructure/management subnets (e.g., internal VPN pools)
is_ignored_ip_range() {
    local ip=$1
    # Matches 10.8.0.0/22 and 10.9.0.0/22 range loops safely
    if [[ $ip =~ ^10\.9\.[0-3]\.[0-9]{1,3}$ ]] || [[ $ip =~ ^10\.8\.[0-3]\.[0-9]{1,3}$ ]]; then
        return 0
    fi
    return 1
}

# ------------------------------------------------------------------------------
# INITIALIZE FIREWALL LAYERS
# ------------------------------------------------------------------------------
echo "[+] Initializing ipset with native timeout rules..."
# Create ipset with a default timeout capability. The OS automatically handles
# deletion when the timer expires. Zero process overhead!
if ! ipset list -n | grep -qw "$IPSET_NAME"; then
    ipset create "$IPSET_NAME" hash:ip timeout "$BAN_DURATION" maxelem "$MAX_ENTRIES"
fi

echo "[+] Injecting blocking rules into Netfilter (iptables)..."
# Clear older instances of the matching ipset rules to prevent duplication
iptables-save | grep -v "$IPSET_NAME" | iptables-restore

# Insert drop rules at the top of INPUT and FORWARD chains
iptables -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP
iptables -I FORWARD -m set --match-set "$IPSET_NAME" src -j DROP

# ------------------------------------------------------------------------------
# CLEANUP ENGINE
# ------------------------------------------------------------------------------
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
    echo "[-] Please verify your log path in 3x-ui Panel Settings."
    exit 1
fi

echo "[+] System fully armed. Monitoring decrypted Xray streams..."
echo "[+] Matching outbound tag: [blocked]"
echo "[+] Banned users will be locked out for $BAN_DURATION seconds."

tail -Fn0 "$XRAY_LOG" | while read -r line; do
    # Modified to look for your default [blocked] tag
    if echo "$line" | grep -q "\[blocked\]"; then
        
        # Parse out the underlying connecting client IP address
        # Handles standard VLESS log format: "accepted tcp:192.168.1.50:54321 bound to..."
        client_ip=$(echo "$line" | grep -oP 'accepted (tcp|udp):\K[0-9.]+(?=:)')

        if [ -n "$client_ip" ]; then
            # Verify the IP is valid and not part of infrastructure protection
            if [[ $client_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                if is_server_ip "$client_ip" || is_dns_ip "$client_ip" || is_ignored_ip_range "$client_ip"; then
                    continue
                fi

                # Commit the ban directly into the Linux Kernel space
                if ! ipset test "$IPSET_NAME" "$client_ip" 2>/dev/null; then
                    echo "[BAN] Torrent detected from client: $client_ip. Dropping firewall access."
                    ipset add "$IPSET_NAME" "$client_ip" -exist
                fi
            fi
        fi
    fi
done
