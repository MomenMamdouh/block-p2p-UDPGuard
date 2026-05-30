#!/bin/bash
# ---------------------------------------------------
# Bloqueo de tráfico BitTorrent con iptables + ipset
# ---------------------------------------------------
if [ "$(id -u)" != "0" ]; then
   echo "Este script debe ejecutarse como root" >&2
   exit 1
fi

IPSET_NAME="torrent_block"
default_int=$(ip route list | grep '^default' | grep -oP 'dev \K\S+')
INITIAL_INTERFACES=("tun0" "tun1" "eth0")

for intf in "${INITIAL_INTERFACES[@]}"; do
    if [ "$intf" == "$default_int" ]; then exists=true; break; fi
done
if [ "$exists" != true ] && [ -n "$default_int" ]; then
    INTERFACES=("${INITIAL_INTERFACES[@]}" "$default_int")
else
    INTERFACES=("${INITIAL_INTERFACES[@]}")
fi

LOG_PREFIX="TORRENT_BLOCK"
MAX_ENTRIES=100000
BLOCK_DURATION=18000
HIGH_PORTS="6881:65535"
SERVER_IPS=$(ip -o addr show | awk '!/^[0-9]+: lo:/ && $3 == "inet" {split($4, a, "/"); print a[1]}')

is_server_ip() {
    for x in $SERVER_IPS; do if [ "$1" == "$x" ]; then return 0; fi; done
    return 1
}
is_dns_ip() {
    for x in "8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1"; do if [ "$1" == "$x" ]; then return 0; fi; done
    return 1
}
is_ignored_ip_range() {
    if [[ $1 =~ ^10\.9\.[0-3]\.[0-9]{1,3}$ ]] || [[ $1 =~ ^10\.8\.[0-3]\.[0-9]{1,3}$ ]]; then return 0; else return 1; fi
}

if ! ipset list -n | grep -qw "$IPSET_NAME"; then
    ipset create "$IPSET_NAME" hash:ip maxelem "$MAX_ENTRIES"
fi
iptables-save | grep -v "$IPSET_NAME" | iptables-restore

for chain in INPUT OUTPUT FORWARD; do
    iptables -I "$chain" -m set --match-set "$IPSET_NAME" src -j DROP
    iptables -I "$chain" -m set --match-set "$IPSET_NAME" dst -j DROP
done

raw_patterns="BitTorrent d1:ad2:id d1:q magnet:? announce.php peer_id info_hash GET_announce GET_scrape ut_hub azureus x-peer-id qbittorrent uTorrent Transmission Deluge find_node protocol=BitTorrent"
read -r -a patterns <<< "$raw_patterns"

for intf in "${INTERFACES[@]}"; do
    for protocol in tcp udp; do
        for str in "${patterns[@]}"; do
            clean_str=$(echo "$str" | tr '_' ' ')
            iptables -I FORWARD -o "$intf" -p "$protocol" --dport "$HIGH_PORTS" -m string --string "$clean_str" --algo bm --from 0 --to 1500 -j LOG --log-prefix "$LOG_PREFIX OUT: "
            iptables -I FORWARD -i "$intf" -p "$protocol" --sport "$HIGH_PORTS" -m string --string "$clean_str" --algo bm --from 0 --to 1500 -j LOG --log-prefix "$LOG_PREFIX IN: "
        done
    done
done

cleanup() {
    echo -e "\n[+] Limpiando reglas..."
    iptables-save | grep -v "$IPSET_NAME" | iptables-restore
    ipset destroy "$IPSET_NAME" 2>/dev/null
    exit 0
}
trap cleanup SIGINT SIGTERM

echo "[+] Script activo. Monitoreando journald..."
journalctl -kf -o short | while read -r line; do
    if echo "$line" | grep -q "$LOG_PREFIX"; then
        src_ip=$(echo "$line" | grep -oP 'SRC=\K[0-9.]+')
        dst_ip=$(echo "$line" | grep -oP 'DST=\K[0-9.]+')
        for ip in "$src_ip" "$dst_ip"; do
            if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                if is_server_ip "$ip" || is_dns_ip "$ip" || is_ignored_ip_range "$ip"; then
                    continue
                fi
                if ! ipset test "$IPSET_NAME" "$ip" 2>/dev/null; then
                    echo "[BLOQUEADO] IP: $ip"
                    ipset add "$IPSET_NAME" "$ip"
                    (sleep "$BLOCK_DURATION"; ipset del "$IPSET_NAME" "$ip" 2>/dev/null) &
                fi
            fi
        done
    fi
done            break
        fi
    done

    if [ "$exists" = false ] && [ -n "$default_interface" ]; then
        INTERFACES=("${INITIAL_INTERFACES[@]}" "$default_interface")
    else
        INTERFACES=("${INITIAL_INTERFACES[@]}")
    fi
}
add_default_interface "$default_int"

LOG_PREFIX="TORRENT_BLOCK"
MAX_ENTRIES=100000
BLOCK_DURATION=18000  # Duración en segundos (5 horas)
HIGH_PORTS="6881:65535"

# Rutas para el archivo de log (ajusta según tu sistema)
LOG_FILE="/var/log/kern.log"
if [ ! -f "$LOG_FILE" ]; then
    LOG_FILE="/var/log/messages"
fi

# ---------------------------------------------------
# RECOLECCIÓN DE IPs LOCALES DEL SERVIDOR
# ---------------------------------------------------
# Obtener todas las IPs locales del servidor (excluyendo loopback)
SERVER_IPS=$(ip -o addr show | awk '!/^[0-9]+: lo:/ && $3 == "inet" {split($4, a, "/"); print a[1]}')

# Función para verificar IPs del servidor (o cliente principal)
is_server_ip() {
    local ip=$1
    for server_ip in $SERVER_IPS; do
        if [ "$ip" == "$server_ip" ]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------
# LISTA DE IPs DNS A IGNORAR
# ---------------------------------------------------
is_dns_ip() {
    local ip=$1
    local dns_ips=("8.8.8.8" "8.8.4.4" "1.1.1.1" "1.0.0.1")
    for dns_ip in "${dns_ips[@]}"; do
        if [ "$ip" == "$dns_ip" ]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------
# LISTA DE RANGOS A IGNORAR
# ---------------------------------------------------
# Se ignorarán completamente los siguientes rangos:
#   - 10.9.0.0/22 (10.9.0.0 - 10.9.3.255)
#   - 10.8.0.0/22 (10.8.0.0 - 10.8.3.255)
is_ignored_ip_range() {
    local ip=$1

    if [[ $ip =~ ^10\.9\.[0-3]\.[0-9]{1,3}$ ]] || [[ $ip =~ ^10\.8\.[0-3]\.[0-9]{1,3}$ ]]; then
        return 0
    fi
    return 1
}

# ---------------------------------------------------
# CREAR O LIMPIAR IPSET
# ---------------------------------------------------
if ! ipset list -n | grep -qw "$IPSET_NAME"; then
    # Si no existe, crearlo
    ipset create "$IPSET_NAME" hash:ip maxelem "$MAX_ENTRIES"
fi

# Limpiar reglas iptables existentes relacionadas con este ipset
iptables-save | grep -v "$IPSET_NAME" | iptables-restore

# ---------------------------------------------------
# INSERTAR REGLAS DE BLOQUEO BIDIRECCIONAL
# ---------------------------------------------------
for chain in INPUT OUTPUT FORWARD; do
    iptables -I "$chain" -m set --match-set "$IPSET_NAME" src -j DROP
    iptables -I "$chain" -m set --match-set "$IPSET_NAME" dst -j DROP
done

# ---------------------------------------------------
# PATRONES DE DETECCIÓN PROFUNDA (DPI)
# ---------------------------------------------------
patterns=(
    "BitTorrent"
    "d1:ad2:id"
    "d1:q"
    "magnet:?"
    "announce.php?passkey="
    "peer_id="
    "info_hash"
    "GET /announce"
    "GET /scrape"
    "ut_hub"
    "azureus"
    "x-peer-id"
    "qbittorrent"
    "uTorrent/"
    "Transmission"
    "Deluge"
    "find_node"
    "protocol=BitTorrent"
    "BitTorrent protocol"
)

# ---------------------------------------------------
# AÑADIR REGLAS DE INSPECCIÓN
# ---------------------------------------------------
# Se inspeccionan los primeros 1500 bytes en el tráfico TCP/UDP
# y se busca cualquiera de las cadenas definidas en "patterns".
for intf in "${INTERFACES[@]}"; do
    for protocol in tcp udp; do
        for str in "${patterns[@]}"; do
            # Tráfico saliente (FORWARD -o)
            iptables -I FORWARD -o "$intf" -p "$protocol" --dport "$HIGH_PORTS" \
                -m string --string "$str" --algo bm --from 0 --to 1500 \
                -j LOG --log-prefix "$LOG_PREFIX OUT: "
            # Tráfico entrante (FORWARD -i)
            iptables -I FORWARD -i "$intf" -p "$protocol" --sport "$HIGH_PORTS" \
                -m string --string "$str" --algo bm --from 0 --to 1500 \
                -j LOG --log-prefix "$LOG_PREFIX IN: "
        done
    done
done

# ---------------------------------------------------
# FUNCIÓN PARA BLOQUEAR CONEXIONES TORNENT (Solo IPs remotas)
# ---------------------------------------------------
block_offenders() {
    echo "Monitoreando logs en: $LOG_FILE"
    tail -Fn0 "$LOG_FILE" | while read -r line; do
        if echo "$line" | grep -q "$LOG_PREFIX"; then
            # Extraer las IPs de origen y destino del log
            src_ip=$(echo "$line" | grep -oP 'SRC=\K[0-9.]+')
            dst_ip=$(echo "$line" | grep -oP 'DST=\K[0-9.]+')

            for ip in "$src_ip" "$dst_ip"; do
                if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    if is_server_ip "$ip"; then
                        echo "Ignorando IP del servidor: $ip"
                    elif is_dns_ip "$ip"; then
                        echo "Ignorando IP DNS: $ip"
                    elif is_ignored_ip_range "$ip"; then
                        echo "Ignorando IP dentro del rango no bloqueado: $ip"
                    else
                        # Bloquear la IP solo si no está ya en el ipset
                        if ! ipset test "$IPSET_NAME" "$ip" 2>/dev/null; then
                            echo "Bloqueando IP sospechosa: $ip"
                            ipset add "$IPSET_NAME" "$ip"
                            # Programar el desbloqueo después de BLOCK_DURATION
                            (
                                sleep "$BLOCK_DURATION"
                                ipset del "$IPSET_NAME" "$ip" 2>/dev/null && \
                                    echo "Desbloqueada IP: $ip"
                            ) &
                        fi
                    fi
                fi
            done
        fi
    done
}

# ---------------------------------------------------
# FUNCIÓN DE LIMPIEZA
# ---------------------------------------------------
cleanup() {
    echo -e "\n[+] Limpiando reglas de iptables e ipset..."
    iptables-save | grep -v "$IPSET_NAME" | iptables-restore
    ipset destroy "$IPSET_NAME"
    exit 0
}

# Capturar señales para limpiar reglas al finalizar
trap cleanup SIGINT SIGTERM

# ---------------------------------------------------
# INICIO
# ---------------------------------------------------
echo "[+] Script de bloqueo de BitTorrent en ejecución."
echo "[+] IPSET: $IPSET_NAME  |  Detección profunda activa."
echo "[+] Interfaces monitoreadas: ${INTERFACES[@]}"
echo "[+] UnknownDeVPN"
block_offenders
