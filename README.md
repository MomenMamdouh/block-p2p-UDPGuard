# BitTorrent Traffic Blocker using iptables + ipset

# Advanced Overview and Operational Considerations

This script was designed with a dual objective: **to dynamically block BitTorrent traffic** while **not limiting the user experience**. It was designed to block only torrent traffic (thus avoiding DMCA-related issues) without affecting other services, such as gaming or general browsing.

The mechanism is based on advanced **Deep Packet Inspection (DPI)** techniques. It scans the first 1500 bytes of each TCP/UDP packet in the port range `6881:65535`, looking for patterns and signatures characteristic of BitTorrent traffic. This method is effective even when clients (such as uTorrent) partially encrypt traffic, as many still expose enough information during the handshake or initial negotiations to be identified. Thus, the script progressively blocks each IP address involved in the BitTorrent packet exchange; once all routes are blocked, the download is interrupted (0 bytes transferred), and the offending user's IP is eventually blocked.

> Thanks for sharing your experiences, @UnknownDev2018. The script has proven to be very comprehensive, as even with clients that encrypt traffic, most BitTorrent connections can be detected. However, if a client evades detection or if traffic is redirected entirely over HTTPS, the effectiveness of the string matching could be reduced, as the inspected content would be encrypted and not display the usual signatures.

# NO BLOCK GAMING

This Bash script is designed to **block BitTorrent traffic** on Linux systems using iptables and ipset. It employs **Deep Packet Inspection (DPI)** to detect BitTorrent patterns and temporarily block suspicious IP addresses. **Importantly, it does not block any ports**—it only monitors the port range `6881:65535` for BitTorrent-related traffic, leaving all online gaming ports completely unaffected.

## Features

- **Deep Packet Inspection (DPI):**  
  Inspects the first 1500 bytes of TCP/UDP packets on the port range `6881:65535` to detect BitTorrent patterns without blocking the ports.

- **Dynamic Blocking:**  
  Automatically adds suspicious IPs to an ipset, temporarily blocking them if BitTorrent traffic is detected.

- **Gaming Traffic Unaffected:**  
  The script solely monitors the specified port range for BitTorrent activity. **Gaming ports remain open and fully functional**.

- **Intelligent Exclusions:**  
  Excludes local server IPs, known DNS servers, and specific IP ranges to avoid unintended disruptions.

- **Multi-Interface Monitoring:**  
  Automatically detects and monitors multiple network interfaces, including the default interface, ensuring comprehensive traffic supervision.

- **Automatic Cleanup:**  
  On termination, the script cleans up iptables rules and destroys the ipset, restoring the system’s original configuration.

## Requirements

- **Operating System:** Linux (Debian/Ubuntu or similar)
- **Permissions:** Must be run as `root`
- **Dependencies:** `iptables`, `ipset`, `ipcalc`, `rsyslog`, `grep`, `awk`, `coreutils`
- **Kernel Module:** `xt_string` (required for string matching in iptables)

## Installation

Update your system and install the required packages:

```bash
sudo apt update && sudo apt install -y iptables ipset grep gawk iproute2 && sudo mv torrent_block.sh /usr/local/bin/torrent_block.sh && sudo chmod +x /usr/local/bin/torrent_block.sh && sudo chown root:root /usr/local/bin/torrent_block.sh && echo -e "[Unit]\nDescription=BitTorrent L7 Deep Packet Inspection and Dynamic Blocker\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/torrent_block.sh\nRestart=always\nRestartSec=5\nUser=root\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=multi-user.target" | sudo tee /etc/systemd/system/torrent-block.service > /dev/null && sudo systemctl daemon-reload && sudo systemctl enable torrent-block.service && sudo systemctl start torrent-block.service && sudo systemctl status torrent-block.service

   ```

4. **Stop the script:**  
   Press `Ctrl+C` or send a termination signal to clean up the iptables rules and ipset.

## Configuration

- **IPSET_NAME:** Name of the ipset (default: `torrent_block`)
- **INTERFACES:** List of network interfaces to monitor (default: `tun0`, `tun1`, `eth0`, plus the detected default interface)
- **BLOCK_DURATION:** Duration (in seconds) for which an IP remains blocked (default: 18000 seconds or 5 hours)
- **HIGH_PORTS:** Port range to inspect (default: `6881:65535`)
- **Exclusions:**  
  - Local server IPs  
  - Known DNS servers (`8.8.8.8`, `8.8.4.4`, `1.1.1.1`, `1.0.0.1`)  
  - Specific IP ranges (`10.9.0.0/22` and `10.8.0.0/22`)
- **DPI Patterns:** Modify or extend the list of BitTorrent-related strings as needed.

## How It Works

1. **Interface Detection:**  
   Automatically detects the default interface and adds it to the monitoring list.

2. **Setup:**  
   Creates or cleans the ipset and inserts iptables rules to block traffic from/to IPs in the set.

3. **Deep Packet Inspection:**  
   Uses iptables rules to inspect TCP/UDP traffic for BitTorrent patterns and logs any matches.

4. **Blocking Offenders:**  
   Monitors logs, extracts source and destination IPs, and adds non-excluded IPs to the ipset. Unblocks them after the defined `BLOCK_DURATION`.

5. **Cleanup:**  
   On termination, removes iptables rules and destroys the ipset to restore the system’s original state.

## Contributing

Contributions are welcome! Fork the repository and submit pull requests with your improvements.

## License

Distributed under the [MIT License](LICENSE).

Security Notice
Warning: This script modifies firewall rules in real-time. Ensure you understand the security implications and have recovery options available. Test in a safe environment before using in production.
