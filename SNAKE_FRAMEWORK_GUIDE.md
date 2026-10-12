# Snake Framework Guide

Snake is a local control panel and CLI for **authorized** wireless-security lab
workflows built on wifite2 and common Kali Linux tools. Use it only on networks
and devices you own or have explicit permission to test.

## Quick start

```bash
cd /path/to/wifite2
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-snake.txt
python snake.py doctor
python snake.py wordlists --rebuild    # optional but recommended on Kali
sudo .venv/bin/python snake.py server
```

Kali (and Debian) mark system Python as externally managed, so do **not** run
`pip install` with system `python3`. A project venv is the supported path.
After `sudo`, keep using `.venv/bin/python` so Flask stays available as root.

Alternatively, install Kali packages instead of pip:

```bash
sudo apt install python3-flask python3-flask-socketio python3-flask-cors python3-scapy
python3 snake.py doctor
sudo python3 snake.py server
```

Open `http://127.0.0.1:5000`. Snake binds to localhost by default. To use a
different port, pass `--port 8080`. Avoid `--host 0.0.0.0` unless the host is on
a trusted, isolated lab network and access is protected.

Snake runs from the repository and uses the `snakefw` package. The old
duplicate `snake/` package has been removed.

## Control panel overview

| Tab | Purpose |
|-----|---------|
| **Dashboard** | Guided setup, stats, recent cracks |
| **Scanner** | Live airodump scan, target selection, **Review** / **Twin** per row |
| **Attacks** | RF Tools, handshake/PMKID/WPS/WEP jobs, Auto Attack, wifite |
| **Cracked** | Saved keys (reveal on demand) |
| **Tools** | Tool readiness, MAC changer, **Wordlists** |
| **Arsenal** | Social playbooks (Pumpkin3, Wifiphisher, EAPHammer), apt bundles, **ncrack** |
| **Twin** | Evil Twin AP + captive portal (three-step setup) |
| **MITM** | LAN ARP poisoning on a **managed** interface (not rogue AP) |
| **Strike** | One-click **Nmap → NetExec → Metasploit** LAN chain with host risk view |
| **AI Agent** | Gemini assistant with tool-calling into Snake APIs (scan, attack, Twin, MITM, Strike, …) |
| **Console** | Live logs and job output |

Every destructive or offensive action requires an explicit **authorization**
confirm in the browser (or `authorized: true` in API calls).

## Requirements

Python packages are listed in `requirements-snake.txt`. Core wireless
workflows normally require:

- aircrack-ng (`airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`)
- a wireless adapter that supports monitor mode and injection
- root privileges for interface changes and packet capture

Optional workflows use hashcat, hcxdumptool/hcxpcapngtool, reaver, bully, bettercap,
ncrack, wifiphisher, wifipumpkin3, eaphammer, Scapy, nmap, macchanger, tshark,
and tools shown by `snake doctor`. Missing optional tools disable only the
workflows that depend on them.

**Suggested Kali packages for full Snake:**

```bash
sudo apt install seclists arp-scan hostapd dnsmasq mdk4
```

| Feature | Tools |
|---------|--------|
| Cracking (GPU optional) | hashcat, hcxtools |
| MITM | bettercap (+ caplets), nmap, arp-scan (or Scapy fallback) |
| Strike | nmap, netexec (`nxc`), ncrack, metasploit-framework (`msfconsole`) |
| Arsenal / SE | wifipumpkin3, wifiphisher, eaphammer (external launch via prepared commands) |
| Evil Twin | hostapd, dnsmasq |
| RF / Twin deauth | mdk4 (fallback: mdk3, then aireplay-ng for deauth only) |

`mdk3` is an optional fallback if `mdk4` is missing.

## Readiness check

```bash
python3 snake.py doctor
python3 snake.py doctor --json
```

The check is non-invasive: it reports packages, tools, wireless interfaces,
wordlist tiers, privileges, and writable runtime directories. The web dashboard
shows the same information under **Guided Setup**.

## Recommended web workflow

1. Run preflight and resolve required missing tools.
2. Select a wireless interface.
3. Build wordlists once (`wordlists --rebuild` or **Tools → Rebuild from SecLists**).
4. Enable monitor mode when the chosen workflow requires it.
5. Start a timed scan preset or scan until stopped.
6. Select only an authorized target (row click, checkbox, or **Review**).
7. Launch the appropriate action; follow **Jobs** and **Console**.
8. Stop Twin, RF, or MITM before leaving; return the adapter to managed mode when finished.

### Capture and crack (Attacks tab)

- **WPA Handshake** — wifite2 capture only (`--no-crack`), then Snake cracks locally.
- **PMKID** — hcxdumptool + hashcat mode 22000.
- **WPS / WEP** — reaver or WEP inject path as configured.
- **Wordlist (CPU)** — starting tier on the attack form. Snake always tries ESSID-derived keys first, then the remaining tiers. If all miss, the hash is saved for **Cracked → Online queue**.

**Auto Attack** runs recommended vectors sequentially for checked Scanner rows
(max five). Jobs are tracked; use **Kill** on running jobs.

### Wordlists (CPU-efficient cracking)

Snake builds three local tiers under `snakefw/wordlists/` from SecLists and
your local rockyou (if present). Passwords shorter than 8 characters are
dropped (invalid for WPA-PSK).

| Tier | Role | Typical size (after rebuild) |
|------|------|------------------------------|
| **Target** | Auto — ESSID tokens, years, light leet | hundreds |
| **Fast** | First catalog pass; WPA-probable + Wi‑Fi mutations | ~15k keys |
| **Smart** | **Default** — Fast + top leaks + keyboard walks | ~350k keys |
| **Deep** | Last local pass — Smart + WPA-filtered rockyou | millions |

```bash
python3 snake.py wordlists --rebuild   # build all three; sets Smart active
python3 snake.py wordlists --use fast
python3 snake.py wordlists --use smart
python3 snake.py wordlists --use deep
python3 snake.py wordlists             # list tiers and active choice
```

In the UI: **Tools → Wordlists** shows counts, hints, and **Use** buttons.
**Attacks → Wordlist (CPU)** overrides the tier for a single job.

hashcat uses workload `-w 2` on Fast/Smart (and the ESSID list) and applies
`best66.rule` when available. **Deep** is a long CPU run. If Fast, Smart, and
Deep all miss, Snake copies the `.cap` / `.hc22000` into
`snakefw/captures/` and lists it under **Cracked → Online queue**.

**Online queue:** press **Send to wpa-sec** (authorization confirm). The hash
leaves this machine. Save a wpa-sec API key to **Check results**. You can also
download the hash and take it to any other GPU service. This does not guarantee
a key — strong passphrases can still miss.

The legacy `wordlist-top4800-probable.txt` at the repo root remains a fallback
only if tiers were never built.

### Evil Twin (Twin tab)

Fluxion-style **rogue AP + captive portal** for lab use (not the same as MITM).

1. **Target** — click **Twin** on a Scanner row (ESSID, BSSID, channel fill in).
2. **Radios** — auto-assign: **managed** iface for the AP, **monitor** iface for deauth.
   - One adapter: twin AP can still start; live deauth is disabled (warning shown).
   - `wlan0mon` is converted to `wlan0` for hostapd. That is required — hostapd cannot AP in monitor mode.
   - NetworkManager is **not** restarted and that iface is marked unmanaged so hostapd does not hit `INTERFACE-DISABLED`.
   - Launch auto-stops RF or scan on the same radio.
   - Readiness chips show hostapd, dnsmasq, root, and RF tool status.
3. **Launch** — confirm authorization. Portal listens on the AP IP (`10.0.0.1:80`), not on `:5000`.

Live view: connected clients, portal hits, captured passwords (hidden until **Reveal**).
Optional password verify uses a spare managed iface and `wpa_supplicant` when the
target uses WPA/WPA2.

Clients may still leave a **WPA** network for an **open** twin if the real AP is still
beaconing and you have only one radio (no deauth). That is client roaming, not a Twin crash.

Stop with **STOP TWIN** or server shutdown. Teardown kills hostapd/dnsmasq/portal,
stops deauth, restores NetworkManager on the AP iface, and removes Twin iptables rules.

### RF Tools (Attacks tab, top panel)

Standalone wireless presets sharing the same engine as Twin deauth:

| Preset | Needs BSSID | Tool order |
|--------|-------------|------------|
| **Deauth** | Yes | mdk4 → mdk3 → aireplay-ng |
| **Beacon flood** | No | mdk4 → mdk3 |
| **Auth DoS** | Yes | mdk4 → mdk3 |

Requires a **monitor** interface. Conflicts with an active scan or Twin on the
same radio are rejected. Jobs end as **DONE**, **KILLED**, or **FAILED** (not CRACKED).
Use **Stop RF** or job **Kill**.

Scanner rows now include **client MACs** when airodump reports stations — useful
for targeted deauth (optional client field in RF form).

### MITM (MITM tab)

**LAN ARP poisoning** on an interface with an IPv4 address on the target LAN.
Use **managed** mode (not the monitor adapter used for Wi‑Fi scans).

1. Set interface and gateway (auto-detected when possible).
2. **Discover** hosts, select targets.
3. **LAUNCH MITM** with a **bettercap profile** (Harvest / Hunt / Hijack), optional
   manual DNS/SSL overrides, and bettercap enabled.

Profiles map to generated caplets under `snakefw/logs/snake_mitm_*.cap`. **Hijack**
loads Kali caplets `hstshijack.cap` and `jsinject.cap` when `bettercap-caplets`
is installed. PCAP paths use real timestamps (no shell `date` in caplets).

Captured HTTP credentials and traffic appear in the MITM panels. Stop with
**STOP ALL** before leaving the tab.

### Strike (Strike tab)

Automated **LAN recon** on a managed interface (wired or Wi‑Fi in managed mode).
Use it host-by-host so Nmap, NetExec, and Metasploit are not wasted on the whole subnet.

1. Join your authorized lab network; open **Strike**.
2. Press **Discover LAN**. Nmap ARP + ICMP + TCP ping lists every live device (phones and Windows that ignore ICMP still show up).
3. Click a host → **Nmap this device** (Quick / Smart / Deep). Optional: **then NetExec**.
4. On that host pick a NetExec protocol + profile (**Identify**, **Enumerate**, **Vuln modules**) and **Run NetExec**.
5. **ncrack** — parallel login tries on open SSH/RDP/SMB/VNC/HTTP ports (after nmap). Logs: `snakefw/logs/arsenal/ncrack_*.log`.
6. **Check this host** / **Auto-check all** run Metasploit *checks only*. **Exploit** stays behind a second confirm after Check.

**Scan all** still runs the old full chain (discover → nmap every host → NetExec → plan) when you want that.

Discovery uses `-PR -PE -PP -PS/-PA` so quiet hosts are not missed. Per-host nmap uses `-Pn` because the host is already known live. NetExec covers SMB, SSH, WinRM, LDAP, RDP, FTP, MSSQL, WMI, NFS, VNC, HTTP.

Results are saved to `snakefw/results/strike_last.json`.

### Pivot (Cracked → LAN)

After a WPA PSK is cracked (or a Twin portal key is **verified**), Snake offers an
**opt-in** Air-to-LAN bridge. It does **not** join automatically.

1. Open **Cracked**, click **Pivot**, and confirm authorization.
2. Snake stops scan/Twin/RF on the client radio, switches it to managed mode,
   associates with `wpa_supplicant`, and requests a DHCP lease.
3. If **launch Strike** is on (default), the LAN recon chain starts on that iface.

Needs a spare **managed** radio when Twin is using the other adapter. Single-radio
labs: stop Twin first. Tools: `wpa_supplicant` plus `dhclient` (or dhcpcd/udhcpc).

### Reports

**Dashboard → Report** or **Strike → Report** opens a print-ready HTML summary:
risk score, wireless results (keys redacted), job timeline, LAN hosts, findings,
and remediation notes. Use the browser **Print / Save PDF** control. JSON is at
`/api/report`. Pass `?include_secrets=1` only when you intentionally need keys.

### Multi-radio and stealth deauth

With two physical adapters, Snake assigns **scan** on radio 1 and **attack / Twin
deauth** on radio 2. The scan radio no longer blocks an RF job on a different phy.
The Dashboard **Radio plan** chips show the assignment.

**Stealth deauth** (RF Tools and Twin) spaces bursts with random pauses. Optional
**Rotate source MAC** uses `macchanger` between bursts. This reduces obvious flood
patterns; it is not a WIPS bypass.

Install gaps:

```bash
sudo apt install nmap metasploit-framework ncrack bettercap-caplets
pipx install netexec   # or: sudo apt install netexec when available
python3 snake.py arsenal              # list playbooks + bundles
python3 snake.py arsenal --install social-wifi --run   # Pumpkin3, Wifiphisher, EAPHammer
```

### Arsenal (Social engineering & upgrades)

The **Arsenal** tab groups lab-only social workflows without replacing Snake Twin:

| Playbook | When to use |
|----------|-------------|
| **Snake Twin** | Built-in captive portal + optional deauth (fastest in-panel) |
| **WiFi Pumpkin 3** | Plugin-rich rogue AP (REST/TUI); use **Prepare command** with scanner ESSID |
| **Wifiphisher** | Pre-built phishing scenarios (OAuth, firmware, etc.) |
| **EAPHammer** | WPA2-Enterprise evil twin / credential capture |
| **bettercap fb-phish** | LAN social lure after MITM on a managed interface |

WPS jobs try **reaver**, then **bully** automatically (same idea as wifite2).

## CLI

```bash
python3 snake.py --help
python3 snake.py doctor
python3 snake.py wordlists --rebuild
python3 snake.py wordlists --use smart
python3 snake.py server
python3 snake.py scan -i wlan0mon -t 30
python3 snake.py status
python3 snake.py monitor -i wlan0
python3 snake.py managed -i wlan0mon
```

Optional shell shortcuts:

```bash
source ./snake.sh
snake-help
```

Default crack paths in `snake.sh` prefer `snakefw/wordlists/snake-smart.txt`.

## Runtime data

- `snakefw/captures/` — packet captures and converted hashes
- `snakefw/logs/` — process and framework logs (including Twin/RF/hostapd)
- `snakefw/results/` — job history and wordlist preference (`wordlist_pref.json`)
- `snakefw/wordlists/` — generated `snake-fast.txt`, `snake-smart.txt`, `snake-deep.txt` (not committed; see `README.md` there)
- `cracked.json` — canonical shared result file at repo root

Writes to JSON result files are atomic and duplicate keys are suppressed.

## AI Agent (Gemini)

The **AI Agent** tab talks to Google Gemini with **automatic function calling** into the same REST API as the web UI (~35 tools).

Setup:

```bash
pip install google-genai requests   # or: pip install -r requirements-snake.txt
export GEMINI_API_KEY="your-key"      # never commit this
sudo .venv/bin/python snake.py server
```

Optional: `SNAKE_AGENT_MODEL` (default `gemini-2.5-flash`), `SNAKE_AGENT_BASE` (auto-set from server host/port).

Tool calls use an **in-process bridge** by default (avoids HTTP deadlock while the agent chat request is open). Set `SNAKE_AGENT_HTTP=1` only if the agent runs against a remote Snake instance.

The agent is instructed on Snake tabs, multi-radio rules, attack vectors, MITM profiles, and must set `user_authorized=True` only after you confirm lab authorization in chat. It should call `plan_attack` before `start_attack`.

API: `/api/agent/status`, `/api/agent/chat`, `/api/agent/reset`.

## Configuration

- `SNAKE_SECRET_KEY` — fixed Flask session secret; otherwise generated at start
- `GEMINI_API_KEY` — enables the AI Agent tab
- `SNAKE_ALLOWED_ORIGINS` — comma-separated cross-origin URLs; unset means same-origin only
- `SNAKE_DIR` — repository path used by `snake.sh`

The Socket.IO browser client is stored locally; the panel does not require
internet access.

## Safe shutdown and recovery

Stop jobs from the **Jobs** panel, stop **Twin** and **MITM** before leaving,
and press `Ctrl+C` in the server terminal. Snake terminates tracked child
process groups, stops scanning, stops Twin/RF/MITM sessions, restores Twin
iptables and the previous IPv4 forwarding state, and restores MITM ARP entries.

If an interrupted tool leaves the adapter in monitor mode:

```bash
sudo .venv/bin/python snake.py managed -i wlan0mon
sudo systemctl restart NetworkManager
```

## Troubleshooting

- **externally-managed-environment:** create `.venv` (see Quick start). Do not use `--break-system-packages` unless you intend to alter Kali system Python.
- **Server package import error:** activate the venv, then `python -m pip install -r requirements-snake.txt`. Use `sudo .venv/bin/python snake.py server`, not bare `sudo python3`.
- **No interfaces:** verify with `iw dev`, reconnect the adapter, rerun `snake doctor`.
- **Operation says a tool is missing:** install the package from doctor hints and rerun preflight.
- **No wordlist / weak cracks:** run `python3 snake.py wordlists --rebuild` (requires `seclists`). Handshake jobs escalate Smart → Deep automatically. If all miss, use **Cracked → Online queue**.
- **No new handshake:** Snake reuses the newest `hs/handshake_*` for that BSSID instead of failing the job.
- **Custom port cannot connect:** use the exact URL printed at server start.
- **Permission denied:** monitor mode, capture, Twin, RF, and MITM require root.
- **Monitor mode does not stick:** run the server as root, select the adapter, press **Monitor Mode**. `airmon-ng check kill` may stop NetworkManager on the same NIC — use Ethernet or another NIC for the control panel if needed.
- **Attack says BSSID is required:** select a Scanner row or **Review** so BSSID/ESSID/channel auto-fill.
- **Wifite / hashcat job errors:** Snake passes correct wifite `-i` / `-b` flags. `No matching network found` means the capture BSSID mismatched — recapture. hashcat needs OpenCL/CUDA/PoCL; Snake falls back to aircrack-ng when no backend is present.
- **Scan finds no networks:** scanning requires monitor mode; Snake can enable it at scan start. If `airodump-ng exited`, check mode and injection support.
- **Twin will not start:** install `hostapd` and `dnsmasq`, run as root, use a managed iface for AP; check Console for hostapd errors (some USB adapters cannot AP).
- **Twin `INTERFACE-DISABLED` / probe send failed:** NetworkManager grabbed the AP radio. Current Snake holds NM off that iface; restart the Snake server so the new Twin code is loaded, then relaunch Twin.
- **RF or Twin says interface in use:** Twin now stops RF/scan on the same radio automatically. If a 409 remains, stop the leftover job from the Jobs panel.
- **MITM discover fails:** join the target LAN on a managed iface with an IPv4 address; do not use the monitor adapter.

Automated tests mock subprocesses and never activate monitor mode, injection,
cracking, MITM, Evil Twin, or mdk3/mdk4.

## API surface (for integrators)

Snake exposes REST + Socket.IO on the same origin as the panel. Examples:

- `/api/health`, `/api/tools`, `/api/wordlists`, `/api/wordlists/build`, `/api/wordlists/select`
- `/api/online-queue`, `/api/online-queue/<id>/submit`, `/api/online-queue/check`
- `/api/scan/start`, `/api/attack`, `/api/job/<id>/kill`
- `/api/rf/status`, `/api/rf/start`, `/api/rf/stop`
- `/api/twin/status`, `/api/twin/start`, `/api/twin/stop`
- `/api/mitm/*` — LAN MITM (see MITM tab)
- `/api/strike/status`, `/api/strike/start`, `/api/strike/stop`, `/api/strike/ncrack`, `/api/strike/report`, `/api/strike/msf`, `/api/strike/msf/auto-check`
- `/api/arsenal/catalog`, `/api/arsenal/command`, `/api/arsenal/ncrack`
- `/api/radios` — current scan / attack / AP / client assignment
- `/api/pivot/status`, `/api/pivot/start`, `/api/pivot/stop` — opt-in join after a cracked PSK
- `/api/report`, `/api/report/html` — engagement deliverable (keys redacted by default)

Live events include `job_update`, `cracked`, `online_queued`, `online_update`, `twin_*`, `rf_*`, `mitm_*`, `strike_*`, and `pivot_*`.
