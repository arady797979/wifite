#!/usr/bin/env python3
"""
Snake Framework - Main CLI Launcher
Usage: python3 snake.py [command] [options]
"""
import sys
import os
import argparse
import time
import json
import importlib.util
from pathlib import Path

# ANSI colors
G  = "\033[92m"    # green
C  = "\033[96m"    # cyan
Y  = "\033[93m"    # yellow
R  = "\033[91m"    # red
M  = "\033[95m"    # magenta
B  = "\033[1m"     # bold
DIM= "\033[2m"     # dim
X  = "\033[0m"     # reset

BANNER = f"""
{G}{B}
  ███████╗███╗   ██╗ █████╗ ██╗  ██╗███████╗
  ██╔════╝████╗  ██║██╔══██╗██║ ██╔╝██╔════╝
  ███████╗██╔██╗ ██║███████║█████╔╝ █████╗  
  ╚════██║██║╚██╗██║██╔══██║██╔═██╗ ██╔══╝  
  ███████║██║ ╚████║██║  ██║██║  ██╗███████╗
  ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
{X}{C}{DIM}  WiFi PenTest Framework v1.0  |  Powered by wifite2 + Snake{X}
{G}  ──────────────────────────────────────────────────────{X}
"""

BASE_DIR  = Path(__file__).resolve().parent
SNAKE_DEPENDENCIES = {
    "flask": "Flask",
    "flask_socketio": "Flask-SocketIO",
    "flask_cors": "Flask-Cors",
}


def print_banner():
    print(BANNER)


def cmd_server(args):
    """Launch the Snake web control panel."""
    print_banner()
    port = args.port
    host = args.host

    print(f"{G}[🐍] Starting Snake control panel...{X}")
    print(f"{C}[*]  URL: http://{host}:{port}{X}")
    print(f"{Y}[*]  Press Ctrl+C to stop{X}\n")

    missing = [name for module, name in SNAKE_DEPENDENCIES.items()
               if importlib.util.find_spec(module) is None]
    if missing:
        print(f"{R}[!] Missing Python packages: {', '.join(missing)}{X}")
        print(f"{Y}[*] Create a venv (Kali blocks system pip):{X}")
        print(f"{Y}    python3 -m venv .venv && source .venv/bin/activate{X}")
        print(f"{Y}    python -m pip install -r requirements-snake.txt{X}")
        print(f"{Y}    sudo .venv/bin/python snake.py server{X}")
        raise SystemExit(2)

    sys.path.insert(0, str(BASE_DIR))
    from snakefw.server.app import run_server
    run_server(host=host, port=port, debug=args.debug)


def cmd_scan(args):
    """Quick CLI scan."""
    print_banner()
    sys.path.insert(0, str(BASE_DIR))
    from snakefw.core.tool_manager import (
        get_interface_mode,
        get_interfaces,
        set_monitor_mode,
    )
    from snakefw.core.scanner import quick_scan

    iface = args.interface
    if not iface:
        ifaces = get_interfaces()
        if not ifaces:
            print(f"{R}[!] No wireless interfaces found!{X}")
            sys.exit(1)
        iface = ifaces[0]

    if get_interface_mode(iface) != "monitor":
        print(f"{Y}[*] Enabling monitor mode on {iface} before scan...{X}")
        iface = set_monitor_mode(iface, callback=print)

    print(f"{G}[*] Scanning on {iface} for {args.time}s...{X}\n")

    def log(m):
        if m != "__networks_updated__":
            print(f"{DIM}  {m}{X}")

    networks = quick_scan(iface, duration=args.time, callback=log)

    if not networks:
        print(f"\n{Y}[!] No networks found.{X}")
        return

    print(f"\n{G}{B}{'─'*80}{X}")
    print(f"{C}{B}  {'THREAT':<12} {'ESSID':<30} {'BSSID':<20} {'CH':>3} {'SIG':>6} {'ENC':<8} {'SCORE':>6}{X}")
    print(f"{G}{'─'*80}{X}")

    for n in networks:
        threat = n.get("threat_level","?")
        color  = {
            "EASY": G, "MEDIUM": Y, "HARD": R,
            "SUSPICIOUS": M, "WPS_TARGET": C
        }.get(threat, X)
        print(
            f"  {color}{B}{threat:<12}{X}"
            f"  {B}{n.get('essid','?'):<30}{X}"
            f"  {DIM}{n.get('bssid','?'):<20}{X}"
            f"  {n.get('channel',0):>3}"
            f"  {n.get('signal',0):>5}dBm"
            f"  {C}{n.get('encryption','?'):<8}{X}"
            f"  {G}{n.get('confidence',0):>5}%{X}"
        )
    print(f"{G}{'─'*80}{X}")


def cmd_crack(args):
    """Attempt to crack a specific network."""
    print_banner()
    sys.path.insert(0, str(BASE_DIR))
    from snakefw.core.tool_manager import CrackEngine

    if not args.file and not args.bssid:
        print(f"{R}[!] Provide --file (cap/hc22000) or --bssid{X}")
        sys.exit(1)

    def log(m):
        level_color = R if "[!]" in m else (G if "[+]" in m or "FOUND" in m or "CRACKED" in m else DIM)
        print(f"  {level_color}{m}{X}")

    engine = CrackEngine(callback=log)

    if args.file:
        fpath = Path(args.file)
        if fpath.suffix in (".cap",):
            key = engine.crack_offline(
                args.file,
                args.bssid or "00:00:00:00:00:00",
                args.essid or "Unknown",
                kind="handshake",
            )
        elif fpath.suffix in (".hc22000", ".22000"):
            key = engine.crack_offline(
                args.file,
                args.bssid or "00:00:00:00:00:00",
                args.essid or "Unknown",
                kind="pmkid",
            )
        else:
            print(f"{R}[!] Unknown file type: {fpath.suffix}{X}")
            sys.exit(1)

        if key:
            print(f"\n{G}{B}[🏆] KEY FOUND: {key}{X}")
        else:
            print(f"\n{R}[✗] Key not found{X}")


def cmd_status(args):
    """Show current saved cracked passwords."""
    print_banner()
    cracked_path = BASE_DIR / "cracked.json"
    snake_path   = BASE_DIR / "snakefw" / "results" / "cracked.json"

    results = []
    for p in (cracked_path, snake_path):
        if p.exists():
            try:
                with open(p) as f:
                    data = json.load(f)
                results.extend(data)
            except Exception:
                pass

    # Deduplicate by bssid+key
    seen = set()
    unique = []
    for r in results:
        k = (r.get("bssid",""), r.get("key",""))
        if k not in seen:
            seen.add(k)
            unique.append(r)

    if not unique:
        print(f"{Y}[*] No cracked passwords yet.{X}")
        return

    print(f"\n{G}{B}{'─'*70}{X}")
    print(f"{C}{B}  {'ESSID':<25} {'BSSID':<20} {'KEY':<20} {'TYPE':<10}{X}")
    print(f"{G}{'─'*70}{X}")
    for r in unique:
        print(
            f"  {B}{r.get('essid','?'):<25}{X}"
            f"  {DIM}{r.get('bssid','?'):<20}{X}"
            f"  {G}{B}{r.get('key','?'):<20}{X}"
            f"  {C}{r.get('type', r.get('attack','WPA')):<10}{X}"
        )
    print(f"{G}{'─'*70}{X}")
    print(f"\n  {G}Total: {len(unique)} cracked passwords{X}\n")


def cmd_doctor(args):
    """Run a non-invasive readiness check."""
    print_banner()
    sys.path.insert(0, str(BASE_DIR))
    from snakefw.core.paths import (
        BUILTIN_WORDLIST,
        CAPTURES_DIR,
        LOGS_DIR,
        RESULTS_DIR,
    )
    from snakefw.core.tool_manager import (
        check_tools, get_interfaces, get_tools_detail, get_wordlist,
    )
    from snakefw.core.wordlists import list_wordlists, wordlist_priority

    package_status = {
        name: importlib.util.find_spec(module) is not None
        for module, name in SNAKE_DEPENDENCIES.items()
    }
    package_status["Scapy (optional MITM fallback)"] = (
        importlib.util.find_spec("scapy") is not None
    )
    tools = check_tools()
    tool_detail = get_tools_detail()
    interfaces = get_interfaces()
    catalog = list_wordlists()
    wordlists = [path for path in wordlist_priority() if Path(path).exists()]
    directories = [CAPTURES_DIR, RESULTS_DIR, LOGS_DIR]

    print(f"{C}{B}Python packages{X}")
    for name, ready in package_status.items():
        print(f"  {G if ready else R}{'✓' if ready else '✗'}{X} {name}")
    print(f"\n{C}{B}Runtime{X}")
    print(f"  {'✓' if os.geteuid() == 0 else '!'} Privileges: "
          f"{'root' if os.geteuid() == 0 else 'non-root (active operations require sudo)'}")
    print(f"  {'✓' if interfaces else '!'} Wireless interfaces: "
          f"{', '.join(interfaces) if interfaces else 'none detected'}")
    active = catalog["active"] or get_wordlist()
    print(f"  {'✓' if active else '✗'} Wordlist: "
          f"{active or f'none (expected {BUILTIN_WORDLIST})'}")
    for entry in catalog["wordlists"]:
        if entry["tier"] in {"fast", "smart", "deep"}:
            mark = "✓" if entry["exists"] else "·"
            detail = f"{entry['count']:,} keys" if entry["exists"] else "not built"
            print(f"    {mark} {entry['label']}: {detail}")
    print(f"  ✓ Writable directories: {', '.join(str(p) for p in directories)}")
    print(f"\n{C}{B}External tools{X}")
    for entry in tool_detail["entries"]:
        name = entry["name"]
        ready = entry["ready"]
        suffix = ""
        if not ready and entry.get("install"):
            suffix = f" {DIM}({entry['install']}){X}"
        if not entry["required"] and not ready:
            print(f"  {DIM}{'·' if not ready else '✓'}{X} {name} {DIM}[optional]{X}{suffix}")
        else:
            print(f"  {G if ready else R}{'✓' if ready else '✗'}{X} {name}{suffix}")

    required = ("airmon-ng", "airodump-ng", "aircrack-ng")
    healthy = all(package_status[name] for name in ("Flask", "Flask-SocketIO", "Flask-Cors"))
    healthy = healthy and all(tools.get(name, False) for name in required)
    print(f"\n{G if healthy else Y}{'[✓] Ready' if healthy else '[!] Setup incomplete'}{X}")
    if args.json:
        payload = {
            "ok": healthy,
            "root": os.geteuid() == 0,
            "packages": package_status,
            "tools": tools,
            "interfaces": interfaces,
            "wordlists": wordlists,
            "wordlist_catalog": catalog,
        }
        print(json.dumps(payload, indent=2))


def cmd_arsenal(args):
    """List Arsenal playbooks / apt bundles or print install command."""
    print_banner()
    sys.path.insert(0, str(BASE_DIR))
    from snakefw.arsenal.engine import apt_install_command, catalog_payload
    from snakefw.core.tool_manager import check_tools
    import subprocess

    payload = catalog_payload(check_tools())
    if args.install:
        try:
            cmd = apt_install_command(args.install)
        except ValueError as exc:
            print(f"{R}[!] {exc}{X}")
            sys.exit(1)
        print(f"{C}Install:{X}\n  {cmd}\n")
        if args.run:
            print(f"{Y}[*] Running apt (root required)...{X}")
            subprocess.run(cmd, shell=True, check=False)
        return

    print(f"{C}{B}MITM profiles (bettercap){X}")
    for key, meta in payload["mitm_profiles"].items():
        print(f"  {G}{key:8}{X} {meta.get('label','')} — {meta.get('hint','')}")
    print(f"\n{C}{B}Apt bundles{X}")
    for bundle in payload["bundles"]:
        print(f"  {G}{bundle['id']}{X}  {bundle['label']}")
        print(f"      {DIM}{bundle['install']}{X}")
    print(f"\n{C}{B}Playbooks{X}")
    for book in payload["playbooks"]:
        mark = f"{G}✓{X}" if book.get("ready") else f"{Y}·{X}"
        print(f"  {mark} {book.get('title')} [{book.get('id')}]")
        if book.get("missing"):
            print(f"      {DIM}missing: {', '.join(book['missing'])}{X}")
    print(f"\n{DIM}Install a bundle: snake arsenal --install social-wifi --run{X}\n")


def cmd_wordlists(args):
    """Build or select CPU-friendly Fast/Smart/Deep wordlists."""
    print_banner()
    sys.path.insert(0, str(BASE_DIR))
    from snakefw.core.wordlists import (
        build_tiered_wordlists,
        list_wordlists,
        set_active_wordlist,
    )

    if args.rebuild:
        print(f"{C}[*] Building Fast / Smart / Deep from SecLists and local rockyou...{X}")
        built = build_tiered_wordlists()
        for tier, info in built.items():
            print(f"  {G}✓{X} {tier}: {info['count']:,} keys → {info['path']}")
        set_active_wordlist(tier="smart")
        print(f"{G}[+] Active wordlist: Smart{X}")
        return

    if args.use:
        chosen = set_active_wordlist(tier=args.use)
        print(f"{G}[+] Active wordlist: {chosen['label']} ({chosen['count']:,} keys){X}")
        print(f"    {chosen['path']}")
        return

    catalog = list_wordlists()
    print(f"{C}{B}CPU wordlists{X}")
    for entry in catalog["wordlists"]:
        mark = f"{G}*{X}" if entry["active"] else " "
        status = f"{entry['count']:,} keys" if entry["exists"] else "not built"
        print(f"  {mark} {entry['label']:<8} {status}")
        print(f"      {DIM}{entry['path']}{X}")
        print(f"      {DIM}{entry['hint']}{X}")
    if not catalog["built"]:
        print(f"\n{Y}[*] Build them with: python3 snake.py wordlists --rebuild{X}")


def cmd_monitor(args):
    """Enable monitor mode on interface."""
    print_banner()
    sys.path.insert(0, str(BASE_DIR))
    from snakefw.core.tool_manager import set_monitor_mode

    iface = args.interface
    print(f"{G}[*] Enabling monitor mode on {iface}...{X}")
    mon = set_monitor_mode(iface, callback=print)
    print(f"\n{G}[+] Monitor interface: {B}{mon}{X}")


def cmd_managed(args):
    """Switch back to managed mode."""
    print_banner()
    sys.path.insert(0, str(BASE_DIR))
    from snakefw.core.tool_manager import set_managed_mode

    iface = args.interface
    print(f"{Y}[*] Switching {iface} to managed mode...{X}")
    managed = set_managed_mode(iface, callback=print)
    print(f"\n{G}[+] Managed interface: {B}{managed}{X}")


def main():
    parser = argparse.ArgumentParser(
        description="🐍 Snake WiFi PenTest Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Commands:
  server     Launch the Snake web control panel
  scan       Quick CLI scan for networks
  crack      Crack a captured handshake or PMKID
  status     Show all cracked passwords
  doctor     Check dependencies and runtime readiness
  wordlists  Build or select Fast / Smart / Deep CPU wordlists
  arsenal    List social/LAN playbooks and apt upgrade bundles
  monitor    Enable monitor mode on an interface
  managed    Switch interface back to managed mode

Examples:
  snake server                    # Start control panel on :5000
  snake server --port 8080        # Custom port
  snake scan -i wlan0 -t 60       # Scan for 60 seconds
  snake crack --file hs/test.cap --bssid AA:BB:CC:DD:EE:FF
  snake status                    # Show cracked passwords
  snake doctor                    # Check setup without changing the system
  snake wordlists --rebuild       # Build Fast/Smart/Deep from SecLists
  snake wordlists --use smart     # Select the CPU default
  snake monitor -i wlan0          # Enable monitor mode
  snake managed -i wlan0mon       # Disable monitor mode

Guide:
  SNAKE_FRAMEWORK_GUIDE.md
        """
    )

    sub = parser.add_subparsers(dest="command")

    # server
    p_srv = sub.add_parser("server", help="Launch web control panel")
    p_srv.add_argument("--host",  default="127.0.0.1")
    p_srv.add_argument("--port",  type=int, default=5000)
    p_srv.add_argument("--debug", action="store_true")

    # scan
    p_scan = sub.add_parser("scan", help="Scan for networks")
    p_scan.add_argument("-i", "--interface", default="")
    p_scan.add_argument("-t", "--time", type=int, default=30)

    # crack
    p_crack = sub.add_parser("crack", help="Crack a capture file")
    p_crack.add_argument("--file",   required=False, help=".cap or .hc22000 file")
    p_crack.add_argument("--bssid",  default="")
    p_crack.add_argument("--essid",  default="Unknown")

    # status
    sub.add_parser("status", help="Show cracked passwords")

    # doctor
    p_doctor = sub.add_parser("doctor", help="Check Snake dependencies and readiness")
    p_doctor.add_argument("--json", action="store_true", help="Also print machine-readable results")

    p_wl = sub.add_parser("wordlists", help="Build or select CPU wordlists")
    p_wl.add_argument("--rebuild", action="store_true", help="Rebuild Fast/Smart/Deep from SecLists")
    p_wl.add_argument("--use", choices=["fast", "smart", "deep"], help="Set the active tier")

    p_ars = sub.add_parser("arsenal", help="Playbooks, ncrack, and apt bundles")
    p_ars.add_argument(
        "--install",
        choices=["wifi-core", "wifi-crack", "lan-strike", "social-wifi"],
        help="Print (or run) apt install for a bundle",
    )
    p_ars.add_argument("--run", action="store_true", help="Execute apt install (requires root)")

    # monitor
    p_mon = sub.add_parser("monitor", help="Enable monitor mode")
    p_mon.add_argument("-i", "--interface", required=True)

    # managed
    p_mgd = sub.add_parser("managed", help="Switch to managed mode")
    p_mgd.add_argument("-i", "--interface", required=True)

    args = parser.parse_args()

    dispatch = {
        "server":  cmd_server,
        "scan":    cmd_scan,
        "crack":   cmd_crack,
        "status":  cmd_status,
        "doctor":  cmd_doctor,
        "wordlists": cmd_wordlists,
        "arsenal": cmd_arsenal,
        "monitor": cmd_monitor,
        "managed": cmd_managed,
    }

    if args.command in dispatch:
        try:
            dispatch[args.command](args)
        except KeyboardInterrupt:
            print(f"\n{Y}[*] Snake stopped. Goodbye 🐍{X}")
            sys.exit(0)
    else:
        print_banner()
        parser.print_help()


if __name__ == "__main__":
    main()
