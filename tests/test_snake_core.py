import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from snakefw.core.network_analyzer import NetworkAnalyzer
from snakefw.core.paths import BUILTIN_WORDLIST, CRACKED_FILE, REPO_DIR
from snakefw.core.wordlists import (
    build_tiered_wordlists,
    cascade_wordlists,
    essid_candidates,
    is_wpa_candidate,
    resolve_wordlist,
    wifi_mutations,
)
from snakefw.core.online_crack import enqueue_failed, list_queue, _match_key
from snakefw.core.ap_support import (
    choose_ap_channel,
    explain_hostapd_failure,
    hostapd_channel_failed,
    parse_iw_phy,
    parse_reg_domain,
)
from snakefw.core.radios import assign_roles, conflicts_with_scanner
from snakefw.core.scanner import Scanner, parse_airodump_csv
from snakefw.core.tool_manager import (
    TOOL_CATALOG,
    CrackEngine,
    build_wifite_command,
    check_tools,
    find_executable,
    find_handshake_cap,
    get_interface_mode,
    is_valid_bssid,
    normalize_bssid,
    parse_airmon_monitor_iface,
    parse_handshake_cap_path,
    set_managed_mode,
)
from snakefw.eviltwin.engine import (
    EvilTwinSession,
    claim_ap_iface,
    parse_station_dump,
    release_ap_iface,
    write_hostapd_conf,
    write_dnsmasq_conf,
)
from snakefw.rf.engine import RF_AUTH, RF_BEACON, RF_DEAUTH, build_rf_command
from snakefw.core.cracked_store import (
    append_cracked,
    cracked_password,
    is_valid_cracked_entry,
    sanitize_cracked_list,
)
from snakefw.strike.parsers import classify_role, next_action, parse_nmap_xml, parse_nxc_text, score_host
from snakefw.strike.msf_map import pick_recommended, suggest_msf
from snakefw.strike.engine import DISCOVER_FLAGS, NXC_PROFILES, PRESETS, sanitize_ips


class TestSnakePaths(unittest.TestCase):
    def test_repository_paths_are_canonical(self):
        self.assertEqual(CRACKED_FILE, REPO_DIR / "cracked.json")
        self.assertEqual(BUILTIN_WORDLIST, REPO_DIR / "wordlist-top4800-probable.txt")

    def test_result_save_is_atomic_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_dir = root / "results"
            result_dir.mkdir()
            main_file = root / "cracked.json"
            engine = CrackEngine()

            with (
                patch("snakefw.core.tool_manager.RESULTS", result_dir),
                patch("snakefw.core.tool_manager.CRACKED_FILE", main_file),
            ):
                engine._save_result("Lab", "AA:BB:CC:DD:EE:FF", "secret", "WPA", "lab.cap")
                engine._save_result("Lab", "AA:BB:CC:DD:EE:FF", "secret", "WPA", "lab.cap")

            with main_file.open(encoding="utf-8") as handle:
                saved = json.load(handle)
            self.assertEqual(len(saved), 1)
            self.assertFalse(main_file.with_suffix(".json.tmp").exists())


class TestSnakeAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = NetworkAnalyzer()

    def test_attack_vectors_match_api_values(self):
        open_network = self.analyzer.analyze({
            "bssid": "AA:BB:CC:DD:EE:01", "essid": "Open", "encryption": "OPN",
        })
        wep_network = self.analyzer.analyze({
            "bssid": "AA:BB:CC:DD:EE:02", "essid": "Legacy", "encryption": "WEP",
        })
        client_network = self.analyzer.analyze({
            "bssid": "AA:BB:CC:DD:EE:03", "essid": "Lab", "encryption": "WPA2",
            "clients": 1,
        })
        self.assertEqual(open_network.attack_vector, "NONE")
        self.assertEqual(wep_network.attack_vector, "WEP")
        self.assertEqual(client_network.attack_vector, "WPA_HANDSHAKE")

    def test_csv_parser_handles_valid_access_point(self):
        csv_text = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
            "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            "AA:BB:CC:DD:EE:FF, now, now, 6, 54, WPA2, CCMP, PSK, -42, 10, 3, "
            "0.0.0.0, 3, Lab,\n\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".csv") as handle:
            handle.write(csv_text)
            handle.flush()
            networks = parse_airodump_csv(handle.name)
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0]["essid"], "Lab")
        self.assertEqual(networks[0]["channel"], 6)
        self.assertEqual(networks[0]["client_macs"], [])

    def test_csv_parser_reads_real_airodump_export(self):
        csv_path = Path(__file__).resolve().parent / "files" / "airodump.csv"
        networks = parse_airodump_csv(str(csv_path))
        self.assertIsNotNone(networks)
        self.assertGreater(len(networks), 10)
        essids = {net["essid"] for net in networks}
        self.assertIn("HOME-89B5-2.4", essids)
        home = next(net for net in networks if net["bssid"] == "00:1D:D5:9B:11:00")
        self.assertEqual(home["essid"], "HOME-1102")
        self.assertGreaterEqual(home["clients"], 1)
        self.assertTrue(home["client_macs"])

    def test_csv_parser_ignores_leading_blank_and_crlf(self):
        csv_text = (
            "\r\n"
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
            "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n"
            "AA:BB:CC:DD:EE:FF, now, now, 11, 54, WPA2, CCMP, PSK, -55, 4, 0, "
            "0.0.0.0, 3, Lab,\r\n"
            "\r\n"
            "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\r\n"
            "11:22:33:44:55:66, now, now, -60, 2, AA:BB:CC:DD:EE:FF,\r\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".csv", newline="") as handle:
            handle.write(csv_text)
            handle.flush()
            networks = parse_airodump_csv(handle.name)
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0]["essid"], "Lab")
        self.assertEqual(networks[0]["clients"], 1)
        self.assertEqual(networks[0]["client_macs"], ["11:22:33:44:55:66"])

    def test_scanner_runs_airodump_in_background_mode(self):
        scanner = Scanner("wlan0mon", band="abg")
        with (
            patch("snakefw.core.scanner.shutil.which", return_value="/usr/sbin/airodump-ng"),
            patch("snakefw.core.scanner.subprocess.Popen") as popen,
            patch("snakefw.core.scanner.threading.Thread"),
        ):
            popen.return_value = object()
            scanner.start()
        cmd = popen.call_args[0][0]
        self.assertIn("--background", cmd)
        self.assertIn("1", cmd)
        self.assertIn("--band", cmd)
        self.assertIn("abg", cmd)
        self.assertEqual(cmd[-1], "wlan0mon")
        scanner._running = False
        if scanner._tmpdir:
            shutil.rmtree(scanner._tmpdir, ignore_errors=True)


class TestWordlists(unittest.TestCase):
    def test_wpa_filter_and_mutations(self):
        self.assertTrue(is_wpa_candidate("password"))
        self.assertFalse(is_wpa_candidate("1234567"))
        self.assertTrue(any(item.startswith("password") for item in wifi_mutations()))

    def test_builder_writes_tiers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fast = root / "fast.txt"
            smart = root / "smart.txt"
            deep = root / "deep.txt"
            source = root / "src.txt"
            source.write_text("password\nshort\n12345678\npassword\n", encoding="utf-8")
            with (
                patch("snakefw.core.wordlists.TIER_FILES", {
                    "fast": fast, "smart": smart, "deep": deep,
                }),
                patch("snakefw.core.wordlists.FAST_SOURCES", (source,)),
                patch("snakefw.core.wordlists.SMART_EXTRA_SOURCES", ()),
                patch("snakefw.core.wordlists.DEEP_SOURCES", ()),
                patch("snakefw.core.wordlists.wifi_mutations", return_value=["qwerty123"]),
            ):
                built = build_tiered_wordlists()
            self.assertGreaterEqual(built["fast"]["count"], 2)
            self.assertIn("password", fast.read_text(encoding="utf-8"))
            self.assertNotIn("short", fast.read_text(encoding="utf-8"))
            self.assertTrue(smart.exists())
            self.assertTrue(deep.exists())

    def test_essid_candidates_cover_name_and_year(self):
        keys = essid_candidates("Orange-Osama")
        self.assertIn("OrangeOsama", keys)
        self.assertIn("orangeosama", keys)
        self.assertTrue(any(item.startswith("OrangeOsama") for item in keys))
        self.assertTrue(all(is_wpa_candidate(item) for item in keys))

    def test_cascade_from_smart_skips_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            fast = Path(tmp) / "fast.txt"
            smart = Path(tmp) / "smart.txt"
            deep = Path(tmp) / "deep.txt"
            fast.write_text("abcdefgh\n", encoding="utf-8")
            smart.write_text("smartpass\n", encoding="utf-8")
            deep.write_text("deeppassw\n", encoding="utf-8")
            with patch("snakefw.core.wordlists.TIER_FILES", {
                "fast": fast, "smart": smart, "deep": deep,
            }):
                names = [item["tier"] for item in cascade_wordlists(tier="smart")]
        self.assertEqual(names, ["smart", "deep"])

    def test_resolve_prefers_named_tier(self):
        with tempfile.TemporaryDirectory() as tmp:
            smart = Path(tmp) / "snake-smart.txt"
            smart.write_text("abcdefgh\n", encoding="utf-8")
            with patch("snakefw.core.wordlists.TIER_FILES", {
                "fast": Path(tmp) / "missing-fast.txt",
                "smart": smart,
                "deep": Path(tmp) / "missing-deep.txt",
            }):
                chosen = resolve_wordlist(tier="smart")
            self.assertEqual(chosen["path"], str(smart))
            self.assertEqual(chosen["tier"], "smart")


class TestOnlineQueue(unittest.TestCase):
    def test_enqueue_copies_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cap = root / "lab.cap"
            cap.write_bytes(b"pcap")
            captures = root / "captures"
            results = root / "results"
            captures.mkdir()
            results.mkdir()
            with (
                patch("snakefw.core.online_crack.CAPTURES_DIR", captures),
                patch("snakefw.core.online_crack.RESULTS_DIR", results),
                patch("snakefw.core.online_crack.QUEUE_FILE", results / "online_queue.json"),
            ):
                item = enqueue_failed("Lab", "AA:BB:CC:DD:EE:FF", cap_file=str(cap), lists_tried=["Smart"])
                queued = list_queue()
            self.assertEqual(item["essid"], "Lab")
            self.assertEqual(item["status"], "queued")
            self.assertTrue(Path(item["cap"]).is_file())
            self.assertEqual(len(queued), 1)

    def test_match_key_from_pot_line(self):
        line = "aabbccddeeff:Lab:SuperSecret"
        self.assertEqual(_match_key(line, "AA:BB:CC:DD:EE:FF", "Lab"), "SuperSecret")


class TestCrackCascade(unittest.TestCase):
    def test_offline_tries_next_list(self):
        engine = CrackEngine(wordlist="")
        first = {"tier": "smart", "label": "Smart", "path": "/tmp/smart.txt", "exists": True, "count": 2}
        second = {"tier": "deep", "label": "Deep", "path": "/tmp/deep.txt", "exists": True, "count": 3}
        with (
            patch.object(engine, "_cascade_entries", return_value=[first, second]),
            patch.object(engine, "crack_pmkid_hashcat", return_value=None),
            patch.object(engine, "crack_handshake_aircrack", side_effect=[None, "foundkey"]),
            patch("snakefw.core.tool_manager.hashcat_has_compute_backend", return_value=False),
        ):
            key = engine.crack_offline("/tmp/lab.cap", "AA:BB:CC:DD:EE:FF", "Lab", kind="handshake")
        self.assertEqual(key, "foundkey")
        self.assertEqual(engine.lists_tried, ["Smart", "Deep"])


class TestBssidHelpers(unittest.TestCase):
    def test_normalize_bssid_compact(self):
        self.assertEqual(normalize_bssid("3042409d493c"), "30:42:40:9D:49:3C")
        self.assertEqual(normalize_bssid("30-42-40-9D-49-3C"), "30:42:40:9D:49:3C")
        self.assertTrue(is_valid_bssid("30:42:40:9D:49:3C"))


class TestWifiteIntegrationHelpers(unittest.TestCase):
    def test_build_wifite_command_uses_supported_flags(self):
        cmd = build_wifite_command(
            "/tmp/Wifite.py",
            "wlan0mon",
            bssid="aa:bb:cc:dd:ee:ff",
            essid="LabNet",
            channel=6,
        )
        self.assertIn("-i", cmd)
        self.assertIn("wlan0mon", cmd)
        self.assertIn("-b", cmd)
        self.assertIn("AA:BB:CC:DD:EE:FF", cmd)
        self.assertIn("-e", cmd)
        self.assertIn("LabNet", cmd)
        self.assertIn("-c", cmd)
        self.assertIn("6", cmd)
        self.assertNotIn("--interface", cmd)
        self.assertNotIn("--target-bssid", cmd)
        self.assertNotIn("--no-crack", cmd)

    def test_build_wifite_command_can_skip_crack(self):
        cmd = build_wifite_command("/tmp/Wifite.py", "wlan0mon", no_crack=True)
        self.assertIn("--no-crack", cmd)
        self.assertNotIn("--dict", cmd)

    def test_parse_handshake_cap_path(self):
        bssid, essid = parse_handshake_cap_path(
            "/home/kali/wifite2/hs/handshake_OrangeOsama_C0-49-43-21-27-0F_2026-10-02T00-33-07.cap"
        )
        self.assertEqual(bssid, "C0:49:43:21:27:0F")
        self.assertEqual(essid, "OrangeOsama")

    def test_find_handshake_cap_matches_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            hs = Path(tmp)
            older = hs / "handshake_OtherNet_AA-BB-CC-DD-EE-FF_2026-10-02T00-00-00.cap"
            newer = hs / "handshake_LabNet_AA-BB-CC-DD-EE-FF_2026-10-02T00-01-00.cap"
            older.write_text("old", encoding="utf-8")
            newer.write_text("new", encoding="utf-8")
            now = time.time()
            os.utime(older, (now - 30, now - 30))
            os.utime(newer, (now - 5, now - 5))
            found = find_handshake_cap(
                str(hs),
                "AA:BB:CC:DD:EE:FF",
                "LabNet",
                min_mtime=now - 20,
            )
            self.assertEqual(found, str(newer))

    def test_find_handshake_cap_reuses_old_when_needed(self):
        with tempfile.TemporaryDirectory() as tmp:
            hs = Path(tmp)
            older = hs / "handshake_LabNet_AA-BB-CC-DD-EE-FF_2026-10-02T00-00-00.cap"
            older.write_text("old", encoding="utf-8")
            now = time.time()
            os.utime(older, (now - 120, now - 120))
            found = find_handshake_cap(str(hs), "AA:BB:CC:DD:EE:FF", "LabNet", min_mtime=0)
            self.assertEqual(found, str(older))
            self.assertIsNone(find_handshake_cap(
                str(hs), "AA:BB:CC:DD:EE:FF", "LabNet", min_mtime=now - 10,
            ))


class TestMonitorModeHelpers(unittest.TestCase):
    def test_parse_airmon_renamed_interface(self):
        output = (
            "phy0    wlan0           iwlwifi\n"
            "\t(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)\n"
        )
        self.assertEqual(parse_airmon_monitor_iface(output, "wlan0"), "wlan0mon")

    def test_parse_airmon_same_interface(self):
        output = "monitor mode enabled on wlan0"
        self.assertEqual(parse_airmon_monitor_iface(output, "wlan0"), "wlan0")

    def test_iw_type_monitor(self):
        iw_info = "Interface wlan0mon\n\tifindex 5\n\twdev 0x2\n\taddr aa:bb\n\ttype monitor\n"
        with patch("snakefw.core.tool_manager.subprocess.check_output", return_value=iw_info):
            self.assertEqual(get_interface_mode("wlan0mon"), "monitor")

    def test_iwconfig_monitor_not_confused_by_essid(self):
        iwconfig = (
            "wlan0mon  IEEE 802.11  ESSID:off/any\n"
            "          Mode:Monitor  Frequency:2.437 GHz\n"
        )

        def fake_output(cmd, **_kwargs):
            if cmd and cmd[0] == "iw":
                raise FileNotFoundError("iw")
            return iwconfig

        with patch("snakefw.core.tool_manager.subprocess.check_output", side_effect=fake_output):
            self.assertEqual(get_interface_mode("wlan0mon"), "monitor")

    def test_essid_alone_is_not_managed(self):
        def fake_output(cmd, **_kwargs):
            if cmd and cmd[0] == "iw":
                raise FileNotFoundError("iw")
            return "wlan0  IEEE 802.11  ESSID:lab\n"

        with patch("snakefw.core.tool_manager.subprocess.check_output", side_effect=fake_output):
            self.assertEqual(get_interface_mode("wlan0"), "unknown")


class TestRfHelpers(unittest.TestCase):
    def test_catalog_includes_twin_and_rf_tools(self):
        for name in ("hostapd", "dnsmasq", "mdk4", "mdk3", "wpa_supplicant", "dhclient"):
            self.assertIn(name, TOOL_CATALOG)
        tools = check_tools()
        self.assertIn("wpa_supplicant", tools)
        self.assertIn("dhclient", tools)

    def test_find_executable_checks_sbin(self):
        found = find_executable("wpa_supplicant")
        if found:
            self.assertTrue(found.endswith("wpa_supplicant"))

    def test_build_rf_prefers_mdk4_flags(self):
        cmd = build_rf_command(
            RF_DEAUTH,
            "wlan0mon",
            bssid="aa:bb:cc:dd:ee:ff",
            channel=6,
            client="11:22:33:44:55:66",
            tool={"kind": "mdk4", "path": "/usr/sbin/mdk4"},
        )
        self.assertEqual(cmd[0], "/usr/sbin/mdk4")
        self.assertIn("d", cmd)
        self.assertIn("-B", cmd)
        self.assertIn("AA:BB:CC:DD:EE:FF", cmd)
        self.assertIn("-S", cmd)

    def test_build_rf_falls_back_to_mdk3(self):
        cmd = build_rf_command(
            RF_DEAUTH,
            "wlan0mon",
            bssid="AA:BB:CC:DD:EE:FF",
            tool={"kind": "mdk3", "path": "/usr/sbin/mdk3"},
        )
        self.assertEqual(cmd[:3], ["/usr/sbin/mdk3", "wlan0mon", "d"])
        self.assertIn("-b", cmd)

    def test_build_rf_aireplay_deauth_only(self):
        cmd = build_rf_command(
            RF_DEAUTH,
            "wlan0mon",
            bssid="AA:BB:CC:DD:EE:FF",
            tool={"kind": "aireplay", "path": "/usr/sbin/aireplay-ng"},
        )
        self.assertIn("--deauth", cmd)
        with self.assertRaises(ValueError):
            build_rf_command(
                RF_BEACON,
                "wlan0mon",
                tool={"kind": "aireplay", "path": "/usr/sbin/aireplay-ng"},
            )

    def test_build_rf_beacon_and_auth(self):
        beacon = build_rf_command(
            RF_BEACON,
            "wlan0mon",
            channel=11,
            tool={"kind": "mdk4", "path": "mdk4"},
        )
        auth = build_rf_command(
            RF_AUTH,
            "wlan0mon",
            bssid="AA:BB:CC:DD:EE:FF",
            tool={"kind": "mdk4", "path": "mdk4"},
        )
        self.assertIn("b", beacon)
        self.assertIn("a", auth)
        self.assertIn("-a", auth)


class TestTwinHelpers(unittest.TestCase):
    def test_hostapd_and_dnsmasq_configs(self):
        with tempfile.TemporaryDirectory() as tmp:
            hostapd = write_hostapd_conf(Path(tmp) / "hostapd.conf", "wlan1", "Lab", 6)
            dnsmasq = write_dnsmasq_conf(Path(tmp) / "dnsmasq.conf", "wlan1", "10.0.0.1")
            hostapd_text = hostapd.read_text(encoding="utf-8")
            dnsmasq_text = dnsmasq.read_text(encoding="utf-8")
        self.assertIn("ssid=Lab", hostapd_text)
        self.assertIn("channel=6", hostapd_text)
        self.assertIn("disassoc_low_ack=0", hostapd_text)
        self.assertIn("skip_inactivity_poll=1", hostapd_text)
        self.assertIn("wmm_enabled=0", hostapd_text)
        self.assertIn("interface=wlan1", dnsmasq_text)
        self.assertIn("address=/#/10.0.0.1", dnsmasq_text)
        self.assertIn("dhcp-authoritative", dnsmasq_text)
        self.assertIn("dhcp-option=114,http://10.0.0.1/", dnsmasq_text)

    def test_hostapd_includes_country_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_hostapd_conf(Path(tmp) / "hostapd.conf", "wlan0", "Lab", 149, country="EG")
            text = path.read_text(encoding="utf-8")
        self.assertIn("hw_mode=a", text)
        self.assertIn("channel=149", text)
        self.assertIn("country_code=EG", text)

    def test_claim_ap_iface_unmanages_networkmanager(self):
        ok = subprocess.CompletedProcess([], 0, "", "")
        unmanaged = subprocess.CompletedProcess([], 0, "10 (unmanaged)\n", "")

        def fake_run(cmd, timeout=8):
            text = " ".join(cmd)
            if "GENERAL.STATE" in text:
                return unmanaged
            return ok

        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "99-snake-unmanaged.conf"
            with patch("snakefw.core.ap_support.shutil.which", return_value="/usr/bin/nmcli"), \
                 patch("snakefw.core.ap_support.NM_UNMANAGED_CONF", conf), \
                 patch("snakefw.core.ap_support.nm_service_active", return_value=True), \
                 patch("snakefw.core.ap_support.time.sleep"), \
                 patch("snakefw.core.ap_support._run", side_effect=fake_run) as run:
                state = claim_ap_iface("wlan0")
                self.assertTrue(state["nm_unmanaged"])
                self.assertIn("interface-name:wlan0", conf.read_text(encoding="utf-8"))
                cmds = [tuple(call.args[0]) for call in run.call_args_list]
                self.assertIn(("nmcli", "device", "set", "wlan0", "managed", "no"), cmds)
                self.assertIn(("iw", "dev", "wlan0", "set", "power_save", "off"), cmds)
                release_ap_iface(state)
            self.assertFalse(conf.exists())

    def test_claim_treats_stopped_networkmanager_as_unmanaged(self):
        with patch("snakefw.core.ap_support.shutil.which", return_value="/usr/bin/nmcli"), \
             patch("snakefw.core.ap_support.nm_service_active", return_value=False), \
             patch("snakefw.core.ap_support.persist_unmanaged", return_value=True), \
             patch("snakefw.core.ap_support._reload_networkmanager"), \
             patch("snakefw.core.ap_support._run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, "", "")
            state = claim_ap_iface("wlan0")
        self.assertTrue(state["nm_unmanaged"])

    def test_select_ap_channel_uses_plan(self):
        session = EvilTwinSession("Lab", "", 48, "wlan0")
        logs = []
        session.on_log = logs.append
        with patch("snakefw.eviltwin.engine.plan_ap_channel", return_value={
            "channel": 149,
            "fallbacks": [153, 6],
            "note": "Target ch48 is NO-IR for AP mode. Using 5GHz ch149",
            "hw_mode": "a",
            "supports_ap": True,
        }):
            session._select_ap_channel()
        self.assertEqual(session.requested_channel, 48)
        self.assertEqual(session.channel, 149)
        self.assertEqual(session._hostapd_candidates(), [149, 153, 6])
        self.assertTrue(any("ch149" in line for line in logs))

    def test_reclaim_after_interface_disabled(self):
        session = EvilTwinSession("Lab", "", 6, "wlan0")
        session.hostapd = type("Hostapd", (), {"output": [
            "AP-ENABLED",
            "wlan0: INTERFACE-DISABLED",
        ]})()
        with patch("snakefw.eviltwin.engine.claim_ap_iface") as claim, \
             patch("snakefw.eviltwin.engine._run"):
            claim.return_value = {"iface": "wlan0", "nm_unmanaged": True}
            session._reclaim_if_hostapd_disabled()
            session._reclaim_if_hostapd_disabled()
        self.assertEqual(claim.call_count, 1)

    def test_parse_station_dump(self):
        output = (
            "Station aa:bb:cc:dd:ee:01 (on wlan1)\n"
            "\tsignal: -41 dBm\n"
            "Station AA:BB:CC:DD:EE:02 (on wlan1)\n"
            "\tsignal: -55 dBm\n"
        )
        clients = parse_station_dump(output)
        self.assertEqual(len(clients), 2)
        self.assertEqual(clients[0]["mac"], "AA:BB:CC:DD:EE:01")
        self.assertEqual(clients[0]["signal"], -41)


class TestManagedMode(unittest.TestCase):
    def test_skip_networkmanager_restart(self):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch("snakefw.core.tool_manager.os.geteuid", return_value=0), \
             patch("snakefw.core.tool_manager.get_interface_mode", side_effect=["monitor", "managed"]), \
             patch("snakefw.core.tool_manager.shutil.which", return_value="/usr/sbin/airmon-ng"), \
             patch("snakefw.core.tool_manager._run_cmd"), \
             patch("snakefw.core.tool_manager.time.sleep"), \
             patch("snakefw.core.tool_manager.get_interfaces", return_value=["wlan0"]), \
             patch("snakefw.core.tool_manager.subprocess.run", side_effect=fake_run):
            result = set_managed_mode("wlan0mon", restart_networkmanager=False)
        self.assertEqual(result, "wlan0")
        self.assertFalse(any(cmd[:2] == ["systemctl", "start"] for cmd in calls))


class TestCrackedStore(unittest.TestCase):
    def test_rejects_empty_key(self):
        bad = {
            "essid": "Orange-Osama",
            "bssid": "C0:49:43:21:27:0F",
            "key": "",
            "type": "WPA",
        }
        self.assertFalse(is_valid_cracked_entry(bad))
        cleaned, removed = sanitize_cracked_list([bad])
        self.assertEqual(cleaned, [])
        self.assertEqual(removed, 1)

    def test_accepts_wps_pin(self):
        row = {"essid": "Lab", "bssid": "AA:BB:CC:DD:EE:FF", "pin": "12345678", "type": "WPS"}
        self.assertTrue(is_valid_cracked_entry(row))
        self.assertEqual(cracked_password(row), "12345678")

    def test_append_rejects_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cracked.json"
            self.assertFalse(append_cracked({"essid": "x", "key": ""}, paths=[path]))
            self.assertFalse(path.exists())


class TestStrikeParsers(unittest.TestCase):
    def test_parse_nmap_xml_host_and_port(self):
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="10.0.0.5" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="445">
                <state state="open"/>
                <service name="microsoft-ds" product="Windows" version="10"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        data = parse_nmap_xml(xml)
        self.assertEqual(data["summary"]["live"], 1)
        host = data["hosts"][0]
        self.assertEqual(host["ip"], "10.0.0.5")
        self.assertEqual(host["ports"][0]["port"], 445)

    def test_parse_nxc_text_finding(self):
        line = "SMB  192.168.1.10  445  DC01  [+] Signing disabled"
        findings = parse_nxc_text(line, protocol="smb")
        self.assertEqual(len(findings), 1)
        self.assertGreater(findings[0]["severity"], 5)

    def test_msf_suggest_for_smb_host(self):
        host = {
            "ip": "10.0.0.5",
            "ports": [{"port": 445, "proto": "tcp", "service": "microsoft-ds"}],
            "services": [],
            "findings": [{"title": "Signing disabled", "detail": "message_signing disabled"}],
        }
        mods = suggest_msf(host)
        self.assertTrue(any("smb" in m["module"] for m in mods))
        host["risk_score"] = score_host(host)
        self.assertGreater(host["risk_score"], 0)

    def test_role_and_next_action(self):
        host = {
            "ip": "10.0.0.8",
            "hostname": "DC01",
            "ports": [{"port": 88}, {"port": 445}],
            "services": ["88/tcp:kerberos"],
            "findings": [{"title": "MS17-010", "detail": "VULNERABLE", "severity": 10}],
        }
        host["role"] = classify_role(host)
        self.assertEqual(host["role"], "dc")
        host["msf_modules"] = suggest_msf(host)
        host["next_action"] = next_action(host)
        self.assertIn("10.0.0.8", host["next_action"])
        rec = pick_recommended([host])
        self.assertIsNotNone(rec)
        self.assertEqual(rec["ip"], "10.0.0.8")

    def test_nxc_noise_is_dropped(self):
        text = "SMB  10.0.0.1  445  HOST  [-] Connection refused"
        self.assertEqual(parse_nxc_text(text, protocol="smb"), [])

    def test_discovery_uses_arp_and_tcp_ping(self):
        self.assertIn("-PR", DISCOVER_FLAGS)
        self.assertTrue(any(flag.startswith("-PS") for flag in DISCOVER_FLAGS))
        self.assertEqual(PRESETS["discover"]["stop_after"], "discover")
        self.assertIn("-Pn", PRESETS["smart"]["service"])

    def test_nxc_enum_profile_has_share_flags(self):
        self.assertIn("--shares", NXC_PROFILES["enum"]["flags"]["smb"])
        self.assertIn("--users", NXC_PROFILES["enum"]["flags"]["ldap"])

    def test_sanitize_ips_rejects_junk(self):
        self.assertEqual(sanitize_ips(["10.0.0.5", "10.0.0.5", "nope", ""]), ["10.0.0.5"])

    def test_alive_host_asks_for_nmap(self):
        host = {"ip": "10.0.0.9", "ports": [], "findings": [], "msf_modules": []}
        self.assertIn("nmap", next_action(host).lower())


class TestApSupport(unittest.TestCase):
    INTEL_PHY = """
	Supported interface modes:
		 * managed
		 * AP
		 * monitor
	Band 1:
		Frequencies:
			* 2412.0 MHz [1] (22.0 dBm)
			* 2437.0 MHz [6] (22.0 dBm)
			* 2462.0 MHz [11] (22.0 dBm)
			* 2484.0 MHz [14] (disabled)
	Band 2:
		Frequencies:
			* 5180.0 MHz [36] (22.0 dBm) (no IR)
			* 5240.0 MHz [48] (22.0 dBm) (no IR)
			* 5260.0 MHz [52] (22.0 dBm) (no IR, radar detection)
			* 5745.0 MHz [149] (22.0 dBm)
			* 5765.0 MHz [153] (22.0 dBm)
			* 5785.0 MHz [157] (22.0 dBm)
			* 5805.0 MHz [161] (22.0 dBm)
			* 5825.0 MHz [165] (22.0 dBm) (no IR)
    """

    def test_parse_intel_no_ir_and_unii3(self):
        radio = parse_iw_phy(self.INTEL_PHY)
        self.assertTrue(radio["supports_ap"])
        self.assertEqual(radio["ap_24"], [1, 6, 11])
        self.assertEqual(radio["ap_5"], [149, 153, 157, 161])
        ch48 = next(row for row in radio["channels"] if row["channel"] == 48)
        self.assertTrue(ch48["no_ir"])
        self.assertFalse(ch48["ap_ok"])

    def test_channel_48_falls_back_to_149(self):
        radio = parse_iw_phy(self.INTEL_PHY)
        plan = choose_ap_channel(48, radio)
        self.assertEqual(plan["channel"], 149)
        self.assertFalse(plan["matched"])
        self.assertIn(6, plan["fallbacks"])
        self.assertIn("NO-IR", plan["note"])

    def test_channel_6_stays(self):
        radio = parse_iw_phy(self.INTEL_PHY)
        plan = choose_ap_channel(6, radio)
        self.assertEqual(plan["channel"], 6)
        self.assertTrue(plan["matched"])

    def test_unprobed_radio_keeps_requested_and_24ghz_fallback(self):
        plan = choose_ap_channel(48, {"channels": [], "ap_24": [], "ap_5": []})
        self.assertEqual(plan["channel"], 48)
        self.assertIn(6, plan["fallbacks"])
        self.assertEqual(plan["reason"], "unprobed")

    def test_hostapd_channel_error_text(self):
        log = (
            "Frequency 5240 (primary) not allowed for AP mode, flags: 0x30073 NO-IR\n"
            "wlan0: IEEE 802.11 Hardware does not support configured channel\n"
        )
        self.assertTrue(hostapd_channel_failed(log))
        msg = explain_hostapd_failure(log, 48, {"ap_24": [1, 6, 11], "ap_5": [149]})
        self.assertIn("48", msg)
        self.assertIn("149", msg)

    def test_parse_self_managed_country(self):
        text = (
            "global\ncountry 00: DFS-UNSET\n\n"
            "phy#0 (self-managed)\ncountry EG: DFS-UNSET\n"
        )
        self.assertEqual(parse_reg_domain(text, "phy0"), "EG")


class TestRadioPlan(unittest.TestCase):
    def test_dual_radio_splits_scan_and_attack(self):
        classified = {
            "interfaces": [
                {"name": "wlan0mon", "mode": "monitor", "phy": "phy0"},
                {"name": "wlan1mon", "mode": "monitor", "phy": "phy1"},
            ],
            "managed": [],
            "monitor": ["wlan0mon", "wlan1mon"],
        }
        plan = assign_roles(classified, session_monitor="wlan0mon")
        self.assertTrue(plan["dual_radio"])
        self.assertEqual(plan["scan_iface"], "wlan0mon")
        self.assertEqual(plan["attack_iface"], "wlan1mon")
        self.assertEqual(plan["deauth_iface"], "wlan1mon")
        self.assertFalse(conflicts_with_scanner("wlan1mon", "wlan0mon", classified))
        self.assertTrue(conflicts_with_scanner("wlan0mon", "wlan0mon", classified))

    def test_single_radio_matches_twin_parent_vif(self):
        classified = {
            "interfaces": [
                {"name": "wlan0", "mode": "managed", "phy": "phy0"},
                {"name": "wlan0mon", "mode": "monitor", "phy": "phy0"},
            ],
            "managed": ["wlan0"],
            "monitor": ["wlan0mon"],
        }
        plan = assign_roles(classified, session_monitor="wlan0mon")
        self.assertTrue(plan["single_radio"])
        self.assertEqual(plan["ap_iface"], "wlan0mon")
        self.assertEqual(plan["deauth_iface"], "")
        self.assertTrue(plan["will_switch_to_managed"])
        self.assertTrue(conflicts_with_scanner("wlan0mon", "wlan0mon", classified))

    def test_managed_plus_second_monitor_is_twin_ready(self):
        classified = {
            "interfaces": [
                {"name": "wlan0", "mode": "managed", "phy": "phy0"},
                {"name": "wlan1mon", "mode": "monitor", "phy": "phy1"},
            ],
            "managed": ["wlan0"],
            "monitor": ["wlan1mon"],
        }
        plan = assign_roles(classified)
        self.assertEqual(plan["ap_iface"], "wlan0")
        self.assertEqual(plan["deauth_iface"], "wlan1mon")
        self.assertEqual(plan["client_iface"], "")
        self.assertTrue(plan["dual_radio"])


class TestStealthRfCommand(unittest.TestCase):
    def test_aireplay_burst_count(self):
        cmd = build_rf_command(
            RF_DEAUTH,
            "wlan0mon",
            bssid="AA:BB:CC:DD:EE:FF",
            count=8,
            tool={"kind": "aireplay", "path": "/usr/sbin/aireplay-ng"},
        )
        self.assertIn("--deauth", cmd)
        self.assertIn("8", cmd)


class TestReportSanitizesSecrets(unittest.TestCase):
    def test_redacts_keys_by_default(self):
        from snakefw.report.builder import build_report

        with (
            patch("snakefw.report.builder.load_all_cracked", return_value=[{
                "essid": "Lab",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "key": "supersecret",
                "attack": "WPA_HANDSHAKE",
            }]),
            patch("snakefw.report.builder.load_last_report", return_value={
                "hosts": [{"ip": "10.0.0.2", "role": "linux", "risk_score": 40}],
                "top_findings": [{"title": "MS17-010", "severity": 10, "ip": "10.0.0.2"}],
            }),
            patch("snakefw.report.builder.classify_wireless_ifaces", return_value={
                "interfaces": [],
                "managed": [],
                "monitor": [],
            }),
        ):
            report = build_report(include_secrets=False)
        self.assertEqual(report["cracked"][0]["key"], "••••••••")
        self.assertGreaterEqual(report["summary"]["risk_score"], 70)
        self.assertTrue(any("PSK" in g["title"] or "SMB" in g["title"] for g in report["guidance"]))


if __name__ == "__main__":
    unittest.main()

