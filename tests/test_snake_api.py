import unittest
from unittest.mock import Mock, patch

from snakefw.eviltwin import routes as twin_routes
from snakefw.rf import routes as rf_routes
from snakefw.server import app as server


class TestSnakeApi(unittest.TestCase):
    def setUp(self):
        server.app.config["TESTING"] = True
        self.client = server.app.test_client()
        server.session.interface = "wlan-test"
        server.session.monitor_iface = ""
        server.session.networks = []
        server._scanner = None
        server._scan_token = 0
        rf_routes._sessions.clear()
        twin_routes._session = None

    def test_index_uses_local_socket_client(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("/static/js/socket.io.min.js", html)
        self.assertIn("/static/js/eviltwin.js", html)
        self.assertIn("tab-twin", html)
        self.assertIn("RF Tools", html)
        self.assertNotIn("cdn.socket.io", html)

    def test_wordlists_select_rejects_unknown(self):
        response = self.client.post("/api/wordlists/select", json={"tier": "nope"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])

    def test_health_shape(self):
        tools = {"airmon-ng": True, "airodump-ng": True, "aircrack-ng": True}
        with (
            patch.object(server, "check_tools", return_value=tools),
            patch.object(server, "get_interfaces", return_value=["wlan-test"]),
            patch.object(server, "get_interface_mode", return_value="managed"),
        ):
            response = self.client.get("/api/health")
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["interfaces"][0]["name"], "wlan-test")
        self.assertIn("wordlists", payload)

    def test_attack_rejects_invalid_target(self):
        response = self.client.post("/api/attack", json={
            "bssid": "not-a-bssid",
            "attack": "WPA_HANDSHAKE",
            "authorized": True,
        })
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])

    def test_attack_resolves_bssid_from_scan_by_index(self):
        server.session.networks = [{
            "bssid": "30:42:40:9D:49:3C",
            "essid": "Eliwa",
            "channel": 11,
            "attack_vector": "WPA_PMKID",
        }]
        with patch.object(server, "_launch_attack_job", return_value="job1") as launch:
            response = self.client.post("/api/attack", json={
                "essid": "Eliwa",
                "attack": "WPA_PMKID",
                "network_index": 0,
                "authorized": True,
            })
        self.assertEqual(response.status_code, 200)
        launch.assert_called_once()
        kwargs = launch.call_args.kwargs
        self.assertEqual(kwargs["bssid"], "30:42:40:9D:49:3C")
        self.assertEqual(kwargs["essid"], "Eliwa")
        self.assertEqual(kwargs["channel"], 11)

    def test_attack_dry_run_lists_requirements(self):
        response = self.client.post("/api/attack", json={
            "bssid": "AA:BB:CC:DD:EE:FF",
            "essid": "Lab",
            "channel": 6,
            "attack": "WPA_PMKID",
            "dry_run": True,
        })
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["dry_run"])
        self.assertIn("hashcat", payload["requirements"])

    def test_attack_requires_authorization(self):
        response = self.client.post("/api/attack", json={
            "bssid": "AA:BB:CC:DD:EE:FF",
            "attack": "WPA_HANDSHAKE",
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("authorized", response.get_json()["error"])

    def test_auto_action_requires_explicit_targets(self):
        response = self.client.post("/api/attack/auto", json={"authorized": True})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Select", response.get_json()["error"])

    def test_monitor_requires_an_interface(self):
        server.session.interface = ""
        server.session.monitor_iface = ""
        response = self.client.post("/api/interface/monitor", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("interface", response.get_json()["error"].lower())

    def test_monitor_returns_verified_interface(self):
        with (
            patch.object(server, "get_interfaces", return_value=["wlan0", "wlan0mon"]),
            patch.object(server, "get_interface_mode", return_value="monitor"),
            patch.object(server, "set_monitor_mode", return_value="wlan0mon") as mocked,
        ):
            response = self.client.post(
                "/api/interface/monitor", json={"interface": "wlan0"}
            )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["interface"], "wlan0mon")
        self.assertEqual(payload["mode"], "monitor")
        mocked.assert_called_once()

    def test_monitor_failure_is_not_reported_as_success(self):
        with (
            patch.object(server, "get_interfaces", return_value=["wlan0"]),
            patch.object(
                server, "set_monitor_mode", side_effect=RuntimeError("airmon failed")
            ),
        ):
            response = self.client.post(
                "/api/interface/monitor", json={"interface": "wlan0"}
            )
        self.assertEqual(response.status_code, 500)
        self.assertFalse(response.get_json()["ok"])
        self.assertIn("airmon failed", response.get_json()["error"])

    def test_scan_enables_monitor_before_starting(self):
        fake_scanner = Mock()
        fake_scanner._running = True
        fake_scanner.get_networks.return_value = []
        fake_scanner.start.return_value = fake_scanner
        with (
            patch.object(server, "get_interfaces", return_value=["wlan-test"]),
            patch.object(server, "get_interface_mode", return_value="managed"),
            patch.object(server, "set_monitor_mode", return_value="wlan-testmon") as mon,
            patch.object(server, "Scanner", return_value=fake_scanner),
        ):
            response = self.client.post("/api/scan/start", json={"band": "bg", "duration": 0})
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["msg"], "Scanning on wlan-testmon")
        mon.assert_called_once()
        self.assertEqual(server.session.monitor_iface, "wlan-testmon")
        fake_scanner.start.assert_called_once()

    def test_scan_uses_existing_monitor_interface(self):
        fake_scanner = Mock()
        fake_scanner._running = True
        fake_scanner.start.return_value = fake_scanner
        server.session.interface = "wlan0"
        server.session.monitor_iface = ""
        with (
            patch.object(server, "get_interfaces", return_value=["wlan0", "wlan0mon"]),
            patch.object(server, "get_interface_mode", side_effect=lambda name: "monitor" if name.endswith("mon") else "managed"),
            patch.object(server, "set_monitor_mode") as mon,
            patch.object(server, "Scanner", return_value=fake_scanner),
        ):
            response = self.client.post("/api/scan/start", json={"band": "bg", "duration": 0})
        self.assertTrue(response.get_json()["ok"])
        mon.assert_not_called()
        self.assertEqual(server.session.monitor_iface, "wlan0mon")

    def test_rf_requires_authorization(self):
        response = self.client.post("/api/rf/start", json={
            "mode": "deauth",
            "bssid": "AA:BB:CC:DD:EE:FF",
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("authorized", response.get_json()["error"])

    def test_rf_status_shape(self):
        with (
            patch("snakefw.rf.routes.classify_wireless_ifaces", return_value={
                "interfaces": [{"name": "wlan0mon", "mode": "monitor"}],
                "managed": [],
                "monitor": ["wlan0mon"],
            }),
            patch("snakefw.rf.routes.get_interface_mode", return_value="monitor"),
            patch("snakefw.rf.routes.resolve_rf_tool", return_value={
                "kind": "mdk4", "path": "/usr/sbin/mdk4", "label": "mdk4",
            }),
        ):
            response = self.client.get("/api/rf/status")
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertIn("deauth", payload["modes"])
        self.assertEqual(payload["readiness"]["tool"], "mdk4")

    def test_twin_requires_authorization(self):
        response = self.client.post("/api/twin/start", json={
            "essid": "Lab",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "channel": 6,
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("authorized", response.get_json()["error"])

    def test_twin_status_reports_readiness(self):
        with (
            patch("snakefw.eviltwin.routes.classify_wireless_ifaces", return_value={
                "interfaces": [
                    {"name": "wlan0", "mode": "managed", "phy": "phy0"},
                    {"name": "wlan1mon", "mode": "monitor", "phy": "phy1"},
                ],
                "managed": ["wlan0"],
                "monitor": ["wlan1mon"],
            }),
            patch("snakefw.eviltwin.routes.get_interface_mode", side_effect=lambda name: (
                "monitor" if "mon" in name else "managed"
            )),
            patch("snakefw.eviltwin.routes.check_tools", return_value={
                "hostapd": True, "dnsmasq": True, "mdk4": True,
            }),
            patch("snakefw.eviltwin.routes.rf_tool_ready", return_value=True),
            patch("os.geteuid", return_value=0),
        ):
            response = self.client.get("/api/twin/status")
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["readiness"]["ready"])
        self.assertEqual(payload["readiness"]["ap_iface"], "wlan0")
        self.assertEqual(payload["readiness"]["deauth_iface"], "wlan1mon")

    def test_twin_does_not_treat_monitor_parent_as_managed_ap(self):
        with (
            patch("snakefw.eviltwin.routes.classify_wireless_ifaces", return_value={
                "interfaces": [
                    {"name": "wlan0", "mode": "managed", "phy": "phy0"},
                    {"name": "wlan0mon", "mode": "monitor", "phy": "phy0"},
                ],
                "managed": ["wlan0"],
                "monitor": ["wlan0mon"],
            }),
            patch("snakefw.eviltwin.routes.get_interface_mode", side_effect=lambda name: (
                "monitor" if "mon" in name else "managed"
            )),
            patch("snakefw.eviltwin.routes.check_tools", return_value={
                "hostapd": True, "dnsmasq": True, "mdk4": True,
            }),
            patch("snakefw.eviltwin.routes.rf_tool_ready", return_value=True),
            patch("os.geteuid", return_value=0),
        ):
            server.session.monitor_iface = "wlan0mon"
            response = self.client.get("/api/twin/status")
        ready = response.get_json()["readiness"]
        self.assertEqual(ready["ap_iface"], "wlan0mon")
        self.assertEqual(ready["deauth_iface"], "")
        self.assertTrue(ready["will_switch_to_managed"])
        self.assertTrue(ready["single_radio"])
        self.assertTrue(ready["ready"])

    def test_index_includes_strike_tab(self):
        response = self.client.get("/")
        html = response.get_data(as_text=True)
        self.assertIn("tab-strike", html)
        self.assertIn("tab-arsenal", html)

    def test_agent_status_shape(self):
        response = self.client.get("/api/agent/status")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("tool_count", payload)
        self.assertGreater(payload["tool_count"], 10)
        self.assertIn("google_genai_installed", payload)

    def test_arsenal_catalog(self):
        response = self.client.get("/api/arsenal/catalog")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertIn("playbooks", payload)
        self.assertIn("bundles", payload)

    def test_strike_start_requires_authorization(self):
        response = self.client.post("/api/strike/start", json={"preset": "quick"})
        self.assertEqual(response.status_code, 403)

    def test_strike_status_shape(self):
        response = self.client.get("/api/strike/status")
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertIn("presets", payload)
        self.assertIn("tools", payload)

    def test_strike_msf_requires_module(self):
        response = self.client.post("/api/strike/msf", json={"action": "check"})
        self.assertEqual(response.status_code, 400)

    def test_strike_autocheck_requires_authorization(self):
        response = self.client.post("/api/strike/msf/auto-check", json={})
        self.assertEqual(response.status_code, 403)

    def test_strike_scan_host_requires_authorization(self):
        response = self.client.post("/api/strike/scan-host", json={"ip": "10.0.0.5"})
        self.assertEqual(response.status_code, 403)

    def test_strike_nxc_requires_authorization(self):
        response = self.client.post("/api/strike/nxc", json={"ip": "10.0.0.5"})
        self.assertEqual(response.status_code, 403)

    def test_strike_status_lists_nxc_profiles(self):
        payload = self.client.get("/api/strike/status").get_json()
        self.assertIn("discover", payload["presets"])
        self.assertIn("enum", payload["nxc_profiles"])
        self.assertIn("smb", payload["nxc_protocols"])

    def test_pivot_requires_authorization(self):
        response = self.client.post("/api/pivot/start", json={
            "essid": "Lab",
            "psk": "secret",
        })
        self.assertEqual(response.status_code, 403)

    def test_report_html_and_json(self):
        with (
            patch("snakefw.report.builder.load_all_cracked", return_value=[]),
            patch("snakefw.report.builder.load_last_report", return_value={}),
            patch("snakefw.report.builder.classify_wireless_ifaces", return_value={
                "interfaces": [], "managed": [], "monitor": [],
            }),
        ):
            html = self.client.get("/api/report/html")
            payload = self.client.get("/api/report")
        self.assertEqual(html.status_code, 200)
        self.assertIn("engagement report", html.get_data(as_text=True))
        self.assertTrue(payload.get_json()["ok"])
        self.assertIn("summary", payload.get_json()["report"])

    def test_index_includes_report_and_pivot_hooks(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("radio-plan", html)
        self.assertIn("rf-stealth", html)
        self.assertIn("openReport", html)
        self.assertIn("online-queue-list", html)
        self.assertIn("wpa-sec", html)

    def test_online_submit_requires_authorization(self):
        response = self.client.post("/api/online-queue/abc123/submit", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("authorization", response.get_json()["error"])

    def test_online_queue_lists_items(self):
        with patch("snakefw.server.app.list_queue", return_value=[{
            "id": "abc123", "essid": "Lab", "status": "queued",
        }]):
            response = self.client.get("/api/online-queue")
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["items"][0]["id"], "abc123")


if __name__ == "__main__":
    unittest.main()

