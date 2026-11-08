import os
import shutil
import tempfile
import unittest

import config as cfgmod
from app import DashboardScreen, DevicesScreen, LanguageScreen, RouterWatchApp, SetupScreen
from textual.widgets import Button, DataTable, Input


def base_cfg(**overrides):
    cfg = dict(cfgmod.DEFAULT_CONFIG)
    cfg.update(
        {
            "lang": "ru",
            "setup_done": True,
            "router_ip": None,
            "interface": "wlan0",
            "capture_all": False,
        }
    )
    cfg.update(overrides)
    return cfg


class AppTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="routerwatch-test-")
        self.old_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self.tmp

    def tearDown(self):
        if self.old_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self.old_xdg
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_dashboard_receives_events(self):
        app = RouterWatchApp(base_cfg())
        async with app.run_test() as pilot:
            await pilot.pause()
            self.assertIsInstance(app.screen, DashboardScreen)
            app.events.put(
                {
                    "type": "request",
                    "ts": 0,
                    "src_ip": "192.168.1.50",
                    "src_mac": "aa:bb:cc:dd:ee:01",
                    "dst_ip": "1.1.1.1",
                    "dst_port": 443,
                    "proto": "tls",
                    "host": "example.com",
                    "path": None,
                    "url": "https://example.com",
                    "size": 1234,
                }
            )
            app.events.put({"type": "device", "ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:01", "name": "test-pc"})
            await pilot.pause(0.6)
            table = app.screen.query_one("#requests-table")
            self.assertEqual(table.row_count, 1)
            self.assertEqual(app.requests, 1)
            self.assertEqual(app.devices.name_for("192.168.1.50", None, "ru"), "test-pc")

    async def test_language_switch_preserves_log(self):
        app = RouterWatchApp(base_cfg())
        async with app.run_test() as pilot:
            await pilot.pause()
            app.events.put(
                {
                    "type": "request",
                    "ts": 0,
                    "src_ip": "192.168.1.50",
                    "src_mac": None,
                    "dst_ip": "1.1.1.1",
                    "dst_port": 53,
                    "proto": "dns",
                    "host": "example.com",
                    "path": None,
                    "url": "https://example.com",
                    "size": 40,
                }
            )
            await pilot.pause(0.6)
            app.set_language("en")
            app.switch_screen(DashboardScreen())
            await pilot.pause(0.6)
            table = app.screen.query_one("#requests-table")
            self.assertEqual(table.row_count, 1)

    async def test_first_run_flow(self):
        app = RouterWatchApp(base_cfg(lang=None, setup_done=False))
        async with app.run_test() as pilot:
            await pilot.pause()
            self.assertIsInstance(app.screen, LanguageScreen)
            await pilot.click("#lang-ru")
            await pilot.pause(0.5)
            self.assertIsInstance(app.screen, SetupScreen)
            app.screen.query_one("#input-ip", Input).value = "127.0.0.1"
            app.screen.query_one("#input-user", Input).value = "admin"
            app.screen.query_one("#input-pass", Input).value = "secret"
            app.screen.query_one("#save", Button).press()
            await pilot.pause(0.6)
            self.assertIsInstance(app.screen, DashboardScreen)
            self.assertTrue(app.cfg["setup_done"])
            self.assertEqual(app.cfg["router_ip"], "127.0.0.1")
            self.assertTrue(os.path.exists(os.path.join(self.tmp, "routerwatch", "config.json")))

    async def test_devices_screen(self):
        app = RouterWatchApp(base_cfg())
        async with app.run_test() as pilot:
            await pilot.pause()
            app.devices.update("192.168.1.50", "aa:bb:cc:dd:ee:01", "test-pc")
            app.push_screen(DevicesScreen())
            await pilot.pause(0.6)
            table = app.screen.query_one("#devices-table", DataTable)
            self.assertEqual(table.row_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
