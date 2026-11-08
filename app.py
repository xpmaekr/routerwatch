from __future__ import annotations

import queue
import threading
import time
from collections import deque

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Select, Static, Switch

import config as cfgmod
from device_names import friendly_name
from i18n import t
from router_client import RouterClient
from sniffer import Capture


def human_size(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KB"
    return f"{value / (1024 * 1024):.1f} MB"


class DeviceStore:
    def __init__(self) -> None:
        self.by_ip: dict[str, str] = {}
        self.by_mac: dict[str, str] = {}
        self.names: dict[str, str] = {}
        self.order: list[str] = []

    def update(self, ip: str | None, mac: str | None, name: str | None = None) -> None:
        if ip and mac:
            self.by_ip[ip] = mac
            self.by_mac[mac] = ip
        if name:
            if ip:
                self.names[ip] = name
            if mac:
                self.names[mac] = name
        key = ip or mac
        if key and key not in self.order:
            self.order.append(key)

    def _raw_name(self, ip: str | None, mac: str | None) -> str | None:
        for key in (ip, mac):
            if key and key in self.names:
                return self.names[key]
        return None

    def name_for(self, ip: str | None, mac: str | None, lang: str) -> str:
        friendly = friendly_name(self._raw_name(ip, mac), mac, lang)
        if friendly:
            return friendly
        if ip:
            return ip
        if mac:
            return mac
        return t(lang, "unknown_device")

    def rows(self, lang: str = "ru") -> list[tuple[str, str, str]]:
        result = []
        seen: set[str] = set()
        for key in self.order:
            ip = key if ":" not in key else self.by_mac.get(key)
            mac = key if ":" in key else self.by_ip.get(key)
            if not ip and not mac:
                continue
            identity = mac or ip
            if identity in seen:
                continue
            seen.add(identity)
            name = friendly_name(self._raw_name(ip, mac), mac, lang) or ""
            result.append((name, ip or "", mac or ""))
        return result


class LanguageScreen(Screen):
    def __init__(self) -> None:
        super().__init__(id="language-screen")

    def compose(self) -> ComposeResult:
        app: "RouterWatchApp" = self.app
        lang = app.lang
        with Vertical(id="lang-box"):
            yield Static(t(lang, "app_title"), id="app-title")
            yield Static(t(lang, "choose_language"), id="lang-title")
            with Horizontal(id="lang-buttons"):
                yield Button(t(lang, "lang_ru"), id="lang-ru", variant="primary")
                yield Button(t(lang, "lang_en"), id="lang-en")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        app: "RouterWatchApp" = self.app
        if event.button.id == "lang-ru":
            app.set_language("ru")
        elif event.button.id == "lang-en":
            app.set_language("en")
        else:
            return
        if app.cfg.get("setup_done"):
            app.switch_screen(DashboardScreen())
        else:
            app.switch_screen(SetupScreen())


class SetupScreen(Screen):
    def __init__(self) -> None:
        super().__init__(id="setup-screen")

    def compose(self) -> ComposeResult:
        app: "RouterWatchApp" = self.app
        lang = app.lang
        cfg = app.cfg
        iface, gateway = cfgmod.default_route()
        router_ip = cfg.get("router_ip") or gateway or "192.168.1.1"
        interfaces = cfgmod.list_interfaces()
        current_iface = cfg.get("interface") or iface or (interfaces[0] if interfaces else "")
        yield Header(show_clock=False)
        with VerticalScroll(id="setup-scroll"):
            with Vertical(id="setup-box"):
                yield Static(t(lang, "setup_title"), classes="title")
                yield Label(t(lang, "router_ip"))
                yield Input(value=router_ip, id="input-ip")
                yield Label(t(lang, "router_user"))
                yield Input(value=cfg.get("username") or "admin", id="input-user")
                yield Label(t(lang, "router_pass"))
                yield Input(value=cfg.get("password") or "", password=True, id="input-pass")
                yield Label(t(lang, "interface"))
                options = [(name, name) for name in interfaces] or [(current_iface, current_iface)]
                yield Select(options, value=current_iface, allow_blank=False, id="select-iface")
                with Horizontal(id="mitm-row"):
                    yield Switch(value=bool(cfg.get("capture_all")), id="switch-mitm")
                    yield Label(t(lang, "capture_all"), id="mitm-label")
                yield Static(t(lang, "capture_all_hint"), classes="hint")
                with Horizontal(id="dhcp-row"):
                    yield Switch(value=bool(cfg.get("router_dhcp_table")), id="switch-dhcp")
                    yield Label(t(lang, "router_dhcp_table"), id="dhcp-label")
                yield Static(t(lang, "router_dhcp_table_hint"), classes="hint")
                with Horizontal(id="setup-buttons"):
                    yield Button(t(lang, "save_connect"), id="save", variant="primary")
                    if cfg.get("setup_done"):
                        yield Button(t(lang, "back"), id="back")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        app: "RouterWatchApp" = self.app
        if event.button.id == "back":
            app.switch_screen(DashboardScreen())
            return
        if event.button.id != "save":
            return
        ip_input = self.query_one("#input-ip", Input)
        user_input = self.query_one("#input-user", Input)
        pass_input = self.query_one("#input-pass", Input)
        iface_select = self.query_one("#select-iface", Select)
        mitm_switch = self.query_one("#switch-mitm", Switch)
        dhcp_switch = self.query_one("#switch-dhcp", Switch)
        app.cfg["router_ip"] = ip_input.value.strip() or None
        app.cfg["username"] = user_input.value.strip() or "admin"
        app.cfg["password"] = pass_input.value
        if iface_select.value not in (Select.BLANK, None):
            app.cfg["interface"] = str(iface_select.value)
        app.cfg["capture_all"] = bool(mitm_switch.value)
        app.cfg["router_dhcp_table"] = bool(dhcp_switch.value)
        app.cfg["setup_done"] = True
        try:
            cfgmod.save_config(app.cfg)
        except Exception as exc:
            app.notify(t(app.lang, "save_error", err=str(exc)), severity="error")
            return
        app.switch_screen(DashboardScreen())


class DevicesScreen(ModalScreen):
    def compose(self) -> ComposeResult:
        app: "RouterWatchApp" = self.app
        lang = app.lang
        with Vertical(id="devices-box"):
            yield Static(t(lang, "devices_title"), classes="title")
            table = DataTable(id="devices-table", zebra_stripes=True)
            yield table
            yield Button(t(lang, "close"), id="close", variant="primary")

    def on_mount(self) -> None:
        self._fill()
        self.set_interval(1.0, self._fill)

    def _fill(self) -> None:
        app: "RouterWatchApp" = self.app
        lang = app.lang
        table = self.query_one("#devices-table", DataTable)
        table.clear(columns=True)
        table.add_columns(t(lang, "device_name"), t(lang, "device_ip"), t(lang, "device_mac"))
        for name, ip, mac in app.devices.rows(lang):
            table.add_row(name or t(lang, "unknown_device"), ip, mac)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close":
            self.app.pop_screen()


class DashboardScreen(Screen):
    def __init__(self) -> None:
        super().__init__()
        self._row_keys: deque = deque()
        self._timer = None

    def compose(self) -> ComposeResult:
        app: "RouterWatchApp" = self.app
        lang = app.lang
        yield Header(show_clock=True)
        yield Static("", id="status-bar")
        yield DataTable(id="requests-table", zebra_stripes=True, cursor_type="row")
        with Horizontal(id="actions"):
            yield Button(t(lang, "btn_start"), id="start", variant="success")
            yield Button(t(lang, "btn_stop"), id="stop", variant="error", disabled=True)
            yield Button(t(lang, "btn_devices"), id="devices")
            yield Button(t(lang, "btn_clear"), id="clear")
            yield Button(t(lang, "btn_setup"), id="setup")
            yield Button(t(lang, "btn_language"), id="language")
            yield Button(t(lang, "btn_quit"), id="quit")
        yield Footer()

    def on_mount(self) -> None:
        app: "RouterWatchApp" = self.app
        lang = app.lang
        table = self.query_one("#requests-table", DataTable)
        table.add_columns(
            t(lang, "col_time"),
            t(lang, "col_device"),
            t(lang, "col_type"),
            t(lang, "col_request"),
            t(lang, "col_size"),
        )
        for event in list(app.request_log):
            self._add_row(event, scroll=False)
        self._refresh_status()
        self._timer = self.set_interval(0.25, self._drain)
        app.probe_router()
        if app.capturing and app.capture and app.capture.running:
            self.query_one("#start", Button).disabled = True
            self.query_one("#stop", Button).disabled = False

    def on_unmount(self) -> None:
        if self._timer:
            self._timer.stop()

    def _drain(self) -> None:
        app: "RouterWatchApp" = self.app
        table = self.query_one("#requests-table", DataTable)
        changed = False
        added = False
        while True:
            try:
                event = app.events.get_nowait()
            except queue.Empty:
                break
            changed = True
            app.handle_event(event)
            if event.get("type") == "request":
                self._add_row(event, scroll=True)
                added = True
            elif event.get("type") == "error":
                message = event.get("message", "")
                if message == "need_root":
                    app.notify(t(app.lang, "need_root"), severity="error", timeout=8)
                else:
                    app.notify(message, severity="error", timeout=8)
        if added:
            table.scroll_end(animate=False)
        if changed:
            self._refresh_status()
            start = self.query_one("#start", Button)
            stop = self.query_one("#stop", Button)
            running = bool(app.capture and app.capture.running)
            start.disabled = running
            stop.disabled = not running

    def _add_row(self, event: dict, scroll: bool) -> None:
        app: "RouterWatchApp" = self.app
        lang = app.lang
        table = self.query_one("#requests-table", DataTable)
        proto = event.get("proto", "other")
        if proto == "dns":
            kind = t(lang, "type_dns")
        elif proto == "tls":
            kind = t(lang, "type_tls")
        elif proto == "http":
            kind = t(lang, "type_http")
        else:
            kind = t(lang, "type_other")
        device = app.devices.name_for(event.get("src_ip"), event.get("src_mac"), lang)
        timestamp = time.strftime("%H:%M:%S", time.localtime(event.get("ts", time.time())))
        key = str(app.next_row_id())
        self._row_keys.append(key)
        table.add_row(
            timestamp,
            device,
            kind,
            event.get("url") or event.get("host") or "",
            human_size(int(event.get("size", 0))),
            key=key,
        )
        while len(self._row_keys) > 2000:
            old = self._row_keys.popleft()
            try:
                table.remove_row(old)
            except Exception:
                break

    def _refresh_status(self) -> None:
        app: "RouterWatchApp" = self.app
        lang = app.lang
        if app.capture and app.capture.running:
            state = t(lang, "status_running")
        elif app.last_capture_error:
            state = t(lang, "status_error")
        else:
            state = t(lang, "status_idle")
        mode = t(lang, "mode_all") if app.cfg.get("capture_all") else t(lang, "mode_local")
        parts = [state, mode]
        if app.info.get("model"):
            parts.append(str(app.info["model"]))
        if app.info.get("logged_in"):
            parts.append(t(lang, "login_ok"))
        elif app.router_checked:
            parts.append(t(lang, "no_router"))
        parts.append(t(lang, "requests_count", n=app.requests))
        parts.append(t(lang, "devices_found", n=len(app.devices.order)))
        self.query_one("#status-bar", Static).update("  ·  ".join(parts))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        app: "RouterWatchApp" = self.app
        button = event.button.id
        if button == "start":
            app.start_capture()
            self._refresh_status()
        elif button == "stop":
            app.stop_capture()
            self._refresh_status()
        elif button == "devices":
            app.push_screen(DevicesScreen())
        elif button == "clear":
            table = self.query_one("#requests-table", DataTable)
            table.clear()
            self._row_keys.clear()
            app.request_log.clear()
            app.requests = 0
            self._refresh_status()
        elif button == "setup":
            app.switch_screen(SetupScreen())
        elif button == "language":
            app.switch_screen(LanguageScreen())
        elif button == "quit":
            app.stop_capture()
            app.exit()


class RouterWatchApp(App):
    CSS = """
    Screen { background: $surface; }
    #language-screen { align: center middle; }
    #setup-screen { align-horizontal: center; }
    #lang-box, #setup-box {
        width: 70;
        height: auto;
        padding: 2 3;
        margin: 2 0;
        border: round $primary;
        background: $panel;
    }
    #app-title { text-style: bold; color: $accent; }
    #lang-title, .title { text-style: bold; margin-bottom: 1; }
    #lang-buttons, #setup-buttons, #actions { height: auto; margin-top: 1; }
    #actions { padding: 1 1; }
    #actions Button { margin-right: 1; }
    .hint { color: $text-muted; margin-bottom: 1; }
    #mitm-row { height: auto; align: left middle; }
    #mitm-label { margin-left: 1; }
    #status-bar {
        height: 1;
        padding: 0 1;
        background: $panel;
        color: $text;
    }
    #requests-table { height: 1fr; }
    #setup-scroll { height: 1fr; }
    #devices-box {
        width: 90%;
        height: 80%;
        padding: 1 2;
        border: round $primary;
        background: $panel;
    }
    #devices-table { height: 1fr; }
    Input { margin-bottom: 1; }
    """

    def __init__(self, cfg: dict) -> None:
        super().__init__()
        self.cfg = cfg
        self.lang = cfg.get("lang") or "ru"
        self.events: queue.Queue = queue.Queue()
        self.devices = DeviceStore()
        self.request_log: deque = deque(maxlen=2000)
        self.capture: Capture | None = None
        self.capturing = False
        self.requests = 0
        self.packets = 0
        self.info: dict = {}
        self.router_checked = False
        self.last_capture_error: str | None = None
        self._row_id = 0

    def on_mount(self) -> None:
        if not self.cfg.get("lang"):
            self.push_screen(LanguageScreen())
        elif not self.cfg.get("setup_done"):
            self.push_screen(SetupScreen())
        else:
            self.push_screen(DashboardScreen())

    def on_unmount(self) -> None:
        if self.capture:
            self.capture.stop()

    def next_row_id(self) -> int:
        self._row_id += 1
        return self._row_id

    def set_language(self, lang: str) -> None:
        self.lang = lang
        self.cfg["lang"] = lang
        try:
            cfgmod.save_config(self.cfg)
        except Exception:
            pass

    def handle_event(self, event: dict) -> None:
        kind = event.get("type")
        if kind == "request":
            self.requests += 1
            self.devices.update(event.get("src_ip"), event.get("src_mac"))
            self.request_log.append(event)
        elif kind == "device":
            self.devices.update(event.get("ip"), event.get("mac"), event.get("name"))
        elif kind == "error":
            self.last_capture_error = event.get("message")
        elif kind == "stopped":
            self.capturing = False

    def start_capture(self) -> None:
        if self.capture and self.capture.running:
            return
        iface = self.cfg.get("interface") or cfgmod.default_route()[0]
        if not iface:
            self.notify(t(self.lang, "status_error"), severity="error")
            return
        _iface, gateway = cfgmod.default_route()
        our_ip = cfgmod.iface_ipv4(iface)
        network, prefix = cfgmod.iface_network(iface)
        self.last_capture_error = None
        self.capture = Capture(
            iface=iface,
            on_event=self.events.put,
            mitm=bool(self.cfg.get("capture_all")),
            gateway_ip=self.cfg.get("router_ip") or gateway,
            our_ip=our_ip,
            network=network,
            prefix=prefix,
        )
        self.capture.start()
        self.capturing = True
        if self.cfg.get("capture_all"):
            self.notify(t(self.lang, "mitm_warning"), severity="warning", timeout=10)
            if iface.startswith("wl"):
                self.notify(t(self.lang, "mitm_wifi_warning"), severity="warning", timeout=10)

    def stop_capture(self) -> None:
        if self.capture:
            self.capture.stop()
        self.capturing = False

    @work(thread=True, exclusive=True)
    def probe_router(self) -> None:
        ip = self.cfg.get("router_ip")
        if not ip:
            self.call_from_thread(self._router_result, {}, [], False)
            return
        client = RouterClient(ip, self.cfg.get("username") or "admin", self.cfg.get("password") or "")
        ok = False
        devices: list[dict] = []
        try:
            ok = client.login()
            if ok:
                devices = client.get_devices(
                    {ip},
                    include_dhcp_table=bool(self.cfg.get("router_dhcp_table")),
                )
        except Exception:
            ok = False
        info = client.get_info()
        self.call_from_thread(self._router_result, info, devices, ok)

    def _router_result(self, info: dict, devices: list[dict], ok: bool) -> None:
        self.info = info or {}
        self.router_checked = True
        for device in devices:
            self.devices.update(device.get("ip"), device.get("mac"), device.get("name"))
        try:
            screen = self.screen
            if isinstance(screen, DashboardScreen):
                screen._refresh_status()
        except Exception:
            pass
        if not ok:
            if (info or {}).get("error") == "another_user":
                self.notify(t(self.lang, "router_busy"), severity="warning", timeout=8)
            else:
                self.notify(t(self.lang, "no_router"), severity="warning", timeout=6)


def main() -> None:
    cfg = cfgmod.load_config()
    app = RouterWatchApp(cfg)
    app.run()


if __name__ == "__main__":
    main()
