from __future__ import annotations

import json
import os
import pwd
import socket
import struct
from pathlib import Path

APP_DIR_NAME = "routerwatch"

DEFAULT_CONFIG: dict = {
    "lang": None,
    "router_ip": None,
    "username": "admin",
    "password": "",
    "interface": None,
    "capture_all": False,
    "router_dhcp_table": False,
    "setup_done": False,
}


def real_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


def config_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME") or (real_home() / ".config"))
    return base / APP_DIR_NAME / "config.json"


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    path = config_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            cfg.update({k: v for k, v in data.items() if k in DEFAULT_CONFIG})
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return cfg


def save_config(cfg: dict) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def _hex_to_ip(value: str) -> str:
    return socket.inet_ntoa(struct.pack("<I", int(value, 16)))


def _read_routes() -> list[dict]:
    routes: list[dict] = []
    try:
        lines = Path("/proc/net/route").read_text().splitlines()[1:]
    except Exception:
        return routes
    for line in lines:
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            routes.append(
                {
                    "iface": parts[0],
                    "dest": int(parts[1], 16),
                    "gateway": int(parts[2], 16),
                    "mask": int(parts[7], 16),
                }
            )
        except ValueError:
            continue
    return routes


def default_route() -> tuple[str | None, str | None]:
    for route in _read_routes():
        if route["dest"] == 0 and route["gateway"]:
            return route["iface"], _hex_to_ip(f"{route['gateway']:08X}")
    return None, None


def iface_ipv4(iface: str | None) -> str | None:
    if not iface:
        return None
    try:
        import fcntl

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            packed = fcntl.ioctl(
                s.fileno(),
                0x8915,
                struct.pack("256s", iface[:15].encode()),
            )
            return socket.inet_ntoa(packed[20:24])
        finally:
            s.close()
    except Exception:
        return None


def iface_network(iface: str | None) -> tuple[str | None, int]:
    if not iface:
        return None, 24
    for route in _read_routes():
        if route["iface"] == iface and route["dest"] != 0 and route["mask"] != 0:
            network = _hex_to_ip(f"{route['dest']:08X}")
            mask = route["mask"]
            prefix = bin(mask).count("1")
            return network, prefix
    return None, 24


def iface_mac(iface: str | None) -> str | None:
    if not iface:
        return None
    try:
        value = Path(f"/sys/class/net/{iface}/address").read_text().strip()
        return value.lower()
    except Exception:
        return None


def list_interfaces() -> list[str]:
    try:
        return [name for _, name in socket.if_nameindex() if name != "lo"]
    except Exception:
        return []
