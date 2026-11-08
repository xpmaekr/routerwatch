# RouterWatch

fully vibecoded tbo

**English** | [Русский](README.ru.md)

TUI network traffic monitor that maps requests to devices on the local network.
It shows who requests what: domains, HTTPS/HTTP, DNS and device names.

```
 Time     Device       Type   Request                       Size
 12:04:11 test-pc      HTTPS  https://github.com           1.2 KB
 12:04:12 phone        DNS    https://api.telegram.org      42 B
 12:04:13 tv           HTTP   http://192.168.1.1/admin      8.4 KB
```

## Features

- Language selection on first launch (RU/EN); settings are remembered.
- Configure router IP, login, password and network interface.
- Request table: time, device, type, readable URL, size.
- Device names from the router's DHCP table, DHCP and mDNS.
- Friendly names: `iPhone 15 Pro`, `Pixel 10a`, `Galaxy S23`; for unnamed devices
  it falls back to the vendor by MAC (OUI): `Apple`, `Samsung`, `Xiaomi`, etc.
- Passive capture without interfering with the network (default).
- Optional MITM mode for traffic from other devices.

## Requirements

- Linux, root privileges (raw `AF_PACKET` sockets).
- Python 3.11+ (tested on 3.14).
- Textual 8.x.
- `openssl` for md5-crypt (a built-in fallback is included).

## Installation

```bash
git clone https://github.com/xpmaekr/routerwatch.git
cd routerwatch
python3 -m pip install --user -r requirements.txt
chmod +x routerwatch
```

Arch/CachyOS:

```bash
sudo pacman -S python-textual openssl
```

## Usage

```bash
./routerwatch
```

The launcher requests sudo itself. Or run it explicitly:

```bash
sudo ./routerwatch
```

On first launch, pick a language and fill in:

- **Router IP** — prefilled from the default route.
- **Login/password** — for the router's web admin (used for the DHCP client list).
- **Interface** — usually detected automatically.
- **Capture the whole network (MITM)** — off by default.
- **Read the router's DHCP table** — off by default; it provides names for all
  devices, but on some Realtek firmware the `/dhcptbl.asp` page can hang the
  router's web interface.

Press **Start**. The **Devices** button shows discovered names/IP/MAC.

## How it works

- `AF_PACKET` listens on the interface and parses Ethernet/IP/TCP/UDP.
- DNS — names from queries; TLS — SNI from ClientHello; HTTP — the `Host` header.
- DHCP and mDNS provide device names, ARP provides IP↔MAC mappings.
- `device_names.py` normalizes hostnames to `iPhone 15`, `Pixel 10a` and adds the
  vendor by MAC prefix. The OUI database is read from `/usr/share/hwdata/oui.txt`
  (or `/usr/share/ieee-data/oui.txt`), with a built-in fallback list.
- For a complete device list, enable login to the Realtek Boa admin and parsing
  of the DHCP clients page (disabled by default).
- MITM: ARP spoofing of the gateway and hosts, enabling `ip_forward`. On stop,
  the ARP tables and `ip_forward` are restored.

## Project layout

- `app.py` — Textual UI: language, setup, dashboard and devices screens.
- `sniffer.py` — passive `AF_PACKET` sniffer: DNS, TLS SNI, HTTP Host, DHCP,
  mDNS, ARP.
- `router_client.py` — Realtek Boa login and DHCP client parsing.
- `config.py` — config and automatic gateway/interface/network/MAC detection.
- `device_names.py` — hostname normalization and vendor lookup by MAC (OUI).
- `i18n.py` — RU/EN interface strings.
- `tests/` — unittest: packet parsing, md5-crypt, UI via Textual pilot.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Limitations

- HTTPS does not reveal the path or content — only the domain.
- Home routers do not provide a per-request log; a sniffer is used instead.
- In MITM mode, a Wi-Fi access point may block client-to-client traffic.
  Ethernet is more reliable.
- Do not stop the program with `kill -9` in MITM mode: ARP entries persist for
  several minutes. Use the **Stop** or **Exit** button.
- On some Realtek firmware, GET `/dhcptbl.asp` hangs the router's web server
  (ping keeps working). That is why reading the DHCP table is disabled by
  default; if you enabled it and the router hung, power-cycle it.

## Privacy and legal

The tool is intended for analyzing **your own** network. Run it only where you
have the right to do so. The router password is stored locally in
`~/.config/routerwatch/config.json` with `0600` permissions and is never sent
anywhere except to the router itself. There is no telemetry.

## License

MIT.
