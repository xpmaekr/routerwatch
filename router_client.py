from __future__ import annotations

import hashlib
import html as html_lib
import http.cookiejar
import re
import socket
import struct
import subprocess
import urllib.error
import urllib.parse
import urllib.request

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
TAG_RE = re.compile(r"<[^>]+>")
ROW_RE = re.compile(r"<tr\b[^>]*>(.*?)</tr>", re.IGNORECASE | re.DOTALL)
CELL_RE = re.compile(r"<t[dh]\b[^>]*>(.*?)</t[dh]>", re.IGNORECASE | re.DOTALL)
LINK_RE = re.compile(r"(?:href|src)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
INFO_RE = re.compile(r"<span[^>]*class=[\"']?infoText[\"']?[^>]*>(.*?)</span>", re.IGNORECASE | re.DOTALL)
SAVE_RE = re.compile(r"<input[^>]*name=[\"']?save[\"']?[^>]*>", re.IGNORECASE)
VALUE_RE = re.compile(r"value\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)

CANDIDATE_PAGES = [
    "/admin/dhcptbl.asp",
    "/dhcptbl.asp",
    "/admin/dhcpcli.asp",
    "/admin/dhcp_cli.asp",
    "/admin/dhcpclient.asp",
    "/admin/dhcpClient.asp",
    "/admin/lan.asp",
    "/admin/lan_status.asp",
    "/admin/status.asp",
    "/admin/wlstatus.asp",
    "/admin/device.asp",
    "/admin/devices.asp",
    "/admin/client.asp",
    "/admin/arp.asp",
    "/admin/netstat.asp",
    "/admin/dhcpd.asp",
    "/admin/dhcp.asp",
    "/boaform/admin/formDHCPClientList",
    "/boaform/admin/formLanStatus",
    "/boaform/admin/formDHCPClient",
]

KEYWORDS = ("dhcp", "client", "device", "lan", "status", "arp", "host", "station", "wireless", "wlan")


def js_quote(value: str) -> str:
    quoted = urllib.parse.quote(value, safe="-_.*")
    quoted = quoted.replace("~", "%7E").replace("%20", "+")
    return quoted


def form_checksum(text: str) -> int:
    csum = 0
    index = 0
    length = len(text)
    while index < length:
        if index + 4 > length:
            if index < length:
                csum += ord(text[index]) << 24
            if index + 1 < length:
                csum += ord(text[index + 1]) << 16
            if index + 2 < length:
                csum += ord(text[index + 2]) << 8
            break
        csum += (
            (ord(text[index]) << 24)
            + (ord(text[index + 1]) << 16)
            + (ord(text[index + 2]) << 8)
            + ord(text[index + 3])
        )
        index += 4
    csum = (csum & 0xFFFF) + (csum >> 16)
    csum &= 0xFFFF
    csum = (~csum) & 0xFFFF
    return csum


def _to64(value: int, count: int) -> str:
    out = []
    for _ in range(count):
        out.append(ITOA64[value & 0x3F])
        value >>= 6
    return "".join(out)


def md5crypt_pure(password: str, salt: str) -> str:
    pw = password.encode("utf-8")
    sl = salt.encode("utf-8")
    magic = b"$1$"
    ctx = pw + magic + sl
    final = hashlib.md5(pw + sl + pw).digest()
    for remaining in range(len(pw), 0, -16):
        ctx += final[: min(16, remaining)]
    counter = len(pw)
    while counter:
        ctx += b"\x00" if (counter & 1) else pw[0:1]
        counter >>= 1
    final = hashlib.md5(ctx).digest()
    for i in range(1000):
        chunk = b""
        chunk += pw if (i & 1) else final
        if i % 3:
            chunk += sl
        if i % 7:
            chunk += pw
        chunk += final if (i & 1) else pw
        final = hashlib.md5(chunk).digest()
    out = magic + sl + b"$"
    out += _to64((final[0] << 16) | (final[6] << 8) | final[12], 4).encode()
    out += _to64((final[1] << 16) | (final[7] << 8) | final[13], 4).encode()
    out += _to64((final[2] << 16) | (final[8] << 8) | final[14], 4).encode()
    out += _to64((final[3] << 16) | (final[9] << 8) | final[15], 4).encode()
    out += _to64((final[4] << 16) | (final[10] << 8) | final[5], 4).encode()
    out += _to64(final[11], 2).encode()
    return out.decode("ascii")


def md5crypt(password: str) -> str:
    try:
        result = subprocess.run(
            ["openssl", "passwd", "-1", "-salt", "", "-stdin"],
            input=password,
            capture_output=True,
            text=True,
            timeout=5,
        )
        value = result.stdout.strip()
        if value.startswith("$1$"):
            return value
    except Exception:
        pass
    return md5crypt_pure(password, "")


def _clean(cell: str) -> str:
    text = TAG_RE.sub(" ", cell)
    text = html_lib.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def parse_device_rows(html: str) -> list[dict]:
    devices: list[dict] = []
    seen: set[str] = set()

    def add(ip: str, mac: str, name: str | None) -> None:
        if not ip or not mac:
            return
        if ip in ("0.0.0.0", "255.255.255.255"):
            return
        try:
            if any(int(part) > 255 for part in ip.split(".")):
                return
        except ValueError:
            return
        key = mac.lower()
        if key in seen:
            return
        seen.add(key)
        devices.append({"ip": ip, "mac": mac.lower(), "name": (name or "").strip() or None})

    for row in ROW_RE.findall(html):
        cells = [_clean(cell) for cell in CELL_RE.findall(row)]
        if not cells:
            cells = [_clean(row)]
        ip = None
        mac = None
        name = None
        for cell in cells:
            if ip is None:
                match = IP_RE.search(cell)
                if match:
                    ip = match.group(0)
                    continue
            if mac is None:
                match = MAC_RE.search(cell)
                if match:
                    mac = match.group(0).replace("-", ":").lower()
                    continue
            if name is None and re.search(r"[A-Za-zА-Яа-я]", cell) and len(cell) <= 64:
                if not IP_RE.search(cell) and not MAC_RE.search(cell):
                    name = cell
        if ip and mac:
            add(ip, mac, name)

    if devices:
        return devices

    for line in html.splitlines():
        if len(line) > 2000:
            continue
        ip_match = IP_RE.search(line)
        mac_match = MAC_RE.search(line)
        if ip_match and mac_match:
            add(ip_match.group(0), mac_match.group(0).replace("-", ":").lower(), None)
    return devices


def _same_host(a: str, b: str) -> bool:
    return a.strip().lower() == b.strip().lower()


class RouterClient:
    def __init__(self, host: str, username: str, password: str, timeout: float = 6.0) -> None:
        if not host.startswith("http"):
            host = "http://" + host
        self.base = host.rstrip("/")
        self.username = username or "admin"
        self.password = password or ""
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.model: str | None = None
        self.firmware: str | None = None
        self.serial: str | None = None
        self.logged_in = False
        self.last_error: str | None = None
        self._save_value = "Login"
        self._pages: dict[str, str] = {}

    def _request(self, path: str, data: bytes | None = None, headers: dict | None = None) -> tuple[int, str, bytes]:
        url = path if path.startswith("http") else self.base + path
        request = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data else "GET")
        request.add_header("User-Agent", "Mozilla/5.0 RouterWatch")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
                charset = response.headers.get_content_charset() or "utf-8"
                try:
                    text = raw.decode(charset, "ignore")
                except LookupError:
                    text = raw.decode("utf-8", "ignore")
                return response.status, text, raw
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read()
            finally:
                exc.close()
            return exc.code, raw.decode("utf-8", "ignore"), raw
        except Exception as exc:
            self.last_error = str(exc)
            return 0, "", b""

    def fetch(self, path: str) -> str:
        if path in self._pages:
            return self._pages[path]
        status, text, _raw = self._request(path)
        if status == 200 and text:
            self._pages[path] = text
            return text
        return ""

    def _parse_login_page(self, html: str) -> None:
        infos = [_clean(item) for item in INFO_RE.findall(html)]
        if len(infos) >= 1:
            self.model = infos[0]
        if len(infos) >= 2:
            self.firmware = infos[1]
        if len(infos) >= 3:
            self.serial = infos[2]
        match = SAVE_RE.search(html)
        if match:
            value_match = VALUE_RE.search(match.group(0))
            if value_match and value_match.group(1):
                self._save_value = value_match.group(1)

    def login(self) -> bool:
        self._pages.clear()
        status, login_html, _raw = self._request("/admin/login.asp")
        if status != 200 or not login_html:
            self.last_error = "login page unavailable"
            return False
        self._parse_login_page(login_html)
        attempts = [
            (md5crypt(self.password), True),
            (self.password, False),
        ]
        for password_value, with_checksum in attempts:
            if self._try_login(password_value, with_checksum):
                self.logged_in = True
                return True
        self.logged_in = False
        return False

    def _try_login(self, password_value: str, with_checksum: bool) -> bool:
        fields = [
            ("challenge", ""),
            ("username", self.username),
            ("password", password_value),
            ("save", self._save_value),
            ("submit-url", "/admin/login.asp"),
        ]
        input_val = "".join(f"{name}={js_quote(value)}&" for name, value in fields)
        if with_checksum:
            body_text = input_val + f"postSecurityFlag={form_checksum(input_val)}"
        else:
            body_text = input_val + "postSecurityFlag="
        body = body_text.encode("utf-8")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": self.base + "/admin/login.asp",
            "Origin": self.base,
        }
        status, text, _raw = self._request("/boaform/admin/formLogin", data=body, headers=headers)
        if status == 0:
            return False
        lowered_text = text.lower()
        if "другой пользователь" in lowered_text or "already logged" in lowered_text:
            self.last_error = "another_user"
            return False
        status2, status_html, _raw2 = self._request("/admin/status.asp")
        if status2 != 200 or not status_html:
            return False
        lowered = status_html.lower()
        if "другой пользователь" in lowered or "already logged" in lowered:
            self.last_error = "another_user"
            return False
        if "name=\"password\"" in lowered or "name=password" in lowered:
            return False
        if "formstatus" in lowered or "состояние устройства" in lowered or "device status" in lowered:
            self.last_error = None
            return True
        return False

    def _discover_pages(self) -> list[str]:
        pages: list[str] = []
        seen: set[str] = set()

        def add(path: str) -> None:
            path = path.split("#")[0]
            if not path or path.startswith("http") and not path.startswith(self.base):
                return
            if path.startswith(self.base):
                path = path[len(self.base) :]
            if not path.startswith("/"):
                path = "/" + path
            if path in seen:
                return
            seen.add(path)
            pages.append(path)

        for entry in ("/admin/status.asp", "/admin/dhcpd.asp"):
            page = self.fetch(entry)
            for link in LINK_RE.findall(page):
                lower = link.lower()
                if any(keyword in lower for keyword in KEYWORDS):
                    add(link)
        for candidate in CANDIDATE_PAGES:
            add(candidate)
        if len(pages) > 30:
            pages = pages[:30]
        return pages

    def get_devices(
        self,
        exclude_ips: set[str] | None = None,
        include_dhcp_table: bool = False,
    ) -> list[dict]:
        exclude = exclude_ips or set()
        devices: list[dict] = []
        seen: set[str] = set()
        pages = self._discover_pages()
        pages.sort(
            key=lambda path: 0
            if any(keyword in path.lower() for keyword in ("dhcp", "client", "device", "host", "station"))
            else 1
        )
        dhcp_table_pages = {"/dhcptbl.asp", "/admin/dhcptbl.asp"}
        for path in pages:
            if path in dhcp_table_pages and not include_dhcp_table:
                continue
            html = self.fetch(path)
            if not html or not MAC_RE.search(html):
                continue
            found = parse_device_rows(html)
            for device in found:
                if device["ip"] in exclude:
                    continue
                key = device["mac"]
                if key in seen:
                    continue
                seen.add(key)
                devices.append(device)
            if devices:
                break
        return devices

    def get_info(self) -> dict:
        return {
            "model": self.model,
            "firmware": self.firmware,
            "serial": self.serial,
            "logged_in": self.logged_in,
            "error": self.last_error,
        }


def probe(host: str, timeout: float = 3.0) -> bool:
    try:
        parsed = urllib.parse.urlparse(host if "://" in host else "http://" + host)
        port = parsed.port or 80
        with socket.create_connection((parsed.hostname, port), timeout=timeout):
            return True
    except Exception:
        return False
