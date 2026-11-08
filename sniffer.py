from __future__ import annotations

import select
import socket
import struct
import threading
import time
from typing import Callable

ETH_P_ALL = 0x0003
ETH_P_ARP = 0x0806
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
PACKET_OUTGOING = getattr(socket, "PACKET_OUTGOING", 4)

DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    43: "DS",
    46: "RRSIG",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY",
}

HTTP_METHODS = {
    b"GET",
    b"POST",
    b"PUT",
    b"HEAD",
    b"DELETE",
    b"OPTIONS",
    b"PATCH",
    b"CONNECT",
    b"TRACE",
}

TLS_PORTS = {443, 8443, 993, 465, 995, 587, 636, 8443}
HTTP_PORTS = {80, 8080, 8008, 8888, 8081}


def mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def mac_to_bytes(value: str) -> bytes:
    return bytes(int(part, 16) for part in value.split(":"))


def parse_ethernet(data: bytes):
    if len(data) < 14:
        return None
    dst = data[0:6]
    src = data[6:12]
    ethertype = struct.unpack("!H", data[12:14])[0]
    offset = 14
    while ethertype in (0x8100, 0x88A8):
        if len(data) < offset + 4:
            return None
        ethertype = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
        offset += 4
    return src, dst, ethertype, data[offset:]


def parse_ipv4(data: bytes):
    if len(data) < 20:
        return None
    version_ihl = data[0]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_len = struct.unpack("!H", data[2:4])[0]
    if total_len < ihl or total_len > len(data):
        total_len = len(data)
    proto = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    frag = struct.unpack("!H", data[6:8])[0]
    frag_offset = frag & 0x1FFF
    payload = data[ihl:total_len]
    return src, dst, proto, frag_offset, payload


def parse_ipv6(data: bytes):
    if len(data) < 40:
        return None
    if data[0] >> 4 != 6:
        return None
    payload_len = struct.unpack("!H", data[4:6])[0]
    next_header = data[6]
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    payload = data[40 : 40 + payload_len]
    offset = 0
    while next_header in (0, 43, 60) and len(payload) >= offset + 8:
        next_header = payload[offset]
        ext_len = (payload[offset + 1] + 1) * 8
        offset += ext_len
    if next_header == 44:
        return None
    return src, dst, next_header, payload[offset:]


def parse_udp(data: bytes):
    if len(data) < 8:
        return None
    src_port, dst_port, length, _ = struct.unpack("!HHHH", data[:8])
    if length >= 8 and length <= len(data):
        payload = data[8:length]
    else:
        payload = data[8:]
    return src_port, dst_port, payload


def parse_tcp(data: bytes):
    if len(data) < 20:
        return None
    src_port, dst_port, seq = struct.unpack("!HHI", data[:8])
    offset_flags = struct.unpack("!H", data[12:14])[0]
    data_offset = (offset_flags >> 12) * 4
    if data_offset < 20 or data_offset > len(data):
        return None
    return src_port, dst_port, seq, data[data_offset:]


def parse_dns_name(data: bytes, offset: int):
    labels: list[str] = []
    original = offset
    jumped = False
    hops = 0
    while True:
        if offset >= len(data):
            return None, original
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                original = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return None, original
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original = offset + 2
            offset = pointer
            jumped = True
            hops += 1
            if hops > 20:
                return None, original
            continue
        if length > 63:
            return None, original
        offset += 1
        if offset + length > len(data):
            return None, original
        labels.append(data[offset : offset + length].decode("latin1", "ignore"))
        offset += length
    name = ".".join(labels)
    return (name or None), original


def parse_dns(data: bytes):
    if len(data) < 12:
        return []
    qdcount = struct.unpack("!H", data[4:6])[0]
    ancount = struct.unpack("!H", data[6:8])[0]
    offset = 12
    questions = []
    for _ in range(qdcount):
        name, offset = parse_dns_name(data, offset)
        if name is None or offset + 4 > len(data):
            break
        qtype, _qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append((name, qtype))
    answers = []
    for _ in range(ancount):
        name, offset = parse_dns_name(data, offset)
        if name is None or offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        if rtype == 1 and rdlength == 4:
            answers.append((name, socket.inet_ntoa(rdata)))
        elif rtype == 28 and rdlength == 16:
            answers.append((name, socket.inet_ntop(socket.AF_INET6, rdata)))
    return questions, answers


def parse_tls_sni(data: bytes):
    if len(data) < 9 or data[0] != 0x16:
        return None
    if data[5] != 0x01:
        return None
    try:
        length = struct.unpack("!I", b"\x00" + data[6:9])[0]
        end = min(len(data), 9 + length)
        pos = 9 + 2 + 32
        if pos + 1 > end:
            return None
        session_len = data[pos]
        pos += 1 + session_len
        if pos + 2 > end:
            return None
        cipher_len = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2 + cipher_len
        if pos + 1 > end:
            return None
        comp_len = data[pos]
        pos += 1 + comp_len
        if pos + 2 > end:
            return None
        ext_total = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2
        ext_end = min(end, pos + ext_total)
        while pos + 4 <= ext_end:
            ext_type, ext_len = struct.unpack("!HH", data[pos : pos + 4])
            pos += 4
            if ext_type == 0:
                if pos + 2 > ext_end:
                    return None
                list_len = struct.unpack("!H", data[pos : pos + 2])[0]
                p = pos + 2
                list_end = min(ext_end, p + list_len)
                while p + 3 <= list_end:
                    name_type = data[p]
                    name_len = struct.unpack("!H", data[p + 1 : p + 3])[0]
                    p += 3
                    if p + name_len > list_end:
                        break
                    if name_type == 0:
                        return data[p : p + name_len].decode("latin1", "ignore")
                    p += name_len
                return None
            pos += ext_len
    except Exception:
        return None
    return None


def parse_http_request(data: bytes):
    if not data:
        return None
    line_end = data.find(b"\r\n")
    if line_end <= 0:
        return None
    try:
        line = data[:line_end].decode("latin1", "ignore")
    except Exception:
        return None
    parts = line.split()
    if len(parts) < 2:
        return None
    method = parts[0].encode("latin1", "ignore")
    if method not in HTTP_METHODS:
        return None
    path = parts[1]
    host = None
    headers = data[line_end + 2 : line_end + 2 + 8192]
    for raw_line in headers.split(b"\r\n"):
        if not raw_line:
            break
        if raw_line.lower().startswith(b"host:"):
            host = raw_line.split(b":", 1)[1].strip().decode("latin1", "ignore")
            break
    return method.decode("latin1", "ignore"), host, path


def parse_dhcp(data: bytes):
    if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
        return None
    mac = mac_to_str(data[28:34])
    options = data[240:]
    hostname = None
    requested_ip = None
    message_type = None
    index = 0
    while index < len(options):
        code = options[index]
        if code == 0:
            index += 1
            continue
        if code == 255:
            break
        if index + 1 >= len(options):
            break
        length = options[index + 1]
        value = options[index + 2 : index + 2 + length]
        index += 2 + length
        if code == 12:
            hostname = value.decode("utf-8", "ignore").strip("\x00 ")
        elif code == 50 and len(value) == 4:
            requested_ip = socket.inet_ntoa(value)
        elif code == 53 and value:
            message_type = value[0]
    return {"mac": mac, "hostname": hostname, "requested_ip": requested_ip, "message_type": message_type}


def parse_arp(data: bytes):
    if len(data) < 28:
        return None
    htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", data[:8])
    if ptype != 0x0800 or plen != 4 or hlen != 6:
        return None
    sha = mac_to_str(data[8:14])
    spa = socket.inet_ntoa(data[14:18])
    tha = mac_to_str(data[18:24])
    tpa = socket.inet_ntoa(data[24:28])
    return oper, sha, spa, tha, tpa


def build_arp_packet(op, sha, spa, tha, tpa, eth_dst, eth_src):
    ethernet = eth_dst + eth_src + struct.pack("!H", ETH_P_ARP)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op)
    arp += mac_to_bytes(sha) + socket.inet_aton(spa)
    arp += mac_to_bytes(tha) + socket.inet_aton(tpa)
    return ethernet + arp


def _build_url(proto: str, host: str | None, path: str | None) -> str:
    if not host:
        host = ""
    if proto == "http":
        scheme = "http://"
    else:
        scheme = "https://"
    url = scheme + host
    if path and path not in ("/", "*"):
        if proto == "http":
            url += path
        elif path.startswith("/"):
            url += path
    return url


class Capture:
    def __init__(
        self,
        iface: str,
        on_event: Callable[[dict], None],
        mitm: bool = False,
        gateway_ip: str | None = None,
        our_ip: str | None = None,
        network: str | None = None,
        prefix: int = 24,
    ) -> None:
        self.iface = iface
        self.on_event = on_event
        self.mitm = mitm
        self.gateway_ip = gateway_ip
        self.our_ip = our_ip
        self.network = network
        self.prefix = prefix
        self.our_mac = None
        self.gateway_mac = None
        self.targets: dict[str, str] = {}
        self.packets = 0
        self.requests = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._dedup: dict[tuple, float] = {}
        self._seen_devices: set[tuple] = set()
        self._last_spoof = 0.0
        self._last_scan = 0.0
        self._old_ip_forward = None
        self._old_rp_filter = {}
        self._sock = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="routerwatch-capture", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=4)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _emit(self, event: dict) -> None:
        try:
            self.on_event(event)
        except Exception:
            pass

    def _run(self) -> None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((self.iface, 0))
            sock.setblocking(False)
            self._sock = sock
        except PermissionError:
            self._emit({"type": "error", "message": "need_root"})
            return
        except Exception as exc:
            self._emit({"type": "error", "message": str(exc)})
            return
        try:
            if self.mitm:
                self._setup_mitm(sock)
            while not self._stop.is_set():
                try:
                    readable, _, _ = select.select([sock], [], [], 0.4)
                except Exception:
                    break
                if readable:
                    for _ in range(400):
                        try:
                            data, addr = sock.recvfrom(65535)
                        except BlockingIOError:
                            break
                        except Exception:
                            break
                        if len(addr) > 2 and addr[2] == PACKET_OUTGOING:
                            continue
                        self._handle_frame(data)
                if self.mitm:
                    now = time.time()
                    if now - self._last_spoof >= 1.5:
                        self._spoof(sock)
                        self._last_spoof = now
                    if now - self._last_scan >= 15:
                        self._refresh_targets()
                        self._last_scan = now
        finally:
            if self.mitm:
                try:
                    self._restore_mitm(sock)
                except Exception:
                    pass
            try:
                sock.close()
            except Exception:
                pass
            self._sock = None
            self._emit({"type": "stopped"})

    def _handle_frame(self, data: bytes) -> None:
        eth = parse_ethernet(data)
        if not eth:
            return
        raw_src_mac, _dst_mac, ethertype, payload = eth
        src_mac = mac_to_str(raw_src_mac)
        self.packets += 1
        if ethertype == ETH_P_ARP:
            self._handle_arp(payload)
        elif ethertype == ETH_P_IP:
            ip = parse_ipv4(payload)
            if not ip:
                return
            src, dst, proto, frag_offset, ip_payload = ip
            if frag_offset != 0:
                return
            if proto == 17:
                self._handle_udp(src, dst, src_mac, ip_payload)
            elif proto == 6:
                self._handle_tcp(src, dst, src_mac, ip_payload)
        elif ethertype == ETH_P_IPV6:
            ip6 = parse_ipv6(payload)
            if not ip6:
                return
            src, dst, proto, ip_payload = ip6
            if proto == 17:
                self._handle_udp(src, dst, src_mac, ip_payload)
            elif proto == 6:
                self._handle_tcp(src, dst, src_mac, ip_payload)

    def _handle_arp(self, payload: bytes) -> None:
        arp = parse_arp(payload)
        if not arp:
            return
        oper, sha, spa, _tha, _tpa = arp
        if oper in (1, 2) and spa and sha and spa != "0.0.0.0":
            self._emit_device(spa, sha, None)

    def _handle_udp(self, src: str, dst: str, src_mac: str, payload: bytes) -> None:
        udp = parse_udp(payload)
        if not udp:
            return
        sport, dport, udp_payload = udp
        if dport == 53 or sport == 53:
            self._handle_dns(src, dst, src_mac, udp_payload, dport, len(udp_payload))
        elif dport in (67, 68) or sport in (67, 68):
            self._handle_dhcp(src, dst, src_mac, udp_payload)
        elif dport == 5353 or sport == 5353:
            self._handle_mdns(src, dst, src_mac, udp_payload, len(udp_payload))

    def _handle_tcp(self, src: str, dst: str, src_mac: str, payload: bytes) -> None:
        tcp = parse_tcp(payload)
        if not tcp:
            return
        sport, dport, _seq, tcp_payload = tcp
        if not tcp_payload:
            return
        if dport == 53 or sport == 53:
            if len(tcp_payload) >= 2:
                msg_len = struct.unpack("!H", tcp_payload[:2])[0]
                self._handle_dns(src, dst, src_mac, tcp_payload[2 : 2 + msg_len], dport, msg_len)
            return
        if dport in TLS_PORTS or sport in TLS_PORTS or tcp_payload[:1] == b"\x16":
            sni = parse_tls_sni(tcp_payload)
            if sni:
                self._emit_request(src, src_mac, dst, dport, "tls", sni, None, len(tcp_payload))
                return
        if dport in HTTP_PORTS or sport in HTTP_PORTS:
            request = parse_http_request(tcp_payload)
            if request:
                method, host, path = request
                self._emit_request(src, src_mac, dst, dport, "http", host or dst, path, len(tcp_payload))

    def _handle_dns(self, src: str, dst: str, src_mac: str, payload: bytes, dport: int, size: int) -> None:
        try:
            questions, _answers = parse_dns(payload)
        except Exception:
            return
        for name, qtype in questions:
            if not name:
                continue
            self._emit_request(src, src_mac, dst, dport, "dns", name, None, size)

    def _handle_mdns(self, src: str, dst: str, src_mac: str, payload: bytes, size: int) -> None:
        try:
            questions, answers = parse_dns(payload)
        except Exception:
            return
        for name, ip in answers:
            if name and ip:
                self._emit_device(ip, None, name.removesuffix(".local"))
        for name, _qtype in questions:
            if name and (name.endswith(".local") or name.endswith(".lan")):
                self._emit_device(src, src_mac, name.removesuffix(".local").removesuffix(".lan"))

    def _handle_dhcp(self, src: str, dst: str, src_mac: str, payload: bytes) -> None:
        dhcp = parse_dhcp(payload)
        if not dhcp:
            return
        hostname = dhcp.get("hostname")
        mac = dhcp.get("mac")
        ip = dhcp.get("requested_ip") or (src if src != "0.0.0.0" else None)
        if hostname and hostname.strip():
            self._emit_device(ip, mac, hostname.strip())
        elif mac:
            self._emit_device(ip, mac, None)

    def _emit_request(
        self,
        src_ip: str,
        src_mac: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
        host: str | None,
        path: str | None,
        size: int,
    ) -> None:
        key = (src_ip, proto, host, path)
        now = time.time()
        last = self._dedup.get(key)
        if last is not None and now - last < 1.5:
            return
        self._dedup[key] = now
        if len(self._dedup) > 4000:
            cutoff = now - 30
            self._dedup = {k: v for k, v in self._dedup.items() if v >= cutoff}
        self.requests += 1
        self._emit(
            {
                "type": "request",
                "ts": now,
                "src_ip": src_ip,
                "src_mac": src_mac,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "proto": proto,
                "host": host,
                "path": path,
                "url": _build_url(proto, host, path),
                "size": size,
            }
        )

    def _emit_device(self, ip: str | None, mac: str | None, name: str | None) -> None:
        key = (ip, mac, name)
        if key in self._seen_devices:
            return
        self._seen_devices.add(key)
        if len(self._seen_devices) > 2000:
            self._seen_devices.clear()
        self._emit({"type": "device", "ip": ip, "mac": mac, "name": name})

    def _setup_mitm(self, sock) -> None:
        from config import default_route, iface_mac, iface_ipv4

        self._old_ip_forward = self._read_sys("/proc/sys/net/ipv4/ip_forward")
        self._write_sys("/proc/sys/net/ipv4/ip_forward", "1")
        for path in (
            f"/proc/sys/net/ipv4/conf/{self.iface}/rp_filter",
            "/proc/sys/net/ipv4/conf/all/rp_filter",
        ):
            self._old_rp_filter[path] = self._read_sys(path)
            self._write_sys(path, "0")
        self.our_mac = iface_mac(self.iface)
        self.our_ip = self.our_ip or iface_ipv4(self.iface)
        if not self.gateway_ip:
            _iface, gateway = default_route()
            self.gateway_ip = gateway
        self.gateway_mac = self._lookup_arp(self.gateway_ip) if self.gateway_ip else None
        if not self.gateway_mac and self.gateway_ip:
            self.gateway_mac = self._arp_request_wait(sock, self.gateway_ip)
        self._emit({"type": "mitm", "enabled": True, "gateway": self.gateway_ip, "gateway_mac": self.gateway_mac})
        self._arp_scan(sock)

    def _restore_mitm(self, sock) -> None:
        if self.gateway_mac and self.our_mac:
            for ip, mac in list(self.targets.items()):
                if not mac or ip == self.our_ip:
                    continue
                for _ in range(3):
                    try:
                        sock.send(build_arp_packet(2, self.gateway_mac, self.gateway_ip, mac, ip, mac_to_bytes(mac), mac_to_bytes(self.gateway_mac)))
                        sock.send(build_arp_packet(2, mac, ip, self.gateway_mac, self.gateway_ip, mac_to_bytes(self.gateway_mac), mac_to_bytes(mac)))
                    except Exception:
                        break
                    time.sleep(0.05)
        if self._old_ip_forward is not None:
            self._write_sys("/proc/sys/net/ipv4/ip_forward", self._old_ip_forward)
        for path, value in self._old_rp_filter.items():
            if value is not None:
                self._write_sys(path, value)
        self._emit({"type": "mitm", "enabled": False})

    def _spoof(self, sock) -> None:
        if not self.gateway_ip or not self.gateway_mac or not self.our_mac:
            return
        our = mac_to_bytes(self.our_mac)
        gw_mac = mac_to_bytes(self.gateway_mac)
        for ip, mac in list(self.targets.items()):
            if not mac or ip in (self.our_ip, self.gateway_ip):
                continue
            target = mac_to_bytes(mac)
            try:
                sock.send(build_arp_packet(2, self.our_mac, self.gateway_ip, mac, ip, target, our))
                sock.send(build_arp_packet(2, self.our_mac, ip, self.gateway_mac, self.gateway_ip, gw_mac, our))
            except Exception:
                pass

    def _refresh_targets(self) -> None:
        for ip, mac in self._read_arp_table().items():
            if ip and mac and ip not in (self.our_ip, self.gateway_ip):
                self.targets[ip] = mac

    def _arp_scan(self, sock) -> None:
        if not self.network or not self.our_mac or not self.our_ip:
            self._refresh_targets()
            return
        import ipaddress

        try:
            net = ipaddress.ip_network(f"{self.network}/{self.prefix}", strict=False)
        except Exception:
            self._refresh_targets()
            return
        hosts = [str(h) for h in net.hosts()]
        if len(hosts) > 512:
            hosts = hosts[:512]
        for ip in hosts:
            if ip in (self.our_ip, self.gateway_ip):
                continue
            try:
                sock.send(build_arp_packet(1, self.our_mac, self.our_ip, "00:00:00:00:00:00", ip, b"\xff" * 6, mac_to_bytes(self.our_mac)))
            except Exception:
                pass
        deadline = time.time() + 1.5
        while time.time() < deadline and not self._stop.is_set():
            try:
                readable, _, _ = select.select([sock], [], [], 0.2)
            except Exception:
                break
            if not readable:
                continue
            try:
                data, addr = sock.recvfrom(65535)
            except Exception:
                continue
            if len(addr) > 2 and addr[2] == PACKET_OUTGOING:
                continue
            eth = parse_ethernet(data)
            if not eth or eth[2] != ETH_P_ARP:
                continue
            arp = parse_arp(eth[3])
            if not arp:
                continue
            oper, sha, spa, _tha, tpa = arp
            if oper == 2 and tpa == self.our_ip and spa != self.gateway_ip:
                self.targets[spa] = sha
                self._emit_device(spa, sha, None)
        self._refresh_targets()
        if self.gateway_mac and self.gateway_ip:
            self.targets[self.gateway_ip] = self.gateway_mac
        self._emit({"type": "targets", "count": len(self.targets)})

    def _arp_request_wait(self, sock, ip: str) -> str | None:
        if not self.our_mac or not self.our_ip:
            return None
        for _ in range(3):
            try:
                sock.send(build_arp_packet(1, self.our_mac, self.our_ip, "00:00:00:00:00:00", ip, b"\xff" * 6, mac_to_bytes(self.our_mac)))
            except Exception:
                return None
            deadline = time.time() + 0.5
            while time.time() < deadline:
                try:
                    readable, _, _ = select.select([sock], [], [], 0.1)
                except Exception:
                    return None
                if not readable:
                    continue
                try:
                    data, addr = sock.recvfrom(65535)
                except Exception:
                    continue
                if len(addr) > 2 and addr[2] == PACKET_OUTGOING:
                    continue
                eth = parse_ethernet(data)
                if not eth or eth[2] != ETH_P_ARP:
                    continue
                arp = parse_arp(eth[3])
                if not arp:
                    continue
                oper, sha, spa, _tha, _tpa = arp
                if oper == 2 and spa == ip:
                    return sha
        return None

    def _read_arp_table(self) -> dict[str, str]:
        result: dict[str, str] = {}
        try:
            lines = open("/proc/net/arp", encoding="utf-8").read().splitlines()[1:]
        except Exception:
            return result
        for line in lines:
            parts = line.split()
            if len(parts) < 6:
                continue
            ip, _hwtype, flags, mac, _mask, device = parts[:6]
            if device != self.iface:
                continue
            if mac and mac != "00:00:00:00:00:00" and int(flags, 16) & 0x2:
                result[ip] = mac.lower()
        return result

    def _lookup_arp(self, ip: str | None) -> str | None:
        if not ip:
            return None
        return self._read_arp_table().get(ip)

    @staticmethod
    def _read_sys(path: str):
        try:
            return open(path, encoding="utf-8").read().strip()
        except Exception:
            return None

    @staticmethod
    def _write_sys(path: str, value: str) -> bool:
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(value)
            return True
        except Exception:
            return False
