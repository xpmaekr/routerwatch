import struct
import unittest

import router_client as rc
import sniffer


def ipv4_header(src, dst, proto, payload_len, ident=0, frag=0):
    total = 20 + payload_len
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        ident,
        frag,
        64,
        proto,
        0,
        bytes(map(int, src.split("."))),
        bytes(map(int, dst.split("."))),
    )


def udp_header(sport, dport, payload_len):
    return struct.pack("!HHHH", sport, dport, 8 + payload_len, 0)


def ethernet_header(ethertype):
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", ethertype)


def dns_query(name, qtype=1):
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b""
    for label in name.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


def client_hello(host):
    name = host.encode()
    server_name = b"\x00" + struct.pack("!H", len(name)) + name
    server_name_list = struct.pack("!H", len(server_name)) + server_name
    sni_ext = struct.pack("!HH", 0, len(server_name_list)) + server_name_list
    extensions = sni_ext
    body = b"\x03\x03" + b"\x11" * 32
    body += b"\x00"
    body += struct.pack("!H", 2) + b"\x00\x2f"
    body += b"\x01\x00"
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def dhcp_packet(mac, hostname):
    packet = bytearray(240)
    packet[0] = 1
    packet[1] = 1
    packet[2] = 6
    packet[4:8] = b"\xde\xad\xbe\xef"
    packet[28:34] = bytes(int(part, 16) for part in mac.split(":"))
    packet[236:240] = b"\x63\x82\x53\x63"
    options = b"\x35\x01\x01" + b"\x0c" + bytes([len(hostname)]) + hostname.encode() + b"\xff"
    return bytes(packet) + options


class SnifferParsingTests(unittest.TestCase):
    def test_dns_query(self):
        payload = dns_query("example.com")
        packet = ethernet_header(0x0800)
        packet += ipv4_header("192.168.1.50", "192.168.1.1", 17, len(udp_header(12345, 53, len(payload))) + len(payload))
        packet += udp_header(12345, 53, len(payload)) + payload
        eth = sniffer.parse_ethernet(packet)
        self.assertIsNotNone(eth)
        ip = sniffer.parse_ipv4(eth[3])
        self.assertIsNotNone(ip)
        udp = sniffer.parse_udp(ip[4])
        self.assertIsNotNone(udp)
        questions, _answers = sniffer.parse_dns(udp[2])
        self.assertEqual(questions[0][0], "example.com")
        self.assertEqual(questions[0][1], 1)

    def test_tls_sni(self):
        payload = client_hello("secure.example.org")
        self.assertEqual(sniffer.parse_tls_sni(payload), "secure.example.org")

    def test_http_request(self):
        payload = b"GET /some/page?x=1 HTTP/1.1\r\nHost: site.example\r\nUser-Agent: x\r\n\r\n"
        method, host, path = sniffer.parse_http_request(payload)
        self.assertEqual(method, "GET")
        self.assertEqual(host, "site.example")
        self.assertEqual(path, "/some/page?x=1")

    def test_dhcp_hostname(self):
        payload = dhcp_packet("aa:bb:cc:dd:ee:01", "test-pc")
        result = sniffer.parse_dhcp(payload)
        self.assertEqual(result["mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(result["hostname"], "test-pc")

    def test_arp_roundtrip(self):
        packet = sniffer.build_arp_packet(2, "aa:bb:cc:dd:ee:01", "192.168.1.50", "aa:bb:cc:dd:ee:02", "192.168.1.1", b"\xff" * 6, b"\xaa\xbb\xcc\xdd\xee\x01")
        eth = sniffer.parse_ethernet(packet)
        self.assertEqual(eth[2], 0x0806)
        arp = sniffer.parse_arp(eth[3])
        self.assertEqual(arp[1], "aa:bb:cc:dd:ee:01")
        self.assertEqual(arp[2], "192.168.1.50")
        self.assertEqual(arp[4], "192.168.1.1")

    def test_build_url(self):
        self.assertEqual(sniffer._build_url("dns", "example.com", None), "https://example.com")
        self.assertEqual(sniffer._build_url("http", "example.com", "/a"), "http://example.com/a")
        self.assertEqual(sniffer._build_url("tls", "example.com", None), "https://example.com")


def tcp_header(sport, dport, payload_len):
    return struct.pack("!HHIIHHHH", sport, dport, 1, 0, 5 << 12, 65535, 0, 0)


def make_dns_frame(name, sport=12345, dport=53):
    payload = dns_query(name)
    udp = udp_header(sport, dport, len(payload))
    ip = ipv4_header("192.168.1.50", "192.168.1.1", 17, len(udp) + len(payload))
    return ethernet_header(0x0800) + ip + udp + payload


def make_tls_frame(host, dport=443):
    payload = client_hello(host)
    tcp = tcp_header(50000, dport, len(payload))
    ip = ipv4_header("192.168.1.50", "93.184.216.34", 6, len(tcp) + len(payload))
    return ethernet_header(0x0800) + ip + tcp + payload


def make_http_frame(host, path, dport=80):
    payload = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    tcp = tcp_header(50001, dport, len(payload))
    ip = ipv4_header("192.168.1.50", "93.184.216.34", 6, len(tcp) + len(payload))
    return ethernet_header(0x0800) + ip + tcp + payload


def make_dhcp_frame(mac, hostname):
    payload = dhcp_packet(mac, hostname)
    udp = udp_header(68, 67, len(payload))
    ip = ipv4_header("0.0.0.0", "255.255.255.255", 17, len(udp) + len(payload))
    return ethernet_header(0x0800) + ip + udp + payload


class CaptureEventTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.capture = sniffer.Capture("wlan0", self.events.append, mitm=False)

    def test_dns_event(self):
        self.capture._handle_frame(make_dns_frame("example.com"))
        requests = [event for event in self.events if event["type"] == "request"]
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["proto"], "dns")
        self.assertEqual(requests[0]["url"], "https://example.com")
        self.assertEqual(requests[0]["src_ip"], "192.168.1.50")
        self.assertEqual(requests[0]["src_mac"], "66:77:88:99:aa:bb")

    def test_tls_event(self):
        self.capture._handle_frame(make_tls_frame("secure.example.org"))
        requests = [event for event in self.events if event["type"] == "request"]
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["proto"], "tls")
        self.assertEqual(requests[0]["url"], "https://secure.example.org")

    def test_http_event(self):
        self.capture._handle_frame(make_http_frame("site.example", "/page?a=1"))
        requests = [event for event in self.events if event["type"] == "request"]
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["proto"], "http")
        self.assertEqual(requests[0]["url"], "http://site.example/page?a=1")

    def test_dhcp_device_event(self):
        self.capture._handle_frame(make_dhcp_frame("aa:bb:cc:dd:ee:01", "test-pc"))
        devices = [event for event in self.events if event["type"] == "device"]
        self.assertTrue(any(event["name"] == "test-pc" for event in devices))
        self.assertTrue(any(event["mac"] == "aa:bb:cc:dd:ee:01" for event in devices))

    def test_arp_device_event(self):
        packet = sniffer.build_arp_packet(
            2, "aa:bb:cc:dd:ee:02", "192.168.1.1", "aa:bb:cc:dd:ee:01", "192.168.1.50", b"\xff" * 6, b"\xaa\xbb\xcc\xdd\xee\x01"
        )
        self.capture._handle_frame(packet)
        devices = [event for event in self.events if event["type"] == "device"]
        self.assertTrue(any(event["ip"] == "192.168.1.1" and event["mac"] == "aa:bb:cc:dd:ee:02" for event in devices))

    def test_dedup(self):
        frame = make_dns_frame("example.com")
        self.capture._handle_frame(frame)
        self.capture._handle_frame(frame)
        requests = [event for event in self.events if event["type"] == "request"]
        self.assertEqual(len(requests), 1)


class RouterClientTests(unittest.TestCase):
    def test_md5crypt_matches_openssl(self):
        self.assertEqual(rc.md5crypt_pure("test", ""), "$1$$whuMjZj.HMFoaTaZRRtkO0")
        self.assertEqual(rc.md5crypt_pure("пароль", ""), "$1$$Y72K7BeKjpEMhhxTyvkYx/")

    def test_js_quote(self):
        self.assertEqual(rc.js_quote("a b~!()*/"), "a+b%7E%21%28%29*%2F")

    def test_device_rows(self):
        html = """
        <table>
        <tr><th>IP</th><th>MAC</th><th>Host</th></tr>
        <tr><td>192.168.1.50</td><td>aa:bb:cc:dd:ee:01</td><td>test-pc</td></tr>
        <tr><td>192.168.1.20</td><td>AA-BB-CC-DD-EE-02</td><td>phone</td></tr>
        </table>
        """
        devices = rc.parse_device_rows(html)
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0]["ip"], "192.168.1.50")
        self.assertEqual(devices[0]["mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(devices[0]["name"], "test-pc")
        self.assertEqual(devices[1]["mac"], "aa:bb:cc:dd:ee:02")

    def test_login_success_uses_status_page(self):
        class Fake(rc.RouterClient):
            def _request(self, path, data=None, headers=None):
                if path == "/boaform/admin/formLogin":
                    return 200, "<html>ok</html>", b""
                if path == "/admin/status.asp":
                    return 200, '<html><form name="status"><title>Состояние устройства</title></html>', b""
                return 404, "", b""

        client = Fake("192.168.1.1", "admin", "admin")
        self.assertTrue(client._try_login("hash", True))
        self.assertIsNone(client.last_error)

    def test_login_detects_busy_router(self):
        class Fake(rc.RouterClient):
            def _request(self, path, data=None, headers=None):
                if path == "/boaform/admin/formLogin":
                    return 200, "ОШИБКА: другой пользователь уже вошёл", b""
                return 404, "", b""

        client = Fake("192.168.1.1", "admin", "admin")
        self.assertFalse(client._try_login("hash", True))
        self.assertEqual(client.last_error, "another_user")


if __name__ == "__main__":
    unittest.main(verbosity=2)
