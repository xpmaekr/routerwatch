from __future__ import annotations

import re

from i18n import t

_DOMAIN_SUFFIXES = (
    ".localdomain",
    ".local",
    ".lan",
    ".home.arpa",
    ".home",
    ".fritz.box",
    ".router",
    ".gateway",
)

_MODEL_WORDS = {
    "se",
    "fe",
    "pro",
    "plus",
    "max",
    "mini",
    "ultra",
    "air",
    "lite",
    "note",
    "fold",
    "flip",
    "edge",
    "neo",
    "prime",
    "youth",
    "turbo",
    "play",
}

_MODEL_RE = re.compile(r"[a-z]{0,6}\d{1,4}[a-z]{0,3}")

_BRANDS = (
    (r"\bapple\b", "Apple"),
    (r"\bsamsung\b|\bsec\b", "Samsung"),
    (r"\bgoogle\b", "Google"),
    (r"\bxiaomi\b|\bbeijing xiaomi\b|\bmi\b", "Xiaomi"),
    (r"\bhuawei\b", "Huawei"),
    (r"\bhonor\b", "Honor"),
    (r"\boneplus\b|\bone plus\b", "OnePlus"),
    (r"\boppo\b", "OPPO"),
    (r"\bvivo\b", "vivo"),
    (r"\brealme\b", "realme"),
    (r"\bmotorola\b|\bmoto\b", "Motorola"),
    (r"\bnokia\b", "Nokia"),
    (r"\bsony\b", "Sony"),
    (r"\blg electronics\b|\blg innotek\b|\blg\b", "LG"),
    (r"\bintel\b", "Intel"),
    (r"\bdell\b", "Dell"),
    (r"\bhewlett[- ]packard\b|\bhp inc\b|\bhp\b", "HP"),
    (r"\blenovo\b", "Lenovo"),
    (r"\basustek\b|\basus\b", "ASUS"),
    (r"\bacer\b", "Acer"),
    (r"\bmicro-star\b|\bmsi\b", "MSI"),
    (r"\braspberry pi\b", "Raspberry Pi"),
    (r"\bespressif\b", "ESP"),
    (r"\btuya\b", "Tuya"),
    (r"\bsonos\b", "Sonos"),
    (r"\broku\b", "Roku"),
    (r"\bamazon\b", "Amazon"),
    (r"\btp-link\b|\btplink\b", "TP-Link"),
    (r"\brealtek\b", "Realtek"),
    (r"\bbroadcom\b", "Broadcom"),
    (r"\bmicrosoft\b", "Microsoft"),
    (r"\bcisco\b", "Cisco"),
    (r"\bnetgear\b", "Netgear"),
    (r"\bd-link\b", "D-Link"),
    (r"\bmikrotik\b", "MikroTik"),
    (r"\bubiquiti\b", "Ubiquiti"),
    (r"\bsynology\b", "Synology"),
    (r"\bqnap\b", "QNAP"),
    (r"\bphilips\b", "Philips"),
    (r"\bsiemens\b", "Siemens"),
    (r"\bbosch\b", "Bosch"),
    (r"\bcanon\b", "Canon"),
    (r"\bepson\b", "Epson"),
    (r"\bbrother\b", "Brother"),
    (r"\bpeloton\b", "Peloton"),
    (r"\btesla\b", "Tesla"),
    (r"\bring\b", "Ring"),
    (r"\bnest\b", "Nest"),
)

_VENDOR_TAIL_RE = re.compile(
    r"(?:\s+|,)+(?:co\.?|ltd\.?|limited|inc\.?|corp\.?|corporation|gmbh|ag|s\.a\.?|b\.v\.?|oy|ab)$",
    re.IGNORECASE,
)

_OUI_FALLBACK = {
    "F0EE7A": "Apple, Inc.",
    "A4C361": "Apple, Inc.",
    "001451": "Apple, Inc.",
    "286FB9": "Nokia Shanghai Bell Co., Ltd.",
    "001A11": "Google, Inc.",
    "3C5AB4": "Google, Inc.",
    "F4F5D8": "Google, Inc.",
    "B827EB": "Raspberry Pi Foundation",
    "DC4F22": "Espressif Inc.",
    "246F28": "Espressif Inc.",
    "84F3EB": "Espressif Inc.",
    "001B63": "Apple, Inc.",
    "0024E8": "Dell Inc.",
    "3C970E": "Hewlett Packard",
    "F8BC12": "Dell Inc.",
}

_OUI_PATHS = (
    "/usr/share/hwdata/oui.txt",
    "/usr/share/ieee-data/oui.txt",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/misc/oui.txt",
    "/usr/share/wireshark/manuf",
)

_oui_cache: dict[str, str] | None = None


def _clean_name(name: str) -> str:
    value = name.strip().strip(".")
    lowered = value.lower()
    for suffix in _DOMAIN_SUFFIXES:
        if lowered.endswith(suffix):
            value = value[: -len(suffix)]
            break
    return value.strip()


def _norm(name: str) -> str:
    value = _clean_name(name)
    value = re.sub(r"[\u0000-\u001f]", "", value)
    value = re.sub(r"[-_.\s]+", " ", value)
    return value.strip().lower()


def _pretty_token(token: str) -> str:
    low = token.lower()
    if low in _MODEL_WORDS:
        return "SE" if low == "se" else low.capitalize()
    match = re.fullmatch(r"([a-z]*)(\d+)([a-z]*)", low)
    if not match:
        return token
    prefix, number, suffix = match.groups()
    out = ""
    if prefix:
        out = prefix.capitalize()
        if len(prefix) > 1:
            out += " "
    out += number
    if suffix:
        if len(suffix) <= 1:
            out += suffix
        else:
            out += " " + suffix.capitalize()
    return out


def _with_model(base: str, rest: str) -> str:
    kept: list[str] = []
    for token in rest.split():
        low = token.lower()
        if low in _MODEL_WORDS or _MODEL_RE.fullmatch(low):
            kept.append(token)
        else:
            break
    if not kept:
        return base
    return base + " " + " ".join(_pretty_token(token) for token in kept)


def _looks_random(text: str) -> bool:
    compact = re.sub(r"[^0-9a-zA-Z]", "", text)
    if len(compact) < 6:
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", compact):
        return True
    digits = sum(ch.isdigit() for ch in compact)
    return digits / len(compact) > 0.6


def name_from_hostname(name: str | None, lang: str = "ru") -> str | None:
    if not name:
        return None
    norm = _norm(name)
    if not norm:
        return None

    def find(pattern: str) -> str | None:
        match = re.search(pattern, norm)
        return match.group(1) if match else None

    brand_only = {
        "apple": "Apple",
        "samsung": "Samsung",
        "google": "Google",
        "xiaomi": "Xiaomi",
        "huawei": "Huawei",
        "honor": "Honor",
        "oneplus": "OnePlus",
        "oppo": "OPPO",
        "vivo": "vivo",
        "realme": "realme",
    }
    if norm in brand_only:
        return brand_only[norm]

    rest = find(r"\biphone\s*(.*)$")
    if rest is not None:
        return _with_model("iPhone", rest)
    rest = find(r"\bipad\s*(.*)$")
    if rest is not None:
        return _with_model("iPad", rest)
    rest = find(r"\bipod\s*(.*)$")
    if rest is not None:
        return _with_model("iPod", rest)
    if re.search(r"\bhomepod\b", norm):
        return "HomePod"
    if re.search(r"\bairpods?\b", norm):
        return "AirPods"
    if re.search(r"\bapple\s*(?:tv|watch)\b", norm):
        return "Apple TV" if "tv" in norm else "Apple Watch"
    if re.search(r"\bapple\s*tv\b", norm):
        return "Apple TV"
    rest = find(r"\bmacbook\s*(.*)$")
    if rest is not None:
        return _with_model("MacBook", rest)
    if re.search(r"\bimac\b", norm):
        return "iMac"
    if re.search(r"\bmac\s*mini\b", norm):
        return "Mac mini"
    if re.search(r"\bmac\s*studio\b", norm):
        return "Mac Studio"
    if re.search(r"\bmac\s*pro\b", norm):
        return "Mac Pro"

    rest = find(r"\bpixel\s*(.*)$")
    if rest is not None:
        return _with_model("Pixel", rest)
    rest = find(r"\bnexus\s*(.*)$")
    if rest is not None:
        return _with_model("Nexus", rest)

    rest = find(r"\bgalaxy\s*(.*)$")
    if rest is not None:
        return _with_model("Galaxy", rest)
    rest = find(r"\bsm[-\s]?([a-z]\d{3}[a-z0-9]*)\b")
    if rest is not None:
        return "Galaxy " + rest.upper()

    rest = find(r"\bredmi\s*(.*)$")
    if rest is not None:
        return _with_model("Redmi", rest)
    rest = find(r"\bpoco\s*(.*)$")
    if rest is not None:
        return _with_model("POCO", rest)
    rest = find(r"\bxiaomi\s*(.*)$")
    if rest is not None:
        return _with_model("Xiaomi", rest)
    rest = find(r"\bmi\s+(\d.*)$")
    if rest is not None:
        return _with_model("Xiaomi", rest)
    rest = find(r"\boneplus\s*(.*)$")
    if rest is not None:
        return _with_model("OnePlus", rest)
    rest = find(r"\bhuawei\s*(.*)$")
    if rest is not None:
        return _with_model("Huawei", rest)
    rest = find(r"\bhonor\s*(.*)$")
    if rest is not None:
        return _with_model("Honor", rest)
    rest = find(r"\boppo\s*(.*)$")
    if rest is not None:
        return _with_model("OPPO", rest)
    rest = find(r"\bvivo\s*(.*)$")
    if rest is not None:
        return _with_model("vivo", rest)
    rest = find(r"\brealme\s*(.*)$")
    if rest is not None:
        return _with_model("realme", rest)
    rest = find(r"\bmoto(?:rola)?\s*(.*)$")
    if rest is not None:
        return _with_model("Motorola", rest)
    rest = find(r"\bnokia\s*(.*)$")
    if rest is not None:
        return _with_model("Nokia", rest)
    rest = find(r"\bxperia\s*(.*)$")
    if rest is not None:
        return _with_model("Sony Xperia", rest)
    rest = find(r"\bnothing\s*(.*)$")
    if rest is not None:
        return _with_model("Nothing Phone", rest)
    rest = find(r"\btecno\s*(.*)$")
    if rest is not None:
        return _with_model("TECNO", rest)
    rest = find(r"\binfinix\s*(.*)$")
    if rest is not None:
        return _with_model("Infinix", rest)

    rest = find(r"\bthinkpad\s*(.*)$")
    if rest is not None:
        return _with_model("ThinkPad", rest)
    if re.search(r"\braspberry\s*pi\b|\brpi\b", norm):
        return "Raspberry Pi"
    if re.search(r"\bsteam\s*deck\b", norm):
        return "Steam Deck"

    if re.search(r"\bdesktop\b", norm):
        return t(lang, "device_windows_pc")
    if re.search(r"\blaptop\b", norm):
        return t(lang, "device_windows_laptop")
    if re.search(r"\bwindows\b|\bwin\s*\d", norm):
        return t(lang, "device_windows_pc")
    if re.search(r"\bubuntu\b|\bdebian\b|\bfedora\b|\barch\s*linux\b|\blinux\b|\bmint\b|\bopensuse\b", norm):
        return t(lang, "device_linux_pc")

    if re.search(r"\besp8266\b", norm):
        return "ESP8266"
    if re.search(r"\besp32\b", norm):
        return "ESP32"
    if re.search(r"\besp\b|\besp[_\-]", norm):
        return "ESP"
    if re.search(r"\btasmota\b", norm):
        return "Tasmota"
    if re.search(r"\bshelly\b", norm):
        return "Shelly"
    if re.search(r"\bsonoff\b", norm):
        return "Sonoff"
    if re.search(r"\btuya\b", norm):
        return "Tuya"
    if re.search(r"\bhome\s*assistant\b", norm):
        return "Home Assistant"
    if re.search(r"\bsynology\b", norm):
        return "Synology NAS"
    if re.search(r"\bqnap\b", norm):
        return "QNAP NAS"
    if re.search(r"\b(printer|brother|epson|canon)\b", norm):
        return t(lang, "device_printer")
    if re.search(r"\bchromecast\b", norm):
        return "Chromecast"
    if re.search(r"\bgoogle\s*(?:home|nest)\b", norm):
        return "Google Nest"
    if re.search(r"\becho\b|\balexa\b", norm):
        return "Amazon Echo"
    if re.search(r"\bfire\s*tv\b", norm):
        return "Fire TV"
    if re.search(r"\bkindle\b", norm):
        return "Kindle"
    if re.search(r"\broku\b", norm):
        return "Roku"
    if re.search(r"\bsonos\b", norm):
        return "Sonos"
    if re.search(r"\bplaystation\b|\bps[45]\b", norm):
        return "PlayStation"
    if re.search(r"\bxbox\b", norm):
        return "Xbox"
    if re.search(r"\bnintendo\b|\bswitch\b", norm):
        return "Nintendo Switch"
    if re.search(r"\bcamera\b|\bipcam\b|\bip\s*cam\b", norm):
        return t(lang, "device_camera")
    if re.search(r"\brouter\b|\bopenwrt\b|\bmikrotik\b|\bkeenetic\b", norm):
        return t(lang, "device_router")
    if re.search(r"\b(android|droid)\b", norm):
        return t(lang, "device_android")
    if re.search(r"\btablet\b", norm):
        return t(lang, "device_tablet")
    if re.search(r"\bphone\b", norm):
        return t(lang, "device_phone")

    if _looks_random(norm):
        return None
    return _clean_name(name) or None


def _load_oui() -> dict[str, str]:
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache
    data: dict[str, str] = {}
    for path in _OUI_PATHS:
        try:
            with open(path, encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    if "(base 16)" not in line:
                        continue
                    prefix, _, vendor = line.partition("(base 16)")
                    prefix = prefix.strip().replace("-", "").upper()
                    vendor = vendor.strip()
                    if len(prefix) == 6 and vendor:
                        data[prefix] = vendor
            if data:
                break
        except OSError:
            continue
    for prefix, vendor in _OUI_FALLBACK.items():
        data.setdefault(prefix, vendor)
    _oui_cache = data
    return data


def vendor_for_mac(mac: str | bytes | None) -> str | None:
    if not mac:
        return None
    if isinstance(mac, bytes):
        mac = ":".join(f"{b:02x}" for b in mac)
    compact = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(compact) < 6:
        return None
    return _load_oui().get(compact[:6])


def brand_from_vendor(vendor: str | None) -> str | None:
    if not vendor:
        return None
    lowered = vendor.lower()
    for pattern, brand in _BRANDS:
        if re.search(pattern, lowered):
            return brand
    cleaned = vendor.split(",")[0].strip()
    previous = None
    while cleaned and cleaned != previous:
        previous = cleaned
        cleaned = _VENDOR_TAIL_RE.sub("", cleaned).strip()
    return (cleaned[:32] or None) if cleaned else None


def friendly_name(name: str | None, mac: str | None = None, lang: str = "ru") -> str | None:
    if name:
        resolved = name_from_hostname(name, lang)
        if resolved:
            return resolved
    if mac:
        brand = brand_from_vendor(vendor_for_mac(mac))
        if brand:
            return brand
    return None
