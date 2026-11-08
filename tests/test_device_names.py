import unittest

from device_names import brand_from_vendor, friendly_name, name_from_hostname, vendor_for_mac
from i18n import t


class HostnameTests(unittest.TestCase):
    def test_apple_models(self):
        self.assertEqual(friendly_name("iPhone-15-Pro-Max"), "iPhone 15 Pro Max")
        self.assertEqual(friendly_name("Alexs-iPhone.local"), "iPhone")
        self.assertEqual(friendly_name("iPad-Air"), "iPad Air")
        self.assertEqual(friendly_name("MacBook-Pro"), "MacBook Pro")

    def test_android_models(self):
        self.assertEqual(friendly_name("pixel_10a"), "Pixel 10a")
        self.assertEqual(friendly_name("Galaxy-S23-Ultra"), "Galaxy S23 Ultra")
        self.assertEqual(friendly_name("Redmi-Note-13-Pro"), "Redmi Note 13 Pro")
        self.assertEqual(friendly_name("OnePlus-12"), "OnePlus 12")

    def test_computers(self):
        self.assertEqual(friendly_name("DESKTOP-AB12CD", None, "ru"), t("ru", "device_windows_pc"))
        self.assertEqual(friendly_name("LAPTOP-XY9Z", None, "en"), t("en", "device_windows_laptop"))
        self.assertEqual(friendly_name("ubuntu-box", None, "ru"), t("ru", "device_linux_pc"))
        self.assertEqual(friendly_name("raspberrypi", None, "ru"), "Raspberry Pi")

    def test_iot(self):
        self.assertEqual(friendly_name("ESP_1A2B3C"), "ESP")
        self.assertEqual(friendly_name("esp32-sensor"), "ESP32")
        self.assertEqual(friendly_name("android-1234abcd"), t("ru", "device_android"))

    def test_unknown_hostname_kept(self):
        self.assertEqual(name_from_hostname("test-pc"), "test-pc")
        self.assertIsNone(name_from_hostname("d8f3a2"))
        self.assertIsNone(name_from_hostname(None))


class OuiTests(unittest.TestCase):
    def test_vendor_lookup(self):
        self.assertIn("Apple", vendor_for_mac("f0:ee:7a:12:34:56"))
        self.assertIn("Nokia", vendor_for_mac("28:6f:b9:12:34:56"))

    def test_brand_normalization(self):
        self.assertEqual(brand_from_vendor("Apple, Inc."), "Apple")
        self.assertEqual(brand_from_vendor("Nokia Shanghai Bell Co., Ltd."), "Nokia")
        self.assertEqual(brand_from_vendor("Raspberry Pi Foundation"), "Raspberry Pi")

    def test_brand_from_mac(self):
        self.assertEqual(friendly_name(None, "f0:ee:7a:12:34:56"), "Apple")
        self.assertEqual(friendly_name(None, "b8:27:eb:12:34:56"), "Raspberry Pi")
        self.assertIsNone(friendly_name(None, "de:ad:be:ef:00:01"))

    def test_brand_from_raw_mac_bytes(self):
        self.assertEqual(friendly_name(None, b"\xf0\xee\x7a\x12\x34\x56"), "Apple")


if __name__ == "__main__":
    unittest.main(verbosity=2)
