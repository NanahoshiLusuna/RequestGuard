"""Neighbor-table parsers and MAC normalization."""

import ipaddress
import unittest

from requestguard.ports import interface_ips, parse_ports
from requestguard.net import (
    link_address,
    normalize_mac,
    parse_arp_an,
    parse_ip_neigh,
    parse_ndp_an,
    parse_proc_arp,
)


class NetTest(unittest.TestCase):
    def test_normalize_mac(self) -> None:
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("a:b:c:d:e:f"), "0a:0b:0c:0d:0e:0f")
        self.assertIsNone(normalize_mac("00:00:00:00:00:00"))
        self.assertIsNone(normalize_mac("ff:ff:ff:ff:ff:ff"))
        self.assertIsNone(normalize_mac("not-a-mac"))

    def test_proc_arp_skips_incomplete_rows(self) -> None:
        text = """\
IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
10.0.0.2         0x1         0x0         00:00:00:00:00:00     *        wlan0
"""
        self.assertEqual(parse_proc_arp(text), {"10.0.0.1": "aa:bb:cc:dd:ee:ff"})

    def test_ip_neigh(self) -> None:
        text = """\
10.0.0.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
10.0.0.2 dev wlan0 FAILED
fe80::1 dev wlan0 lladdr 00:11:22:33:44:55 STALE
2001:db8::5 dev wlan0 lladdr aa:bb:cc:dd:ee:ff INCOMPLETE
"""
        found = parse_ip_neigh(text)
        self.assertEqual(found["10.0.0.1"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(found["fe80::1"], "00:11:22:33:44:55")
        self.assertNotIn("10.0.0.2", found)
        self.assertNotIn("2001:db8::5", found)

    def test_arp_and_ndp(self) -> None:
        arp = "? (10.0.0.1) at a:b:c:d:e:f on en0 ifscope [ethernet]\n? (10.0.0.2) at (incomplete) on en0\n"
        ndp = "Neighbor Linklayer Address Netif\nfe80::1%en0 aa:bb:cc:dd:ee:ff en0 23h R\n"
        self.assertEqual(parse_arp_an(arp), {"10.0.0.1": "0a:0b:0c:0d:0e:0f"})
        self.assertEqual(parse_ndp_an(ndp), {"fe80::1": "aa:bb:cc:dd:ee:ff"})

    def test_missing_neighbor_is_none(self) -> None:
        self.assertIsNone(link_address("203.0.113.50"))

    def test_listen_addresses_skip_loopback(self) -> None:
        for ip in interface_ips():
            self.assertFalse(ipaddress.ip_address(ip).is_loopback)
            self.assertFalse(ipaddress.ip_address(ip).is_link_local)

    def test_parse_ports(self) -> None:
        self.assertEqual(parse_ports("80, 443, 8000-8002"), (80, 443, 8000, 8001, 8002))


if __name__ == "__main__":
    unittest.main()
