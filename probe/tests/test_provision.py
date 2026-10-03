import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('provision', Path(__file__).resolve().parents[1] / 'provision.py')
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


class NetworkSettingsTests(unittest.TestCase):
    def test_configured_networks_define_gateway_and_dhcp(self):
        values = provision.network_settings({'tv_subnet': '192.168.88.0/24', 'home_subnet': '192.168.1.0/24'})
        self.assertEqual(values['TV_GATEWAY'], '192.168.88.1')
        self.assertEqual(values['TV_DHCP_START'], '192.168.88.100')
        self.assertEqual(values['TV_DHCP_END'], '192.168.88.120')
        self.assertEqual(values['HOME_SUBNET'], '192.168.1.0/24')

    def test_overlapping_or_public_networks_are_rejected(self):
        for tv, home in [('192.168.88.0/24', '192.168.88.0/24'),
                         ('192.168.88.0/24', '8.8.8.0/24'),
                         ('192.168.88.0/25', '192.168.1.0/24')]:
            with self.subTest(tv=tv, home=home), self.assertRaises(ValueError):
                provision.network_settings({'tv_subnet': tv, 'home_subnet': home})
