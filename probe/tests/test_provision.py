import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('provision', Path(__file__).resolve().parents[1] / 'provision.py')
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


class NetworkSettingsTests(unittest.TestCase):
    def test_private_config_rejects_injected_lines(self):
        config = {'username': 'operator', 'hostname': 'glass-probe', 'country': 'FR',
                  'keyboard': 'us', 'timezone': 'Etc/UTC', 'wifi_psk': 'a' * 64,
                  'wifi_ssid': 'example', 'ssh_public_key': 'ssh-ed25519 AAAA example',
                  'password_hash': '$6$example'}
        provision.validate_config(config)
        for key, value in [('wifi_ssid', 'example\n[connection]'),
                           ('hostname', 'probe\nmalicious'),
                           ('username', 'root;echo'),
                           ('timezone', '../Etc/UTC')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                provision.validate_config({**config, key: value})

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
