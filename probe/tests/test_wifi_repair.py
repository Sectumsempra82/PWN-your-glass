import configparser
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wifi_repair import BOOT_ARGUMENTS, repair


class WifiRepairTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.state = self.root / 'var/lib/NetworkManager/NetworkManager.state'
        self.cmdline = self.root / 'boot/firmware/cmdline.txt'
        self.state.parent.mkdir(parents=True)
        self.cmdline.parent.mkdir(parents=True)
        self.state.write_text('[main]\nWirelessEnabled=false\nWWANEnabled=false\n')
        self.original = 'console=tty1 root=PARTUUID=660f0ddc-02 rootwait video=HDMI-A-1:d video=HDMI-A-2:d'
        self.cmdline.write_text(self.original + ' ' + ' '.join(sorted(BOOT_ARGUMENTS)) + '\n')

    def test_enables_wifi_and_preserves_other_radio_settings(self):
        repair(self.root)
        config = configparser.ConfigParser()
        config.read(self.state)
        self.assertTrue(config.getboolean('main', 'WirelessEnabled'))
        self.assertFalse(config.getboolean('main', 'WWANEnabled'))
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)

    def test_removes_only_repair_boot_arguments(self):
        repair(self.root)
        self.assertEqual(self.cmdline.read_text(), self.original + '\n')

    def test_repeat_repair_preserves_original_backup(self):
        original_state = self.state.read_text()
        repair(self.root)
        repair(self.root)
        backup = self.state.with_name('NetworkManager.state.before-glass-wifi-repair')
        self.assertEqual(backup.read_text(), original_state)
        self.assertEqual(self.cmdline.read_text(), self.original + '\n')

    def test_missing_boot_file_does_not_mutate_radio_state(self):
        self.cmdline.unlink()
        original_state = self.state.read_text()
        with self.assertRaises(FileNotFoundError):
            repair(self.root)
        self.assertEqual(self.state.read_text(), original_state)


if __name__ == '__main__':
    unittest.main()
