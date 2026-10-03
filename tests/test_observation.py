import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_privacy import p


def row(local='0100007F:0035', remote='08080808:01BB', inode='123', state='01'):
    return ' 0: %s %s %s 0:0 0:0 0 0 0 %s 1\n' % (local, remote, state, inode)


class ObservationTests(unittest.TestCase):
    def test_ipv4_ipv6_udp_and_malformed_rows(self):
        self.assertEqual(p.proc_address('0100007F:0035'), {'address': '127.0.0.1', 'port': 53})
        self.assertEqual(p.proc_address('00000000000000000000000001000000:01BB')['address'], '::1')
        rows, errors = p.socket_rows('header\n' + row(state='07') + 'malformed\n', 'udp', 4)
        self.assertEqual(rows[0]['protocol'], 'udp')
        self.assertEqual(rows[0]['remote']['port'], 443)
        self.assertEqual(rows[0]['attribution'], 'unknown')
        self.assertEqual(len(errors), 1)

    def test_udp_unconnected_and_private_range_are_not_filtered_out(self):
        rows, errors = p.socket_rows('header\n' + row(remote='00000000:0000') + row(remote='010010AC:01BB'), 'udp', 4)
        self.assertFalse(errors)
        self.assertEqual([r['remote_scope'] for r in rows], ['unspecified', 'non-global'])

    def test_owners_unmatched_and_missing_tables_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'net').mkdir()
            (root / 'net/tcp').write_text('header\n' + row() + row(inode='999'))
            proc = root / '23'; (proc / 'fd').mkdir(parents=True)
            (proc / 'stat').write_text('23 (name with spaces) S ' + ' '.join(['0'] * 18 + ['99']))
            (proc / 'comm').write_text('player\n')
            (proc / 'fd/4').symlink_to('socket:[123]')
            (proc / 'exe').symlink_to('/usr/bin/player')
            result = p.connection_snapshot(root)
            self.assertEqual(result['sockets'][0]['owners'][0]['start_ticks'], '99')
            self.assertEqual(result['sockets'][1]['attribution'], 'unknown')
            self.assertTrue(result['errors'])

    def test_disappearing_process_does_not_erase_sockets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'net').mkdir(); (root / '43').mkdir()
            for name in ('tcp', 'tcp6', 'udp', 'udp6'):
                (root / 'net' / name).write_text('header\n' + (row() if name == 'tcp' else ''))
            result = p.connection_snapshot(root)
            self.assertEqual(len(result['sockets']), 1)
            self.assertEqual(result['sockets'][0]['owners'], [])

    def test_capture_discovery_never_reads_capture_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('proc/asound', 'dev/snd', 'tmp'):
                (root / name).mkdir(parents=True, exist_ok=True)
            (root / 'proc/asound/pcm').write_text('00-10: Loopback : capture 1\n00-00: Output : playback 1\n')
            (root / 'dev/snd/pcmC0D10c').touch()
            (root / 'dev/snd/pcmC0D0p').touch()
            (root / 'tmp/capture.rgb').write_bytes(b'private screen data')
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('Must not read image/audio')):
                result = p.capture_inventory(root)
            self.assertEqual(len(result['nodes']), 1)
            self.assertFalse(result['nodes'][0]['automatic_block'])
            self.assertEqual(result['screen']['size'], 19)
            self.assertFalse(result['screen']['contents_read'])

    def test_audit_read_only_and_missing_evidence_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / 'etc').mkdir()
            release = root / 'etc/os-release'; release.write_text('ID=starfish\nVERSION_ID="10.2.1"\n')
            before = release.read_bytes()
            with patch.object(p, 'run', side_effect=AssertionError('No commands')), \
                 patch.object(p, 'luna', side_effect=AssertionError('No service activation')), \
                 patch.object(p, 'atomic', side_effect=AssertionError('No writes')):
                result = p.audit(root)
            self.assertEqual(result['status'], 'unknown')
            self.assertEqual(release.read_bytes(), before)
            self.assertEqual(len(list(root.rglob('*'))), 2)

    def test_no_records_is_not_capture_coverage_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = p.audit(Path(tmp))
            self.assertEqual(report['status'], 'unknown')
            capture = next(f for f in report['findings'] if f['name'] == 'capture coverage')
            self.assertEqual(capture['status'], 'unknown')


class MaintenanceTests(unittest.TestCase):
    def test_owned_but_writable_mount_repaired(self):
        with patch.object(p, 'mountpoints', return_value={'/target'}), patch.object(p, 'same_file', return_value=True), \
             patch.object(p, 'readonly_mount', return_value=False), patch.object(p, 'run') as run:
            p.bind({'mounts': []}, '/source', '/target')
            run.assert_called_once_with(['mount', '-o', 'remount,bind,ro', '/target'])

    def test_changed_startup_prevents_health_repair(self):
        state = {'status': 'applied'}
        with patch.object(p, 'runtime_issues', return_value=['Integrity changed: startup']), \
             patch.object(p, 'compatible', return_value=[]), patch.object(p, 'apply') as apply, \
             patch.object(p, 'verify') as verify, patch.object(p, 'atomic'):
            issues = p.health(state)
            self.assertTrue(issues); apply.assert_not_called(); verify.assert_not_called()

    def test_health_repair_only_after_profile_checks(self):
        with patch.object(p, 'runtime_issues', return_value=[]), patch.object(p, 'compatible', return_value=[]), \
             patch.object(p, 'apply') as apply, patch.object(p, 'maintenance_units'), patch.object(p, 'verify', side_effect=[['drift'], []]), patch.object(p, 'atomic'):
            self.assertEqual(p.health({'status': 'applied'}), [])
            apply.assert_called_once()

    def test_health_failure_replaces_stale_success_report(self):
        with patch.object(p, 'runtime_issues', side_effect=OSError('missing source')), patch.object(p, 'atomic') as write:
            issues = p.health({'status': 'applied'})
            self.assertTrue(issues)
            self.assertEqual(json.loads(write.call_args.args[1])['status'], 'fail')

    def test_preserved_activation_never_gets_overlay(self):
        sources = p.activation_sources()
        self.assertEqual(len(sources), 29)
        for name in sources:
            self.assertNotIn('sdx.service', name)
            self.assertNotIn('pushclient.service', name)

    def test_foreign_firewall_contents_refused(self):
        from subprocess import CompletedProcess
        with patch.object(p, 'run', return_value=CompletedProcess([], 0, '-A DANGBRO_PRIVACY -j ACCEPT\n')) as run:
            with self.assertRaisesRegex(RuntimeError, 'Unexpected firewall'):
                p.firewall()
            self.assertEqual(run.call_count, 1)

    def test_homebrew_underlay_allowed_on_reboot_but_foreign_hosts_refused(self):
        state = {'version': 2, 'integrity': {'/runtime': 'hash'}, 'hosts_underlay_sha256': 'original',
                 'mounts': [{'source': str(p.BASE / 'hosts.filtered'), 'target': '/etc/hosts'}]}
        with patch.object(p, 'sha256', return_value='hash'), patch.object(p, 'mountpoints', return_value={'/etc/hosts'}), \
             patch.object(p, 'same_file', side_effect=lambda source, target: str(source) == '/tmp/hosts'), \
             patch.object(p, 'hosts_underlay_digest', return_value='original'):
            self.assertEqual(p.runtime_issues(state), [])
        with patch.object(p, 'sha256', return_value='hash'), patch.object(p, 'mountpoints', return_value={'/etc/hosts'}), \
             patch.object(p, 'same_file', return_value=False), patch.object(p, 'hosts_underlay_digest', return_value='original'):
            self.assertTrue(p.runtime_issues(state))


if __name__ == '__main__':
    unittest.main()
