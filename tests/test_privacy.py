import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, call

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('privacy', ROOT / 'privacy.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

class PolicyTests(unittest.TestCase):
    def test_only_optional_agreements_are_declined(self):
        original = {'eulaStatus': {'voiceAllowed': True, 'generalTermsAllowed': True,
                                  'networkAllowed': True, 'unknownFutureFlag': True},
                    'eulaInfo': {'eulaList': [
                        {'id': 'S_SVC', 'accepted': True, 'version': 'v1'},
                        {'id': 'S_DPA', 'accepted': True, 'version': 'v2'},
                        {'id': 'S_FUTURE', 'accepted': True}]}}
        result = p.opt_out(original)
        self.assertFalse(result['eulaStatus']['voiceAllowed'])
        for key in ('generalTermsAllowed', 'networkAllowed', 'unknownFutureFlag'):
            self.assertTrue(result['eulaStatus'][key])
        self.assertEqual(result['eulaInfo']['eulaList'][1], {'id': 'S_DPA', 'accepted': False, 'version': 'v2'})
        self.assertTrue(result['eulaInfo']['eulaList'][0]['accepted'])
        self.assertTrue(result['eulaInfo']['eulaList'][2]['accepted'])
        self.assertTrue(original['eulaStatus']['voiceAllowed'])
        self.assertEqual(p.opt_out(result), result)

    def test_all_six_routes_filtered_and_other_routes_unchanged(self):
        routes = [{'serviceName': name, 'domain': 'logging.example', 'baseResource': name + '/', 'domainType': 'default'}
                  for name in p.POLICY['blocked_sdx_services']]
        routes += [{'serviceName': 'sdp_auth', 'domain': 'shared.example', 'baseResource': 'auth/'}]
        data = {'version': '7', 'severDomain': {'10.0.0': routes}}
        before = copy.deepcopy(data)
        result = p.filtered_map(data)
        self.assertEqual(data, before)
        self.assertEqual(result['severDomain']['10.0.0'][-1], routes[-1])
        for route in result['severDomain']['10.0.0'][:-1]:
            self.assertEqual(route['domain'], 'privacy-blocked.invalid')
            self.assertEqual(route['baseResource'], route['serviceName'] + '/')
        self.assertEqual(p.filtered_map(result), result)

    def test_unknown_map_fails_instead_of_silently_skipping(self):
        for data in [{}, {'severDomain': {'10.0.0': []}}, {'severDomain': {'10.0.0': {}}}]:
            with self.assertRaises(RuntimeError): p.filtered_map(data)

    def test_profile_preserves_shared_internet_and_audio_paths(self):
        self.assertNotIn('/usr/sbin/sdx', p.POLICY['executables'])
        self.assertNotIn('/usr/sbin/com.webos.service.pushclient', p.POLICY['executables'])
        self.assertEqual(p.POLICY['mic_devices'], ['/dev/snd/pcmC1D0c'])
        self.assertNotIn('nextlgsdp.com', p.POLICY['blocked_hosts'])
        self.assertEqual(p.POLICY['settings']['option']['hbbTV'], 'offByUser')
        self.assertEqual(p.POLICY['settings']['option']['thirdPartyCookie'], 'offByUser')

    def test_check_on_non_tv_changes_nothing(self):
        result = subprocess.run([sys.executable, str(ROOT / 'privacy.py'), 'check'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('UNSUPPORTED', result.stdout)

class MutationTests(unittest.TestCase):
    def test_mount_journal_is_written_before_mount(self):
        events = []
        state = {'mounts': []}
        with patch.object(p, 'mountpoints', return_value=set()), \
             patch.object(p, 'save', side_effect=lambda state: events.append(('save', copy.deepcopy(state)))), \
             patch.object(p, 'run', side_effect=lambda args: events.append(('run', args))):
            p.bind(state, '/source', '/target')
        self.assertEqual(events[0], ('save', {'mounts': [{'source': '/source', 'target': '/target'}]}))
        self.assertEqual(events[1], ('run', ['mount', '--bind', '/source', '/target']))
        self.assertEqual(events[2][1], ['mount', '-o', 'remount,bind,ro', '/target'])

    def test_existing_owned_mount_is_idempotent(self):
        with patch.object(p, 'mountpoints', return_value={'/target'}), \
             patch.object(p, 'same_file', return_value=True), patch.object(p, 'run') as run:
            p.bind({'mounts': []}, '/source', '/target')
            run.assert_not_called()

    def test_foreign_mount_is_not_replaced(self):
        with patch.object(p, 'mountpoints', return_value={'/target'}), \
             patch.object(p, 'same_file', return_value=False), patch.object(p, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'Conflicting mount'):
                p.bind({'mounts': []}, '/source', '/target')
            run.assert_not_called()

    def test_failed_mount_keeps_recovery_journal(self):
        state = {'mounts': []}
        with patch.object(p, 'mountpoints', return_value=set()), patch.object(p, 'save') as save, \
             patch.object(p, 'run', side_effect=RuntimeError('mount failed')):
            with self.assertRaises(RuntimeError): p.bind(state, '/source', '/target')
            save.assert_called_once()
            self.assertEqual(state['mounts'][0]['target'], '/target')

    def test_unsupported_install_stops_before_mutation(self):
        with patch.object(p, 'compatible', return_value=['unsupported']), patch.object(p, 'save') as save, \
             patch.object(p, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'unsupported'): p.install(False)
            save.assert_not_called(); run.assert_not_called()

    def test_restore_preserves_foreign_mount_and_does_not_reaccept_consents(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            hook = base / 'hook'; hook.touch()
            prefs = base / 'prefs'; prefs.mkdir()
            (prefs / 'webosbrew_telnet_disabled').touch()
            (prefs / 'webosbrew_block_updates').touch()
            state = {'mounts': [{'source': '/ours', 'target': '/owned'}, {'source': '/ours', 'target': '/foreign'}],
                     'settings': {'general': {'homePromotion': 'on'}}, 'telnet_was_disabled': False,
                     'updates_were_blocked': True}
            with patch.object(p, 'BASE', base), patch.object(p, 'HOOK', hook), patch.object(p, 'PREFS', prefs), \
                 patch.object(p, 'mountpoints', return_value={'/owned', '/foreign'}), \
                 patch.object(p, 'same_file', side_effect=lambda source, target: target == '/owned'), \
                 patch.object(p, 'run') as run, patch.object(p, 'firewall'), patch.object(p, 'set_settings') as settings:
                failures = p.restore(state)
            self.assertEqual(failures, ['Foreign mount left untouched: /foreign'])
            self.assertFalse(hook.exists())
            run.assert_any_call(['umount', '/owned'])
            self.assertNotIn(call(['umount', '/foreign']), run.call_args_list)
            settings.assert_called_once_with('general', {'homePromotion': 'on'})
            self.assertFalse((prefs / 'webosbrew_telnet_disabled').exists())
            self.assertTrue((prefs / 'webosbrew_block_updates').exists())
            self.assertEqual(json.loads((base / 'state.json').read_text())['status'], 'restore-incomplete')

    def test_quarantine_refuses_global_namespace(self):
        with patch.object(p.os, 'readlink', return_value='mnt:[1]'), patch.object(p, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'private mount namespace'): p.quarantine()
            run.assert_not_called()


class InstallLifecycleTests(unittest.TestCase):
    def test_first_backup_survives_repeat_install_then_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / 'state'
            prefs = root / 'preferences'; prefs.mkdir()
            hook = root / 'init.d' / '05-dangbro-privacy'
            def tv_path(value):
                path = Path(value)
                return path if path.is_relative_to(root) else root / str(value).lstrip('/')
            source = tv_path(p.__file__); source.parent.mkdir(parents=True); source.write_text('# runtime test')
            routes = [{'serviceName': name, 'domain': 'original.example'} for name in p.POLICY['blocked_sdx_services']]
            original_map = json.dumps({'severDomain': {'10.0.0': routes}})
            for name in p.POLICY['sdx_maps']:
                path = tv_path(name); path.parent.mkdir(parents=True, exist_ok=True); path.write_text(original_map)
            before = {'general': {'homePromotion': 'on'}, 'option': {'hbbTV': 'on'}, 'other': {'contentRecommendation': 'on'}}
            def fake_apply(state):
                state['status'] = 'applied'; p.save(state)
            with patch.object(p, 'BASE', base), patch.object(p, 'HOOK', hook), patch.object(p, 'PREFS', prefs), \
                 patch.object(p, 'Path', side_effect=tv_path), patch.object(p, 'compatible', return_value=[]), \
                 patch.object(p, 'mountpoints', return_value=set()), \
                 patch.object(p, 'run', return_value=subprocess.CompletedProcess([], 1, '')), \
                 patch.object(p, 'get_settings', side_effect=lambda category, keys: before[category]), \
                 patch.object(p, 'apply', side_effect=fake_apply), patch.object(p, 'verify', return_value=[]):
                self.assertEqual(p.install(False), [])
                original_state = json.loads((base / 'state.json').read_text())
                self.assertFalse(original_state['disable_telnet'])
                self.assertEqual((base / 'sdx-original-0.json').read_text(), original_map)
                self.assertTrue(hook.exists())
                self.assertEqual((base / 'privacy.py').read_text(), '# runtime test')
                self.assertEqual(base.stat().st_mode & 0o777, 0o700)
                before['general'] = {'homePromotion': 'off'}
                self.assertEqual(p.install(False), [])
                self.assertEqual(json.loads((base / 'state.json').read_text())['settings'], original_state['settings'])
            with patch.object(p, 'BASE', base), patch.object(p, 'HOOK', hook), patch.object(p, 'PREFS', prefs), \
                 patch.object(p, 'mountpoints', return_value=set()), patch.object(p, 'run'), \
                 patch.object(p, 'firewall'), patch.object(p, 'set_settings') as settings:
                self.assertEqual(p.restore(original_state), [])
                settings.assert_any_call('general', {'homePromotion': 'on'})
                self.assertEqual(p.restore(original_state), [])
            self.assertFalse(hook.exists())
            self.assertEqual((base / 'sdx-original-0.json').read_text(), original_map)

if __name__ == '__main__': unittest.main()
