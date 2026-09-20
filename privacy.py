#!/usr/bin/env python3
"""Selective LG G5 privacy installer. Self-contained; never records or uploads audio."""
import argparse
import copy
import fcntl
import glob
import json
import os
from pathlib import Path
import platform
import pty
import select
import shutil
import signal
import subprocess
import sys
import time
import uuid

BASE = Path('/var/lib/webosbrew/dangbro-privacy')
HOOK = Path('/var/lib/webosbrew/init.d/05-dangbro-privacy')
PREFS = Path('/var/luna/preferences')
CHAIN = 'DANGBRO_PRIVACY'
HOST_MARKER = '# dangbro selective privacy hosts'
MIC_INFO = Path('/proc/asound/card1/pcm0c/info')
OPTIONAL_FLAGS = {'voiceAllowed', 'voice2Allowed', 'marketingOnAllowed', 'acrAllowed',
                  'acrGdprAllowed', 'acrAdAllowed', 'acrOnAllowed', 'remoteDiagAllowed',
                  'customAdAllowed', 'customadsAllowed', 'thirdPartySharingAllowed', 'veranceOnAllowed'}
OPTIONAL_DOCS = {'S_ADG', 'S_ADC', 'S_ADD', 'S_VNG', 'S_NVC', 'S_NVD', 'S_VDC',
                 'S_VDD', 'S_TAG', 'S_TAD', 'S_MKT', 'S_DPA'}
QUEUES = ['/var/spool/rdxd', '/var/spool/uploadd/pending', '/tmp/rdxd', '/tmp/uploadd']
POLICY = json.loads(r'''{
  "executables": [
    "/usr/bin/com.webos.app.voice",
    "/usr/sbin/acr2",
    "/usr/sbin/admanager",
    "/usr/sbin/adoverlay-service",
    "/usr/sbin/amazon-alexa-adapter",
    "/usr/sbin/com.webos.service.microphone",
    "/usr/sbin/contentminer",
    "/usr/sbin/dangbei-adapter",
    "/usr/sbin/lg.thinqai.adapter",
    "/usr/sbin/nlpmanager",
    "/usr/sbin/nudge",
    "/usr/sbin/performer",
    "/usr/sbin/rdxd",
    "/usr/sbin/service-logger",
    "/usr/sbin/trigger_alexa",
    "/usr/sbin/trigger_thinq",
    "/usr/sbin/update",
    "/usr/sbin/uploadd",
    "/usr/sbin/user-context-manager",
    "/usr/sbin/user-intent-manager",
    "/usr/sbin/voiceclick",
    "/usr/sbin/voiceconductor",
    "/usr/sbin/voiceinput",
    "/usr/sbin/voiceinput_hidraw",
    "/usr/sbin/voiceinput_network",
    "/usr/sbin/voiceinput_preprocessor",
    "/usr/sbin/voiceinput_sound"
  ],
  "units": [
    "/etc/systemd/system/com.webos.service.microphone.service",
    "/etc/systemd/system/contentminer.service",
    "/etc/systemd/system/nudge.service",
    "/etc/systemd/system/rdxd.service",
    "/etc/systemd/system/service-logger.service",
    "/etc/systemd/system/update-remote-config.service",
    "/etc/systemd/system/update.service",
    "/etc/systemd/system/uploadd.service",
    "/etc/systemd/system/user-context-manager.service",
    "/etc/systemd/system/voiceconductor.service",
    "/etc/systemd/system/voiceinput.service"
  ],
  "mic_devices": [
    "/dev/snd/pcmC1D0c"
  ],
  "sdx_maps": [
    "/usr/palm/sdx/server_addr_version.conf",
    "/mnt/lg/cmn_data/sdp/sdx/server_addr_version.conf"
  ],
  "blocked_sdx_services": [
    "sdp_logging",
    "ibis_stat_secure",
    "rdx_secure",
    "nudge_log_secure",
    "cdpbeacon_secure",
    "rdxdev_secure"
  ],
  "blocked_hosts": [
    "ad.lgappstv.com",
    "adsdtvc.com",
    "alphonso.tv",
    "cdpbeacon.lgtvcommon.com",
    "eic.cdpbeacon.lgtvcommon.com",
    "eic.privacy-blocked.invalid",
    "eic.rdl.lgtvcommon.com",
    "es.ibsstat.nextlgsdp.com",
    "es.info.lgsmartad.com",
    "es.privacy-blocked.invalid",
    "es.rdx2.nextlgsdp.com",
    "eu.info.lgsmartad.com",
    "eu7.ibsstat.nextlgsdp.com",
    "eu7.privacy-blocked.invalid",
    "eu7.rdx2.nextlgsdp.com",
    "ibsstat.nextlgsdp.com",
    "info.lgsmartad.com",
    "privacy-blocked.invalid",
    "rdl.lgtvcommon.com",
    "rdx2.nextlgsdp.com",
    "smart.adtvc.app"
  ],
  "settings": {
    "option": {
      "watchedListCollection": "off",
      "usageCare": false,
      "thirdPartyCookie": "offByUser",
      "hbbTV": "offByUser",
      "hbbTvDnt": "on",
      "hbbTvDeviceId": "off",
      "turnOnByVoice": "off",
      "dbgLogUpload": false,
      "faultLogUpload": false
    },
    "general": {
      "voiceLongDistance": "off",
      "screenSaverAd": "off",
      "aiNudge": "off",
      "aiSettingsNudge": "off",
      "adCookie": "off",
      "customizedAd": "off",
      "homePromotion": "off"
    },
    "other": {
      "contentRecommendation": "off"
    }
  },
  "preserve_units": [
    "audiod.service",
    "audiooutputd.service",
    "pulseaudio.service",
    "videooutputd.service",
    "pqcontroller.service",
    "panelcontroller.service",
    "arccontroller.service"
  ]
}''')


def run(args, check=True):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    if check and result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args) + '\n' + result.stdout)
    return result


def luna(method, payload):
    # A controlling terminal is needed by luna-send on the tested firmware.
    pid, fd = pty.fork()
    if pid == 0:
        os.execv('/usr/bin/luna-send', ['luna-send', '-w', '10000', '-n', '1',
                   'luna://' + method, json.dumps(payload, separators=(',', ':'))])
    output = bytearray()
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.25)[0]:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
        else:
            raise RuntimeError('Luna request timed out: ' + method)
    finally:
        os.close(fd)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)
    for line in output.decode(errors='replace').splitlines():
        try:
            result = json.loads(line)
        except ValueError:
            continue
        if result.get('returnValue') is True:
            return result
        if 'returnValue' in result:
            raise RuntimeError('Luna rejected ' + method + ': ' + line)
    raise RuntimeError('No successful Luna response: ' + method)


def atomic(path, data, mode=0o600):
    path = Path(path)
    temporary = path.with_name(path.name + '.new')
    with temporary.open('w') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(mode)
    temporary.replace(path)


def save(state):
    atomic(BASE / 'state.json', json.dumps(state, indent=2) + '\n')


def get_settings(category, keys):
    return luna('com.webos.settingsservice/getSystemSettings',
                {'category': category, 'keys': list(keys)})['settings']


def set_settings(category, settings):
    luna('com.webos.settingsservice/setSystemSettings', {'category': category, 'settings': settings})


def opt_out(eula):
    result = copy.deepcopy(eula)
    for key in OPTIONAL_FLAGS & result.get('eulaStatus', {}).keys():
        result['eulaStatus'][key] = False
    for category in ('eulaInfo', 'eulaInfoNetwork'):
        for item in result.get(category, {}).get('eulaList', []):
            if item.get('id') in OPTIONAL_DOCS:
                item['accepted'] = False
    return result


def filtered_map(data):
    result = copy.deepcopy(data)
    versions = result.get('severDomain')
    if not isinstance(versions, dict) or not versions:
        raise RuntimeError('Unknown SDX map schema')
    found = set()
    for routes in versions.values():
        if not isinstance(routes, list):
            raise RuntimeError('Unknown SDX route schema')
        for route in routes:
            if route.get('serviceName') in POLICY['blocked_sdx_services']:
                found.add(route['serviceName'])
                route['domain'] = 'privacy-blocked.invalid'
    if found != set(POLICY['blocked_sdx_services']):
        raise RuntimeError('SDX map does not contain all six reviewed logging routes')
    return result


def mountpoints():
    return {line.split()[4] for line in Path('/proc/self/mountinfo').read_text().splitlines()}


def same_file(source, target):
    try:
        return os.path.samefile(source, target)
    except OSError:
        return False


def compatible():
    errors = []
    if platform.system() != 'Linux' or platform.machine() != 'aarch64':
        return ['This profile requires Linux aarch64 on the tested LG G5.']
    release = Path('/etc/os-release').read_text()
    fields = dict(line.split('=', 1) for line in release.splitlines() if '=' in line)
    if fields.get('ID', '').strip('"') != 'starfish' or fields.get('VERSION_ID', '').strip('"') != '10.2.1':
        errors.append('Only webOS TV 10.2.1 is reviewed.')
    if not MIC_INFO.exists() or 'WoV PDM Mic snd-soc-dummy-dai-0' not in MIC_INFO.read_text():
        errors.append('The capture node is not the reviewed WoV PDM microphone.')
    if Path('/var/lib/webosbrew/init.d/05-lg-privacy').exists():
        errors.append('Existing manual privacy installation detected; migration is not automatic.')
    for command in ('mount', 'umount', 'unshare', 'systemctl', 'iptables', 'luna-send'):
        if not shutil.which(command):
            errors.append('Missing required command: ' + command)
    for path in POLICY['executables'] + POLICY['units'] + POLICY['mic_devices'] + POLICY['sdx_maps']:
        if not Path(path).exists():
            errors.append('Missing reviewed path: ' + path)
    if not Path('/media/developer/apps/usr/palm/services/org.webosbrew.hbchannel.service/startup.sh').exists():
        errors.append('Rooted Homebrew Channel must be installed first.')
    if errors:
        return errors
    model = luna('com.webos.service.tv.systemproperty/getSystemInfo', {'keys': ['modelName']}).get('modelName', '')
    if model != 'OLED65G56LS':
        errors.append('Untested model: ' + repr(model) + '; expected OLED65G56LS.')
    for path in POLICY['sdx_maps']:
        filtered_map(json.loads(Path(path).read_text()))
    for category, settings in POLICY['settings'].items():
        current = get_settings(category, settings)
        if set(settings) - current.keys():
            errors.append('Missing privacy settings in ' + category)
    eula = get_settings('eula', ['eulaStatus', 'eulaInfo', 'eulaInfoNetwork'])
    if not isinstance(eula.get('eulaStatus'), dict) or not (OPTIONAL_FLAGS & eula['eulaStatus'].keys()):
        errors.append('Missing reviewed EULA consent status schema.')
    return errors


def check_telnet_safety():
    keys = Path('/home/root/.ssh/authorized_keys')
    if not (PREFS / 'webosbrew_sshd_enabled').exists() or not keys.exists() or not keys.read_text().strip():
        raise RuntimeError('Enable Homebrew SSH and install your own authorized key before disabling Telnet.')
    if not os.environ.get('SSH_CONNECTION'):
        raise RuntimeError('Run --disable-telnet from a working SSH login to confirm alternate access.')


def bind(state, source, target, layered=False):
    source = str(source)
    mounted = target in mountpoints()
    if mounted and same_file(source, target):
        return
    if mounted and not layered:
        raise RuntimeError('Conflicting mount; refusing to replace: ' + target)
    record = {'source': source, 'target': target}
    if record not in state['mounts']:
        state['mounts'].append(record)
        save(state)  # Record before mutation so an interrupted install remains recoverable.
    run(['mount', '--bind', source, target])
    run(['mount', '-o', 'remount,bind,ro', target])


def stop_processes(paths):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for entry in glob.glob('/proc/[0-9]*/exe'):
            try:
                if os.readlink(entry).removesuffix(' (deleted)') in paths:
                    os.kill(int(entry.split('/')[2]), sig)
            except (FileNotFoundError, ProcessLookupError):
                pass
        if sig == signal.SIGTERM:
            time.sleep(1)


def firewall(remove=False):
    ipt = shutil.which('iptables')
    while run([ipt, '-C', 'OUTPUT', '-j', CHAIN], False).returncode == 0:
        run([ipt, '-D', 'OUTPUT', '-j', CHAIN])
    exists = run([ipt, '-S', CHAIN], False).returncode == 0
    if exists:
        run([ipt, '-F', CHAIN])
    if remove:
        if exists:
            run([ipt, '-X', CHAIN])
        return
    if not exists:
        run([ipt, '-N', CHAIN])
    run([ipt, '-A', CHAIN, '-d', '156.147.69.32/32', '-p', 'tcp', '--dport', '8080', '-j', 'REJECT'])
    run([ipt, '-I', 'OUTPUT', '1', '-j', CHAIN])


def quarantine():
    # Internal action must be in a separate mount namespace; never unmount Homebrew queues globally.
    if os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'):
        raise RuntimeError('Quarantine requires a private mount namespace')
    run(['mount', '--make-rprivate', '/'])
    destination = BASE / 'quarantine' / str(uuid.uuid4())
    count = 0
    for name in QUEUES:
        if name in mountpoints():
            run(['umount', name])
        directory = Path(name)
        if directory.is_symlink():
            raise RuntimeError('Unexpected symlink queue: ' + name)
        if not directory.is_dir():
            continue
        for entry in list(directory.iterdir()):
            target = destination / name.lstrip('/')
            target.mkdir(parents=True, exist_ok=True)
            shutil.move(str(entry), str(target / entry.name))
            count += 1
    print('Quarantined', count, 'diagnostic queue entries; no upload or deletion.')


def apply(state):
    for target in POLICY['executables']:
        bind(state, BASE / 'blocked-executable', target)
    for target in POLICY['units']:
        bind(state, BASE / 'empty-unit', target)
    for target in POLICY['mic_devices']:
        bind(state, '/dev/null', target)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'stop', '--no-block'] + [Path(p).name for p in POLICY['units']])
    stop_processes(set(POLICY['executables']))
    for index, target in enumerate(POLICY['sdx_maps']):
        bind(state, BASE / ('sdx-' + str(index) + '.json'), target)
    # Replace only our hosts layer, preserving Homebrew OTA entries underneath.
    hosts = BASE / 'hosts.filtered'
    if '/etc/hosts' in mountpoints() and same_file(hosts, '/etc/hosts'):
        run(['umount', '/etc/hosts'])
    original = Path('/etc/hosts').read_text()
    if HOST_MARKER in original:
        raise RuntimeError('Unexpected existing DangBro hosts block')
    lines = original.rstrip() + '\n\n' + HOST_MARKER + '\n'
    for host in POLICY['blocked_hosts']:
        lines += '0.0.0.0 ' + host + '\n:: ' + host + '\n'
    atomic(hosts, lines)
    bind(state, hosts, '/etc/hosts', layered=True)
    firewall()
    # Existing SDX processes may have read their route map before the boot hook.
    stop_processes({'/usr/sbin/sdx'})
    for category, settings in POLICY['settings'].items():
        set_settings(category, settings)
    eula = get_settings('eula', ['eulaStatus', 'eulaInfo', 'eulaInfoNetwork'])
    set_settings('eula', opt_out(eula))
    acr = Path('/mnt/lg/cmn_data/acr/data')
    if acr.is_dir():
        (acr / 'eula_allowed').unlink(missing_ok=True)
        (acr / 'eula_disallowed_rebooted').touch()
    run(['unshare', '-m', sys.executable, str(BASE / 'privacy.py'), '_quarantine'])
    if state['disable_telnet']:
        (PREFS / 'webosbrew_telnet_disabled').touch()
    (PREFS / 'webosbrew_block_updates').touch()
    state['status'] = 'applied'
    save(state)
    run(['sync'])


def install(disable_telnet):
    errors = compatible()
    if errors:
        raise RuntimeError('\n'.join(errors))
    if disable_telnet:
        check_telnet_safety()
    if (BASE / 'state.json').exists():
        state = json.loads((BASE / 'state.json').read_text())
        if state['status'] == 'restored':
            raise RuntimeError('Previous install restored. Archive its backup directory before reinstalling.')
        if disable_telnet:
            state['disable_telnet'] = True
            save(state)
        apply(state)
        return verify(state)
    if BASE.exists() or HOOK.exists():
        raise RuntimeError('Unrecognized existing installation; refusing to overwrite.')
    if run([shutil.which('iptables'), '-S', CHAIN], False).returncode == 0:
        raise RuntimeError('Firewall chain name already in use.')
    mounts = mountpoints()
    for target in POLICY['executables'] + POLICY['units'] + POLICY['mic_devices'] + POLICY['sdx_maps']:
        if target in mounts:
            raise RuntimeError('Existing overlay requires manual review: ' + target)
    # Gather all inputs before creating the backup or changing the TV.
    settings = {c: get_settings(c, s) for c, s in POLICY['settings'].items()}
    maps = [Path(path).read_text() for path in POLICY['sdx_maps']]
    filtered = [filtered_map(json.loads(value)) for value in maps]
    BASE.mkdir(mode=0o700)
    state = {'version': 1, 'status': 'installing', 'mounts': [], 'settings': settings,
             'disable_telnet': disable_telnet,
             'telnet_was_disabled': (PREFS / 'webosbrew_telnet_disabled').exists(),
             'updates_were_blocked': (PREFS / 'webosbrew_block_updates').exists()}
    save(state)
    for index, data in enumerate(maps):
        atomic(BASE / ('sdx-original-' + str(index) + '.json'), data)
        atomic(BASE / ('sdx-' + str(index) + '.json'), json.dumps(filtered[index]))
    atomic(BASE / 'blocked-executable', '#!/bin/sh\n# DangBro privacy block\nexit 1\n', 0o755)
    atomic(BASE / 'empty-unit', '')
    atomic(BASE / 'privacy.py', Path(__file__).read_text(), 0o700)
    acr = Path('/mnt/lg/cmn_data/acr/data/eula_allowed')
    if acr.is_file():
        shutil.copy2(acr, BASE / 'original-eula-allowed')
    HOOK.parent.mkdir(exist_ok=True)
    atomic(HOOK, '#!/bin/sh\n/usr/bin/python3 /var/lib/webosbrew/dangbro-privacy/privacy.py boot >>/tmp/dangbro-privacy.log 2>&1\n', 0o755)
    apply(state)
    return verify(state)


def verify(state):
    issues = []
    if state['status'] == 'restored':
        return ['Installer has been restored; protections are no longer applied.']
    expected = set(POLICY['executables'] + POLICY['units'] + POLICY['mic_devices'] + POLICY['sdx_maps'] + ['/etc/hosts'])
    recorded = {record['target'] for record in state['mounts']}
    for target in sorted(expected - recorded):
        issues.append('Installation incomplete, missing overlay: ' + target)
    for record in state['mounts']:
        if record['target'] not in mountpoints() or not same_file(record['source'], record['target']):
            issues.append('Overlay absent: ' + record['target'])
    for category, settings in POLICY['settings'].items():
        actual = get_settings(category, settings)
        for key, value in settings.items():
            if actual.get(key) != value:
                issues.append('Setting mismatch: ' + category + '.' + key)
    eula = get_settings('eula', ['eulaStatus', 'eulaInfo', 'eulaInfoNetwork'])
    if eula != opt_out(eula):
        issues.append('Optional consent enabled')
    for name in POLICY['blocked_sdx_services']:
        result = luna('com.webos.service.sdx/getServerUrl', {'serviceName': name})
        from urllib.parse import urlsplit
        host = urlsplit(result.get('baseUrl', '')).hostname or ''
        if host != 'privacy-blocked.invalid' and not host.endswith('.privacy-blocked.invalid'):
            issues.append('SDX route not blocked: ' + name)
    for entry in glob.glob('/proc/[0-9]*/exe'):
        try:
            if os.readlink(entry).removesuffix(' (deleted)') in POLICY['executables']:
                issues.append('Collector still running: ' + entry)
        except FileNotFoundError:
            pass
    for unit in POLICY['preserve_units']:
        if run(['systemctl', 'is-active', unit], False).returncode:
            issues.append('Preserved AV service inactive: ' + unit)
    if run([shutil.which('iptables'), '-C', 'OUTPUT', '-j', CHAIN], False).returncode:
        issues.append('OTA fallback firewall missing')
    rules = run([shutil.which('iptables'), '-S', CHAIN], False)
    expected_rule = '-A ' + CHAIN + ' -d 156.147.69.32/32 -p tcp -m tcp --dport 8080 -j REJECT --reject-with icmp-port-unreachable'
    if [line for line in rules.stdout.splitlines() if line.startswith('-A ')] != [expected_rule]:
        issues.append('OTA firewall rule missing or unexpected scope')
    hosts = Path('/etc/hosts').read_text()
    for host in POLICY['blocked_hosts']:
        if '0.0.0.0 ' + host + '\n' not in hosts or ':: ' + host + '\n' not in hosts:
            issues.append('Host block missing: ' + host)
    if not (PREFS / 'webosbrew_block_updates').exists():
        issues.append('Homebrew update-block preference missing')
    if state['disable_telnet'] and not (PREFS / 'webosbrew_telnet_disabled').exists():
        issues.append('Telnet boot-disable marker missing')
    if not HOOK.exists():
        issues.append('Boot hook missing')
    return issues


def restore(state):
    # First prevent reapplication. Leave backup/queue data private and never reaccept consent.
    HOOK.unlink(missing_ok=True)
    failures = []
    for record in reversed(state['mounts']):
        target = record['target']
        if target in mountpoints():
            if same_file(record['source'], target):
                run(['umount', target])
            else:
                failures.append('Foreign mount left untouched: ' + target)
    firewall(remove=True)
    for category, settings in state['settings'].items():
        set_settings(category, settings)
    for name, existed in [('webosbrew_telnet_disabled', state['telnet_was_disabled']),
                          ('webosbrew_block_updates', state['updates_were_blocked'])]:
        if existed:
            (PREFS / name).touch()
        else:
            (PREFS / name).unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])
    state['status'] = 'restore-incomplete' if failures else 'restored'
    save(state)
    print('Reboot manually to restart services. Backups and quarantined queues are retained.')
    print('Optional legal consents remain declined; quarantined uploads are not requeued.')
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['check', 'install', 'verify', 'restore', 'boot', '_quarantine'])
    parser.add_argument('--disable-telnet', action='store_true', help='Disable normal-boot Telnet after a working SSH login; no immediate disconnect')
    args = parser.parse_args()
    if args.disable_telnet and args.command != 'install':
        parser.error('--disable-telnet is only valid with install')
    if args.command == 'check':
        errors = compatible()
        for error in errors:
            print('UNSUPPORTED:', error)
        if not errors:
            print('Compatible reviewed profile. No changes made. Installation disables ACR, voice, ads, diagnostics and firmware updates.')
        return bool(errors)
    if os.geteuid() != 0:
        raise RuntimeError('Run as root on the TV.')
    os.umask(0o077)
    if args.command == '_quarantine':
        quarantine()
        return 0
    # Lock outside BASE so check/install never mistake our own lock for an existing install.
    with open('/var/lib/webosbrew/.dangbro-privacy.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == 'install':
            issues = install(args.disable_telnet)
        else:
            state = json.loads((BASE / 'state.json').read_text())
            if args.command == 'boot':
                if state['status'] == 'restored':
                    return 0
                errors = compatible()
                if errors:
                    raise RuntimeError('Boot profile mismatch: ' + '; '.join(errors))
                apply(state)
                issues = verify(state)
            elif args.command == 'restore':
                issues = restore(state)
            else:
                issues = verify(state)
        for issue in issues:
            print('FAIL:', issue)
        print(args.command.upper(), 'FAILED' if issues else 'PASS')
        if args.command == 'install':
            print('Leave the physical mic switch Off. Reboot with Quick Start+ Off, then run verify again.')
            print('Telnet is unchanged now; --disable-telnet affects the next normal boot. Homebrew failsafe may reopen it.')
        return bool(issues)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('ERROR:', error, file=sys.stderr)
        print('If installation partly applied, keep WAN blocked, inspect the local backup, and use restore if needed.', file=sys.stderr)
        sys.exit(1)
