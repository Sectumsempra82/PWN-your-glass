#!/usr/bin/env python3
"""Bounded, private Pi sessions. Observation is default; enforcement is explicit."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

SESSIONS = Path('/var/log/glass-probe/sessions')
TABLE = 'glass_experiment'


def command(args, timeout=15, input_text=None):
    try:
        result = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout)
        return {'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'returncode': None, 'stdout': '', 'stderr': str(error)}


def write(path, data):
    temporary = path.with_suffix('.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream, indent=2); stream.flush(); os.fsync(stream.fileno())
    temporary.chmod(0o600); temporary.replace(path)


def snapshot():
    commands = {'addresses': ['ip', '-j', 'address'], 'routes': ['ip', '-j', 'route'],
                'ipv6_routes': ['ip', '-j', '-6', 'route'], 'firewall': ['nft', '-j', 'list', 'ruleset'],
                'clock': ['timedatectl', 'show', '-p', 'NTPSynchronized'],
                'dns': ['resolvectl', 'status'], 'link': ['ip', '-s', '-j', 'link', 'show', 'eth0']}
    result = {name: command(args) for name, args in commands.items()}
    for name, path in (('boot_id', '/proc/sys/kernel/random/boot_id'),
                       ('resolv_conf', '/etc/resolv.conf'),
                       ('leases', '/var/lib/misc/dnsmasq.leases')):
        try:
            result[name] = Path(path).read_text()
        except OSError:
            result[name] = None
    return result


def dns_rules():
    return '''table inet glass_experiment {
 chain dns_redirect {
  type nat hook prerouting priority -101; policy accept;
  iifname "eth0" meta nfproto ipv4 udp dport 53 counter redirect to :53
  iifname "eth0" meta nfproto ipv4 tcp dport 53 counter redirect to :53
 }
 chain encrypted_dns {
  type filter hook forward priority -10; policy accept;
  iifname "eth0" tcp dport 853 counter reject
  iifname "eth0" udp dport 853 counter reject
 }
}
'''


def packet_stats(text):
    stats = {}
    for label, key in (('captured', 'captured'), ('received by filter', 'received'), ('dropped by kernel', 'dropped')):
        match = re.search(r'(\d+) packets? ' + label, text)
        stats[key] = int(match[1]) if match else None
    return stats


def summary(directory):
    manifest = json.loads((directory / 'session.json').read_text())
    flows, domains, errors = {}, set(), []
    captures = sorted(directory.glob('traffic.pcap*'))
    if not captures:
        errors.append('No capture files retained')
    for path in captures:
        expected = manifest.get('files', {}).get(path.name)
        if not expected or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            errors.append('Capture integrity missing or changed: ' + path.name)
            continue
        args = ['tshark', '-n', '-r', str(path), '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=f',
                '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'ipv6.src', '-e', 'ip.dst', '-e', 'ipv6.dst',
                '-e', 'tcp.srcport', '-e', 'udp.srcport', '-e', 'tcp.dstport', '-e', 'udp.dstport',
                '-e', 'dns.qry.name', '-e', 'tls.handshake.extensions_server_name']
        # Stream decoded fields instead of buffering large captures in RAM.
        with (directory / 'decode-errors.log').open('a') as stderr:
            child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=stderr, text=True)
            for line in child.stdout:
                fields = line.rstrip('\n').split('\t')
                if len(fields) != 11:
                    errors.append('Malformed decoder row'); continue
                timestamp, src4, src6, dst4, dst6, tcp_s, udp_s, tcp_d, udp_d, dns, sni = fields
                domains.update(n for value in (dns, sni) for n in value.split(',') if n)
                if len(domains) > 10000 or len(flows) > 10000:
                    child.kill()
                    errors.append('Report cardinality limit reached; inspect retained capture directly')
                    break
                if not (tcp_s or udp_s):
                    continue
                try:
                    source, destination = str(ipaddress.ip_address(src4 or src6)), str(ipaddress.ip_address(dst4 or dst6))
                    key = (source, int(tcp_s or udp_s), destination, int(tcp_d or udp_d), 'tcp' if tcp_s else 'udp')
                    stamp = float(timestamp)
                except ValueError:
                    errors.append('Undecodable network tuple'); continue
                row = flows.setdefault(key, {'source': source, 'source_port': int(key[1]),
                                             'destination': destination, 'destination_port': int(key[3]),
                                             'protocol': key[4], 'packets': 0, 'first': stamp, 'last': stamp,
                                             'owners': [], 'attribution': 'unknown'})
                row['packets'] += 1; row['first'] = min(row['first'], stamp); row['last'] = max(row['last'], stamp)
            child.stdout.close()
            if child.wait() != 0:
                errors.append('tshark failed on ' + path.name)
    result = {'schema_version': 1, 'session_id': manifest['id'], 'scenario': manifest['scenario'],
              'mode': manifest['mode'], 'upstream_filtering': manifest['upstream_filtering'],
              'scope': 'Pi eth0 observation; does not attest standalone TV protection',
              'capture': manifest.get('capture'), 'flows': list(flows.values()), 'domains': sorted(domains),
              'errors': errors, 'status': 'unknown' if errors or manifest.get('status') != 'complete' else 'pass',
              'limitations': ['Encrypted payloads and ECH/DoH are not decoded.',
                             'Silent traffic does not establish absence of telemetry.',
                             'IPv6 is contained by this topology, not validated on the native LAN.']}
    write(directory / 'report.json', result)
    return result


def correlate(report, observations, tolerance=2):
    if observations.get('command') != 'connections' or observations.get('schema_version') != 1:
        raise ValueError('Expected privacy.py connections --json output')
    for flow in report['flows']:
        matches = []
        for sample in observations['samples']:
            if not flow['first'] - tolerance <= sample['timestamp'] <= flow['last'] + tolerance:
                continue
            for row in sample['sockets']:
                if row['protocol'] != flow['protocol']:
                    continue
                local, remote = row['local'], row['remote']
                direct = (local['address'], local['port'], remote['address'], remote['port'])
                observed = (flow['source'], flow['source_port'], flow['destination'], flow['destination_port'])
                if direct == observed or direct == (observed[2], observed[3], observed[0], observed[1]):
                    matches.extend(row['owners'])
        flow['owners'] = list({json.dumps(owner, sort_keys=True): owner for owner in matches}.values())
        flow['attribution'] = 'correlated-best-effort' if matches else 'unknown'
    report['attribution_caveat'] = 'Clock alignment must be established separately; socket reuse and sampling races remain possible.'
    return report


def record(seconds, scenario, upstream, mode='observe'):
    if os.geteuid() != 0:
        raise RuntimeError('Capture requires sudo')
    os.umask(0o077)
    SESSIONS.mkdir(parents=True, exist_ok=True, mode=0o700)
    if SESSIONS.is_symlink():
        raise RuntimeError('Session root cannot be a symlink')
    used = sum(path.stat().st_size for path in SESSIONS.rglob('*') if path.is_file())
    if used + 160 * 1024 ** 2 > 1024 ** 3 or shutil.disk_usage(SESSIONS).free < 512 * 1024 ** 2:
        raise RuntimeError('Session budget exceeded or low disk space; export evidence before another session')
    with (SESSIONS / '.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        directory = SESSIONS / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8])
        directory.mkdir(mode=0o700)
        before = snapshot()
        manifest = {'schema_version': 1, 'id': directory.name, 'scenario': scenario, 'mode': mode,
                    'upstream_filtering': upstream, 'started': time.time(), 'monotonic_start': time.monotonic(),
                    'status': 'starting', 'before': before}
        write(directory / 'session.json', manifest)
        if before['clock']['returncode'] != 0 or 'NTPSynchronized=yes' not in before['clock']['stdout']:
            raise RuntimeError('Synchronize the Pi clock before recording a comparable session')
        if not Path('/sys/class/net/eth0/carrier').read_text().strip() == '1':
            raise RuntimeError('TV-facing Ethernet has no carrier')
        if command(['nft', 'list', 'table', 'inet', TABLE])['returncode'] == 0:
            raise RuntimeError('Experimental table already exists; inspect interrupted session before cleanup')
        if mode == 'dns-enforced' and command(['systemctl', 'is-active', 'dnsmasq'])['returncode'] != 0:
            raise RuntimeError('DNS enforcement requires the existing probe resolver')
        installed = False
        child = None
        try:
            if mode == 'dns-enforced':
                result = command(['nft', '-f', '-'], input_text=dns_rules())
                if result['returncode'] != 0:
                    raise RuntimeError(result['stderr'])
                installed = True
            with (directory / 'tcpdump.log').open('w') as log:
                child = subprocess.Popen(['tcpdump', '-i', 'eth0', '-n', '-s', '0', '-U', '-C', '16',
                                          '-Z', 'root', '-w', str(directory / 'traffic.pcap')], stdout=subprocess.DEVNULL, stderr=log)
                manifest['status'] = 'recording'; write(directory / 'session.json', manifest)
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    if child.poll() is not None:
                        raise RuntimeError('tcpdump exited early')
                    # No -W: rotated files never wrap or overwrite earlier evidence.
                    if sum(p.stat().st_size for p in directory.glob('traffic.pcap*')) >= 110 * 1000 ** 2:
                        manifest['status'] = 'size-limited'; break
                    time.sleep(min(0.25, max(0, deadline - time.monotonic())))
                else:
                    manifest['status'] = 'complete'
        except BaseException:
            manifest['status'] = 'interrupted'
            raise
        finally:
            if child and child.poll() is None:
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait(); manifest['status'] = 'capture-stop-failed'
            manifest['after'] = snapshot()
            if installed:
                manifest['experiment_firewall'] = command(['nft', '-j', 'list', 'table', 'inet', TABLE])
                if manifest['experiment_firewall']['returncode'] != 0:
                    manifest['status'] = 'filter-lost'
                result = command(['nft', 'delete', 'table', 'inet', TABLE])
                manifest['filter_cleanup'] = result
                if result['returncode'] != 0:
                    manifest['status'] = 'cleanup-failed'
            manifest.update(ended=time.time(), monotonic_end=time.monotonic())
            log_path = directory / 'tcpdump.log'
            manifest['capture'] = packet_stats(log_path.read_text() if log_path.exists() else '')
            if manifest['status'] == 'complete' and (manifest['capture']['dropped'] != 0 or not manifest['capture']['captured']):
                manifest['status'] = 'incomplete-evidence'
            manifest['clock_jump_seconds'] = (manifest['ended'] - manifest['started']) - (manifest['monotonic_end'] - manifest['monotonic_start'])
            if abs(manifest['clock_jump_seconds']) > 1:
                manifest['status'] = 'clock-discontinuity'
            manifest['files'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.glob('traffic.pcap*')}
            write(directory / 'session.json', manifest)
        summary(directory)
        return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    rec = sub.add_parser('record')
    rec.add_argument('--seconds', type=int, default=60)
    rec.add_argument('--scenario', required=True)
    rec.add_argument('--upstream-note', required=True)
    rec.add_argument('--mode', choices=('observe', 'dns-enforced'), default='observe')
    rep = sub.add_parser('report'); rep.add_argument('directory', type=Path)
    rep.add_argument('--connections', type=Path)
    diff = sub.add_parser('compare'); diff.add_argument('before', type=Path); diff.add_argument('after', type=Path)
    args = parser.parse_args()
    if args.action == 'record':
        if not 1 <= args.seconds <= 1800:
            parser.error('--seconds must be 1..1800')
        print(record(args.seconds, args.scenario, args.upstream_note, args.mode))
    elif args.action == 'report':
        result = summary(args.directory)
        if args.connections:
            result = correlate(result, json.loads(args.connections.read_text()))
            write(args.directory / 'report.json', result)
        print(json.dumps(result, indent=2))
    else:
        before, after = (json.loads(path.read_text()) for path in (args.before, args.after))
        print(json.dumps({'added_domains': sorted(set(after['domains']) - set(before['domains'])),
                          'removed_domains': sorted(set(before['domains']) - set(after['domains'])),
                          'same_scenario': before['scenario'] == after['scenario'],
                          'same_upstream': before['upstream_filtering'] == after['upstream_filtering'],
                          'modes': [before['mode'], after['mode']],
                          'statuses': [before['status'], after['status']],
                          'conclusion': 'Differences require interpretation; missing traffic is not proof of blocking.'}, indent=2))


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
