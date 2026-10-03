#!/usr/bin/env python3
"""Regenerate the offline installer's embedded reviewed policy; never fetch data."""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def render():
    profile = json.loads((ROOT / 'profiles/g5-webos-10.2.1.json').read_text())
    records = json.loads((ROOT / 'policies/endpoints.json').read_text())['entries']
    hosts = []
    for entry in records:
        host = entry['host']
        if not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z0-9]+', host):
            raise ValueError('Expected an exact lowercase hostname: ' + host)
        if entry['status'] not in ('approved', 'candidate', 'rejected'):
            raise ValueError('Unknown endpoint status')
        if entry['status'] == 'approved':
            if not entry.get('evidence') or not entry.get('source'):
                raise ValueError('Approval requires evidence and provenance')
            hosts.append(host)
    if len(hosts) != len(set(hosts)):
        raise ValueError('Duplicate approved endpoint')
    profile['blocked_hosts'] = sorted(hosts)
    source = (ROOT / 'privacy.py').read_text()
    payload = "POLICY = json.loads(r'''" + json.dumps(profile, indent=2, sort_keys=True) + "''')"
    return re.sub(r"POLICY = json.loads\(r'''.*?'''\)", lambda _: payload, source, count=1, flags=re.S)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = render()
    if args.check:
        if result != (ROOT / 'privacy.py').read_text():
            raise SystemExit('Embedded policy differs; run tools/build_profile.py')
    else:
        (ROOT / 'privacy.py').write_text(result)
