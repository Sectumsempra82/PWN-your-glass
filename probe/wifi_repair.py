#!/usr/bin/python3
"""One-time offline repair, invoked before NetworkManager starts."""
import configparser
import json
import os
from pathlib import Path
import shutil


BOOT_ARGUMENTS = {
    'systemd.run=/boot/firmware/glass-wifi-repair.py',
    'systemd.run_success_action=reboot',
    'systemd.run_failure_action=none',
    'systemd.unit=kernel-command-line.target',
}


def repair(root: Path) -> None:
    state = root / 'var/lib/NetworkManager/NetworkManager.state'
    cmdline = root / 'boot/firmware/cmdline.txt'
    boot_arguments = cmdline.read_text().split()
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(state)
    if not config.has_section('main'):
        config.add_section('main')
    config.set('main', 'WirelessEnabled', 'true')
    backup = state.with_name('NetworkManager.state.before-glass-wifi-repair')
    if state.exists() and not backup.exists():
        shutil.copy2(state, backup)
    state.parent.mkdir(parents=True, exist_ok=True)
    temporary_state = state.with_suffix('.repair-tmp')
    with temporary_state.open('w') as output:
        config.write(output, space_around_delimiters=False)
        output.flush()
        os.fsync(output.fileno())
    temporary_state.chmod(0o600)
    temporary_state.replace(state)
    temporary_cmdline = cmdline.with_suffix('.repair-tmp')
    with temporary_cmdline.open('w') as output:
        output.write(' '.join(arg for arg in boot_arguments if arg not in BOOT_ARGUMENTS) + '\n')
        output.flush()
        os.fsync(output.fileno())
    temporary_cmdline.replace(cmdline)


if __name__ == '__main__':
    result = Path('/boot/firmware/glass-wifi-repair-result.json')
    try:
        repair(Path('/'))
        result.write_text(json.dumps({'status': 'repaired', 'WirelessEnabled': True}) + '\n')
        os.sync()
    except Exception as error:
        result.write_text(json.dumps({'status': 'failed', 'error': str(error)}) + '\n')
        raise
