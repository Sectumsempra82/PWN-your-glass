# PWN-your-glass

Selective privacy hardening for already-rooted LG webOS TVs.

This repository owns the standalone privacy installer, its policy and its tests. For LAN-only rooting and Homebrew installation, use the separate [local-only dangbro fork](https://github.com/Sectumsempra82/dangbro).

## Status

The initial profile targets **OLED65G56LS / webOS TV 10.2.1 / aarch64**. Other models and layouts are refused. Individual controls were exercised on the original G5; the packaged installer still needs a complete clean-TV install, reboot and restore test. It is experimental.

This initial extraction preserves the installer and tests from [dangbro commit 2f28a22](https://github.com/Sectumsempra82/dangbro/tree/2f28a22b4c494ee5db68d26080d8315f6501f1ca) without changing their behavior. It does not incorporate later device-specific maintenance scripts or third-party hardening tools.

## Install on an already-rooted TV

The installer is one file, uses the Python standard library and downloads nothing. It requires the TV's existing **Python 3.10+**, expected Linux tools and working Homebrew persistence. Clone/download this private repository on your computer; no GitHub credential belongs on the TV.

Copy `privacy.py` using existing SSH access or a USB drive. Replace `TV-IP` with your TV's address:

```sh
scp privacy.py root@TV-IP:/tmp/privacy.py
ssh -t root@TV-IP
python3 /tmp/privacy.py check
python3 /tmp/privacy.py install
```

Read [PRIVACY.md](PRIVACY.md) before applying the profile. Keep the physical microphone switch Off. Disable Quick Start+, reboot, then verify:

```sh
python3 /var/lib/webosbrew/dangbro-privacy/privacy.py verify
```

The existing `dangbro-privacy` install path, hook name, firewall chain and markers are deliberately retained for compatibility. The repository name does not migrate an existing installation. Existing manual `05-lg-privacy` deployments are refused and need a separately reviewed migration.

Telnet is unchanged by default. To disable it on the next normal boot, first enable Homebrew SSH, install your own authorized key, verify a working login, and run from that SSH session:

```sh
python3 /tmp/privacy.py install --disable-telnet
```

Homebrew's emergency failsafe may still start Telnet. The installer never installs passwords or SSH keys.

## Scope and recovery

The profile targets ACR/viewing collection, LG voice features, advertising, recommendations, diagnostic uploads and firmware updates. General networking, shared services and picture/audio processing are preserved. See the full [policy, tradeoffs and recovery guide](PRIVACY.md).

```sh
python3 /var/lib/webosbrew/dangbro-privacy/privacy.py restore
```

Reboot manually after restore. Optional consents remain declined, the ACR allowed marker is not restored, and quarantined uploads are not requeued. Failed installation leaves completed controls in place for inspection. Backups and state remain private on the TV.

Local verification cannot establish zero telemetry or universal microphone containment. IPv6 enforcement, additional capture paths and independent network isolation are outside this initial package.

## Development

Run the host-side suite on Linux, including WSL, using Python 3.10+:

```sh
python3 -m unittest discover -s tests -v
```

The runtime imports Linux/POSIX modules, so native Windows Python is not a supported runtime for the installer or this suite. Tests use temporary fixtures and mocks; they do not require a TV.

`AGENTS.md`, `docs/`, `.notebook/`, local device data, credentials and build output stay untracked. This repository contains no rooting exploit, Homebrew IPK, local web server or TV-specific deployment backup.

## Provenance

Extracted from the privacy component of [Sectumsempra82/dangbro](https://github.com/Sectumsempra82/dangbro). Homebrew persistence is provided by [webosbrew/webos-homebrew-channel](https://github.com/webosbrew/webos-homebrew-channel). No upstream rooting code or downloaded Homebrew package is copied into this repository. A distribution license has not yet been selected.
