#!/usr/bin/env python3
"""Configure a fresh Raspberry Pi OS image. Run inside its chroot only."""
import json
import ipaddress
import pathlib
import re
import shutil
import subprocess
import sys


def run(*args: str, **kwargs: object) -> None:
    subprocess.run(args, check=True, **kwargs)


def write(path: str, content: str, mode: int = 0o644) -> None:
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding='utf-8')
    target.chmod(mode)


def network_settings(config: dict) -> dict[str, str]:
    tv_network = ipaddress.ip_network(config['tv_subnet'], strict=True)
    home_network = ipaddress.ip_network(config['home_subnet'], strict=True)
    if (not isinstance(tv_network, ipaddress.IPv4Network) or tv_network.prefixlen != 24
            or not isinstance(home_network, ipaddress.IPv4Network)
            or not tv_network.is_private or not home_network.is_private
            or tv_network.overlaps(home_network)):
        raise ValueError('Use non-overlapping private IPv4 networks; TV subnet must be /24')
    return {'TV_SUBNET': str(tv_network), 'HOME_SUBNET': str(home_network),
            'TV_GATEWAY': str(tv_network.network_address + 1),
            'TV_DHCP_START': str(tv_network.network_address + 100),
            'TV_DHCP_END': str(tv_network.network_address + 120)}


def validate_config(config: dict) -> None:
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', config['username']):
        raise ValueError('Invalid Linux username')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', config['hostname']):
        raise ValueError('Invalid hostname')
    if not re.fullmatch(r'[A-Z]{2}', config['country']):
        raise ValueError('Invalid wireless country')
    if not re.fullmatch(r'[a-z0-9_+-]+', config['keyboard']):
        raise ValueError('Invalid keyboard layout')
    if not re.fullmatch(r'[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)+', config['timezone']):
        raise ValueError('Invalid timezone')
    if not (pathlib.Path('/usr/share/zoneinfo') / config['timezone']).is_file():
        raise ValueError('Unknown timezone')
    if not re.fullmatch(r'[0-9a-fA-F]{64}', config['wifi_psk']):
        raise ValueError('Expected a 64-digit hexadecimal Wi-Fi PSK')
    for key in ('wifi_ssid', 'ssh_public_key', 'password_hash'):
        value = config[key]
        if not isinstance(value, str) or not value or any(char in value for char in '\r\n\x00'):
            raise ValueError('Invalid private configuration field: ' + key)
    if not config['ssh_public_key'].startswith(('ssh-ed25519 ', 'ecdsa-sha2-', 'ssh-rsa ')):
        raise ValueError('Expected an SSH public key')


def main() -> None:
    if not pathlib.Path('/root/glass-probe-image-build').exists():
        raise SystemExit('Refusing to configure a system without the image-build marker')
    config = json.loads(pathlib.Path(sys.argv[1]).read_text())
    validate_config(config)
    networks = network_settings(config)
    def network_values(template: str) -> str:
        for name, value in networks.items():
            template = template.replace(name, value)
        return template
    username = config['username']
    hostname = config['hostname']
    run('useradd', '-m', '-s', '/bin/bash', '-G', 'sudo,adm,netdev,video,input,spi,i2c,gpio', username)
    run('chpasswd', '-e', input=f"{username}:{config['password_hash']}\n", text=True)
    run('passwd', '-l', 'root')
    write(f'/home/{username}/.ssh/authorized_keys', config['ssh_public_key'] + '\n', 0o600)
    pathlib.Path(f'/home/{username}/.ssh').chmod(0o700)
    run('chown', '-R', f'{username}:{username}', f'/home/{username}/.ssh')
    write('/etc/hostname', hostname + '\n')
    write('/etc/hosts', f'127.0.0.1 localhost\n127.0.1.1 {hostname}\n::1 localhost ip6-localhost ip6-loopback\n')
    write('/etc/timezone', config['timezone'] + '\n')
    pathlib.Path('/etc/localtime').unlink(missing_ok=True)
    pathlib.Path('/etc/localtime').symlink_to('/usr/share/zoneinfo/' + config['timezone'])
    write('/etc/default/keyboard', f'XKBMODEL="pc105"\nXKBLAYOUT="{config["keyboard"]}"\nXKBVARIANT=""\nXKBOPTIONS=""\nBACKSPACE="guess"\n')
    write('/etc/default/locale', 'LANG=en_US.UTF-8\n')
    write('/etc/locale.gen', 'en_US.UTF-8 UTF-8\n')
    run('locale-gen')
    write('/etc/cloud/cloud-init.disabled', '')
    boot_config = pathlib.Path('/boot/firmware/config.txt')
    boot_config.write_text(boot_config.read_text() + '\n[all]\n# Headless probe; LCD backlight wiring remains model-specific.\ndisplay_auto_detect=0\nmax_framebuffers=0\ndisable_splash=1\n')
    cmdline = pathlib.Path('/boot/firmware/cmdline.txt')
    cmdline.write_text(cmdline.read_text().strip() + ' video=HDMI-A-1:d video=HDMI-A-2:d\n')
    run('systemctl', 'mask', 'userconfig.service')
    write('/etc/ssh/sshd_config.d/00-glass-probe.conf', f'PermitRootLogin no\nPasswordAuthentication yes\nPubkeyAuthentication yes\nAllowUsers {username}\n')
    write('/etc/NetworkManager/conf.d/10-glass-probe.conf', '[main]\nno-auto-default=*\n')
    write('/var/lib/NetworkManager/NetworkManager.state', '[main]\nWirelessEnabled=true\n', 0o600)
    write('/etc/NetworkManager/system-connections/glass-uplink.nmconnection', f'''[connection]
id=glass-uplink
type=wifi
interface-name=wlan0
autoconnect=true
autoconnect-retries=0

[wifi]
mode=infrastructure
ssid={config['wifi_ssid']}
powersave=2

[wifi-security]
key-mgmt=wpa-psk
psk={config['wifi_psk']}

[ipv4]
method=auto
dhcp-hostname={hostname}

[ipv6]
method=auto
''', 0o600)
    write('/etc/NetworkManager/system-connections/glass-tv.nmconnection', '''[connection]
id=glass-tv
type=ethernet
interface-name=eth0
autoconnect=true

[ethernet]

[ipv4]
method=manual
address1=TV_GATEWAY/24
never-default=true

[ipv6]
method=disabled
'''.replace('TV_GATEWAY', networks['TV_GATEWAY']), 0o600)
    write('/etc/modprobe.d/glass-wifi-country.conf', f'options cfg80211 ieee80211_regdom={config["country"]}\n')
    write('/etc/systemd/system/glass-radio.service', f'''[Unit]
Description=Enable Wi-Fi with the configured regulatory country
Before=NetworkManager.service
After=systemd-rfkill.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/rfkill unblock wifi
ExecStart=/usr/sbin/iw reg set {config['country']}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
''')
    write('/etc/sysctl.d/90-glass-probe.conf', 'net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=0\n')
    write('/etc/dnsmasq.d/glass-probe.conf', network_values('''interface=eth0
bind-dynamic
listen-address=TV_GATEWAY
dhcp-authoritative
dhcp-range=TV_DHCP_START,TV_DHCP_END,255.255.255.0,12h
dhcp-option=option:router,TV_GATEWAY
dhcp-option=option:dns-server,TV_GATEWAY
domain-needed
bogus-priv
cache-size=1000
'''))
    # This image owns its firewall; NetworkManager sharing is deliberately unused.
    write('/etc/nftables.conf', network_values('''#!/usr/sbin/nft -f
flush ruleset
table inet glass_probe {
    set blocked_v4 { type ipv4_addr; flags interval; }
    set tv_wan_allow_tcp { type ipv4_addr . inet_service; }
    set tv_wan_allow_udp { type ipv4_addr . inet_service; }
    chain input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        ct state established,related accept
        ct state invalid drop
        ip protocol icmp accept
        meta l4proto ipv6-icmp accept
        iifname "wlan0" udp sport 67 udp dport 68 accept
        iifname "wlan0" udp sport 547 udp dport 546 accept
        iifname "wlan0" tcp dport 22 accept
        iifname "wlan0" udp dport 5353 accept
        iifname "eth0" udp dport { 53, 67 } accept
        iifname "eth0" tcp dport 53 accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state invalid drop
        iifname "eth0" ip daddr @blocked_v4 counter drop
        oifname "eth0" ip saddr @blocked_v4 counter drop
        iifname "wlan0" oifname "eth0" ip saddr HOME_SUBNET ip daddr TV_SUBNET counter accept
        iifname "eth0" oifname "wlan0" ip saddr TV_SUBNET ip daddr HOME_SUBNET counter accept
        iifname "eth0" oifname "wlan0" ip saddr TV_SUBNET ip daddr . tcp dport @tv_wan_allow_tcp counter accept
        iifname "eth0" oifname "wlan0" ip saddr TV_SUBNET ip daddr . udp dport @tv_wan_allow_udp counter accept
        iifname "eth0" oifname "wlan0" ip saddr TV_SUBNET limit rate 10/minute burst 20 packets log prefix "glass-tv-egress-deny " counter
        iifname "eth0" oifname "wlan0" ip saddr TV_SUBNET counter drop comment "TV public egress default deny"
        iifname "eth0" oifname "wlan0" meta nfproto ipv4 counter accept
        iifname "wlan0" oifname "eth0" meta nfproto ipv4 ct state established,related counter accept
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "wlan0" ip saddr TV_SUBNET masquerade
    }
}
'''))
    write('/etc/systemd/system/NetworkManager.service.d/glass-firewall.conf', '[Unit]\nRequires=nftables.service\nAfter=nftables.service\n')
    write('/etc/systemd/system/glass-capture.service', '''[Unit]
Description=Bounded TV Ethernet packet capture (16 x 16 MB)
After=NetworkManager.service

[Service]
Type=simple
ExecStart=/usr/bin/tcpdump -i eth0 -nn -s 0 -U -C 16 -W 16 -w /var/log/glass-probe/traffic.pcap -Z root
Restart=on-failure
RestartSec=5
UMask=0077
LogsDirectory=glass-probe
LogsDirectoryMode=0700
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID
ReadWritePaths=/var/log/glass-probe

[Install]
WantedBy=multi-user.target
''')
    write('/etc/systemd/journald.conf.d/glass-probe.conf', '[Journal]\nStorage=persistent\nSystemMaxUse=100M\nRuntimeMaxUse=32M\n')
    write('/etc/avahi/avahi-daemon.conf', '[server]\nhost-name=' + hostname + '\nallow-interfaces=wlan0\n[publish]\npublish-workstation=yes\n[reflector]\nenable-reflector=no\n')
    run('systemctl', 'enable', 'ssh', 'regenerate_ssh_host_keys', 'NetworkManager', 'avahi-daemon', 'nftables', 'dnsmasq', 'glass-radio', 'glass-capture')
    run('systemctl', 'disable', 'apt-daily.timer', 'apt-daily-upgrade.timer')
    # Retain the Pi's stock kernel, overlays and firmware for later display work.
    for filename in ('user-data', 'network-config', 'meta-data'):
        write('/boot/firmware/' + filename, '# Configured offline by glass-probe. Cloud-init is disabled.\n')
    write('/etc/motd', network_values('''glass-probe: TV Ethernet -> Wi-Fi gateway
TV subnet: TV_SUBNET; gateway/DNS: TV_GATEWAY
Observation mode: IPv4 forwarded; TV IPv6 forwarding disabled.
Capture: sudo systemctl status glass-capture
Status: sudo glass-probe-status
Guide: /opt/glass-probe/README.md
'''))
    run('dnsmasq', '--test', '--conf-dir=/etc/dnsmasq.d')
    run('visudo', '-c')
    shutil.rmtree('/var/lib/cloud', ignore_errors=True)
    pathlib.Path(sys.argv[1]).unlink()
    pathlib.Path('/root/glass-probe-image-build').unlink()
    print('Offline system configuration complete (no credentials printed).')


if __name__ == '__main__':
    main()
