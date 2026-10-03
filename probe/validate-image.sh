#!/bin/bash
set -euo pipefail
image=$(realpath "$1")
source_dir=$(realpath "$2")
[[ -f "$image" && "$image" == *.img && "$image" != /dev/* ]] || exit 1
root=$(mktemp -d /var/tmp/glass-validate.XXXXXX)
loop=$(losetup --find --show --partscan "$image")
cleanup() {
    mountpoint -q "$root/proc" && umount "$root/proc" || true
    mountpoint -q "$root/dev" && umount "$root/dev" || true
    mountpoint -q "$root/boot/firmware" && umount "$root/boot/firmware" || true
    mountpoint -q "$root" && umount "$root" || true
    losetup -d "$loop"
    rmdir "$root"
}
trap cleanup EXIT
mount "${loop}p2" "$root"
mount "${loop}p1" "$root/boot/firmware"
mount --bind /dev "$root/dev"
mount -t proc proc "$root/proc"
chroot "$root" dpkg --audit
chroot "$root" dnsmasq --test --conf-dir=/etc/dnsmasq.d
grep '^CONFIG_DIR=' "$root/etc/default/dnsmasq"
chroot "$root" bash -c 'command -v tcpdump iw rfkill; getent passwd; readlink /etc/localtime; cat /etc/default/keyboard; cat /etc/hostname; cat /etc/machine-id; cat /etc/resolv.conf'
chroot "$root" systemctl is-enabled ssh regenerate_ssh_host_keys NetworkManager nftables dnsmasq glass-capture glass-radio avahi-daemon
chroot "$root" systemd-analyze verify glass-capture.service glass-radio.service ssh.service dnsmasq.service nftables.service NetworkManager.service
mkdir -p "$root/run/sshd"
chroot "$root" ssh-keygen -q -t ed25519 -N '' -f /run/sshd/validation-key
chroot "$root" /usr/sbin/sshd -t -h /run/sshd/validation-key
chroot "$root" /usr/sbin/sshd -T -h /run/sshd/validation-key | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers) '
rm "$root/run/sshd/validation-key" "$root/run/sshd/validation-key.pub"
chroot "$root" python3 - <<'PY'
import pathlib, stat, configparser
for name in ('glass-uplink', 'glass-tv'):
    p = pathlib.Path('/etc/NetworkManager/system-connections/' + name + '.nmconnection')
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    config = configparser.ConfigParser()
    config.read(p)
    assert config['connection']['autoconnect'] == 'true'
radio_state = configparser.ConfigParser()
radio_state.read('/var/lib/NetworkManager/NetworkManager.state')
assert radio_state.getboolean('main', 'WirelessEnabled', fallback=False), 'NetworkManager Wi-Fi is disabled in the image'
assert pathlib.Path('/etc/cloud/cloud-init.disabled').exists()
assert pathlib.Path('/etc/systemd/system/userconfig.service').resolve() == pathlib.Path('/dev/null')
assert not pathlib.Path('/root/glass-probe-private.json').exists()
assert not pathlib.Path('/usr/sbin/policy-rc.d').exists()
assert pathlib.Path('/boot/firmware/bcm2711-rpi-4-b.dtb').exists()
assert pathlib.Path('/boot/firmware/kernel8.img').exists()
boot_args = pathlib.Path('/boot/firmware/cmdline.txt').read_text().split()
assert {'video=HDMI-A-1:d', 'video=HDMI-A-2:d'}.issubset(boot_args), 'HDMI outputs must remain disabled'
print('Private-file permissions, first-boot suppression and Pi 4 boot assets verified.')
PY
unshare --net bash "$source_dir/probe/test-gateway.sh" "$root"
df -h "$root"
sync -f "$root"
echo 'Offline image validation passed.'
