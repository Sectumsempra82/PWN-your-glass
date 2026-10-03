#!/bin/bash
# Run as root in Linux/WSL. Never accepts a physical device as its image input.
set -euo pipefail
image=$(realpath "$1")
source_dir=$(realpath "$2")
config=$(realpath "$3")
[[ -f "$image" && "$image" == *.img && "$image" != /dev/* ]] || exit 1
root=$(mktemp -d /var/tmp/glass-image.XXXXXX)
loop=$(losetup --find --show --partscan "$image")
cleanup() {
    if [[ -e "$root/etc/resolv.conf.build-backup" || -L "$root/etc/resolv.conf.build-backup" ]]; then
        rm -f "$root/etc/resolv.conf"
        mv "$root/etc/resolv.conf.build-backup" "$root/etc/resolv.conf"
    fi
    rm -f "$root/usr/sbin/policy-rc.d" "$root/root/glass-probe-private.json"
    mountpoint -q "$root/dev/pts" && umount "$root/dev/pts" || true
    for part in dev proc sys boot/firmware; do
        mountpoint -q "$root/$part" && umount "$root/$part" || true
    done
    mountpoint -q "$root" && umount "$root" || true
    losetup -d "$loop"
    rmdir "$root"
}
trap cleanup EXIT
mount "${loop}p2" "$root"
mount "${loop}p1" "$root/boot/firmware"
mount --bind /dev "$root/dev"
mount -t devpts devpts "$root/dev/pts"
mount -t proc proc "$root/proc"
mount -t sysfs sysfs "$root/sys"
if [[ ! -e "$root/etc/resolv.conf.build-backup" && ! -L "$root/etc/resolv.conf.build-backup" ]]; then
    cp -a "$root/etc/resolv.conf" "$root/etc/resolv.conf.build-backup"
fi
rm "$root/etc/resolv.conf"
cp /etc/resolv.conf "$root/etc/resolv.conf"
printf '#!/bin/sh\nexit 101\n' > "$root/usr/sbin/policy-rc.d"
chmod 755 "$root/usr/sbin/policy-rc.d"
export DEBIAN_FRONTEND=noninteractive
chroot "$root" apt-get update
chroot "$root" apt-get install -y --no-install-recommends \
    openssh-server avahi-daemon network-manager nftables dnsmasq conntrack \
    tcpdump tshark dnsutils curl openssl ca-certificates git python3 python3-venv \
    python3-scapy python3-pytest jq tmux htop iperf3 mtr-tiny traceroute nmap \
    ethtool iw rfkill rsync lsof socat evtest libinput-tools
install -m 600 "$config" "$root/root/glass-probe-private.json"
touch "$root/root/glass-probe-image-build"
install -m 700 "$source_dir/probe/provision.py" "$root/root/provision.py"
chroot "$root" python3 /root/provision.py /root/glass-probe-private.json
install -d "$root/opt/glass-probe" "$root/opt/PWN-your-glass/tests"
install -m 644 "$source_dir/probe/README.md" "$root/opt/glass-probe/README.md"
install -m 755 "$source_dir/probe/glass-probe-status" "$root/usr/local/sbin/glass-probe-status"
install -m 755 "$source_dir/probe/experiment.py" "$root/opt/glass-probe/experiment.py"
install -m 644 "$source_dir/privacy.py" "$source_dir/PRIVACY.md" "$source_dir/README.md" "$root/opt/PWN-your-glass/"
install -m 644 "$source_dir/tests/test_privacy.py" "$root/opt/PWN-your-glass/tests/"
chroot "$root" bash -c 'cd /opt/PWN-your-glass && python3 -m unittest discover -s tests -v'
chroot "$root" dpkg-query -W > "$source_dir/private/probe/packages.tsv"
chroot "$root" apt-get clean
rm "$root/root/provision.py" "$root/usr/sbin/policy-rc.d" "$root/etc/resolv.conf"
mv "$root/etc/resolv.conf.build-backup" "$root/etc/resolv.conf"
sync -f "$root"
echo 'Image package installation and project tests complete.'
