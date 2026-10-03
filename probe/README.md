# Glass probe

Headless Raspberry Pi 4B traffic-observation gateway for PWN-your-glass.
The TV privacy installer remains unchanged and is never run automatically.

## Network and access

- Connect TV Ethernet directly to the Pi Ethernet port. Disable TV Wi-Fi.
- Pi Wi-Fi joins the configured home network; SSH is available on that side.
- TV uses the private `/24` subnet and gateway selected in the private build configuration.
- IPv4 forwarding/NAT starts automatically. TV public egress is default-denied;
  only the configured home LAN and explicitly added TCP/UDP endpoint tuples
  are forwarded. The public allowlist sets start empty. Rate-limited kernel logs
  record denied TV egress for review.
- LAN access is a trust boundary: a LAN host can relay traffic for the TV through
  its own internet connection, which this gateway cannot see as TV-originated
  WAN traffic. Do not advertise or trust a LAN proxy/WPAD service unless its
  destinations are independently constrained. A `wpad` DNS lookup alone does
  not prove the TV downloaded or used a proxy configuration.
- Pi IPv6 forwarding is disabled. Public egress filtering is enforced on the routed IPv4
  path; keep TV Wi-Fi disconnected so it cannot bypass the Pi.
- The routed subnet changes discovery behavior: casting and multicast discovery
  across the home network may not work. No multicast reflector is enabled. Home
  hosts also need a route to the configured TV subnet; multicast discovery needs a
  reflector or a same-subnet design.
- DNS uses the upstream network's resolvers. Existing upstream filtering remains
  part of the experiment and must be recorded in baseline results.
- Plain DNS is offered, not forcibly intercepted. DoH/DoT and TLS payloads remain
  encrypted; packet capture alone cannot establish what those payloads contain.

The hostname and username come from the private build configuration. Root SSH login
is disabled. Verify the Pi's SSH host key before administration. No account password, Wi-Fi secret, private SSH key
or GitHub credential belongs in this directory or on the boot FAT partition.

```powershell
ssh -i "PATH-TO-YOUR-KEY" USERNAME@HOSTNAME.local
```

If `.local` resolution fails, use the Pi's Wi-Fi DHCP address from the router.
An earlier image build could retain NetworkManager's
`WirelessEnabled=false` state. Credentials were present, but the saved radio
setting could switch Wi-Fi off again after the early unblock service. The build
now explicitly enables this state, and image validation rejects disabled Wi-Fi.
On an affected Pi, log in using a local HDMI/keyboard console and run:

```sh
sudo nmcli radio wifi on
sudo nmcli connection up glass-uplink
hostname -I
```

This preserves the existing credentials and persists the enabled radio setting.
For an affected card without console access, `wifi_repair.py` can be placed on the
boot partition as `glass-wifi-repair.py` and invoked once with systemd's kernel
command-line generator. Back up the current boot files first: first boot changes
the partition UUID, so never restore a command line copied from the original
image. The repair preserves that UUID, enables the saved radio state, removes
only its own boot arguments, and leaves a result JSON on the boot partition.
Existing affected image files retain the defect; rebuild using the
corrected provisioner or apply the repair before reusing that image.

The TV-facing Ethernet port runs its own DHCP server: do not attach that port to
the household router/switch as a recovery shortcut.

Boot once with a reliable Pi 4 supply, allow several minutes for filesystem growth
and SSH host-key generation, then check:

```sh
sudo glass-probe-status
iw reg get
timedatectl
sudo journalctl -u glass-radio -u NetworkManager -b --no-pager
```

## Observation and blocking

`glass-capture.service` starts at boot and captures eth0 in both directions.
It retains 16 files of approximately 16 MB each, reusing the oldest slots.
The current ring is reused on restart; export evidence before reboot experiments.
Captures under `/var/log/glass-probe` are root-only, with full packet contents.
System journal storage is capped at 100 MB. SSH administration traffic on wlan0
is not part of the Ethernet capture. Wi-Fi loss does not create another TV route.

```sh
sudo systemctl stop glass-capture
sudo tar -C /var/log -czf /home/USERNAME/tv-captures.tar.gz glass-probe
sudo chown USERNAME:USERNAME /home/USERNAME/tv-captures.tar.gz
sudo chmod 600 /home/USERNAME/tv-captures.tar.gz
sudo systemctl start glass-capture
sudo tshark -r /var/log/glass-probe/traffic.pcap00 -q -z conv,ip
```

Use the actual capture filename shown by `sudo ls /var/log/glass-probe`.
Additional explicit destination blocks apply to existing and new IPv4 flows,
in both directions. The TV's default-deny egress rules run before the broad
forwarding rule and cannot be bypassed by entries in `blocked_v4`:

```sh
sudo nft add element inet glass_probe blocked_v4 '{ 203.0.113.20 }'
sudo nft list table inet glass_probe
sudo nft delete element inet glass_probe blocked_v4 '{ 203.0.113.20 }'
# Clear only experimental blocks:
sudo nft flush set inet glass_probe blocked_v4
```

The default-deny policy and its empty TCP/UDP allowlist are restored from
`/etc/nftables.conf` on reboot. Add only evidence-backed, non-LG endpoint tuples
to both `/etc/nftables.conf` and the live sets. Keep protocol and destination
port narrow; do not allow a shared CDN address across all ports. Example for a
reviewed TCP endpoint:

```sh
sudo nft add element inet glass_probe tv_wan_allow_tcp '{ 203.0.113.20 . 443 }'
```

The equivalent entry must be added to the persistent configuration and reviewed
after monitoring. DNS-based blocking and native IPv6 remain separate controls;
this gateway does not forward IPv6, and TV Wi-Fi must remain off.

## Repeatable experiment sessions

`experiment.py` adds separate private sessions without restarting the existing
background capture service. Copy the script to `/opt/glass-probe/` when updating
an existing probe; future images include it. It is not installed automatically
on an already-running Pi by editing this repository.

```sh
sudo python3 /opt/glass-probe/experiment.py record --seconds 60 \
  --scenario idle --upstream-note 'Existing household Pi-hole filtering retained'
```

Run with the TV on, Ethernet carrier present and Pi NTP synchronized. Sessions
have unique directories under `/var/log/glass-probe/sessions/`; export them before
storage fills. A session stops near 110 MB (up to one polling interval of extra
traffic); capture files rotate without wrapping. The tool reserves space before
starting, refuses further sessions near the 1 GB total budget and never deletes
old evidence automatically. No display is required.

Each session records boot ID, wall/monotonic clocks, routes, DNS, DHCP leases,
firewall/link snapshots and tcpdump loss counters. Unsynchronized startup clocks,
clock jumps, missing counters, packet loss and empty captures prevent a complete
evidence result. Interrupted captures remain available. Do not confuse the
background 256 MB rolling capture with these separately retained sessions.

After an observation baseline, an explicitly selected experiment can redirect
TV IPv4 TCP/UDP port 53 to the Pi resolver and reject forwarded TCP/UDP port 853:

```sh
sudo python3 /opt/glass-probe/experiment.py record --seconds 60 --scenario idle \
  --upstream-note 'Same upstream filtering as baseline' --mode dns-enforced
```

The temporary `inet glass_experiment` nftables table is removed on normal exit,
Ctrl-C or SIGTERM. Power loss resets runtime rules; SIGKILL can leave the table.
New sessions refuse a pre-existing table. Inspect the saved session and
`sudo nft list table inet glass_experiment` before removing only that table with
`sudo nft delete table inet glass_experiment`. Do not flush the probe firewall.
HTTPS/QUIC is not blocked and DoH/ECH remain visibility gaps. This mode does not
install any candidate blocklist or alter household Pi-hole configuration.

```sh
sudo python3 /opt/glass-probe/experiment.py report /var/log/glass-probe/sessions/SESSION
sudo python3 /opt/glass-probe/experiment.py report /var/log/glass-probe/sessions/SESSION \
  --connections /private/tv-connections.json
sudo python3 /opt/glass-probe/experiment.py compare /private/before/report.json /private/after/report.json
```

Connection input is the TV's `privacy.py connections --json` output from the same
window. Establish TV/Pi clock alignment before correlating. Exact endpoint tuples,
protocol and sample time are matched, but socket reuse and missed short-lived
connections remain possible. Unconnected UDP or unobserved owners stay unknown.
Analysis requires tshark, already included on the Pi. Logs and reports can contain
device identifiers; keep exports under the repository's ignored `private/` tree.

Local rule integration test (inside a disposable network namespace only):

```sh
sudo unshare --net python3 probe/tests/check_dns_namespace.py
```

This uses synthetic peers and verifies DNS redirection, port-853 rejection,
HTTPS/QUIC preservation and removal of the experimental rules. It is not evidence
of TV compatibility or standalone-TV network enforcement.

## Included tools and project

tcpdump/tshark, nftables/conntrack/dnsmasq, DNS utilities, curl/OpenSSL, nmap,
iperf3, mtr/traceroute, ethtool/iw, Python/venv/Scapy/pytest, Git, jq, tmux,
htop, rsync, socat, lsof, evtest and libinput tools are installed offline.
No desktop or web dashboard is required. Automatic apt timers are disabled to
keep baseline experiments stable; apply updates deliberately between experiments.

The project snapshot is `/opt/PWN-your-glass`. Its installer targets the TV,
not the Pi. Run only the host-side suite on the Pi:

```sh
cd /opt/PWN-your-glass
python3 -m unittest discover -s tests -v
```

## LCD readiness

Stock Raspberry Pi kernels, firmware and device-tree overlays are retained.
For now HDMI outputs and firmware framebuffers are disabled, the boot splash is
off, and DSI display auto-detection is disabled. This does not switch off a HAT
backlight that is wired directly to power; its wiring must be identified first.
Input diagnostic tools are installed. No unverified LCD overlay or vendor kernel
replacement is activated. JRP4.0 display-controller, GPIO wiring and driver
compatibility still require a product reference; XPT2046 identifies touch only.

## Rebuild

Build on Linux/WSL as root with qemu-user/binfmt support for ARM64, xz-utils,
util-linux, e2fsprogs and standard mount tools. Download the official Raspberry Pi
OS Lite ARM64 image and verify its decompressed SHA-256 against the official
Imager catalog. Keep all image/config artifacts in ignored `private/probe`.

`build-image.sh` downloads, verifies and expands a fresh image to 8 GiB before
installation and validation. Supply the selected official Imager catalog entry
as a JSON metadata file. Never pass a physical card to the build scripts.

Create a private JSON containing `hostname`, `username`, `password_hash` (crypt
format), `ssh_public_key`, `wifi_ssid`, `wifi_psk` (64-hex WPA PSK), `country`,
`timezone`, `keyboard`, `tv_subnet` (a private IPv4 `/24`) and `home_subnet`
(a non-overlapping private IPv4 network). This configuration remains sensitive even when hashed.

```sh
bash probe/build-image.sh /absolute/path/PWN-your-glass \
  /absolute/path/source-image.json /absolute/path/private-config.json \
  /var/tmp/glass-probe-new-build
```

Use a fresh verified image: provisioning intentionally refuses an existing user.
Verify package state, firewall/DNS/SSH configuration, service units and project
tests before writing. Re-identify the physical card by size/serial immediately
before flashing. Read back the complete written image and compare SHA-256.
Actual Pi boot, Wi-Fi, DHCP/NAT, capture and LCD tests cannot be proven by chroot.

`validate-image.sh IMAGE REPOSITORY` checks the image and runs an isolated
gateway simulation. That simulation also needs native nftables, tcpdump and
BusyBox on the build host: QEMU user-mode does not support every Netfilter
socket or capture ioctl. DNS/DHCP and capture-file analysis use the image's
ARM64 binaries; firewall and live capture tests use native host binaries.

`flash-card.ps1` performs an elevated Windows write and full readback comparison.
It requires explicit disk number, serial, capacity, boot drive letter, image SHA-256
and output directory. Inspect the card layout before passing these values.
Use `-VerifyOnly` with the same image and device identity to repeat the complete
readback without writing. It expects the prepared two-partition layout and locks
the boot volume during verification. Windows can add `System Volume Information`
when that volume is mounted, changing its raw hash without changing Pi files.
After confirming that cause, `-RepairBoot` restores only the image prefix through
the end of the FAT boot partition and then verifies the entire image with the
volume locked. `-Eject` requests safe removal after successful verification.
