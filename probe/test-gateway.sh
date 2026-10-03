#!/bin/bash
# Called inside a fresh network namespace by validate-image.sh.
set -euo pipefail
root=$1
mapfile -t tv_addresses < <(python3 - "$root/etc/NetworkManager/system-connections/glass-tv.nmconnection" <<'PY'
import configparser, ipaddress, sys
config = configparser.ConfigParser()
config.read(sys.argv[1])
interface = ipaddress.ip_interface(config['ipv4']['address1'])
print(interface)
print(interface.network.network_address + 100)
print(interface.network)
print(interface.ip)
PY
)
tv_gateway_cidr=${tv_addresses[0]}
tv_host=${tv_addresses[1]}
tv_subnet=${tv_addresses[2]}
tv_gateway=${tv_addresses[3]}
tv_pid=''
wan_pid=''
dns_pid=''
capture_pid=''
cleanup() {
    for pid in "$capture_pid" "$dns_pid" "$tv_pid" "$wan_pid"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -f "$root/run/gateway-test.pcap" "$root/run/gateway-test.pid" "$root/run/gateway-test.leases"
}
trap cleanup EXIT
unshare --net sleep 120 & tv_pid=$!
unshare --net sleep 120 & wan_pid=$!
sleep 0.3
ip link set lo up
ip link add eth0 type veth peer name tv0
ip link set tv0 netns "$tv_pid"
ip link add wlan0 type veth peer name wan0
ip link set wan0 netns "$wan_pid"
ip addr add "$tv_gateway_cidr" dev eth0
ip addr add 198.18.0.1/24 dev wlan0
ip link set eth0 up
ip link set wlan0 up
nsenter -t "$tv_pid" -n ip link set lo up
nsenter -t "$tv_pid" -n ip addr add "$tv_host/24" dev tv0
nsenter -t "$tv_pid" -n ip link set tv0 up
nsenter -t "$tv_pid" -n ip route add default via "$tv_gateway"
nsenter -t "$wan_pid" -n ip link set lo up
nsenter -t "$wan_pid" -n ip addr add 198.18.0.2/24 dev wan0
nsenter -t "$wan_pid" -n ip link set wan0 up
sysctl -q -w net.ipv4.ip_forward=1
nft -c -f "$root/etc/nftables.conf"
nft -f "$root/etc/nftables.conf"
setpriv --bounding-set=-all,+net_raw,+net_admin,+setuid,+setgid tcpdump -i eth0 -nn -U -w "$root/run/gateway-test.pcap" -Z root & capture_pid=$!
chroot "$root" dnsmasq --conf-dir=/etc/dnsmasq.d --keep-in-foreground --log-dhcp --log-facility=- --pid-file=/run/gateway-test.pid --dhcp-leasefile=/run/gateway-test.leases --address=/probe.test/198.18.0.2 --no-resolv & dns_pid=$!
sleep 1
nsenter -t "$tv_pid" -n ping -c 2 -W 2 198.18.0.2 >/dev/null
echo 'PASS: outbound TV traffic and NAT reply path'
answer=$(nsenter -t "$tv_pid" -n chroot "$root" dig +short +time=2 +tries=1 @"$tv_gateway" probe.test)
[[ "$answer" == 198.18.0.2 ]]
echo 'PASS: TV-side DNS service'
nsenter -t "$tv_pid" -n busybox udhcpc -n -q -t 3 -T 2 -i tv0 -s /bin/true
echo 'PASS: TV-side DHCP lease negotiation'
nft add element inet glass_probe blocked_v4 '{ 198.18.0.2 }'
if nsenter -t "$tv_pid" -n ping -c 1 -W 1 198.18.0.2 >/dev/null; then
    echo 'FAIL: blocked destination still reachable'; exit 1
fi
echo 'PASS: destination blocking'
nft flush set inet glass_probe blocked_v4
nsenter -t "$tv_pid" -n ping -c 1 -W 2 198.18.0.2 >/dev/null
echo 'PASS: connectivity restored after clearing experimental blocks'
nsenter -t "$wan_pid" -n ip route add "$tv_subnet" via 198.18.0.1
if nsenter -t "$wan_pid" -n ping -c 1 -W 1 "$tv_host" >/dev/null; then
    echo 'FAIL: unsolicited inbound forwarding accepted'; exit 1
fi
echo 'PASS: unsolicited inbound forwarding denied'
ip -6 addr add fd77::1/64 dev eth0 nodad
ip -6 addr add fd78::1/64 dev wlan0 nodad
nsenter -t "$tv_pid" -n ip -6 addr add fd77::100/64 dev tv0 nodad
nsenter -t "$tv_pid" -n ip -6 route add default via fd77::1
nsenter -t "$wan_pid" -n ip -6 addr add fd78::2/64 dev wan0 nodad
nsenter -t "$wan_pid" -n ip -6 route add fd77::/64 via fd78::1
sysctl -q -w net.ipv6.conf.all.forwarding=1
if nsenter -t "$tv_pid" -n ping -6 -c 1 -W 1 fd78::2 >/dev/null; then
    echo 'FAIL: IPv6 forwarding escaped the firewall'; exit 1
fi
echo 'PASS: firewall denies IPv6 forwarding even if the sysctl is enabled'
kill -INT "$capture_pid"
wait "$capture_pid"
capture_pid=''
[[ $(stat -c %s "$root/run/gateway-test.pcap") -gt 24 ]]
chroot "$root" tshark -r /run/gateway-test.pcap -c 2 2>/dev/null
echo 'PASS: capture file contains traffic and tshark can read it'
nft list table inet glass_probe
