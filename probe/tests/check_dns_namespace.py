#!/usr/bin/env python3
"""Run only inside `unshare --net`; sends traffic between local veth namespaces."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('experiment', Path(__file__).resolve().parents[1] / 'experiment.py')
e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)

SERVER = '''import socket, threading, time, sys
def serve(port, tcp):
 s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
 s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',port))
 if tcp: s.listen()
 while True:
  if tcp:
   c,a=s.accept(); c.sendall(sys.argv[1].encode()); c.close()
  else:
   data,a=s.recvfrom(1024); s.sendto(sys.argv[1].encode(),a)
for p in (53,853,443):
 for tcp in (False,True): threading.Thread(target=serve,args=(p,tcp),daemon=True).start()
time.sleep(60)
'''
CLIENT = '''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if sys.argv[1]=='tcp' else socket.SOCK_DGRAM)
s.settimeout(1)
try:
 s.connect(('198.18.0.2',int(sys.argv[2])))
 if sys.argv[1]!='tcp': s.send(b'test')
 print(s.recv(1024).decode())
except OSError: sys.exit(2)
'''


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


def main():
    if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
        raise RuntimeError('Refusing to modify the host network; use unshare --net')
    children = []
    try:
        tv = subprocess.Popen(['unshare', '--net', 'sleep', '60']); children.append(tv)
        wan = subprocess.Popen(['unshare', '--net', 'sleep', '60']); children.append(wan)
        time.sleep(0.2)
        run('ip', 'link', 'set', 'lo', 'up')
        for interface, peer, child, local, remote in (
            ('eth0', 'tv0', tv, '192.168.88.1/24', '192.168.88.100/24'),
            ('wlan0', 'wan0', wan, '198.18.0.1/24', '198.18.0.2/24')):
            run('ip', 'link', 'add', interface, 'type', 'veth', 'peer', 'name', peer)
            run('ip', 'link', 'set', peer, 'netns', str(child.pid))
            run('ip', 'addr', 'add', local, 'dev', interface); run('ip', 'link', 'set', interface, 'up')
            prefix = ('nsenter', '-t', str(child.pid), '-n')
            run(*prefix, 'ip', 'link', 'set', 'lo', 'up')
            run(*prefix, 'ip', 'addr', 'add', remote, 'dev', peer)
            run(*prefix, 'ip', 'link', 'set', peer, 'up')
            run(*prefix, 'ip', 'route', 'add', 'default', 'via', local.split('/')[0])
        run('sysctl', '-q', '-w', 'net.ipv4.ip_forward=1')
        for child, label in ((None, 'probe'), (wan, 'upstream')):
            prefix = [] if child is None else ['nsenter', '-t', str(child.pid), '-n']
            server = subprocess.Popen(prefix + [sys.executable, '-c', SERVER, label]); children.append(server)
        time.sleep(0.3)
        def query(protocol, port):
            return subprocess.run(['nsenter', '-t', str(tv.pid), '-n', sys.executable, '-c', CLIENT, protocol, str(port)], capture_output=True, text=True)
        for protocol in ('tcp', 'udp'):
            assert query(protocol, 53).stdout.strip() == 'upstream'
            assert query(protocol, 853).stdout.strip() == 'upstream'
        subprocess.run(['nft', '-c', '-f', '-'], input=e.dns_rules(), text=True, check=True)
        subprocess.run(['nft', '-f', '-'], input=e.dns_rules(), text=True, check=True)
        for protocol in ('tcp', 'udp'):
            assert query(protocol, 53).stdout.strip() == 'probe', protocol + ' DNS was not redirected'
            assert query(protocol, 853).returncode == 2, protocol + ' 853 was not blocked'
            assert query(protocol, 443).stdout.strip() == 'upstream', protocol + ' HTTPS/QUIC was affected'
        run('nft', 'delete', 'table', 'inet', e.TABLE)
        for protocol in ('tcp', 'udp'):
            # Conntrack retains existing NAT; each client uses a fresh source port.
            assert query(protocol, 53).stdout.strip() == 'upstream'
            assert query(protocol, 853).stdout.strip() == 'upstream'
        print('PASS: TCP/UDP DNS redirect, port-853 rejection, HTTPS/QUIC preservation, rollback')
    finally:
        for child in reversed(children):
            child.terminate()
        for child in children:
            child.wait()


if __name__ == '__main__': main()
