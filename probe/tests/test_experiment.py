import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('experiment', Path(__file__).resolve().parents[1] / 'experiment.py')
e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)


class ExperimentTests(unittest.TestCase):
    def test_missing_packet_counters_remain_unknown(self):
        self.assertIsNone(e.packet_stats('error opening eth0')['dropped'])
        self.assertEqual(e.packet_stats('10 packets captured\n12 packets received by filter\n2 packets dropped by kernel'),
                         {'captured': 10, 'received': 12, 'dropped': 2})

    def test_exact_tuple_and_time_correlation(self):
        flow = {'source': '192.168.88.100', 'source_port': 1234, 'destination': '1.1.1.1', 'destination_port': 443,
                'protocol': 'udp', 'first': 100, 'last': 105}
        owner = {'pid': 12, 'comm': 'app', 'start_ticks': '44'}
        row = {'protocol': 'udp', 'local': {'address': flow['source'], 'port': 1234},
               'remote': {'address': '1.1.1.1', 'port': 443}, 'owners': [owner]}
        observations = {'schema_version': 1, 'command': 'connections', 'samples': [{'timestamp': 102, 'sockets': [row]}]}
        result = e.correlate({'flows': [flow]}, observations)
        self.assertEqual(result['flows'][0]['owners'], [owner])
        row['protocol'] = 'tcp'
        result = e.correlate({'flows': [flow]}, observations)
        self.assertEqual(result['flows'][0]['attribution'], 'unknown')
        row['protocol'] = 'udp'; observations['samples'][0]['timestamp'] = 200
        self.assertEqual(e.correlate({'flows': [flow]}, observations)['flows'][0]['owners'], [])

    def test_enforcement_is_eth0_only_and_does_not_block_https(self):
        rules = e.dns_rules()
        self.assertIn('iifname "eth0"', rules)
        self.assertIn('udp dport 853', rules)
        self.assertNotIn('443', rules)
        self.assertNotIn('wlan0', rules)

    def test_report_missing_capture_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            e.write(path / 'session.json', {'id': 'one', 'scenario': 'idle', 'mode': 'observe',
                                          'upstream_filtering': 'existing Pi-hole', 'status': 'interrupted'})
            result = e.summary(path)
            self.assertEqual(result['status'], 'unknown')
            self.assertEqual(result['flows'], [])

    def test_record_sessions_never_overwrite_previous_capture(self):
        original_read = Path.read_text
        def read(path, *args, **kwargs):
            if str(path) == '/sys/class/net/eth0/carrier': return '1'
            return original_read(path, *args, **kwargs)
        class Capture:
            def __init__(self, args, **kwargs):
                self.args = args; self.returncode = None
                Path(args[args.index('-w') + 1]).write_bytes(b'fixture pcap')
                kwargs['stderr'].write('10 packets captured\n10 packets received by filter\n0 packets dropped by kernel\n')
                kwargs['stderr'].flush()
            def poll(self): return self.returncode
            def send_signal(self, value): self.returncode = 0
            def wait(self, timeout=None): return self.returncode
        state = {'clock': {'returncode': 0, 'stdout': 'NTPSynchronized=yes'}}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(e, 'SESSIONS', Path(tmp)), patch.object(e, 'snapshot', return_value=state), \
                 patch.object(e.os, 'geteuid', return_value=0), patch.object(Path, 'read_text', read), \
                 patch.object(e, 'command', return_value={'returncode': 1}), patch.object(e, 'summary'), \
                 patch.object(e.subprocess, 'Popen', side_effect=Capture) as popen:
                first = e.record(0.01, 'idle', 'existing filtering')
                second = e.record(0.01, 'idle', 'existing filtering')
            self.assertNotEqual(first, second)
            self.assertEqual((first / 'traffic.pcap').read_bytes(), b'fixture pcap')
            self.assertEqual(json.loads((second / 'session.json').read_text())['status'], 'complete')
            self.assertNotIn('-W', popen.call_args.args[0])

    def test_unsynchronized_clock_refuses_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(e, 'SESSIONS', Path(tmp)), patch.object(e.os, 'geteuid', return_value=0), \
                 patch.object(e, 'snapshot', return_value={'clock': {'returncode': 0, 'stdout': 'NTPSynchronized=no'}}), \
                 patch.object(e.subprocess, 'Popen') as popen:
                with self.assertRaisesRegex(RuntimeError, 'Synchronize'):
                    e.record(1, 'idle', 'existing filtering')
                popen.assert_not_called()

    def test_decoder_rows_become_flows_and_domains(self):
        import hashlib
        import io
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); capture = root / 'traffic.pcap'; capture.write_bytes(b'fixture')
            e.write(root / 'session.json', {'id': 'example', 'scenario': 'idle', 'mode': 'observe',
                    'upstream_filtering': 'existing', 'status': 'complete',
                    'files': {'traffic.pcap': hashlib.sha256(b'fixture').hexdigest()}})
            child = Mock()
            child.stdout = io.StringIO('100\t192.168.88.100\t\t1.1.1.1\t\t\t1234\t\t443\tname.example\t\n')
            child.wait.return_value = 0
            with patch.object(e.subprocess, 'Popen', return_value=child):
                report = e.summary(root)
            self.assertEqual(report['flows'][0]['protocol'], 'udp')
            self.assertEqual(report['flows'][0]['source_port'], 1234)
            self.assertEqual(report['domains'], ['name.example'])
            self.assertEqual(report['flows'][0]['attribution'], 'unknown')


if __name__ == '__main__': unittest.main()
