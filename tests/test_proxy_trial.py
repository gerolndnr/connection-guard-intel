import base64
import ipaddress
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from intel import proxy_trial as trial
from intel.model import Entry, PROXY
from intel.sources import PROXY_SOURCES


def network(text):
    return ipaddress.ip_network(text)


def measurement(endpoint, **kwargs):
    return dict(proxy=endpoint, protocols=['http'], latency_ms=200, uptime_24h=1) | kwargs


class MeasuredProxies(unittest.TestCase):
    def test_measured_candidates_must_be_global_exact_addresses(self):
        data = [
            measurement('8.8.8.8:80'), measurement('8.8.8.8:8080'),
            measurement('[::ffff:8.8.8.8]:443'), measurement('[2606:4700::1]:443'),
            measurement('8.8.8.9:80', latency_ms=0), measurement('8.8.8.10:80', latency_ms=True),
            measurement('8.8.8.11:80', uptime_24h=101), measurement('8.8.8.12:80', uptime_24h=0),
            measurement('8.8.8.13:80', protocols=['vless']), measurement('8.8.8.14:80', protocols=[]),
            measurement('9.9.9.1:65536'), measurement('9.9.9.2:0'), measurement('9.9.9.3/24:80'),
            measurement('10.0.0.1:80'), measurement('224.0.0.1:80'), measurement('user@9.9.9.4:80'),
        ]
        self.assertEqual(trial.measured_proxies(json.dumps(data)),
                         {(network('8.8.8.8'), 80), (network('8.8.8.8'), 8080), (network('8.8.8.8'), 443),
                          (network('2606:4700::1'), 443)})
        with self.assertRaises(ValueError):
            trial.measured_proxies('{"data":[]}')

    def test_corroboration_is_per_group_and_protects_operators_existing_lists(self):
        endpoints = [network(f'8.8.8.{n}') for n in range(1, 7)] + [network('2606:4700::1')]
        entries = [Entry(n, PROXY, 'other', 'exact') for n in endpoints[:5] + endpoints[-1:]]
        entries.append(Entry(endpoints[5], PROXY, 'mirror', 'exact'))
        added = trial.additions(set(endpoints), entries, {'other': 'other', 'mirror': trial.TRIAL_GROUP},
                                [endpoints[0]], [network('8.8.8.2/31'), endpoints[4]])
        self.assertEqual(added, {endpoints[3], endpoints[-1]})
        self.assertEqual(trial.additions(set(endpoints), [], {}, [], []), set())


class TrialBundle(unittest.TestCase):
    def prepare(self, root):
        baseline, inputs, out = (root / name for name in ('baseline', 'inputs', 'candidate'))
        baseline.mkdir()
        (inputs / 'existing').mkdir(parents=True)
        key = ec.generate_private_key(ec.SECP256R1())
        self.seed = dict(VPN=b'1.1.1.1\n', TOR=b'', RELAY=b'104.28.0.0/16\n', HOSTING=b'',
                         PROXY=b'8.8.8.8\n', BOOSTER=b'9.9.9.9\n', MOBILE=b'8.8.4.4\n')
        primary, extra = {}, {}
        for kind, body in self.seed.items():
            name = f'{kind.lower()}.txt'
            (baseline / name).write_bytes(body)
            meta = dict(file=name, bytes=len(body), sha256=trial.sha(body))
            (primary if kind in trial.CATEGORIES else extra)[kind] = meta
        manifest = dict(schema=1, as_of='2026-11-22T20:20:54Z', evaluation_only=False,
                        lists=primary, additional_lists=extra, sources=[])
        data = json.dumps(manifest).encode()
        (baseline / 'manifest.json').write_bytes(data)
        sig = key.sign(data, ec.ECDSA(hashes.SHA256()))
        (baseline / 'manifest.json.sig').write_bytes(base64.b64encode(sig))
        self.source = next(s for s in PROXY_SOURCES if s.id == 'proxy-jetkai')
        body = b'8.8.8.9:8080\n8.8.4.4:80\n9.9.9.9:443\n104.28.10.10:80\n'
        (inputs / 'existing' / self.source.id).write_bytes(body)
        observations = [measurement(f'{ip}:80') for ip in ('8.8.8.9', '8.8.4.4', '9.9.9.9', '104.28.10.10', '8.8.8.10')]
        check = json.dumps(observations).encode()
        (inputs / 'confirmation.json').write_bytes(check)
        self.receipts = dict(
            confirmation=self.receipt(trial.TRIAL_REF, 'main', check),
            sources=[dict(id=self.source.id, **self.receipt(self.source.url, 'main', body))])
        self.write_receipts(inputs)
        return baseline, inputs, out, key.public_key()

    def receipt(self, url, branch, body):
        return dict(url=url.replace(f'/{branch}/', '/' + 'f' * 40 + '/'),
                    committed_at='2026-11-22T19:20:54Z', sha256=trial.sha(body))

    def write_receipts(self, inputs):
        (inputs / 'receipts.json').write_text(json.dumps(self.receipts))

    def test_end_to_end_keeps_the_signed_baseline_unchanged_and_candidate_unsigned(self):
        with tempfile.TemporaryDirectory() as temp:
            baseline, inputs, out, key = self.prepare(Path(temp))
            candidate = trial.build_trial(baseline, inputs, out, key)
            self.assertTrue(candidate['evaluation_only'])
            self.assertNotIn(trial.TRIAL_ID, {s.id for s in PROXY_SOURCES})
            self.assertFalse((out / 'manifest.json.sig').exists())
            self.assertEqual(candidate['proxy_trial']['added'], 1)
            self.assertEqual(candidate['proxy_trial']['confirmed'], 5)
            self.assertEqual(trial.load_networks((out / 'proxy.txt').read_bytes()), [network('8.8.8.8/31')])
            for kind, body in self.seed.items():
                self.assertEqual((baseline / f'{kind.lower()}.txt').read_bytes(), body)
                if kind != PROXY:
                    self.assertEqual((out / f'{kind.lower()}.txt').read_bytes(), body)
            with self.assertRaises(FileExistsError):
                trial.build_trial(baseline, inputs, out, key)

    def test_rejects_future_stale_wrong_origin_and_changed_input(self):
        cases = {
            'future': {'committed_at': '2026-11-22T20:20:55Z'},
            'stale': {'committed_at': '2026-11-22T14:20:53Z'},
            'branch_not_commit': {'url': trial.TRIAL_REF},
            'other_host': {'url': 'https://example.org/data'},
            'body_not_matching_receipt': {'sha256': '0' * 64},
        }
        for case, changes in cases.items():
            with self.subTest(case), tempfile.TemporaryDirectory() as temp:
                baseline, inputs, out, key = self.prepare(Path(temp))
                self.receipts['confirmation'].update(changes)
                self.write_receipts(inputs)
                with self.assertRaises(ValueError):
                    trial.build_trial(baseline, inputs, out, key)
                self.assertFalse(out.exists())

    def test_proxio_requires_a_fresh_success_at_the_same_endpoint_as_the_primary(self):
        with tempfile.TemporaryDirectory() as temp:
            baseline, inputs, out, key = self.prepare(Path(temp))
            observations = [
                measurement('8.8.8.10:443'), measurement('8.8.8.11:443'), measurement('8.8.8.12:443'),
                measurement('8.8.8.13:443'), measurement('8.8.8.14:443'),
            ]
            body = json.dumps(observations).encode()
            (inputs / 'confirmation.json').write_bytes(body)
            self.receipts['confirmation'] = self.receipt(trial.TRIAL_REF, 'main', body)
            fields = dict(protocols=['CONNECT25'], port=443, fail_streak=0, last_results='1101',
                          last_checked='2026-11-22T16:00:00')
            rows = [
                fields | {'ip': '8.8.8.10'},
                fields | {'ip': '8.8.8.11', 'port': 8080},
                fields | {'ip': '8.8.8.12', 'last_checked': '2026-11-21T20:20:53Z'},
                fields | {'ip': '8.8.8.13', 'last_results': '1100'},
                fields | {'ip': '8.8.8.14', 'last_checked': '2026-11-22T19:00:01Z'},
                fields | {'ip': '8.8.8.15'},
            ]
            body = json.dumps(dict(source='https://proxio.io', updated_at='2026-11-22T19:00:00Z',
                                   proxies=rows, count=len(rows))).encode()
            (inputs / 'proxio.json').write_bytes(body)
            self.receipts['secondary'] = self.receipt(trial.SECONDARY_REF, 'main', body)
            self.write_receipts(inputs)
            result = trial.build_trial(baseline, inputs, out, key)
            self.assertEqual(result['proxy_trial']['same_endpoint_confirmations'], 1)
            self.assertEqual(result['proxy_trial']['added'], 1)
            self.assertEqual(trial.load_networks((out / 'proxy.txt').read_bytes()),
                             [network('8.8.8.8'), network('8.8.8.10')])

    def test_rejects_forged_manifest_and_mismatched_signed_list(self):
        with tempfile.TemporaryDirectory() as temp:
            baseline, inputs, out, key = self.prepare(Path(temp))
            (baseline / 'proxy.txt').write_bytes(b'8.8.8.9\n')
            with self.assertRaisesRegex(ValueError, 'signed baseline mismatch'):
                trial.build_trial(baseline, inputs, out, key)
            path = baseline / 'manifest.json'
            path.write_bytes(path.read_bytes() + b' ')
            with self.assertRaises(InvalidSignature):
                trial.build_trial(baseline, inputs, out, key)

    def test_rejects_unknown_or_duplicate_voting_source(self):
        for variant in ('unknown', 'duplicate'):
            with self.subTest(variant), tempfile.TemporaryDirectory() as temp:
                baseline, inputs, out, key = self.prepare(Path(temp))
                if variant == 'unknown':
                    self.receipts['sources'][0]['id'] = 'proxy-benchmark-label'
                else:
                    self.receipts['sources'] *= 2
                self.write_receipts(inputs)
                with self.assertRaisesRegex(ValueError, 'unexpected or duplicate'):
                    trial.build_trial(baseline, inputs, out, key)


if __name__ == '__main__':
    unittest.main()
