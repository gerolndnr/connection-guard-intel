"""Offline tests: parsers on recorded formats (documentation addresses), classification rules, build guards, signing."""
import base64
import datetime
import io
import ipaddress
import json
import os
import tempfile
import unittest
import zipfile

from intel import build, sources
from intel.model import HOSTING, RELAY, TOR, VPN, Entry, net


def nets(entries):
    return sorted(str(e.network) for e in entries)


class Parsers(unittest.TestCase):
    def test_tor_and_icloud(self):
        # Documentation and private ranges are not global and never listed; public exit addresses are.
        self.assertEqual(nets(sources.parse_tor(b'192.0.2.1\n# comment\n10.0.0.1\n')), [])
        self.assertEqual(nets(sources.parse_tor(b'185.220.101.1\n171.25.193.25\n')), ['171.25.193.25/32', '185.220.101.1/32'])
        relay = sources.parse_icloud(b'172.224.226.0/27,GB,GB-EN,London,\n2a02:26f7:b3c0:4000::/64,DE,DE-BE,Berlin,\n')
        self.assertEqual({e.category for e in relay}, {RELAY})
        self.assertEqual(len(relay), 2)

    def test_clouds_and_geofeeds(self):
        aws = json.dumps({'prefixes': [{'ip_prefix': '3.5.140.0/22'}], 'ipv6_prefixes': [{'ipv6_prefix': '2600:1f14::/35'}]}).encode()
        self.assertEqual(nets(sources.parse_aws(aws)), ['2600:1f14::/35', '3.5.140.0/22'])
        gcp = json.dumps({'prefixes': [{'ipv4Prefix': '34.80.0.0/15'}, {'ipv6Prefix': '2600:1900::/35'}]}).encode()
        self.assertEqual(len(sources.parse_gcp(gcp)), 2)
        oracle = json.dumps({'regions': [{'cidrs': [{'cidr': '129.146.0.0/21'}]}]}).encode()
        self.assertEqual(nets(sources.parse_oracle(oracle)), ['129.146.0.0/21'])
        feed = b'# geofeed\n5.101.96.0/21,NL,NL-NH,Amsterdam,1098 XH\n'
        self.assertEqual(nets(sources.parse_geofeed('digitalocean')(feed)), ['5.101.96.0/21'])
        ripe = json.dumps({'data': {'prefixes': [{'prefix': '5.9.0.0/16'}, {'prefix': '2a01:4f8::/32'}]}}).encode()
        self.assertEqual({e.category for e in sources.parse_ripestat('asn-24940')(ripe)}, {HOSTING})

    def test_vpn_operators(self):
        mullvad = json.dumps([{'active': True, 'ipv4_addr_in': '185.65.134.66', 'ipv6_addr_in': '2a03:1b20:4:f011::a01f'},
                              {'active': False, 'ipv4_addr_in': '185.65.134.67'}]).encode()
        got = sources.parse_mullvad(mullvad)
        self.assertEqual(nets(got), ['185.65.134.66/32', '2a03:1b20:4:f011::/64'])
        self.assertEqual({e.method for e in got}, {'exact', 'v6-subnet'})
        nord = json.dumps([{'station': '89.35.28.131', 'ipv6_station': ''}]).encode()
        self.assertEqual(nets(sources.parse_nordvpn(nord)), ['89.35.28.131/32'])
        ivpn = json.dumps({'wireguard': [{'hosts': [{'host': '185.102.219.26', 'ipv6': {'host': '2a07:b944::2:2'}}]}], 'openvpn': []}).encode()
        self.assertEqual(len(sources.parse_ivpn(ivpn)), 2)
        pia = (json.dumps({'regions': [{'servers': {'wg': [{'ip': '158.173.25.177'}], 'meta': [{'ip': '158.173.25.2'}]}}]}) + '\n\nsignature').encode()
        self.assertEqual(nets(sources.parse_pia(pia)), ['158.173.25.177/32', '158.173.25.2/32'])
        surf = json.dumps([{'connectionName': 'al-tia.prod.surfshark.com'}]).encode()
        self.assertEqual(nets(sources.parse_surfshark(surf, resolve=lambda hosts: ['31.171.154.10'])), ['31.171.154.10/32'])
        operator = json.dumps({'data': {'prefixes': [{'prefix': '146.70.0.0/16'}]}}).encode()
        self.assertEqual([(e.category, e.method) for e in sources.parse_operator_asn('operator-asn-1')(operator)], [(VPN, 'operator-asn')])

    def test_new_operator_lists(self):
        air = json.dumps({'servers': [{'ip_v4_in1': '185.65.134.66', 'ip_v4_in2': '185.65.134.67', 'ip_v6_in1': '2a03:1b20:4:f011::a01f', 'ip_v4_in3': ''}]}).encode()
        self.assertEqual(nets(sources.parse_airvpn(air)), ['185.65.134.66/32', '185.65.134.67/32', '2a03:1b20:4:f011::/64'])
        ws = json.dumps({'data': [{'groups': [{'nodes': [{'ip': '89.35.28.131', 'ip2': '89.35.28.132', 'ip3': '89.35.28.133'}]}]}, {'groups': None}]}).encode()
        self.assertEqual(len(sources.parse_windscribe(ws)), 3)
        ov = json.dumps({'datacenters': [{'servers': [{'ip': '37.120.212.227'}]}]}).encode()
        self.assertEqual(nets(sources.parse_ovpn(ov)), ['37.120.212.227/32'])
        az = json.dumps({'locations': [{'pool': 'ar-bue.azirevpn.net'}]}).encode()
        self.assertEqual(nets(sources.parse_azirevpn(az, resolve=lambda hosts: ['45.9.249.10'] if hosts == ['ar-bue.azirevpn.net'] else [])), ['45.9.249.10/32'])
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('a.ovpn', 'client\nremote acc-c01.ipvanish.com 443\n')
            z.writestr('b.ovpn', 'remote 185.65.134.70 1194\n')
        parsed = sources.openvpn_zip('ipvanish', resolve=lambda hosts: ['89.35.28.140'] if hosts == ['acc-c01.ipvanish.com'] else [])(buf.getvalue())
        self.assertEqual(nets(parsed), ['185.65.134.70/32', '89.35.28.140/32'])
        page = b'<td>ae-dub.pvdata.host</td><td>evil.example.com</td>'
        self.assertEqual(nets(sources.page_hosts('privatevpn', r'[a-z0-9-]+\.pvdata\.host', resolve=lambda hosts: ['91.90.120.5'] if hosts == ['ae-dub.pvdata.host'] else [])(page)), ['91.90.120.5/32'])

    def test_private_and_special_addresses_are_never_listed(self):
        for text in ('10.1.2.3', '192.168.0.1', '127.0.0.1', '::1', 'fe80::1', '224.0.0.1', 'not-an-ip'):
            self.assertIsNone(net(text), text)


class Rules(unittest.TestCase):
    def e(self, text, category=VPN, source='op', method='exact'):
        return Entry(ipaddress.ip_network(text), category, source, method)

    def test_a_24_is_inferred_from_a_published_server_only_inside_hosting(self):
        hosting = self.e('31.171.152.0/22', HOSTING, 'asn-x', 'prefix')
        one = [self.e('31.171.154.10/32')]
        self.assertEqual([str(x.network) for x in build.infer_vpn_prefixes(one + [hosting])], ['31.171.154.0/24'])
        self.assertEqual(build.infer_vpn_prefixes(one), [])                       # never outside a hosting range
        two_ops = [self.e('31.171.154.10/32', source='a'), self.e('31.171.154.20/32', source='b')]
        self.assertEqual([x.source for x in build.infer_vpn_prefixes(two_ops + [hosting])], ['several-operators'])

    def test_a_22_needs_two_vpn_24s_inside_hosting(self):
        hosting = self.e('31.171.152.0/22', HOSTING, 'asn-x', 'prefix')
        two = [self.e('31.171.153.10/32'), self.e('31.171.154.10/32')]
        got = sorted(str(x.network) for x in build.infer_vpn_prefixes(two + [hosting]))
        self.assertEqual(got, ['31.171.152.0/22', '31.171.153.0/24', '31.171.154.0/24'])
        self.assertNotIn('31.171.152.0/22', [str(x.network) for x in build.infer_vpn_prefixes(two[:1] + [hosting])])

    def test_dense_hosting_marks_a_whole_asn_only_with_enough_operators_and_never_an_excluded_one(self):
        net_a, net_b = self.e('5.0.0.0/16', HOSTING, 'asn-100', 'prefix'), self.e('6.0.0.0/16', HOSTING, 'asn-100', 'prefix')
        servers = [self.e('5.0.1.1/32', source='a'), self.e('5.0.2.1/32', source='b'), self.e('6.0.3.1/32', source='c')]
        got, dense = build.dense_hosting(servers + [net_a, net_b], min_operators=3, exclude=set())
        self.assertEqual(dense, {100: ['a', 'b', 'c']})
        self.assertEqual(sorted(str(x.network) for x in got), ['5.0.0.0/16', '6.0.0.0/16'])
        self.assertEqual(build.dense_hosting(servers + [net_a, net_b], min_operators=4, exclude=set())[0], [])
        self.assertEqual(build.dense_hosting(servers + [net_a, net_b], min_operators=3, exclude={100})[0], [])
        self.assertEqual(build.dense_hosting(servers + [net_a, net_b], min_operators=None)[0], [])

    def test_lists_collapse_per_category(self):
        result = build.lists([self.e('185.220.101.0/32', TOR, 'tor'), self.e('185.220.101.1/32', TOR, 'tor')])
        self.assertEqual([str(n) for n in result[TOR]], ['185.220.101.0/31'])

    def test_history_keeps_rotated_addresses_for_14_days(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'h.json')
            t0 = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc)
            build.with_history([self.e('185.65.134.66/32')], path, t0)
            later, kept = build.with_history([], path, t0 + datetime.timedelta(days=13))
            self.assertEqual((nets(later), kept), (['185.65.134.66/32'], 1))
            gone, kept = build.with_history([], path, t0 + datetime.timedelta(days=15))
            self.assertEqual((gone, kept), ([], 0))


class Guards(unittest.TestCase):
    def test_shrink_alarm(self):
        previous = {'lists': {VPN: {'networks': 1000}}}
        with self.assertRaises(SystemExit):
            build.check_shrink(previous, {VPN: 700}, force=False)
        self.assertEqual(build.check_shrink(previous, {VPN: 700}, force=True), ['VPN: 1000 -> 700 networks'])
        self.assertEqual(build.check_shrink(previous, {VPN: 900}, force=False), [])

    def test_render_is_the_plugin_list_format(self):
        body = build.render(TOR, [ipaddress.ip_network('185.220.101.1/32'), ipaddress.ip_network('185.220.100.0/24')],
                            [dict(category=TOR, status='ok', id='tor', url='u', terms='t')], '2026-10-06T00:00:00Z').decode()
        data = [l for l in body.splitlines() if l and not l.startswith('#')]
        self.assertEqual(data, ['185.220.101.1', '185.220.100.0/24'])

    def test_signature_verifies_with_the_public_key(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        sig = build.sign(b'manifest', pem)
        key.public_key().verify(base64.b64decode(sig), b'manifest', ec.ECDSA(hashes.SHA256()))
        with self.assertRaises(Exception):
            key.public_key().verify(base64.b64decode(sig), b'tampered', ec.ECDSA(hashes.SHA256()))

    def test_build_end_to_end_offline(self):
        src = [sources.Source('tor', TOR, 'mem://tor', lambda b: sources.parse_tor(b'185.220.101.1\n'), 't', True),
               sources.Source('hidden', VPN, 'mem://x', lambda b: sources.vpn(['89.35.28.131'], 'hidden'), 't', False)]
        orig = build.fetch
        build.fetch = lambda url, headers=None: b''
        try:
            with tempfile.TemporaryDirectory() as d:
                m = build.build(os.path.join(d, 'dist'), sources=src, state=os.path.join(d, 'state'))
                self.assertEqual(m['lists'][TOR]['networks'], 1)
                self.assertEqual(m['lists'][VPN]['networks'], 0)  # not cleared for redistribution
                self.assertFalse(os.path.exists(os.path.join(d, 'dist', 'vpn-history.json')))
        finally:
            build.fetch = orig


if __name__ == '__main__':
    unittest.main()
