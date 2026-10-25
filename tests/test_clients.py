"""The Python client against a local server with a test key: it must refuse what the plugin refuses."""
import datetime
import hashlib
import http.server
import json
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'clients', 'python'))
import cg_intel  # noqa: E402

from intel import build  # noqa: E402

NOW = datetime.datetime(2026, 10, 25, 12, tzinfo=datetime.timezone.utc)


class Client(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP256R1())
        self.private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        self.public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.files = {}
        files = self.files

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = files.get(self.path.lstrip('/'))
                self.send_response(200 if body is not None else 404)
                self.end_headers()
                if body is not None:
                    self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.host = f'http://127.0.0.1:{self.server.server_address[1]}/'
        self.publish({'VPN': '89.35.28.0/24\n2a0d:5600::/32\n', 'TOR': '185.220.101.1\n', 'RELAY': '', 'HOSTING': '5.0.0.0/16\n'},
                     {'MOBILE': '172.56.0.0/16\n'})

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def publish(self, lists, additional, as_of='2026-10-25T03:17:00Z'):
        manifest = dict(schema=1, as_of=as_of, evaluation_only=False, lists={}, additional_lists={})
        for target, group in (('lists', lists), ('additional_lists', additional)):
            for name, text in group.items():
                body = f'# {name}\n{text}'.encode()
                self.files[name.lower() + '.txt'] = body
                manifest[target][name] = dict(file=name.lower() + '.txt', bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
        raw = json.dumps(manifest).encode()
        self.files['manifest.json'] = raw
        self.files['manifest.json.sig'] = build.sign(raw, self.private).encode()

    def download(self):
        return cg_intel.Intel.download(self.host, self.public, now=NOW)

    def test_lookup_names_categories_and_labels(self):
        intel = self.download()
        self.assertEqual(intel.lookup('89.35.28.7'), dict(categories=['VPN'], labels=[], block=True, as_of='2026-10-25T03:17:00Z'))
        self.assertEqual(intel.lookup('2a0d:5600::1')['categories'], ['VPN'])
        self.assertEqual(intel.lookup('::ffff:185.220.101.1')['categories'], ['TOR'])
        self.assertEqual(intel.lookup('172.56.1.1')['labels'], ['MOBILE'])
        self.assertFalse(intel.lookup('5.0.1.1')['block'])  # hosting is review only
        self.assertEqual(intel.lookup('8.8.8.8')['categories'], [])

    def test_forged_manifest_is_refused(self):
        self.files['manifest.json'] = self.files['manifest.json'].replace(b'89.35', b'89.36') + b' '
        with self.assertRaises(Exception):
            self.download()

    def test_list_that_does_not_match_the_manifest_is_refused(self):
        self.files['vpn.txt'] = self.files['vpn.txt'].replace(b'89.35.28.0/24', b'89.35.29.0/24')
        with self.assertRaises(ValueError):
            self.download()

    def test_stale_lists_are_refused(self):
        self.publish({'VPN': '', 'TOR': '', 'RELAY': '', 'HOSTING': ''}, {}, as_of='2026-10-21T00:00:00Z')
        with self.assertRaises(ValueError):
            self.download()


if __name__ == '__main__':
    unittest.main()
