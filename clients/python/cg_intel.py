"""Connection Guard Intel for Python bots and tools.

Downloads the signed lists from intel.connectionguard.net, verifies the signature and every list's SHA-256, and
answers lookups in memory: the addresses you check never leave your machine.

    from cg_intel import Intel
    intel = Intel.download()                  # once a day is enough; the lists are rebuilt daily
    intel.lookup('203.0.113.7')               # {'categories': ['VPN'], 'labels': [], 'block': True, 'as_of': '...'}

Needs `cryptography` (pip install cryptography). One file, MIT licence; the lists carry their own terms
(github.com/gerolndnr/connection-guard-intel/blob/main/SOURCES.md).
"""
import base64
import bisect
import datetime
import hashlib
import ipaddress
import json
import urllib.request

HOST = 'https://intel.connectionguard.net/'
PUBLIC_KEY = b'''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExDOqYg3Tc2Vu2P/gIiVQw3nbjJOL
/UvLivduLU0PsRqsknUQd682QMgR6FHzPD04tx0xC/QzOCRPacU3vA958Q==
-----END PUBLIC KEY-----
'''
# Categories that mean "not a direct home connection"; RELAY (iCloud Private Relay, WARP) is your choice.
BLOCK = ('VPN', 'TOR', 'PROXY')
MAX_AGE_HOURS = 72
USER_AGENT = 'cg-intel-python/1.0 (+https://github.com/gerolndnr/connection-guard-intel)'


def _get(url, limit):
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read(limit + 1)
    if len(body) > limit:
        raise ValueError(f'{url}: larger than {limit} bytes')
    return body


class _Ranges:
    """Sorted, merged address ranges per family; membership by binary search."""
    def __init__(self, networks):
        self.starts, self.ends = {4: [], 6: []}, {4: [], 6: []}
        networks = list(networks)
        for version in (4, 6):
            for n in ipaddress.collapse_addresses(n for n in networks if n.version == version):
                self.starts[version].append(int(n.network_address))
                self.ends[version].append(int(n.broadcast_address))

    def __contains__(self, address):
        value, starts = int(address), self.starts[address.version]
        i = bisect.bisect_right(starts, value) - 1
        return i >= 0 and value <= self.ends[address.version][i]

    def __len__(self):
        return len(self.starts[4]) + len(self.starts[6])


class Intel:
    def __init__(self, manifest, lists):
        self.as_of = manifest['as_of']
        self.lists = lists

    @classmethod
    def download(cls, host=HOST, public_key=PUBLIC_KEY, now=None):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        raw = _get(host + 'manifest.json', 65536)
        signature = base64.b64decode(_get(host + 'manifest.json.sig', 256).strip())
        serialization.load_pem_public_key(public_key).verify(signature, raw, ec.ECDSA(hashes.SHA256()))  # raises if forged
        manifest = json.loads(raw)
        if manifest.get('evaluation_only'):
            raise ValueError('evaluation-only build')
        as_of = datetime.datetime.fromisoformat(manifest['as_of'].replace('Z', '+00:00'))
        now = now or datetime.datetime.now(datetime.timezone.utc)
        if now - as_of > datetime.timedelta(hours=MAX_AGE_HOURS):
            raise ValueError(f'lists are older than {MAX_AGE_HOURS} hours ({manifest["as_of"]})')
        lists = {}
        for name, meta in {**manifest['lists'], **manifest.get('additional_lists', {})}.items():
            if meta['file'] != name.lower() + '.txt':
                raise ValueError(f'unexpected file name {meta["file"]}')
            body = _get(host + meta['file'], meta['bytes'])
            if hashlib.sha256(body).hexdigest() != meta['sha256']:
                raise ValueError(f'{meta["file"]}: hash does not match the signed manifest')
            lines = (l.strip() for l in body.decode().splitlines())
            lists[name] = _Ranges(ipaddress.ip_network(l, strict=False) for l in lines if l and not l.startswith('#'))
        return cls(manifest, lists)

    def lookup(self, ip):
        """Categories (VPN, TOR, PROXY, RELAY, HOSTING) and labels (BOOSTER, MOBILE, SHARED) of an address.

        An address on no list is unknown, not clean. HOSTING is a data centre: worth a look, not a verdict."""
        address = ipaddress.ip_address(ip)
        if address.version == 6 and address.ipv4_mapped:  # ::ffff:a.b.c.d from dual-stack proxies
            address = address.ipv4_mapped
        found = sorted(name for name, ranges in self.lists.items() if address in ranges)
        labels = [f for f in found if f in ('BOOSTER', 'MOBILE', 'SHARED')]
        categories = [f for f in found if f not in labels]
        return dict(categories=categories, labels=labels, block=any(c in BLOCK for c in categories), as_of=self.as_of)


if __name__ == '__main__':
    import sys
    intel = Intel.download()
    for arg in sys.argv[1:]:
        print(arg, intel.lookup(arg))
