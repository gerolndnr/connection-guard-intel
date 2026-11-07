"""Reverse DNS (PTR) as a false-positive guard: what does the network's own name say about an address?

Consumer ISPs name their customer addresses (`dsl`, `dyn`, `pool`, `cable`, `cust`); data centres name servers
(`server`, `vps`, `baremetal`) or not at all; VPN operators sometimes put their brand in the name. Measured on the
benchmark cohorts (25 Oct 2026), the address spelled out in the name (`unn-149-40-52-40.datapacket.com`) and `static`
appear in data centres and consumer networks alike and say nothing; and an operator may name its servers like
consumer lines (`adsl.inet-telecom.org` for IVPN), so the guard only judges blocks outside known hosting ranges. A block whose sampled addresses carry consumer names does not belong on a VPN list,
whatever source put it there.

    python -m intel.rdns --dataset <mc-antivpn-bench jsonl>     # how well the classes separate the cohorts
"""
import argparse
import collections
import ipaddress
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor

RESIDENTIAL, SERVER, VPN_NAME = 'residential', 'server', 'vpn'

VPN_BRANDS = re.compile(r'(nordvpn|mullvad|protonvpn|proton\.me|expressvpn|expressnetw|surfshark|privateinternetaccess|'
                        r'privacy\.network|cyberghost|cg-dialup|ipvanish|purevpn|ptoserver|pointtoserver|windscribe|'
                        r'whiskergalaxy|hidemyass|hma\.rocks|hideservers|torguard|vyprvpn|strongvpn|ivpn|azirevpn|ovpn\.com|'
                        r'airvpn|privado|hotspotshield|tunnelbear|zenmate|astrill|31173\.se|packethub|cyberzone|\bvpn\b|-vpn|vpn-)')
# Words consumer access networks use for subscriber addresses. Checked against the benchmark's residential, mobile
# and VPN cohorts (python -m intel.rdns). `res` was left out: it names routers in data centres (res-cs1.voxility.net).
RESIDENTIAL_WORDS = re.compile(r'(^|[.\-_\d])(dsl|adsl|vdsl|xdsl|dyn|dynamic|dynip|dhcp|pool|ppp|pppoe|dialup|dial|cable|'
                               r'cpe|customer|cust|subscriber|sub|broadband|bb|fiber|fibre|ftth|fttx|fttb|home|resi|'
                               r'residential|user|client|wireless|wifi|lte|mobile|gprs|umts|3g|4g|5g|cgnat|nat|catv|hsd|'
                               r'kabel|dip|dip0|business|biz|abo|fixed|access|pat)([.\-_\d]|$)')
SERVER_WORDS = re.compile(r'(^|[.\-_\d])(server|srv|vps|vds|dedi|dedicated|hosted|hosted-by|hosting|baremetal|colo|'
                          r'colocation|datacenter|rack|compute|instance|ec2|kvm|xen)([.\-_\d]|$)')


def classify(name):
    """'vpn', 'server', 'residential' or None (no name, or nothing telling)."""
    if not name:
        return None
    low = name.lower().rstrip('.')
    if VPN_BRANDS.search(low):
        return VPN_NAME
    # Only the host part and the labels before the registered domain describe the address.
    head = '.'.join(low.split('.')[:-2]) or low
    if SERVER_WORDS.search(head):
        return SERVER
    if RESIDENTIAL_WORDS.search(head):
        return RESIDENTIAL
    return None


def _resolver():
    try:
        for line in open('/etc/resolv.conf'):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == 'nameserver' and ':' not in parts[1]:
                return parts[1]
    except OSError:
        pass
    return '1.1.1.1'


def _name(msg, i):
    """A possibly compressed domain name at offset i of a DNS message; returns (name, offset after it)."""
    labels, end, jumps = [], None, 0
    while True:
        length = msg[i]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = i + 2
            i, jumps = ((length & 0x3F) << 8) | msg[i + 1], jumps + 1
            if jumps > 16:
                raise ValueError('compression loop')
            continue
        if length == 0:
            return '.'.join(labels), (end if end is not None else i + 1)
        labels.append(msg[i + 1:i + 1 + length].decode('ascii', 'replace'))
        i += 1 + length


def ptr(ip, timeout=2.0, server=None):
    """The PTR name of an address, or None. A plain UDP query with a timeout: the system's gethostbyaddr waits
    several seconds for every address without a name, which made a few thousand lookups take over ten minutes."""
    import os
    import struct
    try:
        qname = ipaddress.ip_address(str(ip)).reverse_pointer
    except ValueError:
        return None
    qid = int.from_bytes(os.urandom(2), 'big')
    query = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0) + b''.join(
        bytes([len(l)]) + l.encode() for l in qname.split('.')) + b'\x00' + struct.pack('>HH', 12, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (server or _resolver(), 53))
            msg = sock.recv(4096)
        except OSError:
            return None
    try:
        rid, flags, qd, an = struct.unpack('>HHHH', msg[:8])
        if rid != qid or flags & 0x000F:
            return None
        i = 12
        for _ in range(qd):
            i = _name(msg, i)[1] + 4
        for _ in range(an):
            i = _name(msg, i)[1]
            rtype, _, _, rdlen = struct.unpack('>HHIH', msg[i:i + 10])
            i += 10
            if rtype == 12:
                return _name(msg, i)[0] or None
            i += rdlen
    except (ValueError, IndexError, struct.error):
        return None
    return None


def lookup_all(ips, workers=64, resolve=None):
    resolve = resolve or ptr
    ips = list(ips)
    with ThreadPoolExecutor(workers) as pool:
        return dict(zip(ips, pool.map(resolve, ips)))


def samples(network, per_block=3):
    """A few addresses of a block, spread over it: the first usable, the middle and the last usable."""
    if network.num_addresses <= 2:
        return [network.network_address]
    first, last = network.network_address + 1, network.broadcast_address - 1
    middle = network.network_address + network.num_addresses // 2
    return sorted({first, middle, last})[:per_block]


def guard(networks, resolve=None, per_block=3, min_residential=2):
    """Splits networks into (kept, dropped): a network is dropped when at least `min_residential` of its sampled
    addresses carry consumer names and none carries a VPN name. IPv4 networks larger than a /24 are judged per /24."""
    units = []
    for n in networks:
        if n.version == 4 and n.prefixlen < 24:
            units += [(n, s) for s in n.subnets(new_prefix=24)]
        else:
            units.append((n, n))
    names = lookup_all({a for _, u in units for a in samples(u, per_block)}, resolve=resolve)
    bad = collections.defaultdict(list)
    for parent, unit in units:
        classes = [classify(names.get(a)) for a in samples(unit, per_block)]
        if classes.count(RESIDENTIAL) >= min_residential and VPN_NAME not in classes:
            bad[parent].append(unit)
    kept, dropped = [], []
    for n in networks:
        if n not in bad:
            kept.append(n)
            continue
        dropped += bad[n]
        if n.version == 4 and n.prefixlen < 24:
            kept += [u for u in n.subnets(new_prefix=24) if u not in set(bad[n])]
    return kept, dropped


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--dataset', required=True)
    a = p.parse_args(argv)
    items = [json.loads(l) for l in open(a.dataset)]
    names = lookup_all({i['ip'] for i in items})
    table = collections.defaultdict(collections.Counter)
    for i in items:
        table[i['cohort']][classify(names.get(i['ip'])) or ('none' if names.get(i['ip']) is None else 'other')] += 1
    cols = ('vpn', 'server', 'residential', 'other', 'none')
    print(f"{'cohort':16}" + ''.join(f'{c:>12}' for c in cols))
    for cohort, c in sorted(table.items()):
        print(f'{cohort:16}' + ''.join(f'{c[k]:>12}' for k in cols))


if __name__ == '__main__':
    main()
