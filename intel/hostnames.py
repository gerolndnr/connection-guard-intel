"""VPN servers found by their operator's host-name scheme: names tried in DNS, no list needed.

Some operators name every server after a pattern (`node-nl-05.protonvpn.net`) but publish no list we may use, or a
list that misses servers. Trying the pattern finds those servers. Numbers are tried in blocks of 100 per country (the
first is 1-99, since numbering need not start at 1: Proton's US servers start at 56), and the next block only while
the last one had a hit, so most countries cost 99 queries and the US with 400 servers about 500. Only the operator's
own domain is queried.
"""
from concurrent.futures import ThreadPoolExecutor
import socket

from .model import VPN, Entry, net

# ISO 3166-1 alpha-2, plus "uk", which several operators use for GB.
COUNTRIES = tuple(sorted(set('''
ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bv bw by bz ca cc cd
cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et fi fj fk fm fo fr ga gb gd ge gf
gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn
kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na
nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si
sj sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug um us uy uz va vc ve vg vi
vn vu wf ws ye yt za zm zw uk'''.split())))

BLOCK = 100
MAX_NUMBER = 999

# source: (template with {cc} and {n}, the operator, how it is known). Each scheme was checked by hand in DNS.
SCHEMES = {
    'protonvpn-dns': ('node-{cc}-{n:02d}.protonvpn.net', 'ProtonVPN',
                      'Server names of Proton\'s apps and support pages; Proton\'s server API needs a login'),
}


def _resolve(host):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, None)})
    except OSError:
        return []


def enumerate_hosts(template, countries=COUNTRIES, resolve=None, block=BLOCK, max_number=MAX_NUMBER, workers=32):
    """{host: [addresses]} for every name of the scheme that resolves."""
    resolve = resolve or _resolve
    found, pending = {}, {cc: 1 for cc in countries}
    # Blocks are aligned to multiples of `block`, so the first one is 1..block-1.
    with ThreadPoolExecutor(workers) as pool:
        while pending:
            names = [(cc, template.format(cc=cc, n=n)) for cc, start in pending.items()
                     for n in range(start, min(start - start % block + block, max_number + 1))]
            hits = set()
            for (cc, host), ips in zip(names, pool.map(lambda x: resolve(x[1]), names)):
                if ips:
                    found[host] = ips
                    hits.add(cc)
            pending = {cc: pending[cc] - pending[cc] % block + block for cc in hits
                       if pending[cc] - pending[cc] % block + block <= max_number}
    return found


def parse_scheme(source, template, resolve=None, countries=COUNTRIES):
    def parse(_body):
        out = []
        for ips in enumerate_hosts(template, countries, resolve).values():
            for ip in ips:
                method = 'v6-subnet' if ':' in ip else 'exact'
                n = net(ip, method)
                if n is not None:
                    out.append(Entry(n, VPN, source, method))
        return out
    return parse
