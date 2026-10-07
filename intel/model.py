"""Entries, categories and the fetch helper shared by every source."""
import gzip
import http.client
import ipaddress
import json
import urllib.request
from dataclasses import dataclass

# What a listed network means for a login check. Mirrors the plugin's local list types (docs/LOCAL_DATA.md).
VPN = 'VPN'          # a commercial VPN service's server or exit: positive
TOR = 'TOR'          # Tor exit: positive
RELAY = 'RELAY'      # privacy relay (iCloud Private Relay): its own operator choice, allowed by default
HOSTING = 'HOSTING'  # data centre / cloud: review only, never a VPN verdict on its own
CATEGORIES = (VPN, TOR, RELAY, HOSTING)
# Published in manifest.json under `additional_lists`, never in `lists`: Connection Guard 0.6.0 accepts a manifest only
# when `lists` holds exactly the four categories above, and ignores other top-level fields.
PROXY = 'PROXY'      # open proxy listed by several public proxy lists: positive (Connection Guard 0.6.1 and later)
ADDITIONAL = (PROXY,)

USER_AGENT = 'connection-guard-intel/0.1 (+https://github.com/gerolndnr/connection-guard-intel)'


@dataclass(frozen=True)
class Entry:
    network: ipaddress._BaseNetwork
    category: str
    source: str
    # exact: the address the operator publishes; prefix: a range the operator or cloud publishes;
    # v6-subnet: the /64 around a published IPv6 server address (exit addresses vary inside it).
    method: str


def net(text, method='exact'):
    """Parses an address or CIDR; returns None for anything unusable (private, reserved, malformed)."""
    try:
        n = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None
    if not n.is_global or n.is_multicast:
        return None
    if method == 'v6-subnet' and n.version == 6 and n.prefixlen > 64:
        n = n.supernet(new_prefix=64)
    return n


def _get(url, headers, timeout, limit, start=0):
    hdrs = {'User-Agent': USER_AGENT, 'Accept': '*/*', **headers}
    if start:
        hdrs['Range'] = f'bytes={start}-'
    chunks, size = [], 0
    with urllib.request.urlopen(urllib.request.Request(url, headers=hdrs), timeout=timeout) as resp:
        meta = dict(length=resp.headers.get('Content-Length'), encoding=resp.headers.get('Content-Encoding', ''),
                    partial=resp.status == 206)
        try:
            # read(n) may return early on chunked answers; read until the end or the bound.
            while size <= limit:
                chunk = resp.read(min(1 << 20, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
        except http.client.IncompleteRead as e:
            chunks.append(e.partial)
    return b''.join(chunks), meta


def fetch(url, timeout=60, limit=64_000_000, headers=None):
    """Downloads `url` completely or raises. A connection that ends early is resumed with a Range request when the
    server supports it; otherwise the short answer is an error, never a short but valid list."""
    headers = dict(headers or {})
    body, meta = _get(url, {**headers, 'Accept-Encoding': 'gzip'}, timeout, limit)
    expected = int(meta['length']) if meta['length'] else None
    for _ in range(8):
        if expected is None or len(body) >= expected or meta['encoding']:
            break
        more, more_meta = _get(url, headers, timeout, limit - len(body), start=len(body))
        if not more_meta['partial'] or not more:
            break
        body += more
    if len(body) > limit:
        raise ValueError(f'{url}: answer larger than {limit} bytes')
    if expected is not None and len(body) != expected:
        raise ValueError(f'{url}: got {len(body)} of {expected} bytes')
    if 'gzip' in meta['encoding']:
        body = gzip.decompress(body)
        if len(body) > limit:
            raise ValueError(f'{url}: answer larger than {limit} bytes')
    return body


def fetch_json(url, **kw):
    return json.loads(fetch(url, **kw))
