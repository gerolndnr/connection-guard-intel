// Connection Guard Intel for Node.js bots and tools (Node 18 or later, no dependencies).
//
// Downloads the signed lists from intel.connectionguard.net, verifies the signature and every list's SHA-256, and
// answers lookups in memory: the addresses you check never leave your machine.
//
//   import { downloadIntel } from "./cg-intel.mjs";
//   const intel = await downloadIntel();        // once a day is enough; the lists are rebuilt daily
//   intel.lookup("203.0.113.7");                // { categories: ["VPN"], labels: [], block: true, asOf: "..." }
//
// MIT licence; the lists carry their own terms (github.com/gerolndnr/connection-guard-intel/blob/main/SOURCES.md).
import { createHash, createPublicKey, verify } from "node:crypto";
import { isIP } from "node:net";

export const HOST = "https://intel.connectionguard.net/";
export const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExDOqYg3Tc2Vu2P/gIiVQw3nbjJOL
/UvLivduLU0PsRqsknUQd682QMgR6FHzPD04tx0xC/QzOCRPacU3vA958Q==
-----END PUBLIC KEY-----
`;
// Categories that mean "not a direct home connection"; RELAY (iCloud Private Relay, WARP) is your choice.
export const BLOCK = ["VPN", "TOR", "PROXY"];
const LABELS = ["BOOSTER", "MOBILE", "SHARED"];
const MAX_AGE_HOURS = 72;
const USER_AGENT = "cg-intel-js/1.0 (+https://github.com/gerolndnr/connection-guard-intel)";

async function get(url, limit) {
  const res = await fetch(url, { headers: { "User-Agent": USER_AGENT } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const body = Buffer.from(await res.arrayBuffer());
  if (body.length > limit) throw new Error(`${url}: larger than ${limit} bytes`);
  return body;
}

/** An address as a BigInt; IPv4 and IPv6 are kept apart by `family`. */
function toBig(ip) {
  if (isIP(ip) === 4) return { family: 4, value: ip.split(".").reduce((v, o) => (v << 8n) + BigInt(Number(o)), 0n) };
  if (isIP(ip) !== 6) throw new Error(`not an IP address: ${ip}`);
  let text = ip.toLowerCase();
  if (text.includes(".")) { // IPv4-mapped tail
    const tail = text.slice(text.lastIndexOf(":") + 1), v4 = toBig(tail).value;
    text = `${text.slice(0, text.lastIndexOf(":") + 1)}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const [head, tail = ""] = text.split("::");
  const left = head ? head.split(":") : [], right = tail ? tail.split(":") : [];
  const groups = text.includes("::") ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right] : left;
  return { family: 6, value: groups.reduce((v, g) => (v << 16n) + BigInt(parseInt(g || "0", 16)), 0n) };
}

class Ranges {
  constructor(lines) {
    const byFamily = { 4: [], 6: [] };
    for (const line of lines) {
      const [ip, len] = line.split("/");
      const { family, value } = toBig(ip);
      const bits = family === 4 ? 32n : 128n, size = 1n << (bits - BigInt(len ?? bits));
      byFamily[family].push([value, value + size - 1n]);
    }
    this.ranges = {};
    for (const family of [4, 6]) {
      const sorted = byFamily[family].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)), merged = [];
      for (const r of sorted) {
        const last = merged[merged.length - 1];
        if (last && r[0] <= last[1] + 1n) { if (r[1] > last[1]) last[1] = r[1]; } else merged.push([...r]);
      }
      this.ranges[family] = merged;
    }
  }
  has({ family, value }) {
    const list = this.ranges[family];
    let lo = 0, hi = list.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (value < list[mid][0]) hi = mid - 1; else if (value > list[mid][1]) lo = mid + 1; else return true;
    }
    return false;
  }
}

export async function downloadIntel({ host = HOST, publicKey = PUBLIC_KEY, now = Date.now() } = {}) {
  const raw = await get(`${host}manifest.json`, 65536);
  const signature = Buffer.from((await get(`${host}manifest.json.sig`, 256)).toString().trim(), "base64");
  if (!verify("sha256", raw, createPublicKey(publicKey), signature)) throw new Error("manifest signature rejected");
  const manifest = JSON.parse(raw.toString());
  if (manifest.evaluation_only) throw new Error("evaluation-only build");
  if (now - Date.parse(manifest.as_of) > MAX_AGE_HOURS * 3600_000) throw new Error(`lists are older than ${MAX_AGE_HOURS} hours`);
  const lists = {};
  for (const [name, meta] of Object.entries({ ...manifest.lists, ...(manifest.additional_lists ?? {}) })) {
    if (meta.file !== `${name.toLowerCase()}.txt`) throw new Error(`unexpected file name ${meta.file}`);
    const body = await get(`${host}${meta.file}`, meta.bytes);
    if (createHash("sha256").update(body).digest("hex") !== meta.sha256) throw new Error(`${meta.file}: hash does not match the signed manifest`);
    lists[name] = new Ranges(body.toString().split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")));
  }
  return {
    asOf: manifest.as_of,
    /** Categories (VPN, TOR, PROXY, RELAY, HOSTING) and labels (BOOSTER, MOBILE, SHARED). On no list = unknown, not clean. */
    lookup(ip) {
      let address = toBig(ip);
      // Dual-stack proxies can spell mapped addresses with a dotted or hexadecimal tail.
      if (address.family === 6 && address.value >> 32n === 0xffffn)
        address = { family: 4, value: address.value & 0xffffffffn };
      const found = Object.keys(lists).filter((name) => lists[name].has(address)).sort();
      const categories = found.filter((f) => !LABELS.includes(f));
      return { categories, labels: found.filter((f) => LABELS.includes(f)), block: categories.some((c) => BLOCK.includes(c)), asOf: manifest.as_of };
    },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const intel = await downloadIntel();
  for (const ip of process.argv.slice(2)) console.log(ip, intel.lookup(ip));
}
