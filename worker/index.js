// intel.connectionguard.net: serves the latest build from the `lists` branch, cached at the edge.
// manifest.json and its signature are cached for one minute. Each list is cached under the sha256 the current manifest
// names for it, and only bytes that match that sha256 are served, so a manifest and its lists always belong together:
// right after a build, a list whose new bytes have not reached GitHub's CDN yet is answered with 503 (retry shortly)
// instead of the previous version.
// The plugin verifies manifest.json.sig and every list's sha256 itself; this Worker only delivers bytes.
const ORIGIN = "https://raw.githubusercontent.com/gerolndnr/connection-guard-intel/lists/";
const TEXT = "text/plain; charset=utf-8";
const LISTS = new Map([["vpn.txt", "VPN"], ["tor.txt", "TOR"], ["relay.txt", "RELAY"], ["hosting.txt", "HOSTING"]]);
const META = new Map([["manifest.json", "application/json"], ["manifest.json.sig", TEXT]]);
const HEADERS = { "x-robots-tag": "noindex", "access-control-allow-origin": "*" };

async function cached(key, load, ctx) {
  const request = new Request(key);
  let response = await caches.default.match(request);
  if (!response) {
    response = await load();
    if (response.ok) ctx.waitUntil(caches.default.put(request, response.clone()));
  }
  return response;
}

async function meta(name, ctx) {
  return cached(ORIGIN + name, async () => {
    const upstream = await fetch(ORIGIN + name);
    if (!upstream.ok) return new Response("lists temporarily unavailable\n", { status: 502 });
    return new Response(await upstream.arrayBuffer(), { headers: { ...HEADERS, "content-type": META.get(name), "cache-control": "public, max-age=60" } });
  }, ctx);
}

const hex = (buffer) => [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function list(name, ctx) {
  const manifest = await meta("manifest.json", ctx);
  if (!manifest.ok) return manifest;
  const sha = (await manifest.clone().json()).lists?.[LISTS.get(name)]?.sha256;
  if (!/^[0-9a-f]{64}$/.test(sha ?? "")) return new Response("lists temporarily unavailable\n", { status: 502 });
  // Keyed by content hash, so a cached copy never outlives its manifest; the query also skips stale CDN copies.
  return cached(`${ORIGIN}${name}?sha256=${sha}`, async () => {
    const upstream = await fetch(`${ORIGIN}${name}?sha256=${sha}`);
    if (!upstream.ok) return new Response("lists temporarily unavailable\n", { status: 502 });
    const body = await upstream.arrayBuffer();
    if (hex(await crypto.subtle.digest("SHA-256", body)) !== sha) {
      return new Response("lists are being updated, retry in a minute\n", { status: 503, headers: { "retry-after": "60" } });
    }
    return new Response(body, { headers: { ...HEADERS, "content-type": TEXT, "cache-control": "public, max-age=86400", etag: `"${sha}"` } });
  }, ctx);
}

export default {
  async fetch(request, env, ctx) {
    if (request.method !== "GET" && request.method !== "HEAD") return new Response("method not allowed\n", { status: 405 });
    const name = new URL(request.url).pathname.slice(1);
    if (name === "") {
      return new Response("Connection Guard Intel lists: vpn.txt, tor.txt, relay.txt, hosting.txt, manifest.json, manifest.json.sig\n" +
        "Source and terms: https://github.com/gerolndnr/connection-guard-intel\n", { headers: { "content-type": TEXT } });
    }
    let response;
    if (META.has(name)) response = await meta(name, ctx);
    else if (LISTS.has(name)) response = await list(name, ctx);
    else return new Response("not found\n", { status: 404 });
    return request.method === "HEAD" ? new Response(null, { status: response.status, headers: response.headers }) : response;
  },
};
