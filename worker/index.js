// intel.connectionguard.net: serves the latest build from the `lists` branch, cached at the edge.
// manifest.json and its signature are cached for one minute, so they always belong together; lists for 15 minutes.
// Right after a daily build a cached list can still be the previous one: its sha256 then fails the plugin's check and
// the plugin keeps its current data and tries again later.
// The plugin verifies manifest.json.sig and every list's sha256 itself; this Worker only delivers bytes.
const ORIGIN = "https://raw.githubusercontent.com/gerolndnr/connection-guard-intel/lists/";
const FILES = new Map([
  ["vpn.txt", "text/plain; charset=utf-8"], ["tor.txt", "text/plain; charset=utf-8"],
  ["relay.txt", "text/plain; charset=utf-8"], ["hosting.txt", "text/plain; charset=utf-8"],
  ["manifest.json", "application/json"], ["manifest.json.sig", "text/plain; charset=utf-8"],
]);

export default {
  async fetch(request, env, ctx) {
    if (request.method !== "GET" && request.method !== "HEAD") return new Response("method not allowed\n", { status: 405 });
    const name = new URL(request.url).pathname.slice(1);
    if (name === "") {
      return new Response("Connection Guard Intel lists: vpn.txt, tor.txt, relay.txt, hosting.txt, manifest.json, manifest.json.sig\n" +
        "Source and terms: https://github.com/gerolndnr/connection-guard-intel\n", { headers: { "content-type": "text/plain; charset=utf-8" } });
    }
    const type = FILES.get(name);
    if (!type) return new Response("not found\n", { status: 404 });
    const key = new Request(ORIGIN + name);
    let response = await caches.default.match(key);
    if (!response) {
      const upstream = await fetch(ORIGIN + name);
      if (!upstream.ok) return new Response("lists temporarily unavailable\n", { status: 502 });
      response = new Response(await upstream.arrayBuffer(), { headers: {
        "content-type": type, "cache-control": `public, max-age=${name.startsWith("manifest") ? 60 : 900}`, "x-robots-tag": "noindex", "access-control-allow-origin": "*",
      } });
      ctx.waitUntil(caches.default.put(key, response.clone()));
    }
    return request.method === "HEAD" ? new Response(null, { headers: response.headers }) : response;
  },
};
