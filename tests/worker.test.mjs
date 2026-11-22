import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import worker from "../worker/index.js";

const host = "https://intel.connectionguard.net/";
const hash = (body) => createHash("sha256").update(body).digest("hex");

function fixture(t, files, manifest, signature = "test signature") {
  const originalFetch = globalThis.fetch;
  const originalCaches = globalThis.caches;
  const cached = new Map(), upstream = [], pending = [];
  globalThis.caches = { default: {
    async match(request) { return cached.get(request.url)?.clone(); },
    async put(request, response) { cached.set(request.url, response); },
  } };
  globalThis.fetch = async (url) => {
    upstream.push(url);
    const name = new URL(url).pathname.split("/").pop();
    if (name === "manifest.json") return Response.json(manifest);
    if (name === "manifest.json.sig") return new Response(signature);
    return Object.hasOwn(files, name) ? new Response(files[name]) : new Response(null, { status: 404 });
  };
  t.after(async () => {
    await Promise.all(pending);
    globalThis.fetch = originalFetch;
    if (originalCaches === undefined) delete globalThis.caches;
    else globalThis.caches = originalCaches;
  });
  return {
    upstream,
    request: (path, method = "GET") => worker.fetch(new Request(host + path, { method }), {},
      { waitUntil(promise) { pending.push(promise); } }),
  };
}

test("the public routes deliver exactly the primary lists and published optional lists", async (t) => {
  const files = {
    "vpn.txt": "192.0.2.1\n", "tor.txt": "192.0.2.2\n",
    "relay.txt": "198.51.100.0/24\n", "hosting.txt": "203.0.113.0/24\n",
    "proxy.txt": "192.0.2.3\n", "booster.txt": "192.0.2.4\n", "mobile.txt": "2001:db8::/32\n",
    "shared.txt": "192.0.2.5\n",
  };
  const entry = (name) => ({ file: name, sha256: hash(files[name]) });
  const { request, upstream } = fixture(t, files, {
    lists: { VPN: entry("vpn.txt"), TOR: entry("tor.txt"), RELAY: entry("relay.txt"), HOSTING: entry("hosting.txt") },
    additional_lists: { PROXY: entry("proxy.txt"), BOOSTER: entry("booster.txt"), MOBILE: entry("mobile.txt"),
      SHARED: entry("shared.txt") },
  });
  const index = await (await request("")).text();
  for (const [name, body] of Object.entries(files).filter(([name]) => name !== "shared.txt")) {
    assert.ok(index.includes(name));
    const response = await request(name);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("etag"), `"${hash(body)}"`);
    assert.equal(await response.text(), body);
    assert.ok(upstream.some((url) => url.endsWith(`${name}?sha256=${hash(body)}`)));
  }
  assert.ok(!index.includes("shared.txt"));
  assert.equal((await request("shared.txt")).status, 404);
  assert.ok(!upstream.some((url) => url.includes("shared.txt")));
  const head = await request("mobile.txt", "HEAD");
  assert.equal(head.status, 200);
  assert.equal(head.headers.get("etag"), `"${hash(files["mobile.txt"])}"`);
  assert.equal(await head.text(), "");
  assert.equal(await (await request("manifest.json.sig")).text(), "test signature");
});

test("missing optional metadata does not affect the core, and wrong label bytes are not served", async (t) => {
  const files = { "vpn.txt": "192.0.2.1\n", "booster.txt": "outdated\n", "mobile.txt": "unlisted\n" };
  const { request, upstream } = fixture(t, files, {
    lists: { VPN: { sha256: hash(files["vpn.txt"]) } },
    additional_lists: { BOOSTER: { sha256: hash("192.0.2.4\n") } },
  });
  assert.equal((await request("vpn.txt")).status, 200);
  const mismatched = await request("booster.txt");
  assert.equal(mismatched.status, 503);
  assert.equal(mismatched.headers.get("retry-after"), "60");
  assert.equal((await request("mobile.txt")).status, 502);
  assert.ok(!upstream.some((url) => url.includes("mobile.txt")));
});
