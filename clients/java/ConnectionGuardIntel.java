import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Connection Guard Intel for Java plugins and tools (Java 11 or later, no dependencies). Copy this file into your
 * project and change the package.
 *
 * <p>Downloads the signed lists from intel.connectionguard.net, verifies the signature and every list's SHA-256, and
 * answers lookups in memory: the addresses you check never leave your server. Download off the main thread, once a
 * day; {@link #lookup} is fast and thread-safe.
 *
 * <pre>
 * ConnectionGuardIntel intel = ConnectionGuardIntel.download();
 * ConnectionGuardIntel.Result r = intel.lookup("203.0.113.7");
 * if (r.block()) ...   // VPN, Tor or proxy
 * </pre>
 *
 * MIT licence; the lists carry their own terms (github.com/gerolndnr/connection-guard-intel/blob/main/SOURCES.md).
 */
public final class ConnectionGuardIntel {
    public static final String HOST = "https://intel.connectionguard.net/";
    public static final String PUBLIC_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExDOqYg3Tc2Vu2P/gIiVQw3nbjJOL"
            + "/UvLivduLU0PsRqsknUQd682QMgR6FHzPD04tx0xC/QzOCRPacU3vA958Q==";
    /** Categories that mean "not a direct home connection"; RELAY (iCloud Private Relay, WARP) is your choice. */
    public static final Set<String> BLOCK = Set.of("VPN", "TOR", "PROXY");
    public static final Set<String> LABELS = Set.of("BOOSTER", "MOBILE", "SHARED");
    private static final Duration MAX_AGE = Duration.ofHours(72);
    private static final String USER_AGENT = "cg-intel-java/1.0 (+https://github.com/gerolndnr/connection-guard-intel)";

    /** Categories (VPN, TOR, PROXY, RELAY, HOSTING) and labels (BOOSTER, MOBILE, SHARED). On no list = unknown, not clean. */
    public static final class Result {
        private final List<String> categories, labels;
        private final Instant asOf;
        Result(List<String> categories, List<String> labels, Instant asOf) { this.categories = categories; this.labels = labels; this.asOf = asOf; }
        public List<String> categories() { return categories; }
        public List<String> labels() { return labels; }
        public boolean block() { return categories.stream().anyMatch(BLOCK::contains); }
        public Instant asOf() { return asOf; }
        @Override public String toString() { return "categories=" + categories + " labels=" + labels + " block=" + block() + " as_of=" + asOf; }
    }

    private static final class Ranges {
        final BigInteger[][] starts = new BigInteger[2][], ends = new BigInteger[2][];
        Ranges(List<String> lines) {
            List<List<BigInteger[]>> byFamily = List.of(new ArrayList<>(), new ArrayList<>());
            for (String line : lines) {
                String[] parts = line.split("/");
                byte[] address = parse(parts[0]);
                int bits = address.length * 8, length = parts.length > 1 ? Integer.parseInt(parts[1]) : bits;
                BigInteger start = new BigInteger(1, address), size = BigInteger.ONE.shiftLeft(bits - length);
                byFamily.get(address.length == 4 ? 0 : 1).add(new BigInteger[]{start, start.add(size).subtract(BigInteger.ONE)});
            }
            for (int f = 0; f < 2; f++) {
                List<BigInteger[]> sorted = byFamily.get(f), merged = new ArrayList<>();
                sorted.sort(Comparator.comparing(r -> r[0]));
                for (BigInteger[] r : sorted) {
                    BigInteger[] last = merged.isEmpty() ? null : merged.get(merged.size() - 1);
                    if (last != null && r[0].compareTo(last[1].add(BigInteger.ONE)) <= 0) { if (r[1].compareTo(last[1]) > 0) last[1] = r[1]; }
                    else merged.add(r.clone());
                }
                starts[f] = merged.stream().map(r -> r[0]).toArray(BigInteger[]::new);
                ends[f] = merged.stream().map(r -> r[1]).toArray(BigInteger[]::new);
            }
        }
        boolean contains(byte[] address) {
            int f = address.length == 4 ? 0 : 1;
            BigInteger value = new BigInteger(1, address);
            int i = Arrays.binarySearch(starts[f], value);
            if (i < 0) i = -i - 2;
            return i >= 0 && value.compareTo(ends[f][i]) <= 0;
        }
    }

    private final Map<String, Ranges> lists;
    private final Instant asOf;

    private ConnectionGuardIntel(Map<String, Ranges> lists, Instant asOf) { this.lists = lists; this.asOf = asOf; }

    public Instant asOf() { return asOf; }

    public static ConnectionGuardIntel download() throws Exception { return download(HOST, PUBLIC_KEY); }

    public static ConnectionGuardIntel download(String host, String base64PublicKey) throws Exception {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();
        byte[] manifest = get(client, host + "manifest.json", 65536);
        byte[] signature = Base64.getDecoder().decode(new String(get(client, host + "manifest.json.sig", 256), StandardCharsets.US_ASCII).trim());
        PublicKey key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey)));
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(key);
        verifier.update(manifest);
        if (!verifier.verify(signature)) throw new SecurityException("manifest signature rejected");
        String text = new String(manifest, StandardCharsets.UTF_8);
        if (text.matches("(?s).*\"evaluation_only\"\\s*:\\s*true.*")) throw new IllegalStateException("evaluation-only build");
        Matcher asOfMatch = Pattern.compile("\"as_of\"\\s*:\\s*\"([^\"]+)\"").matcher(text);
        if (!asOfMatch.find()) throw new IllegalStateException("manifest without as_of");
        Instant asOf = Instant.parse(asOfMatch.group(1));
        if (Duration.between(asOf, Instant.now()).compareTo(MAX_AGE) > 0) throw new IllegalStateException("lists are older than 72 hours");
        // The manifest is signed; its list entries are flat objects {"addresses","bytes","file","networks","sha256"}.
        Pattern entry = Pattern.compile("\"([A-Z]+)\"\\s*:\\s*\\{([^{}]*\"file\"[^{}]*)\\}");
        Map<String, Ranges> lists = new TreeMap<>();
        Matcher m = entry.matcher(text);
        while (m.find()) {
            String name = m.group(1), body = m.group(2);
            String file = field(body, "file"), sha256 = field(body, "sha256");
            int bytes = Integer.parseInt(field(body, "bytes"));
            if (!file.equals(name.toLowerCase(Locale.ROOT) + ".txt")) throw new IllegalStateException("unexpected file name " + file);
            byte[] list = get(client, host + file, bytes);
            if (!hex(MessageDigest.getInstance("SHA-256").digest(list)).equals(sha256)) throw new SecurityException(file + ": hash does not match the signed manifest");
            List<String> lines = new ArrayList<>();
            for (String line : new String(list, StandardCharsets.UTF_8).split("\n")) if (!line.isBlank() && !line.startsWith("#")) lines.add(line.trim());
            lists.put(name, new Ranges(lines));
        }
        if (!lists.keySet().containsAll(List.of("VPN", "TOR", "RELAY", "HOSTING"))) throw new IllegalStateException("manifest without the four base lists");
        return new ConnectionGuardIntel(Collections.unmodifiableMap(lists), asOf);
    }

    public Result lookup(String ip) {
        byte[] address = parse(ip);
        List<String> categories = new ArrayList<>(), labels = new ArrayList<>();
        lists.forEach((name, ranges) -> { if (ranges.contains(address)) (LABELS.contains(name) ? labels : categories).add(name); });
        return new Result(List.copyOf(categories), List.copyOf(labels), asOf);
    }

    /** A literal address only: never resolves a host name. */
    private static byte[] parse(String literal) {
        if (!literal.matches("[0-9a-fA-F:.]+") || !(literal.contains(":") || literal.matches("\\d{1,3}(\\.\\d{1,3}){3}")))
            throw new IllegalArgumentException("not an IP address: " + literal);
        try { return InetAddress.getByName(literal).getAddress(); }
        catch (java.net.UnknownHostException e) { throw new IllegalArgumentException("not an IP address: " + literal); }
    }

    private static String field(String body, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"?([^\",}]+)\"?").matcher(body);
        if (!m.find()) throw new IllegalStateException("manifest entry without " + name);
        return m.group(1).trim();
    }

    private static byte[] get(HttpClient client, String url, int limit) throws Exception {
        HttpResponse<byte[]> res = client.send(HttpRequest.newBuilder(URI.create(url)).header("User-Agent", USER_AGENT)
                .timeout(Duration.ofSeconds(60)).build(), HttpResponse.BodyHandlers.ofByteArray());
        if (res.statusCode() != 200) throw new IllegalStateException(url + ": HTTP " + res.statusCode());
        if (res.body().length > limit) throw new IllegalStateException(url + ": larger than " + limit + " bytes");
        return res.body();
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (byte b : bytes) out.append(String.format("%02x", b));
        return out.toString();
    }

    public static void main(String[] args) throws Exception {
        ConnectionGuardIntel intel = download();
        for (String ip : args) System.out.println(ip + " " + intel.lookup(ip));
    }
}
