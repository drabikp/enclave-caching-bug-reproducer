package com.parkdots.repro;

import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Counts Azure SDK HTTP requests by category, populated by {@link CountingHttpClient}.
 *
 * <p>Categories are derived from the URL: anything to
 * {@code login.microsoftonline.com} is counted as {@code oauth-token}; Key Vault requests are
 * categorized by the final path segment (e.g. {@code /verify}, {@code /unwrapkey}) — a request
 * whose path is just {@code /keys/<name>/<version>} (no trailing operation) counts as
 * {@code key-get}.
 *
 * <p>All state is static so the SPI-registered HTTP client and the reproducer's main code share
 * the same instance without a wiring step.
 */
public final class KvOperationCounter {

    private static final ConcurrentMap<String, AtomicInteger> counts = new ConcurrentHashMap<>();

    private KvOperationCounter() {}

    static void increment(String url) {
        String category = categorize(url);
        counts.computeIfAbsent(category, k -> new AtomicInteger()).incrementAndGet();
    }

    /** Snapshots all counters and resets them. Map ordering is alphabetical for stable output. */
    public static java.util.SortedMap<String, Integer> resetAndSnapshot() {
        java.util.TreeMap<String, Integer> snapshot = new java.util.TreeMap<>();
        counts.forEach((k, v) -> snapshot.put(k, v.getAndSet(0)));
        return snapshot;
    }

    static String categorize(String url) {
        if (url == null) {
            return "unknown";
        }
        String lower = url.toLowerCase(Locale.ROOT);

        if (lower.contains("login.microsoftonline.com") || lower.contains("/oauth2/")) {
            return "oauth-token";
        }
        if (!lower.contains(".vault.azure.net") && !lower.contains(".vault.azure.cn")
                && !lower.contains(".vault.usgovcloudapi.net") && !lower.contains(".vault.microsoftazure.de")) {
            return "other";
        }
        // Strip query string
        int q = lower.indexOf('?');
        String path = q < 0 ? lower : lower.substring(0, q);
        // Walk back to find the segment after .../keys/{name}/{version}/...
        int idx = path.indexOf("/keys/");
        if (idx < 0) {
            return "key-vault-other";
        }
        // The structure is /keys/{name}/{version}[/op]. We want the last segment after that.
        String afterKeys = path.substring(idx + "/keys/".length());
        String[] parts = afterKeys.split("/");
        // parts[0] = name, parts[1] = version (if present), parts[2] = op (if present)
        if (parts.length <= 2) {
            return "key-get";
        }
        String op = parts[parts.length - 1];
        return op.isEmpty() ? "key-get" : op;
    }
}
