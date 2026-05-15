package com.parkdots.repro;

import com.microsoft.sqlserver.jdbc.SQLServerColumnEncryptionAzureKeyVaultProvider;
import com.microsoft.sqlserver.jdbc.SQLServerConnection;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Reproducer for the MSSQL JDBC enclave CEK-caching bug.
 *
 * <p>The bug arises from a combination of driver behaviors:
 * <ul>
 *   <li>{@code SQLServerConnection.java:1511} (in
 *       {@code registerColumnEncryptionKeyStoreProviders}) calls
 *       {@code provider.setColumnEncryptionCacheTtl(Duration.ZERO)} on every globally registered
 *       provider at <b>registration time</b>, disabling its internal CEK cache before any query
 *       runs.</li>
 *   <li>{@code SQLServerSymmetricKeyCache.java:100} (in {@code getKey}) re-issues the same poison
 *       call whenever the symmetric key cache misses for a CEK. This is reached from <b>both</b>
 *       the non-enclave query path and the enclave query path: the enclave path also routes
 *       through it for the <i>parameter</i> CEK at {@code ISQLServerEnclaveProvider.java:262}
 *       (via {@code SQLServerSecurityUtility.decryptSymmetricKey}). So the very first enclave
 *       query with an encrypted parameter re-poisons the cache even if it was manually
 *       restored.</li>
 *   <li>For the <i>enclave</i> CEK itself, {@code ISQLServerEnclaveProvider.java:229} calls
 *       {@code provider.decryptColumnEncryptionKey(...)} <b>directly</b>, with no caching layer
 *       at all. So once the provider's cache is disabled, every enclave query pays a full Key
 *       Vault round-trip for the enclave CEK.</li>
 * </ul>
 *
 * <p>Four phases:
 * <ol>
 *   <li><b>Phase 1 — Registration-time poison.</b> Observe the TTL transition from {@code PT2H}
 *       to {@code PT0S} when {@code registerColumnEncryptionKeyStoreProviders} is called, then
 *       manually restore the TTL so phases 2a/2b can measure cache-working behavior.</li>
 *   <li><b>Phase 2a — SQL round-trip floor.</b> N iterations of {@code SELECT 1}. No AE
 *       machinery engaged; pure JDBC + network cost.</li>
 *   <li><b>Phase 2b — AE non-enclave query.</b> N iterations of
 *       {@code SELECT Description FROM ... WHERE Id = ?}. Result decryption uses the
 *       <i>standard</i> path (symmetric key cache). The very first iteration fires the per-query
 *       poison ({@link CountingKeyVaultProvider#setColumnEncryptionCacheTtl} counter shows
 *       {@code setTtl=1}); subsequent iterations hit the symmetric cache and are fast. The
 *       difference vs phase 2a isolates AE driver overhead with caching working.</li>
 *   <li><b>Phase 3 — Enclave query (the bug).</b> N iterations of
 *       {@code SELECT Id FROM ... WHERE Description LIKE ?}. The enclave path uses
 *       {@code ISQLServerEnclaveProvider.java:229} which bypasses the symmetric cache, and the
 *       provider's own cache was disabled by phase 2b's poison fire. <i>Every</i> measured
 *       iteration calls Key Vault for the enclave CEK. The difference vs phase 2b isolates the
 *       enclave-specific bypass cost.</li>
 * </ol>
 *
 * <p>HTTP-level evidence: {@link KvOperationCounter} (wired in via the {@code HttpClientProvider}
 * SPI) counts real Azure Key Vault HTTP requests per category — {@code key-get},
 * {@code unwrapkey}, {@code verify}, {@code sign}, {@code oauth-token}. The bug's signature in
 * those counts is that {@code unwrapkey} (and {@code verify}) accumulate one per enclave query
 * in phase 3, instead of staying constant from phase 2b onwards.
 */
public final class EnclaveCachingBugReproducer {

    public static void main(String[] args) throws Exception {
        ReproducerConfig cfg = ReproducerConfig.load();

        if (cfg.captureJdbcTrace) {
            configureJdbcTraceLogging(cfg.jdbcTraceLogPath);
        }

        SQLServerColumnEncryptionAzureKeyVaultProvider azureProvider =
                new SQLServerColumnEncryptionAzureKeyVaultProvider(cfg.keyVaultClientId, cfg.keyVaultClientSecret);

        final Duration originalTtl = azureProvider.getColumnEncryptionKeyCacheTtl();

        CountingKeyVaultProvider counter = new CountingKeyVaultProvider(azureProvider);

        phase1RegistrationPoison(azureProvider, counter, originalTtl);

        Properties connProps = new Properties();
        connProps.setProperty("user", cfg.jdbcUser);
        connProps.setProperty("password", cfg.jdbcPassword);

        try (Connection conn = DriverManager.getConnection(cfg.jdbcUrl, connProps)) {
            System.out.println("[setup] connected to " + conn.getMetaData().getURL());

            ensureSeedData(conn, cfg);
            restoreTtl(azureProvider, originalTtl, "seeding");
            counter.resetAndSnapshot();
            KvOperationCounter.resetAndSnapshot();
            System.out.println();

            long baselineNanos = phase2aSqlBaseline(conn, cfg, counter);
            long ae2bNanos = phase2bAeNonEnclave(conn, cfg, counter, azureProvider);
            long enclaveNanos = phase3Enclave(conn, cfg, counter, azureProvider);

            printSummary(cfg, baselineNanos, ae2bNanos, enclaveNanos);
        }
    }

    private static void phase1RegistrationPoison(SQLServerColumnEncryptionAzureKeyVaultProvider azureProvider,
                                                  CountingKeyVaultProvider counter,
                                                  Duration originalTtl) throws SQLException {
        System.out.println("=== Phase 1: Registration-time poison (SQLServerConnection.java:1511) ===");
        System.out.println("  Azure delegate TTL before registration: " + originalTtl);

        SQLServerConnection.registerColumnEncryptionKeyStoreProviders(
                Map.of("AZURE_KEY_VAULT", counter));

        Duration afterReg = azureProvider.getColumnEncryptionKeyCacheTtl();
        System.out.println("  Azure delegate TTL after registration:  " + afterReg
                + (Duration.ZERO.equals(afterReg) ? "  <-- poison fired (driver disabled the cache)" : ""));

        if (!originalTtl.equals(afterReg)) {
            azureProvider.setColumnEncryptionCacheTtl(originalTtl);
            System.out.println("  Manually restored TTL to " + originalTtl + " so phases 2a/2b can measure");
            System.out.println("  cache-working behavior. In real applications no such restoration happens;");
            System.out.println("  the cache stays disabled.");
        }
        counter.resetAndSnapshot();
        KvOperationCounter.resetAndSnapshot();
        System.out.println();
    }

    private static long phase2aSqlBaseline(Connection conn, ReproducerConfig cfg,
                                            CountingKeyVaultProvider counter) throws SQLException {
        System.out.println("=== Phase 2a: SQL round-trip floor (non-encrypted query) ===");
        System.out.println("  Query: SELECT 1");
        runBaselineLoop(conn, cfg.warmup);
        counter.resetAndSnapshot();
        KvOperationCounter.resetAndSnapshot();

        long startNanos = System.nanoTime();
        runBaselineLoop(conn, cfg.iterations);
        long elapsedNanos = System.nanoTime() - startNanos;

        CountingKeyVaultProvider.Counts counts = counter.resetAndSnapshot();
        System.out.println("  Measured " + cfg.iterations + " iterations");
        System.out.println("  Provider counters: " + counts);
        System.out.println("  KV HTTP counts:    " + KvOperationCounter.resetAndSnapshot());
        System.out.println("  Total elapsed: " + ms(elapsedNanos) + " (avg "
                + perOp(elapsedNanos, cfg.iterations) + " per query)");
        System.out.println();
        return elapsedNanos;
    }

    private static long phase2bAeNonEnclave(Connection conn, ReproducerConfig cfg,
                                             CountingKeyVaultProvider counter,
                                             SQLServerColumnEncryptionAzureKeyVaultProvider azureProvider) throws SQLException {
        System.out.println("=== Phase 2b: AE non-enclave query (caching DOES work for this) ===");
        System.out.println("  Query: SELECT Description FROM " + cfg.qualifiedTable() + " WHERE Id = ?");
        System.out.println("  Azure delegate TTL at phase start: " + azureProvider.getColumnEncryptionKeyCacheTtl());

        runAeNonEnclaveLoop(conn, cfg, cfg.warmup);
        CountingKeyVaultProvider.Counts warmupCounts = counter.resetAndSnapshot();
        Duration ttlAfterWarmup = azureProvider.getColumnEncryptionKeyCacheTtl();
        java.util.SortedMap<String, Integer> warmupKv = KvOperationCounter.resetAndSnapshot();
        System.out.println("  After " + cfg.warmup + " warmup iteration(s):");
        System.out.println("    Provider counters: " + warmupCounts);
        System.out.println("    KV HTTP counts:    " + warmupKv);
        System.out.println("    Azure delegate TTL: " + ttlAfterWarmup
                + (Duration.ZERO.equals(ttlAfterWarmup) ? "  <-- per-query poison fired during warmup" : ""));

        long startNanos = System.nanoTime();
        runAeNonEnclaveLoop(conn, cfg, cfg.iterations);
        long elapsedNanos = System.nanoTime() - startNanos;

        CountingKeyVaultProvider.Counts measured = counter.resetAndSnapshot();
        System.out.println("  Measured " + cfg.iterations + " iterations");
        System.out.println("  Provider counters: " + measured + "  <-- decrypt=0 means symmetric cache hits, no KV");
        System.out.println("  KV HTTP counts:    " + KvOperationCounter.resetAndSnapshot());
        System.out.println("  Total elapsed: " + ms(elapsedNanos) + " (avg "
                + perOp(elapsedNanos, cfg.iterations) + " per query)");
        System.out.println();
        return elapsedNanos;
    }

    private static long phase3Enclave(Connection conn, ReproducerConfig cfg,
                                       CountingKeyVaultProvider counter,
                                       SQLServerColumnEncryptionAzureKeyVaultProvider azureProvider) throws SQLException {
        System.out.println("=== Phase 3: Enclave query (the bug) ===");
        System.out.println("  Query: SELECT Id FROM " + cfg.qualifiedTable() + " WHERE Description LIKE ?");
        System.out.println("  Azure delegate TTL at phase start: " + azureProvider.getColumnEncryptionKeyCacheTtl()
                + " (was poisoned by phase 2b — not restored)");

        runEnclaveLoop(conn, cfg, cfg.warmup);
        CountingKeyVaultProvider.Counts warmupCounts = counter.resetAndSnapshot();
        java.util.SortedMap<String, Integer> warmupKv = KvOperationCounter.resetAndSnapshot();
        System.out.println("  After " + cfg.warmup + " warmup iteration(s):");
        System.out.println("    Provider counters: " + warmupCounts);
        System.out.println("    KV HTTP counts:    " + warmupKv);

        long startNanos = System.nanoTime();
        int rows = runEnclaveLoop(conn, cfg, cfg.iterations);
        long elapsedNanos = System.nanoTime() - startNanos;

        CountingKeyVaultProvider.Counts measured = counter.resetAndSnapshot();
        Duration ttlAfter = azureProvider.getColumnEncryptionKeyCacheTtl();
        System.out.println("  Measured " + cfg.iterations + " iterations");
        System.out.println("  Provider counters: " + measured + "  <-- decrypt=" + cfg.iterations
                + " means the enclave path bypassed all caches");
        System.out.println("  KV HTTP counts:    " + KvOperationCounter.resetAndSnapshot());
        System.out.println("  Total elapsed: " + ms(elapsedNanos) + " (avg "
                + perOp(elapsedNanos, cfg.iterations) + " per query)");
        System.out.println("  Rows returned (last iteration): " + rows);
        System.out.println("  Azure delegate TTL: " + ttlAfter);
        System.out.println();
        return elapsedNanos;
    }

    private static void printSummary(ReproducerConfig cfg, long baselineNanos, long ae2bNanos, long enclaveNanos) {
        double avgBaseline = baselineNanos / (double) cfg.iterations;
        double avg2b = ae2bNanos / (double) cfg.iterations;
        double avgEnclave = enclaveNanos / (double) cfg.iterations;
        double aeDriverOverhead = avg2b - avgBaseline;
        double enclaveBypassOverhead = avgEnclave - avg2b;
        double totalRatio = avgEnclave / Math.max(avgBaseline, 1.0);

        System.out.println("=== Summary ===");
        System.out.printf("  Phase 2a — SQL floor (non-encrypted):       avg %s per query%n", perNanos(avgBaseline));
        System.out.printf("  Phase 2b — AE non-enclave (cache works):    avg %s per query  (%s vs 2a: AE driver overhead)%n",
                perNanos(avg2b), signedDelta(aeDriverOverhead));
        System.out.printf("  Phase 3  — AE enclave (the bug):            avg %s per query  (%s vs 2b: enclave-bypass KV cost)%n",
                perNanos(avgEnclave), signedDelta(enclaveBypassOverhead));
        System.out.println();
        System.out.printf("  Bug-attributable overhead per enclave query: ~%s%n", perNanos(enclaveBypassOverhead));
        System.out.println("    (this is pure Azure Key Vault round-trip cost; the KV HTTP counts in");
        System.out.println("     phase 3's measured loop show the precise breakdown — typically 1 key-get +");
        System.out.println("     1 unwrapkey + 1 verify per iteration, sometimes 2 key-get when the Azure");
        System.out.println("     SDK validates the key version before each crypto op)");
        System.out.printf("  Total slowdown vs SQL floor: %.1fx%n", totalRatio);
        System.out.println();
        System.out.println("The bug fires immediately on the first enclave query with an encrypted parameter:");
        System.out.println(" * Registration (phase 1) disables the Azure provider's CEK cache");
        System.out.println("   (SQLServerConnection.java:1511).");
        System.out.println(" * Even with the cache manually restored, the first AE query (phase 2b's warmup)");
        System.out.println("   re-poisons it: any non-enclave path to a CEK goes through");
        System.out.println("   SQLServerSymmetricKeyCache.getKey which calls");
        System.out.println("   provider.setColumnEncryptionCacheTtl(ZERO) (SQLServerSymmetricKeyCache.java:100).");
        System.out.println(" * Phase 2b is still fast because the symmetric key cache absorbs subsequent");
        System.out.println("   lookups for the same CEK — the bug doesn't surface here.");
        System.out.println(" * Phase 3 is slow because the enclave path's enclave-CEK lookup");
        System.out.println("   (ISQLServerEnclaveProvider.java:229) bypasses the symmetric cache and calls");
        System.out.println("   provider.decryptColumnEncryptionKey directly, hitting the disabled provider");
        System.out.println("   cache for every iteration.");
    }

    /**
     * Attaches a {@link FileHandler} to the MSSQL JDBC driver's root logger
     * ({@code com.microsoft.sqlserver.jdbc}) at {@link Level#FINER}. The handler writes to
     * {@code logPath} (relative paths resolve against the working directory) and does not
     * propagate to the console, so the reproducer's regular stdout output stays clean. The
     * resulting file is the "JDBC trace logs" artifact Microsoft asks for in their bug report
     * template — see
     * <a href="https://docs.microsoft.com/sql/connect/jdbc/tracing-driver-operation">the tracing
     * driver operation docs</a>.
     */
    private static void configureJdbcTraceLogging(String logPath) throws IOException {
        Path target = Paths.get(logPath).toAbsolutePath();
        Path parent = target.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.deleteIfExists(target);

        FileHandler handler = new FileHandler(target.toString(), false);
        handler.setFormatter(new SimpleFormatter());
        handler.setLevel(Level.FINER);

        Logger jdbcLogger = Logger.getLogger("com.microsoft.sqlserver.jdbc");
        jdbcLogger.setLevel(Level.FINER);
        jdbcLogger.addHandler(handler);
        jdbcLogger.setUseParentHandlers(false);

        System.out.println("[setup] capturing MSSQL JDBC trace at FINER -> " + target);
        System.out.println("[setup] (attach this file to the Microsoft bug report)");
    }

    /**
     * Resets the Azure delegate's CEK cache TTL to {@code target} if it differs from the current
     * value. Goes directly through the delegate so the restoration doesn't inflate the wrapper's
     * {@code setTtl} counter — which should reflect only driver-initiated writes.
     */
    private static void restoreTtl(SQLServerColumnEncryptionAzureKeyVaultProvider azureProvider,
                                    Duration target, String after) {
        Duration current = azureProvider.getColumnEncryptionKeyCacheTtl();
        if (!target.equals(current)) {
            azureProvider.setColumnEncryptionCacheTtl(target);
            System.out.println("[setup] TTL was " + current + " after " + after
                    + (Duration.ZERO.equals(current) ? "  <-- poison fired" : "")
                    + "; restored to " + target);
        }
    }

    /**
     * Idempotent seed: counts existing rows and inserts a handful only if the table is empty.
     * Uses {@link PreparedStatement} so the AE-aware JDBC driver encrypts the {@code Description}
     * parameter client-side — that's the only path that works for randomized-encrypted columns
     * (inline string literals trigger {@code Operand type clash}).
     */
    private static void ensureSeedData(Connection conn, ReproducerConfig cfg) throws SQLException {
        int existing;
        try (PreparedStatement count = conn.prepareStatement("SELECT COUNT(*) FROM " + cfg.qualifiedTable());
             ResultSet rs = count.executeQuery()) {
            rs.next();
            existing = rs.getInt(1);
        }
        if (existing > 0) {
            System.out.println("[seed] " + cfg.qualifiedTable() + " already has " + existing + " row(s), skipping");
            return;
        }

        List<String> rows = List.of("apple banana", "cherry date", "elderberry fig");
        try (PreparedStatement ins = conn.prepareStatement(
                "INSERT INTO " + cfg.qualifiedTable() + " (Description) VALUES (?)")) {
            for (String value : rows) {
                ins.setNString(1, value);
                ins.executeUpdate();
            }
        }
        System.out.println("[seed] inserted " + rows.size() + " row(s) into " + cfg.qualifiedTable());
    }

    private static void runBaselineLoop(Connection conn, int iterations) throws SQLException {
        for (int i = 0; i < iterations; i++) {
            try (PreparedStatement ps = conn.prepareStatement("SELECT 1");
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    rs.getInt(1);
                }
            }
        }
    }

    private static void runAeNonEnclaveLoop(Connection conn, ReproducerConfig cfg, int iterations) throws SQLException {
        for (int i = 0; i < iterations; i++) {
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT Description FROM " + cfg.qualifiedTable() + " WHERE Id = ?")) {
                ps.setInt(1, 1);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        rs.getNString(1);
                    }
                }
            }
        }
    }

    private static int runEnclaveLoop(Connection conn, ReproducerConfig cfg, int iterations) throws SQLException {
        int rows = 0;
        for (int i = 0; i < iterations; i++) {
            rows = runEnclaveQuery(conn, cfg, "%a%");
        }
        return rows;
    }

    private static int runEnclaveQuery(Connection conn, ReproducerConfig cfg, String likeParam) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT Id FROM " + cfg.qualifiedTable() + " WHERE Description LIKE ?")) {
            ps.setNString(1, likeParam);
            int rows = 0;
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    rs.getInt(1);
                    rows++;
                }
            }
            return rows;
        }
    }

    private static String ms(long nanos) {
        return String.format("%.1f ms", nanos / 1_000_000.0);
    }

    private static String perOp(long totalNanos, int ops) {
        return perNanos(totalNanos / (double) ops);
    }

    private static String perNanos(double nanos) {
        return String.format("%.1f ms", nanos / 1_000_000.0);
    }

    /** Signed millisecond delta with a unary sign in front: "+12.3 ms", "-2.1 ms", "+0.0 ms". */
    private static String signedDelta(double nanos) {
        double ms = nanos / 1_000_000.0;
        return String.format("%+.1f ms", ms);
    }
}
