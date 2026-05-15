package com.parkdots.repro;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Loads configuration from {@code reproducer.properties} (or a path passed via
 * {@code -Dreproducer.config=...}), with environment-variable overrides. An env var whose name
 * is the property key uppercased with dots replaced by underscores wins over the file. For
 * example, {@code JDBC_PASSWORD} overrides {@code jdbc.password}.
 */
final class ReproducerConfig {

    final String jdbcUrl;
    final String jdbcUser;
    final String jdbcPassword;
    final String keyVaultClientId;
    final String keyVaultClientSecret;
    final String schema;
    final String table;
    final int iterations;
    final int warmup;
    final boolean captureJdbcTrace;
    final String jdbcTraceLogPath;

    private ReproducerConfig(Properties p) {
        this.jdbcUrl = require(p, "jdbc.url");
        this.jdbcUser = require(p, "jdbc.user");
        this.jdbcPassword = require(p, "jdbc.password");
        this.keyVaultClientId = require(p, "keyvault.clientId");
        this.keyVaultClientSecret = require(p, "keyvault.clientSecret");
        this.schema = p.getProperty("repro.schema", "dbo");
        this.table = p.getProperty("repro.table", "EnclaveCachingRepro");
        this.iterations = Integer.parseInt(p.getProperty("repro.iterations", "100"));
        this.warmup = Integer.parseInt(p.getProperty("repro.warmup", "2"));
        this.captureJdbcTrace = Boolean.parseBoolean(p.getProperty("repro.captureJdbcTrace", "false"));
        this.jdbcTraceLogPath = p.getProperty("repro.jdbcTraceLogPath", "mssql-jdbc-trace.log");
    }

    static ReproducerConfig load() throws IOException {
        Properties p = new Properties();
        Path path = Path.of(System.getProperty("reproducer.config", "reproducer.properties"));
        if (Files.exists(path)) {
            try (InputStream in = Files.newInputStream(path)) {
                p.load(in);
            }
            System.out.println("[config] loaded " + path.toAbsolutePath());
        } else {
            System.out.println("[config] " + path + " not found; relying on environment variables only");
        }
        applyEnvOverrides(p);
        return new ReproducerConfig(p);
    }

    private static void applyEnvOverrides(Properties p) {
        for (String key : new String[]{
                "jdbc.url", "jdbc.user", "jdbc.password",
                "keyvault.clientId", "keyvault.clientSecret",
                "repro.schema", "repro.table", "repro.iterations", "repro.warmup",
                "repro.captureJdbcTrace", "repro.jdbcTraceLogPath"
        }) {
            String envName = key.toUpperCase().replace('.', '_');
            String envValue = System.getenv(envName);
            if (envValue != null && !envValue.isBlank()) {
                p.setProperty(key, envValue);
            }
        }
    }

    private static String require(Properties p, String key) {
        String v = p.getProperty(key);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException(
                    "Required property '" + key + "' is missing. " +
                    "Set it in reproducer.properties or via env var " + key.toUpperCase().replace('.', '_'));
        }
        return v;
    }

    String qualifiedTable() {
        return "[" + schema + "].[" + table + "]";
    }
}
