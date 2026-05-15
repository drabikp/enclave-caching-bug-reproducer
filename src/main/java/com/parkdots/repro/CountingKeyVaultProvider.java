package com.parkdots.repro;

import com.microsoft.sqlserver.jdbc.SQLServerColumnEncryptionAzureKeyVaultProvider;
import com.microsoft.sqlserver.jdbc.SQLServerColumnEncryptionKeyStoreProvider;
import com.microsoft.sqlserver.jdbc.SQLServerException;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thin wrapper around {@link SQLServerColumnEncryptionAzureKeyVaultProvider} that counts JDBC
 * provider invocations. It performs <b>no caching of its own</b> — the point is to observe how
 * many times the driver reaches into the provider and whether the driver's poison calls fire.
 *
 * <p><b>Important:</b> this wrapper <b>must</b> propagate {@link #setColumnEncryptionCacheTtl}
 * calls to the delegate. The abstract base's implementation is an empty no-op, so without an
 * explicit override-and-forward the driver's two poison calls
 * ({@code provider.setColumnEncryptionCacheTtl(Duration.ZERO)} from
 * {@code SQLServerConnection.java:1511} and {@code SQLServerSymmetricKeyCache.java:100}, the
 * latter reached from both the non-enclave path <i>and</i> the enclave path via
 * {@code ISQLServerEnclaveProvider.java:262}) would never reach the wrapped Azure provider.
 * The wrapper would then accidentally shield the bug it is meant to expose — phase 3's enclave
 * latency would collapse to phase 2's baseline. That shielding is exactly the mechanism the
 * production {@code CachingKeyVaultProvider} in {@code encryption-support} uses to <i>fix</i>
 * the bug; here we deliberately undo it to expose the bug.
 */
final class CountingKeyVaultProvider extends SQLServerColumnEncryptionKeyStoreProvider {

    private final SQLServerColumnEncryptionAzureKeyVaultProvider delegate;
    final AtomicInteger decryptCount = new AtomicInteger();
    final AtomicInteger encryptCount = new AtomicInteger();
    final AtomicInteger verifyCount = new AtomicInteger();
    final AtomicInteger setTtlCount = new AtomicInteger();
    private volatile String name = "AZURE_KEY_VAULT";

    CountingKeyVaultProvider(SQLServerColumnEncryptionAzureKeyVaultProvider delegate) {
        this.delegate = delegate;
    }

    /** Snapshots and clears all counters (per-counter atomic; the snapshot is sequential). */
    Counts resetAndSnapshot() {
        return new Counts(
                decryptCount.getAndSet(0),
                encryptCount.getAndSet(0),
                verifyCount.getAndSet(0),
                setTtlCount.getAndSet(0));
    }

    /** Returns the wrapped Azure provider so callers can inspect its TTL state directly. */
    SQLServerColumnEncryptionAzureKeyVaultProvider delegate() {
        return delegate;
    }

    @Override
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public byte[] decryptColumnEncryptionKey(String masterKeyPath, String encryptionAlgorithm, byte[] encryptedCek)
            throws SQLServerException {
        decryptCount.incrementAndGet();
        return delegate.decryptColumnEncryptionKey(masterKeyPath, encryptionAlgorithm, encryptedCek);
    }

    @Override
    public byte[] encryptColumnEncryptionKey(String masterKeyPath, String encryptionAlgorithm, byte[] cek)
            throws SQLServerException {
        encryptCount.incrementAndGet();
        return delegate.encryptColumnEncryptionKey(masterKeyPath, encryptionAlgorithm, cek);
    }

    @Override
    public boolean verifyColumnMasterKeyMetadata(String masterKeyPath, boolean allowEnclaveComputations,
                                                  byte[] signature) throws SQLServerException {
        verifyCount.incrementAndGet();
        return delegate.verifyColumnMasterKeyMetadata(masterKeyPath, allowEnclaveComputations, signature);
    }

    /**
     * Forwards the TTL setter to the delegate. The driver's poison call
     * ({@code setColumnEncryptionCacheTtl(Duration.ZERO)} from
     * {@code SQLServerSymmetricKeyCache.getKey}) lands here; we count it and propagate so that
     * the Azure provider's internal CEK cache is actually disabled — which is the point of this
     * reproducer.
     */
    @Override
    public void setColumnEncryptionCacheTtl(Duration duration) {
        setTtlCount.incrementAndGet();
        delegate.setColumnEncryptionCacheTtl(duration);
    }

    /**
     * Forwards the TTL getter to the delegate so callers see the delegate's actual TTL state.
     * Used by the reproducer to observe the transition from {@code PT2H} to {@code PT0S} when
     * the driver's poison call fires.
     */
    @Override
    public Duration getColumnEncryptionKeyCacheTtl() {
        return delegate.getColumnEncryptionKeyCacheTtl();
    }

    record Counts(int decrypt, int encrypt, int verify, int setTtl) {}
}
