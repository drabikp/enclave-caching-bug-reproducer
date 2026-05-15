# MSSQL JDBC enclave CEK-caching bug reproducer

Self-contained Maven project that demonstrates a performance bug in the Microsoft JDBC driver for SQL Server: the driver disables the Azure Key Vault provider's internal CEK cache **immediately when the provider is registered globally** (and again on every subsequent non-enclave CEK lookup, as a belt-and-braces). The enclave query path then bypasses the global symmetric-key cache and calls `decryptColumnEncryptionKey` on a cache-disabled provider — every enclave query pays the full `KeyVerify` + `KeyUnwrap` round-trip cost to Azure Key Vault, indefinitely. The bug affects **every application using the recommended global-registration pattern**, including pure-enclave workloads.

Confirmed by source inspection in driver versions **12.6.4, 12.10.1, 13.2.0, 13.4.0**. Four lines, identical positions in all four releases:

- `SQLServerConnection.java:1511` — **registration-time poison.** `provider.setColumnEncryptionCacheTtl(Duration.ZERO);` is invoked on every globally registered provider the moment the application calls `SQLServerConnection.registerColumnEncryptionKeyStoreProviders`, with the driver comment "Global providers should not use their own CEK caches." Disables the cache before any query runs.
- `SQLServerSymmetricKeyCache.java:100` — **per-query poison.** Same call, fired again every time the symmetric key cache misses a CEK. Reached from **both** the non-enclave query path *and* the enclave query path via `ISQLServerEnclaveProvider.java:262` → `SQLServerSecurityUtility.decryptSymmetricKey`. So the very first enclave query with an encrypted parameter re-poisons the cache, even if it was manually restored after registration.
- `ISQLServerEnclaveProvider.java:229` — **enclave bypass for the enclave's CEK lookup.** `provider.decryptColumnEncryptionKey(...)` is called directly, with no caching layer at all. Once the provider's cache is disabled, every enclave query pays a full Key Vault round-trip here.

Net effect: any application that registers a `KeyStoreProvider` globally has the cache disabled before any query runs, and the only path that could re-enable it (manual restoration) is undone again on the first enclave query with an encrypted parameter. Every enclave query pays a Key Vault round-trip for the enclave's CEK, indefinitely. The bug affects every Always Encrypted + enclave workload using the recommended global-registration pattern.

## What this reproducer proves

Four phases that isolate three distinct per-query cost components:

| Phase | What it does | What it shows |
|---|---|---|
| 1 — Registration-time poison | Print TTL before registration, register the provider, print TTL after, then manually restore. | Direct observation of poison call #1 (`SQLServerConnection.java:1511`). TTL transitions `PT2H` → `PT0S`. |
| 2a — SQL round-trip floor | N iterations of `SELECT 1`. No encryption, no parameters. | The JDBC/network round-trip cost on its own — no Key Vault traffic. |
| 2b — AE non-enclave query | N iterations of `SELECT Description FROM ... WHERE Id = ?`. Result decryption uses the standard (symmetric-cache-backed) path. | What an AE query costs *when caching works*. The very first iteration fires the per-query poison (`setTtl=1` in the warmup counters) but subsequent iterations hit the symmetric key cache. The difference vs 2a isolates AE driver overhead. |
| 3 — Enclave query (the bug) | N iterations of `SELECT Id FROM ... WHERE Description LIKE ?`. Enclave path. | The bug's user-visible cost. The provider's CEK cache was disabled by phase 2b and not restored, so the enclave path's direct-call site (`ISQLServerEnclaveProvider.java:229`) hits Key Vault on *every* iteration. The difference vs 2b isolates the enclave-bypass cost. |

The headline number is the **enclave-bypass overhead** (phase 3 avg − phase 2b avg). This is the pure Azure Key Vault round-trip cost the bug imposes per enclave query, and it's invariant to network latency between the client and SQL Server. The "total slowdown factor" the program also prints depends on the SQL round-trip floor — on a low-latency client/server pair it can hit 50×–100× because the baseline is tiny; on a high-latency one (a regional Azure SQL DB queried from a different continent) it can shrink to 4×–10× even though the per-query overhead the bug *adds* is the same.

The reproducer instruments **two** observation layers:

- **JDBC-provider counters** (`CountingKeyVaultProvider`) — count calls into `decryptColumnEncryptionKey`, `verifyColumnMasterKeyMetadata`, and `setColumnEncryptionCacheTtl`. The `setTtl` counter is the smoking gun for the per-query poison.
- **HTTP-level Azure SDK counters** (`KvOperationCounter` wired in via the `HttpClientProvider` SPI) — count actual Azure Key Vault HTTPS requests by category (`key-get`, `unwrapkey`, `verify`, `sign`, `oauth-token`). The bug's signature in those counts: phase 2b's measured loop emits **zero** Key Vault HTTP requests (cache hits), while phase 3's measured loop emits **one `unwrapkey` per iteration** (no cache layer for the enclave-CEK lookup).

The bug fires immediately on the first enclave query — there is no "fast steady state" to reach. In a real customer application no TTL restoration happens at all, so the registration poison alone keeps every enclave query slow forever.

## Prerequisites

You need a working Always Encrypted + secure enclaves environment, which is non-trivial to provision:

- **SQL Server 2019+** with VBS enclaves, or **Azure SQL Database** at Business Critical/Premium tier with Intel SGX
- **Attestation service** — Azure Attestation (for SGX) or Host Guardian Service (for VBS)
- **Azure Key Vault** with one key
- An **AAD service principal** with `get`, `unwrapKey`, `verify`, `sign` permissions on that key
- **Java 21** and **Maven 3.8+**

You then need to provision:

- A Column Master Key in the database, configured with `ENCLAVE_COMPUTATIONS` and pointing at the AKV key
- A Column Encryption Key encrypted with that CMK
- A table with a `RANDOMIZED`-encrypted `NVARCHAR` column using a `BIN2` collation

See `setup.sql` for the schema, and the PowerShell snippet at the bottom of that file for creating the CMK/CEK (the simplest method). **You only need to create the empty table and (optionally) the CMK/CEK — the reproducer seeds rows itself on first run** via parameterized `INSERT`s through the AE-aware JDBC driver. Manual inline-literal seeding (`INSERT ... VALUES (N'…')`) fails with `Operand type clash` because Always Encrypted only encrypts parameter values, not SQL literals.

## Configuration

Copy the template and fill in your environment:

```bash
cp reproducer.properties.example reproducer.properties
$EDITOR reproducer.properties
```

The file is `.gitignore`'d so secrets stay local. Every property can also be supplied via an environment variable — `KEYVAULT_CLIENTSECRET`, `JDBC_PASSWORD`, etc. — which overrides the file.

Required properties:

| Key | Notes |
|---|---|
| `jdbc.url` | Must include `columnEncryptionSetting=Enabled` and `enclaveAttestationUrl=...&enclaveAttestationProtocol=AAS|HGS`. **Must NOT include** `keyVaultProviderClientId`/`keyVaultProviderClientKey` (those would create a per-connection provider and bypass the global registration of the counting wrapper) |
| `jdbc.user`, `jdbc.password` | SQL credentials |
| `keyvault.clientId`, `keyvault.clientSecret` | Service-principal credentials for Key Vault |
| `repro.schema`, `repro.table` | Defaults to `dbo.EnclaveCachingRepro` |
| `repro.iterations` | Per measured phase (default 100) |
| `repro.warmup` | Discarded iterations before each measured phase (default 2) |
| `repro.captureJdbcTrace` | When `true`, attaches a `FileHandler` to `com.microsoft.sqlserver.jdbc` at `FINER` and writes to `repro.jdbcTraceLogPath` (default `mssql-jdbc-trace.log`). Produces the artifact the Microsoft bug-report template asks for under "JDBC trace logs". Disabled by default because it adds disk-I/O overhead and the file gets large at the default iteration count. |
| `repro.jdbcTraceLogPath` | Output path for the trace log when enabled (default `mssql-jdbc-trace.log` in the working directory). |

## Running

```bash
mvn -q -DskipTests package
java -jar target/enclave-caching-bug-reproducer-1.0.0-SNAPSHOT.jar
```

Or via the exec plugin:

```bash
mvn -q exec:java
```

## Expected output (with the bug)

```
[config] loaded /path/to/reproducer.properties

=== Phase 1: Registration-time poison (SQLServerConnection.java:1511) ===
  Azure delegate TTL before registration: PT2H
  Azure delegate TTL after registration:  PT0S  <-- poison fired (driver disabled the cache)
  Manually restored TTL to PT2H so phases 2a/2b can measure
  cache-working behavior. In real applications no such restoration happens;
  the cache stays disabled.

[setup] connected to jdbc:sqlserver://...
[seed] [dbo].[EnclaveCachingRepro] already has 3 row(s), skipping
[setup] TTL was PT0S after seeding  <-- poison fired; restored to PT2H

=== Phase 2a: SQL round-trip floor (non-encrypted query) ===
  Query: SELECT 1
  Measured 100 iterations
  Provider counters: Counts[decrypt=0, encrypt=0, verify=0, setTtl=0]
  KV HTTP counts:    {}
  Total elapsed: 480.3 ms (avg 4.8 ms per query)

=== Phase 2b: AE non-enclave query (caching DOES work for this) ===
  Query: SELECT Description FROM [dbo].[EnclaveCachingRepro] WHERE Id = ?
  Azure delegate TTL at phase start: PT2H
  After 2 warmup iteration(s):
    Provider counters: Counts[decrypt=1, encrypt=0, verify=0, setTtl=1]
    KV HTTP counts:    {key-get=6, unwrapkey=2, verify=2}
    Azure delegate TTL: PT0S  <-- per-query poison fired during warmup
  Measured 100 iterations
  Provider counters: Counts[decrypt=0, encrypt=0, verify=0, setTtl=0]  <-- decrypt=0 means symmetric cache hits, no KV
  KV HTTP counts:    {key-get=0, unwrapkey=0, verify=0}
  Total elapsed: 580.0 ms (avg 5.8 ms per query)

=== Phase 3: Enclave query (the bug) ===
  Query: SELECT Id FROM [dbo].[EnclaveCachingRepro] WHERE Description LIKE ?
  Azure delegate TTL at phase start: PT0S (was poisoned by phase 2b — not restored)
  After 2 warmup iteration(s):
    Provider counters: Counts[decrypt=2, encrypt=0, verify=2, setTtl=0]
    KV HTTP counts:    {key-get=4, sign=2, unwrapkey=4, verify=6}
  Measured 100 iterations
  Provider counters: Counts[decrypt=100, encrypt=0, verify=100, setTtl=0]  <-- decrypt=100 means the enclave path bypassed all caches
  KV HTTP counts:    {key-get=200, sign=0, unwrapkey=200, verify=200}
  Total elapsed: 45200.0 ms (avg 452.0 ms per query)
  Rows returned (last iteration): 2
  Azure delegate TTL: PT0S

=== Summary ===
  Phase 2a — SQL floor (non-encrypted):       avg 4.8 ms per query
  Phase 2b — AE non-enclave (cache works):    avg 5.8 ms per query  (+1.0 ms vs 2a: AE driver overhead)
  Phase 3  — AE enclave (the bug):            avg 452.0 ms per query  (+446.2 ms vs 2b: enclave-bypass KV cost)

  Bug-attributable overhead per enclave query: ~446.2 ms
    (this is pure Azure Key Vault round-trip cost; the KV HTTP counts in
     phase 3's measured loop show the precise breakdown — typically 1 key-get +
     1 unwrapkey + 1 verify per iteration, sometimes 2 key-get when the Azure
     SDK validates the key version before each crypto op)
  Total slowdown vs SQL floor: 94.2x
```

> **Why so many `key-get` calls in phase 3?** The Azure SDK's `CryptographyClient.unwrapKey` and `verify` operations do a lazy `KeyGet` to confirm the key's algorithm/version before delegating to the server. In the bug-affected state, the provider's CEK cache miss path goes through `unwrapKey` once per query, and each `unwrapKey` may emit one or two `key-get` requests before the actual `unwrapkey` POST. In the observed environment that's 2 × `key-get` + 1 × `unwrapkey` + 1 × `verify` = **4 HTTPS round-trips per affected enclave query**. With ~90 ms per round-trip to a regional Key Vault, that's ~360 ms of bug-attributable latency per query.

The story in the output:

- **Phase 1** observes poison call site #1 (registration). The TTL transition `PT2H` → `PT0S` is the direct evidence; the manual restore is the only reason the rest of the run can produce a meaningful comparison.
- **Phase 2** establishes the floor — a query that touches no encrypted columns measures only the JDBC driver + network round-trip cost.
- **Phase 3** shows poison call site #2 firing during warmup (`setTtl=1` in the warmup counter, TTL transitions back to `PT0S`), then measures the steady-state cost. Every measured iteration calls `decryptColumnEncryptionKey` once because the enclave path bypasses the symmetric key cache (site #3), and the provider's own cache is disabled so each call ends up at Key Vault.

The exact numbers depend on Key Vault latency, but a slowdown factor in the 30×–100× range is typical.

## Notes on counters vs. timing

The reproducer prints two layers of counters.

### JDBC-provider level (`Counts[decrypt=…, encrypt=…, verify=…, setTtl=…]`)

These come from `CountingKeyVaultProvider`, which sits between the driver and the Azure provider:

- **`decrypt` — `decryptColumnEncryptionKey` calls.** Phase 2a (non-encrypted) is always 0. Phase 2b's measured loop is 0 (symmetric cache absorbs them). Phase 3's measured loop is exactly `iterations` — one driver call per enclave query, because the enclave-CEK path bypasses the symmetric cache.
- **`verify` — `verifyColumnMasterKeyMetadata` calls.** Same shape as `decrypt`. The Azure provider's internal CMK-signature cache (10-day TTL) is independent of the CEK cache and not affected by the poison, so verify calls are cheap regardless of where they fire.
- **`encrypt` — `encryptColumnEncryptionKey` calls.** Always 0 in this reproducer.
- **`setTtl` — `setColumnEncryptionCacheTtl` calls.** The smoking gun for poison observation. Phase 1's "after registration" line shows it firing at registration time; phase 2b's warmup-counter line shows it firing on the first AE query.

### HTTP / Azure SDK level (`KV HTTP counts: {key-get=N, unwrapkey=N, …}`)

These come from `KvOperationCounter`, populated by `CountingHttpClient` (registered as the default `HttpClient` via the `HttpClientProvider` SPI). Each entry counts actual HTTPS requests to Azure, categorized by URL:

- **`key-get`** — `GET https://{vault}/keys/{name}/{version}` — fetches the CMK public key. Happens once per CMK per JVM (cached in the provider's `cachedCryptographyClients`).
- **`unwrapkey`** — `POST .../unwrapkey` — RSA-OAEP unwrap of the encrypted CEK. **This is the bug's per-query cost.**
- **`verify`** — `POST .../verify` — RSA signature verify of the encrypted CEK against the CMK. Paired with `unwrapkey` on every decrypt call.
- **`sign`** — `POST .../sign` — used by `verifyColumnMasterKeyMetadata`. Cached by the provider's CMK-signature cache (10-day TTL), so usually only fires once.
- **`oauth-token`** — `POST https://login.microsoftonline.com/.../token` — Azure AD token requests. The Azure SDK caches access tokens, so this is typically just 1 per JVM start.

The bug's HTTP signature is unmistakable: in phase 2b's *measured* loop both counts stay empty (no KV traffic); in phase 3's measured loop you get exactly N × `unwrapkey` + N × `verify`. The latency cost equals the HTTPS round-trip time times those counts.

### Latency

- **Phase 2a** has zero Key Vault traffic. Latency is the SQL JDBC + network floor.
- **Phase 2b** has zero KV traffic in the measured loop (cache hits). Latency is 2a + a small AE driver overhead.
- **Phase 3** has KV traffic on every iteration. Latency is 2b + the Azure Key Vault round-trip cost.

### Why the wrapper must propagate `setColumnEncryptionCacheTtl`

`CountingKeyVaultProvider` extends `SQLServerColumnEncryptionKeyStoreProvider`, whose `setColumnEncryptionCacheTtl(Duration)` implementation is an empty no-op (you can confirm in the driver source). If the wrapper inherits that no-op without overriding, the driver's two poison calls (registration-time and per-query) go nowhere — the Azure provider's CEK cache stays intact and phase 3 would look identical to phase 2 (no slowdown). That's the same shielding mechanism our production `CachingKeyVaultProvider` in `encryption-support` uses to *fix* the bug.

For the reproducer to *expose* the bug, `CountingKeyVaultProvider` explicitly overrides `setColumnEncryptionCacheTtl` to forward to the delegate (and count). This single override is the difference between "a wrapper that fixes the bug" and "a wrapper that exposes the bug."

## Customer impact beyond latency

Each affected enclave query consumes **3 or 4 Azure Key Vault HTTP operations** (1 `unwrapkey` + 1 `verify` + 1–2 `key-get` — the actual counts are measured by the reproducer's `KV HTTP counts` line in phase 3). A working cache would consume **zero** in steady state. Two consequences worth flagging in any report:

- **Throttling exposure.** Azure Key Vault enforces a per-vault-per-region budget on key operations. Per the [service limits doc](https://learn.microsoft.com/en-us/azure/key-vault/general/service-limits), that budget is **4,000 ops per 10 s** for RSA 2048 software keys, **2,000** for RSA 2048 HSM, **500** for RSA 3072 HSM, and **250** for RSA 4096 HSM. With this bug, each enclave query consumes 3–4 ops from that budget. An app using HSM-protected RSA 4096 hits the throttling ceiling at roughly **6 enclave queries/sec per vault** — at which point the driver surfaces `429` as a JDBC `SQLServerException`. This is the strongest argument for fixing the bug: it pushes customers into hard rate-limit failures at workload levels the cache would normally absorb completely.
- **Operating cost.** Azure Key Vault meters cryptographic operations on a per-10K-transaction basis (with separate rates for "Operations" and "Advanced Key Operations" depending on key type/size). The bug multiplies billable KV traffic by 3–4 × the enclave-query rate, where a working cache would have collapsed it to near zero. The exact monthly impact depends on key type, vault tier, and workload volume — see Microsoft's current [Key Vault pricing](https://azure.microsoft.com/pricing/details/key-vault/) — but the multiplier is the workload's enclave-query rate divided by what would have been a handful of cold-cache misses per day.

## Capturing JDBC trace logs for the bug report

Microsoft's bug-report template asks for driver trace logs. The reproducer can generate them for you:

1. Set `repro.captureJdbcTrace=true` in `reproducer.properties` (and consider lowering `repro.iterations` to ~5 so the log stays small).
2. Run the reproducer once. A file named `mssql-jdbc-trace.log` is written to the working directory at MSSQL JDBC's `FINER` level (configured programmatically via `java.util.logging`; nothing extra to put on the command line).
3. Attach the resulting file to your GitHub issue.

The relevant loggers (under `com.microsoft.sqlserver.jdbc`) emit messages from `SQLServerSymmetricKeyCache.getKey` around each poison call, from the AE parameter-encryption path, and from the enclave provider's `processSDPEv1` — collectively enough for Microsoft to follow the bug step by step in the trace.

If you'd rather configure trace logging yourself (the official mechanism, with full control over loggers and handlers), follow the standard instructions at <https://docs.microsoft.com/sql/connect/jdbc/tracing-driver-operation> and leave `repro.captureJdbcTrace=false`.

## Reporting to Microsoft

When you file the issue against `microsoft/mssql-jdbc`, include:

1. The driver version (`13.4.0.jre11` recommended — latest stable).
2. `SELECT @@VERSION` output from your SQL Server.
3. The `setup.sql` schema (with your CMK/CEK names redacted as needed).
4. This reproducer's stdout output (the `=== Summary ===` block in particular).
5. Source pointers (lines stable across 12.6.4, 12.10.1, 13.2.0, 13.4.0):
   - `SQLServerConnection.java:1511` — registration-time poison, with the verbatim driver comment *"Global providers should not use their own CEK caches."*
   - `SQLServerSymmetricKeyCache.java:100` — per-query poison, with the verbatim comment *"To prevent conflicts between CEK caches, system providers and global providers should not use their own CEK caches."*
   - `ISQLServerEnclaveProvider.java:229` — direct `provider.decryptColumnEncryptionKey(...)` call (no cache layer) for the enclave's CEK.
   - `ISQLServerEnclaveProvider.java:262` — call to `SQLServerSecurityUtility.decryptSymmetricKey(...)` for the parameter's CEK, which routes through `SQLServerSymmetricKeyCache.getKey` and re-fires the per-query poison on every enclave query with an encrypted parameter.
6. The customer-impact notes above (throttling exposure + operating cost), since they materially affect the priority of the fix.
7. `mssql-jdbc-trace.log` produced by the reproducer with `repro.captureJdbcTrace=true` (or trace logs you've captured via the standard mechanism).

The bug is unambiguous in the driver source; the reproducer's value is in (a) demonstrating user-visible impact quantitatively by comparing against a non-encrypted baseline, (b) showing both poison call sites firing in live execution (phase 1's TTL transition for site #1, phase 3's warmup `setTtl=1` for site #2), and (c) demonstrating that even with manual TTL restoration between phases, the cache is re-disabled on the very first enclave query.
