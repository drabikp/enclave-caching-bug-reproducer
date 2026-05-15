-- ============================================================================
-- Schema setup for the enclave-caching bug reproducer
-- ============================================================================
-- Prerequisites:
--   * SQL Server 2019+ with Always Encrypted with secure enclaves enabled,
--     OR Azure SQL Database Business Critical / Premium with Intel SGX.
--   * Attestation configured (Azure Attestation or Host Guardian Service).
--   * An Azure Key Vault key, with the AAD principal (used by the reproducer)
--     granted: get, unwrapKey, verify, sign.
--   * A Column Master Key with ENCLAVE_COMPUTATIONS already registered, and a
--     Column Encryption Key encrypted with it. The CMK SIGNATURE and CEK
--     ENCRYPTED_VALUE are pre-computed using PowerShell or SSMS — they are
--     NOT shown literally below because they are environment-specific.
--
-- The easiest way to create the CMK and CEK is via PowerShell's SqlServer
-- module (see the snippet at the bottom of this file).
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Step 1: Create the Column Master Key (CMK)
-- ----------------------------------------------------------------------------
-- Replace KEY_PATH with the URL of your CMK key in Azure Key Vault.
-- Replace SIGNATURE with the signature blob generated when ENCLAVE_COMPUTATIONS
-- is enabled. PowerShell snippet below produces both.
--
-- CREATE COLUMN MASTER KEY [ReproCMK]
-- WITH (
--     KEY_STORE_PROVIDER_NAME = N'AZURE_KEY_VAULT',
--     KEY_PATH = N'https://<vault>.vault.azure.net/keys/<keyname>/<version>',
--     ENCLAVE_COMPUTATIONS (SIGNATURE = 0x<hex-from-powershell>)
-- );

-- ----------------------------------------------------------------------------
-- Step 2: Create the Column Encryption Key (CEK)
-- ----------------------------------------------------------------------------
-- ENCRYPTED_VALUE is produced when the CEK is created with the
-- New-SqlColumnEncryptionKey cmdlet in PowerShell.
--
-- CREATE COLUMN ENCRYPTION KEY [ReproCEK]
-- WITH VALUES (
--     COLUMN_MASTER_KEY = [ReproCMK],
--     ALGORITHM = 'RSA_OAEP',
--     ENCRYPTED_VALUE = 0x<hex-from-powershell>
-- );

-- ----------------------------------------------------------------------------
-- Step 3: Create the table
-- ----------------------------------------------------------------------------
-- The Description column uses RANDOMIZED encryption with a BIN2 collation,
-- which is what enables enclave-based LIKE/range predicates.
IF OBJECT_ID('dbo.EnclaveCachingRepro', 'U') IS NOT NULL DROP TABLE dbo.EnclaveCachingRepro;
GO

CREATE TABLE dbo.EnclaveCachingRepro (
    Id          INT IDENTITY(1, 1) PRIMARY KEY,
    Description NVARCHAR(200) COLLATE Latin1_General_BIN2
        ENCRYPTED WITH (
            ENCRYPTION_TYPE = RANDOMIZED,
            ALGORITHM       = 'AEAD_AES_256_CBC_HMAC_SHA_256',
            COLUMN_ENCRYPTION_KEY = [ReproCEK]
        ) NOT NULL
);
GO

-- ----------------------------------------------------------------------------
-- Step 4: Seed data
-- ----------------------------------------------------------------------------
-- DO NOT seed with inline literals here.
--   INSERT INTO ... VALUES (N'apple banana')  -- triggers "Operand type clash"
-- because Always Encrypted columns require client-side encryption, which only
-- happens for parameter values (not for SQL literals). To seed manually you
-- would need a parameterized INSERT executed by an AE-aware client.
--
-- The reproducer handles this automatically: on its first run, if the table
-- is empty, it inserts three rows via a JDBC PreparedStatement (the driver
-- encrypts the parameter client-side using the registered AKV provider).
-- Subsequent runs see the rows and skip seeding.

-- ============================================================================
-- PowerShell helper (run from the client, requires the SqlServer module
-- and Az.KeyVault module — both available from the PowerShell Gallery).
-- ============================================================================
/*
$server = "<server>.database.windows.net"
$database = "<database>"
$vaultName = "<your-vault>"
$keyName = "<your-key>"

# 1) Open a SQL connection with full access
$connectionString = "Server=$server;Database=$database;Authentication=Active Directory Integrated;TrustServerCertificate=False;Encrypt=True"
$database = (Get-SqlDatabase -ServerInstance $server -DatabaseName $database)

# 2) Create the CMK settings pointing to the AKV key, with enclave signature
$cmkPath = "Azure Key Vault/$vaultName/$keyName"
$cmkSettings = New-SqlAzureKeyVaultColumnMasterKeySettings -KeyURL "https://$vaultName.vault.azure.net/keys/$keyName" -AllowEnclaveComputations

# 3) Create the CMK in the database
New-SqlColumnMasterKey -Name "ReproCMK" -InputObject $database -ColumnMasterKeySettings $cmkSettings

# 4) Create the CEK
New-SqlColumnEncryptionKey -Name "ReproCEK" -InputObject $database -ColumnMasterKey "ReproCMK"
*/
