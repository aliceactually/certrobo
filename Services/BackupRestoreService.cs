using CertRobo.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertRobo.Services;

public sealed record StateBackupWithRootCaPkcs12Result(
    byte[] ArchiveBytes,
    int ExportedAuthorityId,
    string ExportedAuthorityName,
    string Pkcs12EntryPath,
    string GeneratedPkcs12Passphrase);

/// <summary>
/// Provides consistent online backup and restore of the SQLite database, encrypted CA signing key(s),
/// and ASP.NET Core DataProtection key ring, plus optional Administrator-authorized inclusion of a
/// Diceware-protected Root CA PKCS#12 artifact inside the state backup archive.
/// </summary>
public sealed class BackupRestoreService(
    IDbContextFactory<CertRoboDbContext> dbFactory,
    CaKeyCustodyOptions caOptions,
    CertificateAuthorityService? caService = null,
    IServiceScopeFactory? scopeFactory = null)
{
    public const int RootCaPkcs12IterationCount = 100_000;

    public async Task<byte[]> CreateConsistentBackupArchiveAsync(
        string sqliteFilePath,
        string dataProtectionKeysDir,
        CancellationToken cancellationToken = default)
    {
        string tempSnapshotDb = Path.Combine(Path.GetTempPath(), $"certrobo-backup-{Guid.NewGuid():N}.db");
        IAsyncDisposable lifecycleLock = await CertificateAuthorityService.AcquireLifecycleLockAsync(
            caOptions.StorageDirectory,
            cancellationToken,
            TimeSpan.FromMilliseconds(Math.Max(100, caOptions.CrossProcessLockTimeoutMs)));
        try
        {
            return await CreateBackupZipCoreAsync(
                sqliteFilePath,
                dataProtectionKeysDir,
                tempSnapshotDb,
                optionalExtraEntry: null,
                cancellationToken);
        }
        finally
        {
            try
            {
                if (File.Exists(tempSnapshotDb))
                {
                    File.Delete(tempSnapshotDb);
                }
            }
            finally
            {
                await lifecycleLock.DisposeAsync();
            }
        }
    }

    /// <summary>
    /// Creates a consistent state backup archive that also includes an explicitly opt-in, password-protected
    /// PKCS#12 bundle (`PBES2-PBKDF2-HMAC-SHA256` + `AES-256-CBC` + PKCS#12 `HMAC-SHA256` MAC, 100,000 iterations)
    /// for a selected locally managed Root CA. Requires an active Administrator account and unlocked CA key custody.
    /// Never logs, persists, or writes the generated 7-word EFF Diceware passphrase into the backup archive.
    /// </summary>
    public async Task<StateBackupWithRootCaPkcs12Result> CreateConsistentBackupWithRootCaPkcs12Async(
        string sqliteFilePath,
        string dataProtectionKeysDir,
        string? requestingUserId,
        int selectedRootCaAuthorityId,
        string? expectedSecurityStamp = null,
        string? customWordlistPath = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(requestingUserId))
        {
            throw new UnauthorizedAccessException("Administrator authentication is required to export a Root CA PKCS#12 in the state backup.");
        }

        await VerifyAdministratorAuthorizationAsync(requestingUserId, expectedSecurityStamp, cancellationToken);

        string tempSnapshotDb = Path.Combine(Path.GetTempPath(), $"certrobo-backup-{Guid.NewGuid():N}.db");
        IAsyncDisposable lifecycleLock = await CertificateAuthorityService.AcquireLifecycleLockAsync(
            caOptions.StorageDirectory,
            cancellationToken,
            TimeSpan.FromMilliseconds(Math.Max(100, caOptions.CrossProcessLockTimeoutMs)));
        try
        {
            await using CertRoboDbContext db = await dbFactory.CreateDbContextAsync(cancellationToken);
            await db.EnsureSchemaUpgradedAsync(cancellationToken);

            CaAuthorityRecord? authority = await db.CaAuthorities
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == selectedRootCaAuthorityId, cancellationToken)
                ?? throw new InvalidOperationException($"Selected CA authority #{selectedRootCaAuthorityId} was not found.");

            if (authority.IsIntermediate)
            {
                throw new InvalidOperationException(
                    $"Selected CA '{authority.Name}' (ID #{authority.Id}) is an Intermediate CA. Only a locally managed Root CA can be selected for the Root CA PKCS#12 backup option.");
            }

            if (string.IsNullOrWhiteSpace(authority.EncryptedPrivateKeyPath) || !File.Exists(authority.EncryptedPrivateKeyPath))
            {
                throw new InvalidOperationException(
                    $"Cannot create Root CA PKCS#12 for '{authority.Name}' (ID #{authority.Id}): its encrypted private key file was not found in CA storage.");
            }

            string? storagePassphrase = ResolveEffectiveStoragePassphrase();
            if (string.IsNullOrWhiteSpace(storagePassphrase))
            {
                throw new InvalidOperationException(
                    $"Cannot create Root CA PKCS#12 for '{authority.Name}' (ID #{authority.Id}) because CA key custody is currently locked. Unlock the CA signing key first or perform an ordinary state backup without the optional PKCS#12.");
            }

            string generatedPassphrase = EffDicewarePassphraseGenerator.GeneratePassphrase(
                EffDicewarePassphraseGenerator.DefaultPassphraseWords,
                EffDicewarePassphraseGenerator.DefaultSeparator,
                customWordlistPath);

            byte[] p12Bytes = await BuildProtectedRootCaPkcs12Async(
                authority,
                storagePassphrase,
                generatedPassphrase,
                cancellationToken);

            string safeSlug = string.Concat(authority.Name.Select(ch =>
                char.IsLetterOrDigit(ch) || ch is '-' or '_' ? char.ToLowerInvariant(ch) : '-')).Trim('-');
            if (string.IsNullOrEmpty(safeSlug))
            {
                safeSlug = "root-ca";
            }

            string entryPath = $"ca-pkcs12/root-ca-{authority.Id}-{safeSlug}.p12";

            byte[] archiveBytes = await CreateBackupZipCoreAsync(
                sqliteFilePath,
                dataProtectionKeysDir,
                tempSnapshotDb,
                (entryPath, p12Bytes),
                cancellationToken);

            return new StateBackupWithRootCaPkcs12Result(
                archiveBytes,
                authority.Id,
                authority.Name,
                entryPath,
                generatedPassphrase);
        }
        finally
        {
            try
            {
                if (File.Exists(tempSnapshotDb))
                {
                    File.Delete(tempSnapshotDb);
                }
            }
            finally
            {
                await lifecycleLock.DisposeAsync();
            }
        }
    }

    private async Task VerifyAdministratorAuthorizationAsync(
        string requestingUserId,
        string? expectedSecurityStamp,
        CancellationToken cancellationToken)
    {
        if (scopeFactory != null)
        {
            await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
            UserManager<ApplicationUser>? userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
            if (userManager != null)
            {
                ApplicationUser? user = await userManager.FindByIdAsync(requestingUserId);
                if (user == null || user.IsDisabled)
                {
                    throw new UnauthorizedAccessException("The requesting account is disabled or does not exist.");
                }

                if (!string.IsNullOrEmpty(expectedSecurityStamp)
                    && !string.Equals(user.SecurityStamp, expectedSecurityStamp, StringComparison.Ordinal))
                {
                    throw new UnauthorizedAccessException("The current session has been invalidated. Please sign in again.");
                }

                if (!await userManager.IsInRoleAsync(user, AppRoles.Administrator))
                {
                    throw new UnauthorizedAccessException("Only an Administrator may include a Root CA PKCS#12 in the state backup.");
                }

                return;
            }
        }

        await using CertRoboDbContext db = await dbFactory.CreateDbContextAsync(cancellationToken);
        ApplicationUser? dbUser = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == requestingUserId, cancellationToken);
        if (dbUser == null || dbUser.IsDisabled)
        {
            throw new UnauthorizedAccessException("The requesting account is disabled or does not exist.");
        }

        if (!string.IsNullOrEmpty(expectedSecurityStamp)
            && !string.Equals(dbUser.SecurityStamp, expectedSecurityStamp, StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("The current session has been invalidated. Please sign in again.");
        }

        string? adminRoleId = await db.Roles
            .AsNoTracking()
            .Where(r => r.NormalizedName == AppRoles.Administrator.ToUpperInvariant() || r.Name == AppRoles.Administrator)
            .Select(r => r.Id)
            .FirstOrDefaultAsync(cancellationToken);

        bool isAdmin = !string.IsNullOrEmpty(adminRoleId)
            && await db.UserRoles.AsNoTracking().AnyAsync(ur => ur.UserId == requestingUserId && ur.RoleId == adminRoleId, cancellationToken);

        if (!isAdmin)
        {
            throw new UnauthorizedAccessException("Only an Administrator may include a Root CA PKCS#12 in the state backup.");
        }
    }

    private string? ResolveEffectiveStoragePassphrase()
    {
        if (caService != null)
        {
            return caService.ResolveEffectivePassphrase();
        }

        if (!string.IsNullOrEmpty(caOptions.PassphraseEnvironmentVariable))
        {
            string? envVal = Environment.GetEnvironmentVariable(caOptions.PassphraseEnvironmentVariable);
            if (!string.IsNullOrWhiteSpace(envVal))
            {
                return envVal.Trim();
            }
        }

        if (!string.IsNullOrWhiteSpace(caOptions.PassphraseFilePath) && File.Exists(caOptions.PassphraseFilePath))
        {
            string fileVal = File.ReadAllText(caOptions.PassphraseFilePath).Trim();
            if (!string.IsNullOrEmpty(fileVal))
            {
                return fileVal;
            }
        }

        return string.IsNullOrWhiteSpace(caOptions.ConfiguredPassphrase) ? null : caOptions.ConfiguredPassphrase;
    }

    private static async Task<byte[]> BuildProtectedRootCaPkcs12Async(
        CaAuthorityRecord authority,
        string storagePassphrase,
        string pkcs12Passphrase,
        CancellationToken cancellationToken)
    {
        using X509Certificate2 rootCert = X509Certificate2.CreateFromPem(authority.IssuerCertificatePem);
        if (!CaChainAndConstraintValidator.IsSelfSignedCryptographically(rootCert))
        {
            throw new InvalidOperationException(
                $"Selected CA '{authority.Name}' (ID #{authority.Id}) is not a self-signed Root CA.");
        }

        byte[] encryptedKeyBytes = await File.ReadAllBytesAsync(authority.EncryptedPrivateKeyPath, cancellationToken);
        X509Certificate2 rootCertWithPrivateKey;
        try
        {
            if (rootCert.GetRSAPublicKey() != null)
            {
                using RSA rsa = RSA.Create();
                rsa.ImportEncryptedPkcs8PrivateKey(storagePassphrase, encryptedKeyBytes, out _);
                if (!rootCert.PublicKey.ExportSubjectPublicKeyInfo().SequenceEqual(rsa.ExportSubjectPublicKeyInfo()))
                {
                    throw new CryptographicException($"Decrypted private key for CA '{authority.Name}' does not match its certificate public key.");
                }
                rootCertWithPrivateKey = rootCert.CopyWithPrivateKey(rsa);
            }
            else if (rootCert.GetECDsaPublicKey() != null)
            {
                using ECDsa ecdsa = ECDsa.Create();
                ecdsa.ImportEncryptedPkcs8PrivateKey(storagePassphrase, encryptedKeyBytes, out _);
                if (!rootCert.PublicKey.ExportSubjectPublicKeyInfo().SequenceEqual(ecdsa.ExportSubjectPublicKeyInfo()))
                {
                    throw new CryptographicException($"Decrypted private key for CA '{authority.Name}' does not match its certificate public key.");
                }
                rootCertWithPrivateKey = rootCert.CopyWithPrivateKey(ecdsa);
            }
            else
            {
                throw new NotSupportedException($"Unsupported public key algorithm on CA '{authority.Name}'.");
            }
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException(
                $"Cannot create Root CA PKCS#12 for '{authority.Name}' (ID #{authority.Id}): failed to unlock or verify its encrypted private key.",
                ex);
        }

        List<X509Certificate2> extraChain = [];
        try
        {
            using (rootCertWithPrivateKey)
            {
                X509Certificate2Collection exportCollection = [rootCertWithPrivateKey];

                if (!string.IsNullOrWhiteSpace(authority.ChainCertificatesPem))
                {
                    extraChain = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                        null,
                        authority.ChainCertificatesPem,
                        "root CA chain");
                    string rootThumbprint = rootCert.GetCertHashString(HashAlgorithmName.SHA256);
                    foreach (X509Certificate2 extra in extraChain)
                    {
                        if (!extra.GetCertHashString(HashAlgorithmName.SHA256).Equals(rootThumbprint, StringComparison.OrdinalIgnoreCase))
                        {
                            exportCollection.Add(extra);
                        }
                    }
                }

                // Modern interoperable PKCS#12 profile: PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC (100,000 iterations)
                // for key & cert bags, and PKCS#12 HMAC-SHA256 integrity MAC (100,000 iterations).
                PbeParameters pbeParameters = new(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    RootCaPkcs12IterationCount);

                byte[] p12Bytes = exportCollection.ExportPkcs12(pbeParameters, pkcs12Passphrase);

                // Immediately verify round-trip decryption, MAC check, and key correspondence via .NET X509CertificateLoader
                X509Certificate2Collection loadedCollection = X509CertificateLoader.LoadPkcs12Collection(
                    p12Bytes,
                    pkcs12Passphrase,
                    X509KeyStorageFlags.Exportable);
                try
                {
                    X509Certificate2? loadedWithKey = loadedCollection.FirstOrDefault(c => c.HasPrivateKey);
                    if (loadedWithKey == null
                        || !loadedWithKey.GetCertHashString(HashAlgorithmName.SHA256).Equals(
                            rootCert.GetCertHashString(HashAlgorithmName.SHA256),
                            StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("Generated Root CA PKCS#12 failed post-creation verification.");
                    }
                }
                finally
                {
                    foreach (X509Certificate2 c in loadedCollection)
                    {
                        c.Dispose();
                    }
                }

                return p12Bytes;
            }
        }
        finally
        {
            foreach (X509Certificate2 extra in extraChain)
            {
                extra.Dispose();
            }
        }
    }

    private async Task<byte[]> CreateBackupZipCoreAsync(
        string sqliteFilePath,
        string dataProtectionKeysDir,
        string tempSnapshotDb,
        (string EntryPath, byte[] Content)? optionalExtraEntry,
        CancellationToken cancellationToken)
    {
        await using (CertRoboDbContext db = await dbFactory.CreateDbContextAsync(cancellationToken))
        {
            string vacuumSql = "VACUUM INTO '" + tempSnapshotDb.Replace("'", "''") + "';";
#pragma warning disable EF1002
            await db.Database.ExecuteSqlRawAsync(vacuumSql, cancellationToken);
#pragma warning restore EF1002
        }

        RestrictFilePermissionsIfUnix(tempSnapshotDb);

        using MemoryStream ms = new();
        using (ZipArchive zip = new(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            if (File.Exists(tempSnapshotDb))
            {
                zip.CreateEntryFromFile(tempSnapshotDb, "database/certrobo.db");
            }
            else if (File.Exists(sqliteFilePath))
            {
                zip.CreateEntryFromFile(sqliteFilePath, "database/certrobo.db");
            }

            if (Directory.Exists(caOptions.StorageDirectory))
            {
                foreach (string keyFile in Directory.GetFiles(caOptions.StorageDirectory, "*.p8.enc"))
                {
                    zip.CreateEntryFromFile(keyFile, $"ca/{Path.GetFileName(keyFile)}");
                }
            }

            if (Directory.Exists(dataProtectionKeysDir))
            {
                foreach (string dpFile in Directory.GetFiles(dataProtectionKeysDir, "*.xml"))
                {
                    zip.CreateEntryFromFile(dpFile, $"dataprotection/{Path.GetFileName(dpFile)}");
                }
            }

            if (optionalExtraEntry.HasValue)
            {
                ZipArchiveEntry extra = zip.CreateEntry(optionalExtraEntry.Value.EntryPath, CompressionLevel.Optimal);
                await using Stream entryStream = extra.Open();
                await entryStream.WriteAsync(optionalExtraEntry.Value.Content, cancellationToken);
            }
        }

        return ms.ToArray();
    }

    public static void RestoreBackupArchive(
        byte[] archiveBytes,
        string targetSqliteFilePath,
        string targetCaStorageDir,
        string targetDataProtectionKeysDir)
    {
        IAsyncDisposable lifecycleLock = CertificateAuthorityService
            .AcquireLifecycleLockAsync(targetCaStorageDir)
            .GetAwaiter()
            .GetResult();
        try
        {
            SqliteConnection.ClearAllPools();

            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(targetSqliteFilePath))!);
            Directory.CreateDirectory(targetCaStorageDir);
            Directory.CreateDirectory(targetDataProtectionKeysDir);

            using MemoryStream ms = new(archiveBytes);
            using ZipArchive zip = new(ms, ZipArchiveMode.Read);

            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                if (entry.FullName == "database/certrobo.db")
                {
                    entry.ExtractToFile(targetSqliteFilePath, overwrite: true);
                    RestrictFilePermissionsIfUnix(targetSqliteFilePath);
                }
                else if (entry.FullName.StartsWith("ca/", StringComparison.Ordinal) && entry.FullName.EndsWith(".p8.enc", StringComparison.Ordinal))
                {
                    string fileName = Path.GetFileName(entry.FullName);
                    string destPath = Path.Combine(targetCaStorageDir, fileName);
                    entry.ExtractToFile(destPath, overwrite: true);
                    RestrictFilePermissionsIfUnix(destPath);
                }
                else if (entry.FullName.StartsWith("dataprotection/", StringComparison.Ordinal) && entry.FullName.EndsWith(".xml", StringComparison.Ordinal))
                {
                    string fileName = Path.GetFileName(entry.FullName);
                    string destPath = Path.Combine(targetDataProtectionKeysDir, fileName);
                    entry.ExtractToFile(destPath, overwrite: true);
                    RestrictFilePermissionsIfUnix(destPath);
                }
            }

            RewriteRestoredKeyPaths(targetSqliteFilePath, targetCaStorageDir);
        }
        finally
        {
            lifecycleLock.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    private static void RewriteRestoredKeyPaths(string sqliteFilePath, string caStorageDir)
    {
        if (!File.Exists(sqliteFilePath))
        {
            return;
        }

        using SqliteConnection connection = new($"Data Source={sqliteFilePath}");
        connection.Open();

        RewriteTableKeyPaths(connection, "CaAuthorities");
        RewriteTableKeyPaths(connection, "PendingCaEnrollments");

        void RewriteTableKeyPaths(SqliteConnection db, string tableName)
        {
            using SqliteCommand exists = db.CreateCommand();
            exists.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$tableName";
            exists.Parameters.AddWithValue("$tableName", tableName);
            if (Convert.ToInt64(exists.ExecuteScalar()) == 0)
            {
                return;
            }

            List<(long Id, string ExistingPath)> records = [];
            using (SqliteCommand select = db.CreateCommand())
            {
                select.CommandText = $"SELECT Id, EncryptedPrivateKeyPath FROM \"{tableName}\"";
                using SqliteDataReader reader = select.ExecuteReader();
                while (reader.Read())
                {
                    records.Add((reader.GetInt64(0), reader.GetString(1)));
                }
            }

            foreach ((long id, string existingPath) in records)
            {
                string restoredPath = Path.Combine(caStorageDir, Path.GetFileName(existingPath));
                using SqliteCommand update = db.CreateCommand();
                update.CommandText = $"UPDATE \"{tableName}\" SET EncryptedPrivateKeyPath=$path WHERE Id=$id";
                update.Parameters.AddWithValue("$path", restoredPath);
                update.Parameters.AddWithValue("$id", id);
                update.ExecuteNonQuery();
            }
        }
    }

    private static void RestrictFilePermissionsIfUnix(string filePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                File.SetUnixFileMode(filePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch
            {
                // Ignore if filesystem does not support UnixFileMode
            }
        }
    }
}
