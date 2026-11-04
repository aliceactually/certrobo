using CertRobo.Data;
using CertRobo.Models;
using CertRobo.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertRobo.Tests;

public sealed class Pkcs12AndBackupCustodyTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly CryptoFactory _crypto = new();

    public Pkcs12AndBackupCustodyTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"certrobo-p12-backup-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    [Fact]
    public async Task PasswordlessLeafPkcs12Export_IncludesEmptyPasswordIntegrityMac_RoundTripsInDotNetAndOpenSsl_AndDetectsCorruption()
    {
        const string caSecret = "LeafP12MacTestSecret!2026";
        string dbPath = Path.Combine(_tempRoot, "leaf-p12.db");
        string caDir = Path.Combine(_tempRoot, "leaf-p12-ca");

        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir);
        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
        ApplicationUser admin = await BootstrapAdminAsync(sp);

        CaAuthorityRecord rootCa = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Test Root CA", "root.contoso.com", "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Rsa, 2048, 3650, caSecret, pathLengthConstraint: 1);
        CaAuthorityRecord subCa = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Test Issuing CA", "issuing.contoso.com", "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa, 256, 1825, caSecret,
            parentAuthority: rootCa, parentPassphrase: caSecret, pathLengthConstraint: 0);

        KeyPair leafKp = _crypto.KeyGen(256);
        string csr = _crypto.CSRGen(leafKp, "p12-leaf.contoso.com", ["p12-leaf.contoso.com", "api.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
        IssuanceOutcome outcome = await caService.IssueCertificateFromCsrAsync(admin.Id, csr);
        Assert.True(outcome.Succeeded, outcome.ErrorMessage);

        Tuple<string, byte[]>? export = PkcsBuilder.Export(
            outcome.CertificatePem!,
            leafKp.Private,
            rootCaCertPath: null,
            chainPemContent: outcome.Record!.ChainPem);
        Assert.NotNull(export);
        Assert.Equal("p12-leaf.contoso.com.zip", export.Item1);

        using MemoryStream zipMs = new(export.Item2);
        using ZipArchive zip = new(zipMs, ZipArchiveMode.Read);

        // Preserve all existing archive entry names
        string[] expectedEntries =
        [
            "p12-leaf.contoso.com.crt",
            "p12-leaf.contoso.com.p7b",
            "p12-leaf.contoso.com-chained.crt",
            "rootca.crt",
            "ca-chain.crt",
            "p12-leaf.contoso.com-chained.p7b",
            "p12-leaf.contoso.com.key",
            "p12-leaf.contoso.com.pem",
            "p12-leaf.contoso.com-chained.pem",
            "p12-leaf.contoso.com.p12",
            "p12-leaf.contoso.com-chained.p12"
        ];
        foreach (string expected in expectedEntries)
        {
            Assert.NotNull(zip.GetEntry(expected));
        }

        foreach (string p12EntryName in new[] { "p12-leaf.contoso.com.p12", "p12-leaf.contoso.com-chained.p12" })
        {
            byte[] p12Bytes = ReadZipEntryBytes(zip, p12EntryName);

            // 1. Positive round-trip with .NET X509CertificateLoader (both empty string and null password)
            X509Certificate2Collection loadedEmpty = X509CertificateLoader.LoadPkcs12Collection(p12Bytes, "");
            X509Certificate2Collection loadedNull = X509CertificateLoader.LoadPkcs12Collection(p12Bytes, null);
            int expectedCount = p12EntryName.Contains("-chained") ? 3 : 1;
            Assert.Equal(expectedCount, loadedEmpty.Count);
            Assert.Equal(expectedCount, loadedNull.Count);
            Assert.Contains(loadedEmpty, c => c.HasPrivateKey && c.Subject.Contains("p12-leaf.contoso.com"));
            foreach (var c in loadedEmpty) c.Dispose();
            foreach (var c in loadedNull) c.Dispose();

            // 2. Positive verification with OpenSSL pkcs12: must NOT warn "MAC is absent!" and must verify MAC
            string p12Path = Path.Combine(_tempRoot, p12EntryName);
            await File.WriteAllBytesAsync(p12Path, p12Bytes);
            var (osslExit, osslOut) = await RunOpenSslAsync(["pkcs12", "-in", p12Path, "-info", "-noout", "-passin", "pass:"]);
            Assert.True(osslExit == 0, $"openssl pkcs12 failed ({osslExit}): {osslOut}");
            Assert.DoesNotContain("MAC is absent", osslOut, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("MAC:", osslOut, StringComparison.OrdinalIgnoreCase);

            // 3. Corruption detection: flip a byte inside the encrypted payload and confirm both .NET and OpenSSL reject it
            byte[] corrupted = (byte[])p12Bytes.Clone();
            corrupted[p12Bytes.Length / 2] ^= 0x5A;

            Assert.ThrowsAny<CryptographicException>(() =>
                X509CertificateLoader.LoadPkcs12Collection(corrupted, ""));

            string corruptedPath = Path.Combine(_tempRoot, "corrupted-" + p12EntryName);
            await File.WriteAllBytesAsync(corruptedPath, corrupted);
            var (corruptExit, corruptOut) = await RunOpenSslAsync(["pkcs12", "-in", corruptedPath, "-info", "-noout", "-passin", "pass:"]);
            Assert.NotEqual(0, corruptExit);
            Assert.Contains("error:", corruptOut, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task EffWordlistGenerator_ValidatesOfficialWordlist_RejectsMissingOrInvalidFiles_AndSamplesSevenWordsWithReplacement()
    {
        // 1. Validate official embedded/file wordlist has 7,776 entries and passes SHA-256 verification
        IReadOnlyList<string> words = EffDicewarePassphraseGenerator.GetValidatedWordlist();
        Assert.Equal(7776, words.Count);
        Assert.Equal("abacus", words[0]);
        Assert.Equal("zoom", words[^1]);

        // 2. Verify 7-word generation with consistent '-' separator and sampling WITH replacement
        string passphrase = EffDicewarePassphraseGenerator.GeneratePassphrase();
        string[] parts = passphrase.Split('-');
        Assert.Equal(7, parts.Length);
        Assert.All(parts, word => Assert.Contains(word, words));

        // Deterministic selector returning the same index proves sampling with replacement is permitted
        string repeatedWordPass = EffDicewarePassphraseGenerator.GeneratePassphrase(
            wordCount: 7,
            separator: "-",
            uniformIndexSelector: _ => 42);
        Assert.Equal(string.Join("-", Enumerable.Repeat(words[42], 7)), repeatedWordPass);

        // Out-of-range selector index is rejected
        Assert.Throws<InvalidOperationException>(() =>
            EffDicewarePassphraseGenerator.GeneratePassphrase(uniformIndexSelector: _ => 7776));
        Assert.Throws<InvalidOperationException>(() =>
            EffDicewarePassphraseGenerator.GeneratePassphrase(uniformIndexSelector: _ => -1));

        // 3. Missing or invalid wordlist files fail safely
        string missingPath = Path.Combine(_tempRoot, "does-not-exist-wordlist.txt");
        Assert.Throws<FileNotFoundException>(() =>
            EffDicewarePassphraseGenerator.GetValidatedWordlist(missingPath));

        string truncatedPath = Path.Combine(_tempRoot, "truncated-wordlist.txt");
        await File.WriteAllTextAsync(truncatedPath, "11111\tabacus\n11112\tabdomen\n");
        Assert.Throws<InvalidOperationException>(() =>
            EffDicewarePassphraseGenerator.GetValidatedWordlist(truncatedPath));

        string tamperedShaText = Encoding.UTF8.GetString(
            await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory, "Resources", "Passphrases", "eff_large_wordlist.txt")))
            .Replace("11111\tabacus", "11111\tabacux");
        Assert.Throws<InvalidOperationException>(() =>
            EffDicewarePassphraseGenerator.ParseAndValidateWordlistBytes(
                Encoding.UTF8.GetBytes(tamperedShaText),
                "tampered",
                verifyOfficialSha256: true));
    }

    [Fact]
    public async Task StateBackupWithRootCaPkcs12_EnforcesAdminAuth_HandlesLockedAndUnlockedCustody_PreservesOrdinaryBackupRestore_AndVerifiesWithOpenSslAndDotNet()
    {
        const string storageSecret = "StateBackupStorageCustody!2026";
        string dbPath = Path.Combine(_tempRoot, "state-backup.db");
        string caDir = Path.Combine(_tempRoot, "state-backup-ca");
        string dpDir = Path.Combine(_tempRoot, "state-backup-dp");
        Directory.CreateDirectory(dpDir);

        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir, dpDir);
        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
        BackupRestoreService backupService = sp.GetRequiredService<BackupRestoreService>();
        ApplicationUser admin = await BootstrapAdminAsync(sp);

        ApplicationUser issuerUser;
        using (IServiceScope scope = sp.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            var (ok, err, created) = await acct.CreateUserAsync(
                "issuer-only",
                "IssuerPass!2026",
                "issuer@contoso.com",
                [AppRoles.Issuer],
                ["*.contoso.com"]);
            Assert.True(ok, err);
            issuerUser = created!;
        }

        // Provision a Root CA (#1) and a Subordinate Intermediate CA (#2)
        CaAuthorityRecord rootCa = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Contoso Root CA", "root.contoso.com", "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Rsa, 2048, 3650, storageSecret, pathLengthConstraint: 1);
        CaAuthorityRecord subCa = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Contoso Issuing Intermediate CA", "issuing.contoso.com", "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa, 256, 1825, storageSecret,
            parentAuthority: rootCa, parentPassphrase: storageSecret, pathLengthConstraint: 0);

        // 1. Authorization checks: anonymous, non-admin Issuer, stale security stamp, or disabled account are rejected
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            backupService.CreateConsistentBackupWithRootCaPkcs12Async(dbPath, dpDir, null, rootCa.Id));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            backupService.CreateConsistentBackupWithRootCaPkcs12Async(dbPath, dpDir, issuerUser.Id, rootCa.Id));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            backupService.CreateConsistentBackupWithRootCaPkcs12Async(dbPath, dpDir, admin.Id, rootCa.Id, expectedSecurityStamp: "stale-stamp"));

        // 2. Selecting an Intermediate CA (#2) instead of a Root CA (#1) fails clearly
        InvalidOperationException intermediateEx = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            backupService.CreateConsistentBackupWithRootCaPkcs12Async(dbPath, dpDir, admin.Id, subCa.Id));
        Assert.Contains("Intermediate CA", intermediateEx.Message);

        // 3. When CA key custody is locked:
        //    - Ordinary state backup MUST succeed (and contain no .p12)
        //    - Opt-in Root CA PKCS#12 backup MUST fail clearly rather than silently omitting the .p12
        caService.LockRuntimePassphrase();

        byte[] ordinaryBackupWhileLocked = await backupService.CreateConsistentBackupArchiveAsync(dbPath, dpDir);
        using (MemoryStream ordMs = new(ordinaryBackupWhileLocked))
        using (ZipArchive ordZip = new(ordMs, ZipArchiveMode.Read))
        {
            Assert.NotNull(ordZip.GetEntry("database/certrobo.db"));
            Assert.Equal(2, ordZip.Entries.Count(e => e.FullName.StartsWith("ca/") && e.FullName.EndsWith(".p8.enc")));
            Assert.DoesNotContain(ordZip.Entries, e => e.FullName.EndsWith(".p12", StringComparison.OrdinalIgnoreCase));
        }

        InvalidOperationException lockedP12Ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            backupService.CreateConsistentBackupWithRootCaPkcs12Async(dbPath, dpDir, admin.Id, rootCa.Id));
        Assert.Contains("locked", lockedP12Ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(storageSecret, lockedP12Ex.Message);

        // 4. Unlock CA custody and create opt-in state backup with Root CA PKCS#12
        caService.UnlockRuntimePassphrase(storageSecret);

        StateBackupWithRootCaPkcs12Result optInResult = await backupService.CreateConsistentBackupWithRootCaPkcs12Async(
            dbPath,
            dpDir,
            admin.Id,
            rootCa.Id,
            expectedSecurityStamp: admin.SecurityStamp);

        Assert.Equal(rootCa.Id, optInResult.ExportedAuthorityId);
        Assert.Equal("Contoso Root CA", optInResult.ExportedAuthorityName);
        Assert.StartsWith("ca-pkcs12/root-ca-", optInResult.Pkcs12EntryPath);
        Assert.EndsWith(".p12", optInResult.Pkcs12EntryPath);

        string[] passphraseWords = optInResult.GeneratedPkcs12Passphrase.Split('-');
        Assert.Equal(7, passphraseWords.Length);
        Assert.NotEqual(storageSecret, optInResult.GeneratedPkcs12Passphrase);

        // 5. Inspect the archive: must contain database/certrobo.db, ca/*.p8.enc, and the .p12 entry,
        //    and MUST NOT contain the generated passphrase or the storage passphrase in any entry name or plaintext content.
        byte[] exportedP12Bytes;
        using (MemoryStream optMs = new(optInResult.ArchiveBytes))
        using (ZipArchive optZip = new(optMs, ZipArchiveMode.Read))
        {
            Assert.NotNull(optZip.GetEntry("database/certrobo.db"));
            Assert.Equal(2, optZip.Entries.Count(e => e.FullName.StartsWith("ca/") && e.FullName.EndsWith(".p8.enc")));
            ZipArchiveEntry? p12Entry = optZip.GetEntry(optInResult.Pkcs12EntryPath);
            Assert.NotNull(p12Entry);
            Assert.Single(optZip.Entries, e => e.FullName.EndsWith(".p12", StringComparison.OrdinalIgnoreCase));

            foreach (ZipArchiveEntry entry in optZip.Entries)
            {
                Assert.DoesNotContain(optInResult.GeneratedPkcs12Passphrase, entry.FullName, StringComparison.OrdinalIgnoreCase);
                byte[] entryBytes = ReadZipEntryBytes(optZip, entry.FullName);
                string ascii = Encoding.ASCII.GetString(entryBytes);
                Assert.DoesNotContain(optInResult.GeneratedPkcs12Passphrase, ascii, StringComparison.Ordinal);
                Assert.DoesNotContain(storageSecret, ascii, StringComparison.Ordinal);
                Assert.DoesNotContain("BEGIN PRIVATE KEY", ascii, StringComparison.Ordinal);
            }

            exportedP12Bytes = ReadZipEntryBytes(optZip, optInResult.Pkcs12EntryPath);
        }

        // 6. Verify PKCS#12 password protection with .NET X509CertificateLoader and OpenSSL:
        //    - Wrong password / empty password must fail
        //    - Correct 7-word passphrase must succeed, match Root CA certificate and private key, and report PBES2 / AES-256-CBC / SHA-256 MAC in OpenSSL
        Assert.ThrowsAny<CryptographicException>(() =>
            X509CertificateLoader.LoadPkcs12Collection(exportedP12Bytes, ""));
        Assert.ThrowsAny<CryptographicException>(() =>
            X509CertificateLoader.LoadPkcs12Collection(exportedP12Bytes, "wrong-passphrase"));
        Assert.ThrowsAny<CryptographicException>(() =>
            X509CertificateLoader.LoadPkcs12Collection(exportedP12Bytes, storageSecret));

        X509Certificate2Collection loadedRootP12 = X509CertificateLoader.LoadPkcs12Collection(
            exportedP12Bytes,
            optInResult.GeneratedPkcs12Passphrase,
            X509KeyStorageFlags.Exportable);
        try
        {
            X509Certificate2 loadedRoot = Assert.Single(loadedRootP12);
            Assert.True(loadedRoot.HasPrivateKey);
            Assert.Equal(rootCa.ThumbprintOrSerialHex, loadedRoot.GetCertHashString(HashAlgorithmName.SHA256));
            using X509Certificate2 originalRoot = X509Certificate2.CreateFromPem(rootCa.IssuerCertificatePem);
            using RSA loadedRsa = loadedRoot.GetRSAPrivateKey()!;
            Assert.Equal(
                originalRoot.PublicKey.ExportSubjectPublicKeyInfo(),
                loadedRsa.ExportSubjectPublicKeyInfo());
        }
        finally
        {
            foreach (var c in loadedRootP12) c.Dispose();
        }

        string rootP12File = Path.Combine(_tempRoot, "exported-root-ca.p12");
        await File.WriteAllBytesAsync(rootP12File, exportedP12Bytes);

        var (wrongOsslExit, _) = await RunOpenSslAsync(["pkcs12", "-in", rootP12File, "-info", "-noout", "-passin", "pass:wrong-pass"]);
        Assert.NotEqual(0, wrongOsslExit);

        var (okOsslExit, okOsslOut) = await RunOpenSslAsync([
            "pkcs12", "-in", rootP12File, "-info", "-nokeys",
            "-passin", $"pass:{optInResult.GeneratedPkcs12Passphrase}"
        ]);
        Assert.True(okOsslExit == 0, $"OpenSSL pkcs12 failed ({okOsslExit}): {okOsslOut}");
        Assert.Contains("PBES2", okOsslOut, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("PBKDF2", okOsslOut, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("aes-256-cbc", okOsslOut, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Iteration 100000", okOsslOut, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("MAC: sha256, Iteration 100000", okOsslOut, StringComparison.OrdinalIgnoreCase);

        // 7. Verify restoring the archive works normally and preserves local users, roles, and encrypted .p8.enc keys
        //    (which still require storageSecret, NOT the generated PKCS#12 passphrase)
        string restoreDir = Path.Combine(_tempRoot, "restored-from-optin");
        string restoredDb = Path.Combine(restoreDir, "certrobo.db");
        string restoredCa = Path.Combine(restoreDir, "ca");
        string restoredDp = Path.Combine(restoreDir, "dp");

        BackupRestoreService.RestoreBackupArchive(optInResult.ArchiveBytes, restoredDb, restoredCa, restoredDp);
        Assert.Empty(Directory.GetFiles(restoredCa, "*.p12"));

        using ServiceProvider restoredSp = BuildServiceProvider(restoredDb, restoredCa, restoredDp);
        CertificateAuthorityService restoredCaService = restoredSp.GetRequiredService<CertificateAuthorityService>();

        // Generated PKCS#12 passphrase does NOT unlock the restored .p8.enc CA storage keys
        Assert.Throws<InvalidOperationException>(() =>
            restoredCaService.UnlockRuntimePassphrase(optInResult.GeneratedPkcs12Passphrase));

        // Original storageSecret unlocks restored CA keys and preserves users/roles
        restoredCaService.UnlockRuntimePassphrase(storageSecret);
        CaKeyCustodyReport restoredReport = await restoredCaService.InspectKeyCustodyAsync();
        Assert.True(restoredReport.IsCustodyHealthy);

        using (IServiceScope restoredScope = restoredSp.CreateScope())
        {
            AccountManagementService restoredAcct = restoredScope.ServiceProvider.GetRequiredService<AccountManagementService>();
            IReadOnlyList<UserSummaryDto> restoredUsers = await restoredAcct.ListUsersAsync();
            Assert.Contains(restoredUsers, u => u.UserName == "admin" && u.Roles.Contains(AppRoles.Administrator));
            Assert.Contains(restoredUsers, u => u.UserName == "issuer-only" && u.Roles.Contains(AppRoles.Issuer));
        }
    }

    private static byte[] ReadZipEntryBytes(ZipArchive zip, string entryName)
    {
        ZipArchiveEntry entry = zip.GetEntry(entryName)!;
        using MemoryStream ms = new();
        using Stream s = entry.Open();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    private static async Task<(int ExitCode, string Output)> RunOpenSslAsync(IReadOnlyList<string> args)
    {
        ProcessStartInfo psi = new("openssl")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        using Process proc = Process.Start(psi)!;
        string stdout = await proc.StandardOutput.ReadToEndAsync();
        string stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        return (proc.ExitCode, stdout + "\n" + stderr);
    }

    private static async Task<ApplicationUser> BootstrapAdminAsync(ServiceProvider sp)
    {
        using IServiceScope scope = sp.CreateScope();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        var (ok, err, user) = await acct.BootstrapFirstAdminAsync("admin", "AdminSecret!2026", "admin@contoso.com", "*");
        Assert.True(ok, err);
        return user!;
    }

    private static ServiceProvider BuildServiceProvider(
        string sqlitePath,
        string caStorageDir,
        string? dpKeysDir = null)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection();
        services.AddDbContextFactory<CertRoboDbContext>(options =>
            options.UseSqlite($"Data Source={sqlitePath}"));
        services.AddScoped(sp =>
            sp.GetRequiredService<IDbContextFactory<CertRoboDbContext>>().CreateDbContext());

        services.AddIdentityCore<ApplicationUser>(options =>
        {
            options.Password.RequiredLength = 12;
            options.Password.RequireDigit = true;
            options.Password.RequireLowercase = true;
            options.Password.RequireUppercase = true;
            options.Password.RequireNonAlphanumeric = false;
        })
        .AddRoles<IdentityRole>()
        .AddEntityFrameworkStores<CertRoboDbContext>()
        .AddDefaultTokenProviders();

        services.AddSingleton(new CaKeyCustodyOptions
        {
            StorageDirectory = caStorageDir,
            PassphraseEnvironmentVariable = null
        });

        services.AddScoped<AccountManagementService>();
        services.AddScoped<IssuancePolicyService>();
        services.AddSingleton<CertificateAuthorityService>();
        services.AddSingleton<BackupRestoreService>();

        ServiceProvider sp = services.BuildServiceProvider();
        using IServiceScope scope = sp.CreateScope();
        CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
        db.EnsureSchemaUpgradedAsync().GetAwaiter().GetResult();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        acct.EnsureRolesAndDefaultsAsync().GetAwaiter().GetResult();
        return sp;
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try
        {
            if (Directory.Exists(_tempRoot))
            {
                Directory.Delete(_tempRoot, recursive: true);
            }
        }
        catch
        {
        }
    }
}
