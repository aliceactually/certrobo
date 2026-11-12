using CertRobo.Data;
using CertRobo.Models;
using CertRobo.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Asn1.X509;
using System.Diagnostics;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace CertRobo.Tests;

public sealed class CliUiAndFilePermissionsTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly CryptoFactory _crypto = new();

    public CliUiAndFilePermissionsTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"certrobo-cli-ui-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    [Fact]
    public async Task CliIssueCsr_HandlesUnwritableDestinations_PostIssuanceWriteFailures_AndRetryOrExportRecovery_WithoutDuplicateIssuance_AndExcludesRootFromTlsServerChain()
    {
        const string secret = "CliIssueRecoverySecret!2026";
        string dbPath = Path.Combine(_tempRoot, "cli-issue.db");
        string caDir = Path.Combine(_tempRoot, "cli-issue-ca");
        string passFile = Path.Combine(_tempRoot, "cli-issue.pass");
        await File.WriteAllTextAsync(passFile, secret + "\n");

        // 1. Bootstrap admin & initialise Root CA + Subordinate Intermediate CA via CLI, verifying concise default output (#24)
        var (bootExit, bootStdout, bootStderr) = await RunCliAsync(dbPath, caDir, passFile, ["--bootstrap-admin", "admin", "AdminSecret!2026", "*"]);
        Assert.Equal(0, bootExit);
        Assert.Contains("Bootstrapped initial administrator 'admin'", bootStdout);
        Assert.DoesNotContain("CREATE TABLE", bootStdout);
        Assert.DoesNotContain("Executed DbCommand", bootStdout);
        Assert.Equal(string.Empty, bootStderr.Trim());

        // Also verify --verbose opts back into diagnostic SQL logging without leaking secrets (#24)
        var (rootExit, rootStdout, _) = await RunCliAsync(
            dbPath, caDir, passFile,
            ["--init-ca", "Contoso Root CA", "root-ca.contoso.com", "RSA-2048", "3650", "http://pki.contoso.com/ca.crl", "http://pki.contoso.com/ca.crt", "--verbose"]);
        Assert.Equal(0, rootExit);
        Assert.Contains("Executed DbCommand", rootStdout);
        Assert.Contains("Initialised and activated Root CA", rootStdout);
        Assert.DoesNotContain(secret, rootStdout);

        var (subExit, subStdout, _) = await RunCliAsync(
            dbPath, caDir, passFile,
            ["--init-ca", "Contoso Issuing Intermediate CA", "issuing-ca.contoso.com", "ECDSA-256", "1825", "http://pki.contoso.com/ca.crl", "http://pki.contoso.com/ca.crt", "--subordinate"]);
        Assert.Equal(0, subExit);
        Assert.Contains("Initialised and activated Intermediate CA", subStdout);
        Assert.DoesNotContain("Executed DbCommand", subStdout);

        // 2. Generate CSR for leaf1
        KeyPair kp1 = _crypto.KeyGen(256);
        string csr1 = _crypto.CSRGen(kp1, "leaf1.contoso.com", ["leaf1.contoso.com", "api1.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string csr1Path = Path.Combine(_tempRoot, "leaf1.csr");
        await File.WriteAllTextAsync(csr1Path, csr1);

        // 2a. Missing / unwritable destination preflight: must exit non-zero cleanly BEFORE allocating a serial or issuing a certificate
        string missingDirCertPath = Path.Combine(_tempRoot, "no-such-dir", "leaf1.crt");
        var (preFailExit, preFailStdout, preFailStderr) = await RunCliAsync(
            dbPath, caDir, passFile,
            ["--issue-csr", "admin", csr1Path, missingDirCertPath]);
        Assert.NotEqual(0, preFailExit);
        Assert.Contains("Issuance aborted before signing", preFailStderr);
        Assert.DoesNotContain("Unhandled exception", preFailStderr);

        using (ServiceProvider checkSp = BuildServiceProvider(dbPath, caDir, passFile))
        {
            CertificateAuthorityService caService = checkSp.GetRequiredService<CertificateAuthorityService>();
            IReadOnlyList<IssuedCertificateRecord> issuedAfterPreflightFail = await caService.SearchCertificatesAsync("leaf1.contoso.com", IssuanceStatus.Issued);
            Assert.Empty(issuedAfterPreflightFail);
            Assert.Equal(1000L, (await caService.GetActiveAuthorityAsync())!.LastAllocatedSerial);
        }

        // 2b. Post-issuance write failure (simulated failure on second output file after signing):
        //     Must exit non-zero cleanly with recovery instructions, leave no partial output files behind,
        //     and allow retry with the same CSR (or --export-issued) without allocating a second certificate!
        string outDir = Path.Combine(_tempRoot, "outputs");
        Directory.CreateDirectory(outDir);
        string leaf1CertPath = Path.Combine(outDir, "leaf1.crt");
        string leaf1TlsChainPath = Path.Combine(outDir, "leaf1-tlschain.crt");
        string leaf1RootPath = Path.Combine(outDir, "leaf1-root.crt");
        string leaf1FullChainPath = Path.Combine(outDir, "leaf1-fullchain.crt");

        var (postFailExit, _, postFailStderr) = await RunCliAsync(
            dbPath, caDir, passFile,
            ["--issue-csr", "admin", csr1Path, leaf1CertPath, leaf1TlsChainPath],
            extraEnv: new Dictionary<string, string> { ["CERTROBO_TEST_FAIL_CLI_OUTPUT_PATH"] = "CHAIN" });
        Assert.NotEqual(0, postFailExit);
        Assert.Contains("was issued and recorded, but writing output file(s) failed", postFailStderr);
        Assert.Contains("--export-issued", postFailStderr);
        Assert.DoesNotContain("Unhandled exception", postFailStderr);
        Assert.False(File.Exists(leaf1CertPath));
        Assert.False(File.Exists(leaf1TlsChainPath));

        string issuedSerialHex;
        using (ServiceProvider checkSp = BuildServiceProvider(dbPath, caDir, passFile))
        {
            CertificateAuthorityService caService = checkSp.GetRequiredService<CertificateAuthorityService>();
            IReadOnlyList<IssuedCertificateRecord> issuedRecords = await caService.SearchCertificatesAsync("leaf1.contoso.com", IssuanceStatus.Issued);
            IssuedCertificateRecord singleIssued = Assert.Single(issuedRecords);
            issuedSerialHex = singleIssued.SerialNumberHex;
        }

        // 2c. Retry the exact same `--issue-csr` command without fault injection:
        //     Must recover the already-issued certificate (same serial, still only 1 database record) and write all output files!
        var (retryExit, retryStdout, retryStderr) = await RunCliAsync(
            dbPath, caDir, passFile,
            ["--issue-csr", "admin", csr1Path, leaf1CertPath, leaf1TlsChainPath, "--root-out", leaf1RootPath, "--fullchain-out", leaf1FullChainPath]);
        Assert.True(retryExit == 0, $"Retry failed ({retryExit}): {retryStdout}\n{retryStderr}");
        Assert.Contains($"Recovered already-issued certificate serial {issuedSerialHex}", retryStdout);
        Assert.True(File.Exists(leaf1CertPath));
        Assert.True(File.Exists(leaf1TlsChainPath));
        Assert.True(File.Exists(leaf1RootPath));
        Assert.True(File.Exists(leaf1FullChainPath));

        using (ServiceProvider checkSp = BuildServiceProvider(dbPath, caDir, passFile))
        {
            CertificateAuthorityService caService = checkSp.GetRequiredService<CertificateAuthorityService>();
            IReadOnlyList<IssuedCertificateRecord> issuedRecords = await caService.SearchCertificatesAsync("leaf1.contoso.com", IssuanceStatus.Issued);
            Assert.Single(issuedRecords);
            Assert.Equal(1001L, (await caService.GetActiveAuthorityAsync())!.LastAllocatedSerial);

            // 2d. Concurrent retry/issuance race for a fresh CSR (leaf-concurrent.contoso.com):
            //     Multiple concurrent --issue-csr / recoverExistingForSameCsr calls for the same CSR must serialise
            //     under the lifecycle lock and produce only ONE issued certificate (serial 1002), never duplicates.
            UserManager<ApplicationUser> userMgr = checkSp.GetRequiredService<UserManager<ApplicationUser>>();
            ApplicationUser admin = (await userMgr.FindByNameAsync("admin"))!;
            KeyPair concurrentKp = _crypto.KeyGen(256);
            string concurrentCsr = _crypto.CSRGen(
                concurrentKp,
                "leaf-concurrent.contoso.com",
                ["leaf-concurrent.contoso.com"],
                "US", "WA", "Redmond", "Contoso", "IT", "");

            Task<IssuanceOutcome>[] concurrentTasks = Enumerable.Range(0, 4)
                .Select(_ => caService.IssueCertificateFromCsrAsync(
                    admin.Id,
                    concurrentCsr,
                    recoverExistingForSameCsr: true))
                .ToArray();
            IssuanceOutcome[] concurrentOutcomes = await Task.WhenAll(concurrentTasks);
            Assert.All(concurrentOutcomes, o => Assert.True(o.Succeeded, o.ErrorMessage));
            Assert.Single(concurrentOutcomes.Select(o => o.Record!.SerialNumberHex).Distinct(StringComparer.OrdinalIgnoreCase));
            Assert.Equal(1, concurrentOutcomes.Count(o => !o.WasRecoveredExisting));
            Assert.Equal(3, concurrentOutcomes.Count(o => o.WasRecoveredExisting));
            Assert.Single(await caService.SearchCertificatesAsync("leaf-concurrent.contoso.com", IssuanceStatus.Issued));
            Assert.Equal(1002L, (await caService.GetActiveAuthorityAsync())!.LastAllocatedSerial);
        }

        // 3. Verify #22 TLS server-chain vs root vs fullchain semantics under the Intermediate CA:
        //    - leaf1CertPath: 1 cert (leaf)
        //    - leaf1TlsChainPath (<outChainPath>): 2 certs (leaf + intermediate CA, excluding self-signed Root CA!)
        //    - leaf1RootPath (--root-out): 1 cert (self-signed Root CA)
        //    - leaf1FullChainPath (--fullchain-out): 3 certs (leaf + intermediate CA + Root CA)
        List<X509Certificate2> leafOnlyCerts = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
            null, await File.ReadAllTextAsync(leaf1CertPath), "leaf");
        List<X509Certificate2> tlsServerChainCerts = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
            null, await File.ReadAllTextAsync(leaf1TlsChainPath), "tlsServerChain");
        List<X509Certificate2> rootOnlyCerts = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
            null, await File.ReadAllTextAsync(leaf1RootPath), "rootOut");
        List<X509Certificate2> fullChainCerts = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
            null, await File.ReadAllTextAsync(leaf1FullChainPath), "fullChainOut");

        try
        {
            Assert.Single(leafOnlyCerts);
            Assert.Equal(2, tlsServerChainCerts.Count);
            Assert.DoesNotContain(tlsServerChainCerts, CaChainAndConstraintValidator.IsSelfSignedCryptographically);
            Assert.Contains(tlsServerChainCerts, c => c.Subject.Contains("leaf1.contoso.com"));
            Assert.Contains(tlsServerChainCerts, c => c.Subject.Contains("issuing-ca.contoso.com"));

            X509Certificate2 rootAnchor = Assert.Single(rootOnlyCerts);
            Assert.True(CaChainAndConstraintValidator.IsSelfSignedCryptographically(rootAnchor));
            Assert.Contains("root-ca.contoso.com", rootAnchor.Subject);

            Assert.Equal(3, fullChainCerts.Count);
        }
        finally
        {
            foreach (var c in leafOnlyCerts.Concat(tlsServerChainCerts).Concat(rootOnlyCerts).Concat(fullChainCerts)) c.Dispose();
        }

        // 4. Also verify `--export-issued <serialHex>` writes the exact same outputs to a new path
        string exportedCertPath = Path.Combine(outDir, "exported-leaf1.crt");
        string exportedChainPath = Path.Combine(outDir, "exported-leaf1-chain.crt");
        var (expExit, expStdout, expStderr) = await RunCliAsync(
            dbPath, caDir, passFile,
            ["--export-issued", issuedSerialHex, exportedCertPath, exportedChainPath]);
        Assert.True(expExit == 0, $"--export-issued failed ({expExit}): {expStdout}\n{expStderr}");
        Assert.Equal(await File.ReadAllTextAsync(leaf1CertPath), await File.ReadAllTextAsync(exportedCertPath));
        Assert.Equal(await File.ReadAllTextAsync(leaf1TlsChainPath), await File.ReadAllTextAsync(exportedChainPath));

        // 5. Verify #22 root-only CA topology: when the active CA is a self-signed Root CA (no intermediate),
        //    <outTlsServerChainPath> contains only the leaf certificate (1 cert, excluding the self-signed Root CA),
        //    while --root-out provides the Root CA and --fullchain-out provides leaf + Root CA (2 certs).
        string rootOnlyDb = Path.Combine(_tempRoot, "root-only-cli.db");
        string rootOnlyCaDir = Path.Combine(_tempRoot, "root-only-cli-ca");
        await RunCliAsync(rootOnlyDb, rootOnlyCaDir, passFile, ["--bootstrap-admin", "admin", "AdminSecret!2026", "*"]);
        await RunCliAsync(rootOnlyDb, rootOnlyCaDir, passFile, ["--init-ca", "Standalone Root CA", "standalone-root.contoso.com", "ECDSA-256", "3650"]);

        string rLeafPath = Path.Combine(outDir, "rleaf.crt");
        string rTlsChainPath = Path.Combine(outDir, "rleaf-tlschain.crt");
        string rRootPath = Path.Combine(outDir, "rleaf-root.crt");
        string rFullPath = Path.Combine(outDir, "rleaf-full.crt");
        var (rIssueExit, _, _) = await RunCliAsync(
            rootOnlyDb, rootOnlyCaDir, passFile,
            ["--issue-csr", "admin", csr1Path, rLeafPath, rTlsChainPath, "--root-out", rRootPath, "--fullchain-out", rFullPath]);
        Assert.Equal(0, rIssueExit);

        List<X509Certificate2> rTlsCerts = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
            null, await File.ReadAllTextAsync(rTlsChainPath), "rTlsChain");
        List<X509Certificate2> rRootCerts = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
            null, await File.ReadAllTextAsync(rRootPath), "rRoot");
        List<X509Certificate2> rFullCerts = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
            null, await File.ReadAllTextAsync(rFullPath), "rFull");
        try
        {
            Assert.Single(rTlsCerts); // Leaf only (self-signed root excluded from TLS server chain)
            Assert.False(CaChainAndConstraintValidator.IsSelfSignedCryptographically(rTlsCerts[0]));
            Assert.Single(rRootCerts);
            Assert.True(CaChainAndConstraintValidator.IsSelfSignedCryptographically(rRootCerts[0]));
            Assert.Equal(2, rFullCerts.Count);
        }
        finally
        {
            foreach (var c in rTlsCerts.Concat(rRootCerts).Concat(rFullCerts)) c.Dispose();
        }
    }

    [Fact]
    public async Task AdminUiRevocation_RequiresConfirmation_SupportsReasonSelection_CancelsCleanly_ChecksAdminRole_AndHandlesPublicationFailure()
    {
        string tempDir = Path.Combine(_tempRoot, "admin-ui-revoke");
        Directory.CreateDirectory(tempDir);

        await using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("CertRobo:DataDirectory", tempDir);
            builder.UseSetting("CertRobo:SqliteFilePath", Path.Combine(tempDir, "certrobo.db"));
            builder.UseSetting("CertRobo:CaStorageDirectory", Path.Combine(tempDir, "ca"));
        });

        using IServiceScope scope = factory.Services.CreateScope();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
        var (_, _, adminUser) = await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");

        const string secret = "AdminRevokeUiSecret!2026";
        await caService.CreateSelfSignedOrIntermediateCaAsync(
            "UI Test CA", "ui-ca.contoso.com", "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa, 256, 365, secret);

        KeyPair kp1 = _crypto.KeyGen(256);
        string csr1 = _crypto.CSRGen(kp1, "cert1.contoso.com", ["cert1.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
        IssuanceOutcome issued1 = await caService.IssueCertificateFromCsrAsync(adminUser!.Id, csr1);

        KeyPair kp2 = _crypto.KeyGen(256);
        string csr2 = _crypto.CSRGen(kp2, "cert2.contoso.com", ["cert2.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
        IssuanceOutcome issued2 = await caService.IssueCertificateFromCsrAsync(adminUser.Id, csr2);

        TestAuthStateProvider authProvider = new(adminUser.Id, "admin", AppRoles.Administrator);

        CertRobo.Pages.Admin adminPage = new();
        SetProperty(adminPage, "AccountService", acct);
        SetProperty(adminPage, "CaService", caService);
        SetProperty(adminPage, "CesService", scope.ServiceProvider.GetRequiredService<AdCsCesEnrollmentService>());
        SetProperty(adminPage, "BackupService", scope.ServiceProvider.GetRequiredService<BackupRestoreService>());
        SetProperty(adminPage, "MigrationService", scope.ServiceProvider.GetRequiredService<LegacySettingsMigrationService>());
        SetProperty(adminPage, "Configuration", scope.ServiceProvider.GetRequiredService<IConfiguration>());
        SetProperty(adminPage, "HostEnvironment", scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>());
        SetProperty(adminPage, "AuthenticationStateProvider", authProvider);
        SetProperty(adminPage, "NotificationService", scope.ServiceProvider.GetRequiredService<Radzen.NotificationService>());

        await InvokeMethodAsync(adminPage, "OnInitializedAsync");

        // 1. Clicking RevokeCertClick stages confirmation for cert1 without revoking it in the database
        await InvokeMethodAsync(adminPage, "RevokeCertClick", issued1.Record!.Id);
        Assert.Equal(issued1.Record.Id, GetField<int?>(adminPage, "pendingRevokeCertId"));
        IssuedCertificateRecord? stillIssuedAfterStage = (await caService.SearchCertificatesAsync("cert1.contoso.com", null)).Single();
        Assert.Equal(IssuanceStatus.Issued, stillIssuedAfterStage.Status);

        // 2. Clicking CancelRevokeCertClick clears the staged confirmation and makes no database changes
        await InvokeMethodAsync(adminPage, "CancelRevokeCertClick");
        Assert.Null(GetField<int?>(adminPage, "pendingRevokeCertId"));
        Assert.Equal(IssuanceStatus.Issued, (await caService.SearchCertificatesAsync("cert1.contoso.com", null)).Single().Status);

        // 3. Non-admin principal or disabled admin attempting ConfirmRevokeCertClick is rejected without revoking
        await InvokeMethodAsync(adminPage, "RevokeCertClick", issued1.Record.Id);
        authProvider.SetPrincipal("issuer-id", "alice-issuer", AppRoles.Issuer);
        await InvokeMethodAsync(adminPage, "ConfirmRevokeCertClick");
        Assert.Equal(IssuanceStatus.Issued, (await caService.SearchCertificatesAsync("cert1.contoso.com", null)).Single().Status);
        Assert.Contains("Authorisation Error", GetField<string?>(adminPage, "statusBannerMessage"));

        authProvider.SetPrincipal(adminUser.Id, "admin", AppRoles.Administrator);
        await acct.SetUserDisabledAsync(adminUser.Id, true);
        await InvokeMethodAsync(adminPage, "ConfirmRevokeCertClick");
        Assert.Equal(IssuanceStatus.Issued, (await caService.SearchCertificatesAsync("cert1.contoso.com", null)).Single().Status);
        Assert.Contains("Authorisation Error", GetField<string?>(adminPage, "statusBannerMessage"));
        await acct.SetUserDisabledAsync(adminUser.Id, false);

        // 4. Restore Administrator principal, select reason 4 (Superseded), and confirm revocation
        authProvider.SetPrincipal(adminUser.Id, "admin", AppRoles.Administrator);
        SetField(adminPage, "pendingRevokeReasonCode", CrlReason.Superseded);
        await InvokeMethodAsync(adminPage, "ConfirmRevokeCertClick");

        Assert.Null(GetField<int?>(adminPage, "pendingRevokeCertId"));
        IssuedCertificateRecord revokedCert1 = (await caService.SearchCertificatesAsync("cert1.contoso.com", null)).Single();
        Assert.Equal(IssuanceStatus.Revoked, revokedCert1.Status);
        Assert.Equal(CrlReason.Superseded, revokedCert1.RevocationReasonCode);
        Assert.Contains("4 — Superseded", GetField<string?>(adminPage, "statusBannerMessage"));

        // 5. Lock CA signing key, stage & confirm revocation of cert2 with reason 5 (CessationOfOperation) ->
        //    revocation is recorded with Pending CRL Publication warning
        caService.LockRuntimePassphrase();
        await InvokeMethodAsync(adminPage, "RevokeCertClick", issued2.Record!.Id);
        SetField(adminPage, "pendingRevokeReasonCode", CrlReason.CessationOfOperation);
        await InvokeMethodAsync(adminPage, "ConfirmRevokeCertClick");

        IssuedCertificateRecord revokedCert2 = (await caService.SearchCertificatesAsync("cert2.contoso.com", null)).Single();
        Assert.Equal(IssuanceStatus.Revoked, revokedCert2.Status);
        Assert.Equal(CrlReason.CessationOfOperation, revokedCert2.RevocationReasonCode);
        Assert.Contains("CRL Publication Pending", GetField<string?>(adminPage, "statusBannerMessage"));

        // 6. Service-level guard rejects unsupported CRL reason codes (such as 7 or 99)
        RevocationOutcome badReasonOutcome = await caService.RevokeCertificateAsync(issued1.Record.Id, 7, "admin");
        Assert.False(badReasonOutcome.RevocationAccepted);
        Assert.Equal(RevocationPublicationStatus.Rejected, badReasonOutcome.PublicationStatus);
    }

    [Fact]
    public async Task SqliteDatabaseFiles_AreCreatedWithPrivate0600Permissions_OnFirstStart_CliInvocation_AndRestore()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        const string secret = "SqlitePermissionsSecret!2026";
        string dbPath = Path.Combine(_tempRoot, "private-perms.db");
        string caDir = Path.Combine(_tempRoot, "private-perms-ca");
        string passFile = Path.Combine(_tempRoot, "private-perms.pass");
        await File.WriteAllTextAsync(passFile, secret + "\n");

        // 1. Direct CLI invocation creating the database for the first time
        var (bootExit, _, _) = await RunCliAsync(dbPath, caDir, passFile, ["--bootstrap-admin", "admin", "AdminSecret!2026", "*"]);
        Assert.Equal(0, bootExit);
        Assert.True(File.Exists(dbPath));

        UnixFileMode expectedPrivateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        Assert.Equal(expectedPrivateMode, File.GetUnixFileMode(dbPath));

        // 1b. While an active WAL connection/transaction is open, verify -wal and -shm actively exist and have 0600 permissions
        using (ServiceProvider openSp = BuildServiceProvider(dbPath, caDir, passFile))
        using (IServiceScope openScope = openSp.CreateScope())
        {
            CertRoboDbContext openDb = openScope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            await openDb.Database.OpenConnectionAsync();
            await openDb.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");
            await using var tx = await openDb.Database.BeginTransactionAsync();
            await openDb.Database.ExecuteSqlRawAsync("UPDATE \"SubjectDefaults\" SET \"Country\" = 'US';");
            CertRoboDbContext.RestrictSqliteDatabaseFilePermissionsIfUnix(dbPath);

            Assert.True(File.Exists(dbPath + "-wal"));
            Assert.True(File.Exists(dbPath + "-shm"));
            Assert.Equal(expectedPrivateMode, File.GetUnixFileMode(dbPath));
            Assert.Equal(expectedPrivateMode, File.GetUnixFileMode(dbPath + "-wal"));
            Assert.Equal(expectedPrivateMode, File.GetUnixFileMode(dbPath + "-shm"));
            await tx.RollbackAsync();
        }

        // 2. Loosen mode to 0644 to simulate a pre-existing database, then restart/run CLI and verify EnsureSchemaUpgradedAsync tightens it back to 0600
        File.SetUnixFileMode(dbPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        string backupZipPath = Path.Combine(_tempRoot, "backup.zip");
        var (bakExit, _, _) = await RunCliAsync(dbPath, caDir, passFile, ["--backup", backupZipPath]);
        Assert.Equal(0, bakExit);
        Assert.Equal(expectedPrivateMode, File.GetUnixFileMode(dbPath));

        // 3. Restore to a new path and verify restored DB and any companion files have 0600 permissions
        string restoredDbPath = Path.Combine(_tempRoot, "restored", "certrobo.db");
        string restoredCaDir = Path.Combine(_tempRoot, "restored", "ca");
        var (resExit, _, _) = await RunCliAsync(restoredDbPath, restoredCaDir, passFile, ["--restore", backupZipPath]);
        Assert.Equal(0, resExit);
        Assert.Equal(expectedPrivateMode, File.GetUnixFileMode(restoredDbPath));
        Assert.Equal(expectedPrivateMode, File.GetUnixFileMode(backupZipPath));
    }

    [Fact]
    public async Task BackupAndRestore_CreateSnapshotDatabase_KeyFiles_AndDataProtectionXml_PrivatelyBeforeWritingContents()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        UnixFileMode expectedFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        UnixFileMode expectedDirMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        UnixFileMode forbiddenGroupOtherMask =
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

        string sourceDir = Path.Combine(_tempRoot, "privacy-probe-source");
        string sourceDbPath = Path.Combine(sourceDir, "certrobo.db");
        string sourceCaDir = Path.Combine(sourceDir, "ca");
        string sourceDpDir = Path.Combine(sourceDir, "dp");
        string passFile = Path.Combine(sourceDir, "ca.pass");
        Directory.CreateDirectory(sourceDir);
        Directory.CreateDirectory(sourceCaDir);
        Directory.CreateDirectory(sourceDpDir);
        await File.WriteAllTextAsync(passFile, "ProbeSecret!2026\n");

        byte[] sampleKeyBytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(4096);
        byte[] sampleDpBytes = System.Text.Encoding.UTF8.GetBytes("<key id=\"probe\">" + new string('X', 65536) + "</key>");
        await BackupRestoreService.WritePrivateFileBytesAsync(Path.Combine(sourceCaDir, "ca-key-probe.p8.enc"), sampleKeyBytes);
        await BackupRestoreService.WritePrivateFileBytesAsync(Path.Combine(sourceDpDir, "key-probe.xml"), sampleDpBytes);

        using ServiceProvider sp = BuildServiceProvider(sourceDbPath, sourceCaDir, passFile);
        using (IServiceScope scope = sp.CreateScope())
        {
            CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            await db.EnsureSchemaUpgradedAsync();
        }

        // Populate a ~64 MiB SQLite database with incompressible random pages so VACUUM INTO and restore stream writes
        // are observable in-flight.
        await using (SqliteConnection conn = new($"Data Source={sourceDbPath}"))
        {
            await conn.OpenAsync();
            await using (SqliteCommand createCmd = conn.CreateCommand())
            {
                createCmd.CommandText = "CREATE TABLE IF NOT EXISTS BulkProbePayload (Id INTEGER PRIMARY KEY, Payload BLOB NOT NULL);";
                await createCmd.ExecuteNonQueryAsync();
            }

            await using var tx = await conn.BeginTransactionAsync();
            await using SqliteCommand insertCmd = conn.CreateCommand();
            insertCmd.Transaction = (SqliteTransaction)tx;
            insertCmd.CommandText = "INSERT INTO BulkProbePayload (Payload) VALUES ($blob);";
            SqliteParameter blobParam = insertCmd.Parameters.Add("$blob", SqliteType.Blob);
            for (int i = 0; i < 64; i++)
            {
                blobParam.Value = System.Security.Cryptography.RandomNumberGenerator.GetBytes(1024 * 1024);
                await insertCmd.ExecuteNonQueryAsync();
            }
            await tx.CommitAsync();
        }

        BackupRestoreService backupService = new(
            sp.GetRequiredService<IDbContextFactory<CertRoboDbContext>>(),
            sp.GetRequiredService<CaKeyCustodyOptions>());

        // 0. Verify CreatePrivateStagingDirectory creates a 0700 directory
        var createStagingDirMethod = typeof(BackupRestoreService).GetMethod(
            "CreatePrivateStagingDirectory",
            BindingFlags.Static | BindingFlags.NonPublic)!;
        string testStagingDir = (string)createStagingDirMethod.Invoke(null, null)!;
        try
        {
            Assert.Equal(expectedDirMode, File.GetUnixFileMode(testStagingDir));
        }
        finally
        {
            if (Directory.Exists(testStagingDir))
            {
                Directory.Delete(testStagingDir, recursive: true);
            }
        }

        // 1. Backup probe: invoke CreateBackupZipCoreAsync with a controlled snapshot path
        //    and sample its UnixFileMode from the moment of creation while VACUUM INTO is actively running.
        string controlledSnapshotDir = Path.Combine(_tempRoot, "controlled-backup-probe");
        Directory.CreateDirectory(controlledSnapshotDir);
        string controlledSnapshotPath = Path.Combine(controlledSnapshotDir, "snapshot.db");

        // Also verify EnsureEmptyPrivateFileCreated replaces a pre-existing permissive (0644) file with a 0600 empty file
        string preExistingPermissiveSnapshot = Path.Combine(controlledSnapshotDir, "preexisting-permissive.db");
        await File.WriteAllTextAsync(preExistingPermissiveSnapshot, "stale");
        File.SetUnixFileMode(
            preExistingPermissiveSnapshot,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        BackupRestoreService.EnsureEmptyPrivateFileCreated(preExistingPermissiveSnapshot);
        Assert.Equal(expectedFileMode, File.GetUnixFileMode(preExistingPermissiveSnapshot));
        Assert.Equal(0L, new FileInfo(preExistingPermissiveSnapshot).Length);

        var createBackupZipCoreMethod = typeof(BackupRestoreService).GetMethod(
            "CreateBackupZipCoreAsync",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

        List<UnixFileMode> observedBackupModes = [];
        bool observedBackupInFlight = false;
        using CancellationTokenSource backupObserverCts = new();

        Task<byte[]> backupTask = Task.Run(async () =>
        {
            Task<byte[]> inner = (Task<byte[]>)createBackupZipCoreMethod.Invoke(
                backupService,
                [sourceDbPath, sourceDpDir, controlledSnapshotPath, null, CancellationToken.None])!;
            return await inner;
        });

        Task backupObserver = Task.Run(() =>
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            while (!backupTask.IsCompleted && !backupObserverCts.IsCancellationRequested)
            {
                try
                {
                    if (File.Exists(controlledSnapshotPath))
                    {
                        UnixFileMode mode = File.GetUnixFileMode(controlledSnapshotPath);
                        long len = new FileInfo(controlledSnapshotPath).Length;
                        if (len < 60L * 1024 * 1024)
                        {
                            observedBackupInFlight = true;
                        }
                        observedBackupModes.Add(mode);
                    }
                }
                catch
                {
                }
            }
        });

        byte[] archiveBytes = await backupTask;
        backupObserverCts.Cancel();
        await backupObserver;

        Assert.True(File.Exists(controlledSnapshotPath));
        observedBackupModes.Add(File.GetUnixFileMode(controlledSnapshotPath));
        Assert.True(observedBackupInFlight, "Expected backup probe to observe snapshot.db while VACUUM INTO was in flight.");
        Assert.All(observedBackupModes, m => Assert.Equal(UnixFileMode.None, m & forbiddenGroupOtherMask));
        Assert.Equal(expectedFileMode, File.GetUnixFileMode(controlledSnapshotPath));

        // 2. Fresh restore probe: invoke RestoreBackupArchive into a fresh directory and sample modes while streaming
        string freshRestoreDir = Path.Combine(_tempRoot, "fresh-restore-probe");
        string freshRestoreDb = Path.Combine(freshRestoreDir, "certrobo.db");
        string freshRestoreCa = Path.Combine(freshRestoreDir, "ca");
        string freshRestoreDp = Path.Combine(freshRestoreDir, "dp");

        List<UnixFileMode> observedRestoreModes = [];
        bool observedRestoreInFlight = false;
        using CancellationTokenSource restoreObserverCts = new();

        Task restoreTask = Task.Run(() =>
            BackupRestoreService.RestoreBackupArchive(archiveBytes, freshRestoreDb, freshRestoreCa, freshRestoreDp));

        Task restoreObserver = Task.Run(() =>
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            while (!restoreTask.IsCompleted && !restoreObserverCts.IsCancellationRequested)
            {
                try
                {
                    if (File.Exists(freshRestoreDb))
                    {
                        UnixFileMode mode = File.GetUnixFileMode(freshRestoreDb);
                        long len = new FileInfo(freshRestoreDb).Length;
                        if (len < 60L * 1024 * 1024)
                        {
                            observedRestoreInFlight = true;
                        }
                        observedRestoreModes.Add(mode);
                    }

                    string caKeyFile = Path.Combine(freshRestoreCa, "ca-key-probe.p8.enc");
                    if (File.Exists(caKeyFile))
                    {
                        observedRestoreModes.Add(File.GetUnixFileMode(caKeyFile));
                    }

                    string dpXmlFile = Path.Combine(freshRestoreDp, "key-probe.xml");
                    if (File.Exists(dpXmlFile))
                    {
                        observedRestoreModes.Add(File.GetUnixFileMode(dpXmlFile));
                    }
                }
                catch
                {
                }
            }
        });

        await restoreTask;
        restoreObserverCts.Cancel();
        await restoreObserver;

        observedRestoreModes.Add(File.GetUnixFileMode(freshRestoreDb));
        observedRestoreModes.Add(File.GetUnixFileMode(Path.Combine(freshRestoreCa, "ca-key-probe.p8.enc")));
        observedRestoreModes.Add(File.GetUnixFileMode(Path.Combine(freshRestoreDp, "key-probe.xml")));

        Assert.True(observedRestoreInFlight, "Expected restore probe to observe certrobo.db while extraction was in flight.");
        Assert.All(observedRestoreModes, m => Assert.Equal(UnixFileMode.None, m & forbiddenGroupOtherMask));
        Assert.Equal(expectedFileMode, File.GetUnixFileMode(freshRestoreDb));
        Assert.Equal(expectedFileMode, File.GetUnixFileMode(Path.Combine(freshRestoreCa, "ca-key-probe.p8.enc")));
        Assert.Equal(expectedFileMode, File.GetUnixFileMode(Path.Combine(freshRestoreDp, "key-probe.xml")));

        // 3. Existing permissive target probe: pre-populate 0644 files and hold an open read handle to the old DB inode.
        //    RestoreBackupArchive must unlink the old permissive inodes before creating new 0600 files so neither
        //    the path nor the pre-existing file descriptor can read the newly restored contents.
        string permissiveDir = Path.Combine(_tempRoot, "permissive-restore-probe");
        string permissiveDb = Path.Combine(permissiveDir, "certrobo.db");
        string permissiveCa = Path.Combine(permissiveDir, "ca");
        string permissiveDp = Path.Combine(permissiveDir, "dp");
        Directory.CreateDirectory(permissiveDir);
        Directory.CreateDirectory(permissiveCa);
        Directory.CreateDirectory(permissiveDp);

        string permissiveKey = Path.Combine(permissiveCa, "ca-key-probe.p8.enc");
        string permissiveXml = Path.Combine(permissiveDp, "key-probe.xml");
        await File.WriteAllBytesAsync(permissiveDb, "OLD_PERMISSIVE_DB"u8.ToArray());
        await File.WriteAllBytesAsync(permissiveKey, "OLD_PERMISSIVE_KEY"u8.ToArray());
        await File.WriteAllBytesAsync(permissiveXml, "OLD_PERMISSIVE_XML"u8.ToArray());

        UnixFileMode worldReadableMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
        File.SetUnixFileMode(permissiveDb, worldReadableMode);
        File.SetUnixFileMode(permissiveKey, worldReadableMode);
        File.SetUnixFileMode(permissiveXml, worldReadableMode);

        await using FileStream preOpenedOldDbHandle = new(permissiveDb, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        BackupRestoreService.RestoreBackupArchive(archiveBytes, permissiveDb, permissiveCa, permissiveDp);

        Assert.Equal(expectedFileMode, File.GetUnixFileMode(permissiveDb));
        Assert.Equal(expectedFileMode, File.GetUnixFileMode(permissiveKey));
        Assert.Equal(expectedFileMode, File.GetUnixFileMode(permissiveXml));

        preOpenedOldDbHandle.Position = 0;
        using StreamReader oldReader = new(preOpenedOldDbHandle, leaveOpen: true);
        string oldInodeContents = await oldReader.ReadToEndAsync();
        Assert.Equal("OLD_PERMISSIVE_DB", oldInodeContents);
        Assert.True(new FileInfo(permissiveDb).Length > 60L * 1024 * 1024);
    }

    private sealed class TestAuthStateProvider : AuthenticationStateProvider
    {
        private ClaimsPrincipal _principal;

        public TestAuthStateProvider(string userId, string userName, string role)
        {
            _principal = BuildPrincipal(userId, userName, role);
        }

        public void SetPrincipal(string userId, string userName, string role)
        {
            _principal = BuildPrincipal(userId, userName, role);
        }

        private static ClaimsPrincipal BuildPrincipal(string userId, string userName, string role) =>
            new(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, userId),
                    new Claim(ClaimTypes.Name, userName),
                    new Claim(ClaimTypes.Role, role)
                ],
                "TestAuth"));

        public override Task<AuthenticationState> GetAuthenticationStateAsync() =>
            Task.FromResult(new AuthenticationState(_principal));
    }

    private static void SetProperty(object instance, string name, object value)
    {
        var prop = instance.GetType().GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!;
        prop.SetValue(instance, value);
    }

    private static T GetField<T>(object instance, string name)
    {
        var field = instance.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!;
        return (T)field.GetValue(instance)!;
    }

    private static void SetField(object instance, string name, object? value)
    {
        var field = instance.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!;
        field.SetValue(instance, value);
    }

    private static async Task InvokeMethodAsync(object instance, string name, params object[] args)
    {
        var method = instance.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!;
        if (method.Invoke(instance, args) is Task task)
        {
            await task;
        }
    }

    private static ServiceProvider BuildServiceProvider(
        string sqlitePath,
        string caStorageDir,
        string passFilePath)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection();
        services.AddDbContextFactory<CertRoboDbContext>(options =>
            options.UseSqlite($"Data Source={sqlitePath}"));
        services.AddScoped(sp =>
            sp.GetRequiredService<IDbContextFactory<CertRoboDbContext>>().CreateDbContext());

        services.AddIdentityCore<ApplicationUser>()
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<CertRoboDbContext>();

        services.AddSingleton(new CaKeyCustodyOptions
        {
            StorageDirectory = caStorageDir,
            PassphraseEnvironmentVariable = null,
            PassphraseFilePath = passFilePath,
            PublicBaseUrl = "http://pki.contoso.com"
        });

        services.AddScoped<AccountManagementService>();
        services.AddScoped<IssuancePolicyService>();
        services.AddSingleton<CertificateAuthorityService>();
        return services.BuildServiceProvider();
    }

    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunCliAsync(
        string dbPath,
        string caDir,
        string passFile,
        IReadOnlyList<string> cliArgs,
        IReadOnlyDictionary<string, string>? extraEnv = null)
    {
        string certRoboDll = typeof(Program).Assembly.Location;
        ProcessStartInfo psi = new("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(certRoboDll);
        foreach (string arg in cliArgs)
        {
            psi.ArgumentList.Add(arg);
        }

        psi.Environment["CertRobo__DataDirectory"] = Path.GetDirectoryName(dbPath)!;
        psi.Environment["CertRobo__SqliteFilePath"] = dbPath;
        psi.Environment["CertRobo__CaStorageDirectory"] = caDir;
        psi.Environment["CertRobo__CaPassphraseFile"] = passFile;
        psi.Environment["CertRobo__PublicBaseUrl"] = "http://pki.contoso.com";
        psi.Environment.Remove("CERTROBO_CA_PASSPHRASE");

        if (extraEnv != null)
        {
            foreach (var kv in extraEnv)
            {
                psi.Environment[kv.Key] = kv.Value;
            }
        }

        using Process proc = Process.Start(psi)!;
        string stdout = await proc.StandardOutput.ReadToEndAsync();
        string stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        return (proc.ExitCode, stdout, stderr);
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
