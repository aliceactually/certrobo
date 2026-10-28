using CertRobo.Data;
using CertRobo.Models;
using CertRobo.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertRobo.Tests;

public sealed class ExternalCaEnrollmentTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly string _dbPath;
    private readonly string _caDir;
    private readonly string _dpDir;
    private ServiceProvider _services;

    public ExternalCaEnrollmentTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"certrobo-external-ca-{Guid.NewGuid():N}");
        _dbPath = Path.Combine(_tempRoot, "certrobo.db");
        _caDir = Path.Combine(_tempRoot, "ca");
        _dpDir = Path.Combine(_tempRoot, "dataprotection-keys");
        Directory.CreateDirectory(_tempRoot);
        Directory.CreateDirectory(_dpDir);
        _services = BuildServices(_dbPath, _caDir, _dpDir);
    }

    [Fact]
    public async Task PendingRequest_PersistsAcrossRestart_RepeatedDownloadUsesSameKey_AndBackupIncludesPendingKey()
    {
        const string passphrase = "PendingVaultPass!2026";
        CertificateAuthorityService caService = _services.GetRequiredService<CertificateAuthorityService>();
        BackupRestoreService backupService = _services.GetRequiredService<BackupRestoreService>();

        PendingCaEnrollmentRecord pending = await CreatePendingAsync(caService, passphrase);
        Assert.True(File.Exists(pending.EncryptedPrivateKeyPath));

        var firstDownload = await caService.GetPendingCaCsrForDownloadAsync(pending.Id);
        var secondDownload = await caService.GetPendingCaCsrForDownloadAsync(pending.Id);
        Assert.NotNull(firstDownload);
        Assert.NotNull(secondDownload);
        Assert.Equal(firstDownload.Value.CsrPem, secondDownload.Value.CsrPem);
        Assert.Equal(pending.PublicKeySpkiSha256Hex, Sha256OfCsrPublicKey(firstDownload.Value.CsrPem));

        // Restart against the same SQLite/key storage and verify request/key reference are resumed.
        _services.Dispose();
        _services = BuildServices(_dbPath, _caDir, _dpDir);
        caService = _services.GetRequiredService<CertificateAuthorityService>();
        PendingCaEnrollmentRecord? resumed = await caService.GetActivePendingEnrollmentAsync();
        Assert.NotNull(resumed);
        Assert.Equal(pending.Id, resumed.Id);
        Assert.Equal(pending.CsrPem, resumed.CsrPem);
        Assert.Equal(pending.EncryptedPrivateKeyPath, resumed.EncryptedPrivateKeyPath);

        byte[] backup = await _services.GetRequiredService<BackupRestoreService>()
            .CreateConsistentBackupArchiveAsync(_dbPath, _dpDir);
        using MemoryStream backupStream = new(backup);
        using ZipArchive archive = new(backupStream, ZipArchiveMode.Read);
        Assert.NotNull(archive.GetEntry("database/certrobo.db"));
        Assert.NotNull(archive.GetEntry("ca/" + Path.GetFileName(pending.EncryptedPrivateKeyPath)));

        string restoredRoot = Path.Combine(_tempRoot, "portable-restore");
        string restoredDb = Path.Combine(restoredRoot, "certrobo.db");
        string restoredCa = Path.Combine(restoredRoot, "ca");
        string restoredDp = Path.Combine(restoredRoot, "dp");
        _services.Dispose();
        Directory.Delete(_caDir, recursive: true);
        BackupRestoreService.RestoreBackupArchive(backup, restoredDb, restoredCa, restoredDp);
        _services = BuildServices(restoredDb, restoredCa, restoredDp);

        PendingCaEnrollmentRecord? restoredPending = await _services
            .GetRequiredService<CertificateAuthorityService>()
            .GetActivePendingEnrollmentAsync();
        Assert.NotNull(restoredPending);
        Assert.Equal(
            Path.Combine(restoredCa, Path.GetFileName(pending.EncryptedPrivateKeyPath)),
            restoredPending.EncryptedPrivateKeyPath);
        Assert.True(File.Exists(restoredPending.EncryptedPrivateKeyPath));
    }

    [Fact]
    public async Task ManualExternalCaReplacement_IsExplicitAndAtomic_PreservesHistoricalIssuerAndCrl()
    {
        const string passphrase = "ReplacementVaultPass!2026";
        using IServiceScope scope = _services.CreateScope();
        AccountManagementService accounts = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        var (_, _, admin) = await accounts.BootstrapFirstAdminAsync(
            "admin", "AdminPass!2026", "admin@contoso.com", "*.contoso.com");
        Assert.NotNull(admin);

        CertificateAuthorityService caService = _services.GetRequiredService<CertificateAuthorityService>();
        CaAuthorityRecord oldCa = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Old Issuer",
            "old-issuer.contoso.com",
            "US",
            "Washington",
            "Redmond",
            "Contoso",
            "PKI",
            CertificateKeyFamily.Rsa,
            2048,
            365,
            passphrase);

        CryptoFactory crypto = new();
        KeyPair oldLeafKey = crypto.KeyGen(256);
        string oldCsr = crypto.CSRGen(
            oldLeafKey,
            "old.contoso.com",
            ["old.contoso.com"],
            "US",
            "Washington",
            "Redmond",
            "Contoso",
            "IT",
            "");
        IssuanceOutcome oldIssued = await caService.IssueCertificateFromCsrAsync(admin!.Id, oldCsr);
        Assert.True(oldIssued.Succeeded, oldIssued.ErrorMessage);
        Assert.Equal(oldCa.Id, oldIssued.Record!.CaAuthorityId);

        PendingCaEnrollmentRecord pending = await CreatePendingAsync(caService, passphrase);
        Assert.Equal(oldCa.Id, (await caService.GetActiveAuthorityAsync())!.Id);

        using TestCaRoot externalRoot = TestCaRoot.Create(
            "CN=Disposable External Root CA,O=CertRobo Tests,C=US",
            pathLengthConstraint: 1);
        using X509Certificate2 signedIssuingCa = SignPendingCa(
            pending.CsrPem,
            externalRoot,
            isCa: true,
            keyUsage: X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature);

        // Accept unordered and duplicate chain inputs.
        string unorderedPrimaryBundle = externalRoot.Certificate.ExportCertificatePem()
            + "\n"
            + signedIssuingCa.ExportCertificatePem()
            + "\n"
            + externalRoot.Certificate.ExportCertificatePem();

        CaBundleValidationResult validation = await caService.ValidateAndStageSignedCaBundleAsync(
            pending.Id,
            signedCertBytes: null,
            signedCertText: unorderedPrimaryBundle,
            chainCertBytes: null,
            chainCertText: externalRoot.Certificate.ExportCertificatePem());
        Assert.True(validation.IsValid, validation.ErrorMessage);
        Assert.NotNull(validation.Summary);
        Assert.Equal(2, validation.Summary.ChainElements.Count);

        // Staging does not replace the active issuer.
        Assert.Equal(oldCa.Id, (await caService.GetActiveAuthorityAsync())!.Id);
        KeyPair duringPendingKey = crypto.KeyGen(256);
        string duringPendingCsr = crypto.CSRGen(
            duringPendingKey,
            "during-pending.contoso.com",
            ["during-pending.contoso.com"],
            "US", "Washington", "Redmond", "Contoso", "IT", "");
        IssuanceOutcome duringPending = await caService.IssueCertificateFromCsrAsync(admin.Id, duringPendingCsr);
        Assert.True(duringPending.Succeeded, duringPending.ErrorMessage);
        Assert.Equal(oldCa.Id, duringPending.Record!.CaAuthorityId);

        CaAuthorityRecord replacement = await caService.ActivatePendingCaEnrollmentAsync(pending.Id);
        Assert.NotEqual(oldCa.Id, replacement.Id);
        Assert.True(replacement.IsActive);
        Assert.Equal($"/authorities/{replacement.Id}/ca.crl", replacement.CrlDistributionPointUrl);
        Assert.Equal($"/authorities/{replacement.Id}/issuer.crt", replacement.AuthorityIssuerCertUrl);

        IReadOnlyList<CaAuthorityRecord> authorities = await caService.ListAuthoritiesAsync();
        Assert.False(authorities.Single(c => c.Id == oldCa.Id).IsActive);
        Assert.True(authorities.Single(c => c.Id == replacement.Id).IsActive);

        KeyPair newLeafKey = crypto.KeyGen(2048);
        string newCsr = crypto.CSRGen(
            newLeafKey,
            "new.contoso.com",
            ["new.contoso.com"],
            "US",
            "Washington",
            "Redmond",
            "Contoso",
            "IT",
            "");
        IssuanceOutcome newIssued = await caService.IssueCertificateFromCsrAsync(admin.Id, newCsr);
        Assert.True(newIssued.Succeeded, newIssued.ErrorMessage);
        Assert.Equal(replacement.Id, newIssued.Record!.CaAuthorityId);
        Assert.Contains(signedIssuingCa.ExportCertificatePem().Trim(), newIssued.Record.ChainPem);
        Assert.Contains(externalRoot.Certificate.ExportCertificatePem().Trim(), newIssued.Record.ChainPem);

        // Historical export resolution must keep the old leaf associated with its original issuer.
        string? oldResolvedChain = await caService.ResolveCertificateChainPemAsync(oldIssued.CertificatePem!);
        Assert.Equal(oldIssued.Record.ChainPem, oldResolvedChain);
        Assert.DoesNotContain(signedIssuingCa.GetCertHashString(HashAlgorithmName.SHA256), oldResolvedChain);

        // Historical revocation still signs and persists the old issuer's CRL after rollover.
        var (revoked, revokeError) = await caService.RevokeCertificateAsync(
            oldIssued.Record.Id,
            Org.BouncyCastle.Asn1.X509.CrlReason.KeyCompromise,
            "admin");
        Assert.True(revoked, revokeError);
        PublishedCrlRecord? oldIssuerCrl = await caService.GetLatestCrlAsync(caAuthorityId: oldCa.Id);
        PublishedCrlRecord? activeIssuerCrl = await caService.GetLatestCrlAsync(caAuthorityId: replacement.Id);
        Assert.NotNull(oldIssuerCrl);
        Assert.NotNull(activeIssuerCrl);
        Assert.Equal(2, oldIssuerCrl.CrlNumber);
        Assert.Equal(1, activeIssuerCrl.CrlNumber);
        IReadOnlyList<CrlRefreshOutcome> rolloverRefresh = await caService.RefreshDueCrlsAsync(
            TimeSpan.FromDays(8));
        Assert.Contains(rolloverRefresh, r =>
            r.CaAuthorityId == oldCa.Id && r.Succeeded && r.PublishedCrl!.CrlNumber == 3);
        Assert.Contains(rolloverRefresh, r =>
            r.CaAuthorityId == replacement.Id && r.Succeeded && r.PublishedCrl!.CrlNumber == 2);

        // PEM server chain excludes the trust root; PKCS #12 and PKCS #7 include the full chain.
        Tuple<string, byte[]> export = Assert.IsType<Tuple<string, byte[]>>(PkcsBuilder.Export(
            newIssued.CertificatePem!,
            newLeafKey.Private,
            chainPemContent: newIssued.Record.ChainPem));
        using MemoryStream zipStream = new(export.Item2);
        using ZipArchive zip = new(zipStream, ZipArchiveMode.Read);
        string serverChainPem;
        using (StreamReader reader = new(zip.GetEntry("new.contoso.com-chained.crt")!.Open()))
        {
            serverChainPem = await reader.ReadToEndAsync();
        }
        Assert.Contains(signedIssuingCa.ExportCertificatePem().Trim(), serverChainPem);
        Assert.DoesNotContain(externalRoot.Certificate.ExportCertificatePem().Trim(), serverChainPem);
        Assert.NotNull(zip.GetEntry("rootca.crt"));
        ZipArchiveEntry chainedP7b = zip.GetEntry("new.contoso.com-chained.p7b")!;
        using (MemoryStream p7b = new())
        {
            await chainedP7b.Open().CopyToAsync(p7b);
            List<X509Certificate2> parsedP7b = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                p7b.ToArray(),
                null,
                "exported P7B");
            Assert.Equal(3, parsedP7b.Count);
            foreach (X509Certificate2 c in parsedP7b) c.Dispose();
        }
        Assert.NotNull(zip.GetEntry("new.contoso.com-chained.p12"));
    }

    [Fact]
    public async Task FailedManualCompletionAndCancellation_LeaveActiveCaIntact()
    {
        const string passphrase = "FailureVaultPass!2026";
        CertificateAuthorityService caService = _services.GetRequiredService<CertificateAuthorityService>();
        CaAuthorityRecord oldCa = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Active Root",
            "active-root.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Rsa,
            2048,
            365,
            passphrase);

        PendingCaEnrollmentRecord pending = await CreatePendingAsync(caService, passphrase);
        using TestCaRoot externalRoot = TestCaRoot.Create("CN=External Root,O=Tests,C=US", 1);

        // Sign a different CSR: public key correspondence must fail.
        using RSA wrongKey = RSA.Create(2048);
        CertificateRequest wrongRequest = new(
            "CN=Wrong Pending CA,O=Tests,C=US",
            wrongKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        wrongRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        wrongRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            true));
        using X509Certificate2 wrongCert = wrongRequest.Create(
            externalRoot.Certificate.SubjectName,
            X509SignatureGenerator.CreateForRSA(externalRoot.Key, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(30),
            [0x21, 0x22, 0x23]);

        CaBundleValidationResult failed = await caService.ValidateAndStageSignedCaBundleAsync(
            pending.Id,
            null,
            wrongCert.ExportCertificatePem(),
            null,
            externalRoot.Certificate.ExportCertificatePem());
        Assert.False(failed.IsValid);
        Assert.Contains("match", failed.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(oldCa.Id, (await caService.GetActiveAuthorityAsync())!.Id);
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => caService.ActivatePendingCaEnrollmentAsync(pending.Id));

        string pendingKeyPath = pending.EncryptedPrivateKeyPath;
        var (cancelled, cancelError) = await caService.CancelPendingCaEnrollmentAsync(pending.Id);
        Assert.True(cancelled, cancelError);
        Assert.False(File.Exists(pendingKeyPath));
        Assert.Equal(oldCa.Id, (await caService.GetActiveAuthorityAsync())!.Id);
        Assert.Null(await caService.GetActivePendingEnrollmentAsync());
    }

    [Fact]
    public async Task ValidatorRejectsInvalidCaResponsesAndUnsafeConstraints()
    {
        const string passphrase = "ValidationVaultPass!2026";
        CertificateAuthorityService caService = _services.GetRequiredService<CertificateAuthorityService>();

        // Non-CA response
        PendingCaEnrollmentRecord pending = await CreatePendingAsync(caService, passphrase);
        using TestCaRoot root = TestCaRoot.Create("CN=Validation Root,O=Tests,C=US", 2);
        using X509Certificate2 nonCa = SignPendingCa(
            pending.CsrPem,
            root,
            isCa: false,
            keyUsage: X509KeyUsageFlags.DigitalSignature);
        CaBundleValidationResult nonCaResult = await caService.ValidateAndStageSignedCaBundleAsync(
            pending.Id, null, nonCa.ExportCertificatePem(), null, root.Certificate.ExportCertificatePem());
        Assert.False(nonCaResult.IsValid);
        Assert.Contains("not a valid CA", nonCaResult.ErrorMessage);
        await caService.CancelPendingCaEnrollmentAsync(pending.Id);

        // CA certificate without CrlSign
        pending = await CreatePendingAsync(caService, passphrase);
        using X509Certificate2 noCrlSign = SignPendingCa(
            pending.CsrPem,
            root,
            isCa: true,
            keyUsage: X509KeyUsageFlags.KeyCertSign);
        CaBundleValidationResult noCrlResult = await caService.ValidateAndStageSignedCaBundleAsync(
            pending.Id, null, noCrlSign.ExportCertificatePem(), null, root.Certificate.ExportCertificatePem());
        Assert.False(noCrlResult.IsValid);
        Assert.Contains("CrlSign", noCrlResult.ErrorMessage);
        await caService.CancelPendingCaEnrollmentAsync(pending.Id);

        // Not-yet-valid and expired responses
        pending = await CreatePendingAsync(caService, passphrase);
        using X509Certificate2 future = SignPendingCa(
            pending.CsrPem,
            root,
            true,
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            notBefore: DateTimeOffset.UtcNow.AddDays(2),
            notAfter: DateTimeOffset.UtcNow.AddDays(30));
        CaBundleValidationResult futureResult = await caService.ValidateAndStageSignedCaBundleAsync(
            pending.Id, null, future.ExportCertificatePem(), null, root.Certificate.ExportCertificatePem());
        Assert.False(futureResult.IsValid);
        Assert.Contains("not yet valid", futureResult.ErrorMessage);
        await caService.CancelPendingCaEnrollmentAsync(pending.Id);

        pending = await CreatePendingAsync(caService, passphrase);
        using X509Certificate2 expired = SignPendingCa(
            pending.CsrPem,
            root,
            true,
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            notBefore: DateTimeOffset.UtcNow.AddDays(-30),
            notAfter: DateTimeOffset.UtcNow.AddDays(-1));
        CaBundleValidationResult expiredResult = await caService.ValidateAndStageSignedCaBundleAsync(
            pending.Id, null, expired.ExportCertificatePem(), null, root.Certificate.ExportCertificatePem());
        Assert.False(expiredResult.IsValid);
        Assert.Contains("expired", expiredResult.ErrorMessage);
        await caService.CancelPendingCaEnrollmentAsync(pending.Id);

        // Parent pathLen=0 cannot authorize another issuing intermediate.
        pending = await CreatePendingAsync(caService, passphrase);
        using TestCaRoot pathZeroRoot = TestCaRoot.Create("CN=Path Zero Root,O=Tests,C=US", 0);
        using X509Certificate2 pathViolation = SignPendingCa(
            pending.CsrPem,
            pathZeroRoot,
            true,
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign);
        CaBundleValidationResult pathResult = await caService.ValidateAndStageSignedCaBundleAsync(
            pending.Id, null, pathViolation.ExportCertificatePem(), null, pathZeroRoot.Certificate.ExportCertificatePem());
        Assert.False(pathResult.IsValid);
        Assert.Contains("pathLenConstraint", pathResult.ErrorMessage);
        await caService.CancelPendingCaEnrollmentAsync(pending.Id);

        // Unsupported critical restriction on the returned Issuing CA.
        pending = await CreatePendingAsync(caService, passphrase);
        using X509Certificate2 unknownCritical = SignPendingCa(
            pending.CsrPem,
            root,
            true,
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            additionalExtensions:
            [
                new System.Security.Cryptography.X509Certificates.X509Extension(
                    "1.2.3.4.5.6.7.8.9",
                    [0x05, 0x00],
                    critical: true)
            ]);
        CaBundleValidationResult criticalResult = await caService.ValidateAndStageSignedCaBundleAsync(
            pending.Id, null, unknownCritical.ExportCertificatePem(), null, root.Certificate.ExportCertificatePem());
        Assert.False(criticalResult.IsValid);
        Assert.Contains("unsupported critical extension", criticalResult.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        await caService.CancelPendingCaEnrollmentAsync(pending.Id);

        // Issuer name equality is not accepted as proof: a certificate signed by another key must fail.
        pending = await CreatePendingAsync(caService, passphrase);
        using RSA rogueSigner = RSA.Create(2048);
        CertificateRequest loaded = CertificateRequest.LoadSigningRequestPem(
            pending.CsrPem,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        CertificateRequest brokenRequest = new(loaded.SubjectName, loaded.PublicKey, HashAlgorithmName.SHA256);
        brokenRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        brokenRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            true));
        using X509Certificate2 brokenSignature = brokenRequest.Create(
            root.Certificate.SubjectName,
            X509SignatureGenerator.CreateForRSA(rogueSigner, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(30),
            RandomNumberGenerator.GetBytes(16));
        CaBundleValidationResult brokenResult = await caService.ValidateAndStageSignedCaBundleAsync(
            pending.Id, null, brokenSignature.ExportCertificatePem(), null, root.Certificate.ExportCertificatePem());
        Assert.False(brokenResult.IsValid);
        Assert.Contains("signature verification failed", brokenResult.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task IssuanceHonorsDnsNameAndEkuConstraintsFromExternalChain()
    {
        const string passphrase = "ConstraintVaultPass!2026";
        CertificateAuthorityService caService = _services.GetRequiredService<CertificateAuthorityService>();
        using IServiceScope scope = _services.CreateScope();
        AccountManagementService accounts = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        var (_, _, admin) = await accounts.BootstrapFirstAdminAsync(
            "admin", "AdminPass!2026", "admin@contoso.com", "*");
        Assert.NotNull(admin);

        NameConstraints nameConstraints = new(
            permitted: (IList<GeneralSubtree>)new GeneralSubtree[]
            {
                new GeneralSubtree(new GeneralName(GeneralName.DnsName, ".contoso.com"))
            },
            excluded: (IList<GeneralSubtree>)new GeneralSubtree[]
            {
                new GeneralSubtree(new GeneralName(GeneralName.DnsName, ".blocked.contoso.com"))
            });
        OidCollection serverOnlyEku = [];
        serverOnlyEku.Add(new Oid(CertificateProfiles.ServerAuthOid));

        using TestCaRoot constrainedRoot = TestCaRoot.Create(
            "CN=Constrained External Root,O=Tests,C=US",
            1,
            [
                new System.Security.Cryptography.X509Certificates.X509Extension(
                    X509Extensions.NameConstraints.Id,
                    nameConstraints.GetDerEncoded(),
                    critical: true),
                new X509EnhancedKeyUsageExtension(serverOnlyEku, critical: false)
            ]);

        PendingCaEnrollmentRecord pending = await CreatePendingAsync(caService, passphrase);
        using X509Certificate2 signedCa = SignPendingCa(
            pending.CsrPem,
            constrainedRoot,
            true,
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign);
        CaBundleValidationResult staged = await caService.ValidateAndStageSignedCaBundleAsync(
            pending.Id,
            null,
            signedCa.ExportCertificatePem(),
            null,
            constrainedRoot.Certificate.ExportCertificatePem());
        Assert.True(staged.IsValid, staged.ErrorMessage);
        Assert.Contains(CertificateProfiles.ServerAuthOid, staged.Summary!.EffectivePermittedEkuOids);
        Assert.Contains(".contoso.com", staged.Summary.PermittedDnsSubtrees);
        await caService.ActivatePendingCaEnrollmentAsync(pending.Id);

        CryptoFactory crypto = new();
        KeyPair allowedKey = crypto.KeyGen(256);
        string allowedCsr = crypto.CSRGen(
            allowedKey,
            "api.contoso.com",
            ["api.contoso.com"],
            "US", "Washington", "Redmond", "Contoso", "IT", "");
        IssuanceOutcome allowed = await caService.IssueCertificateFromCsrAsync(admin!.Id, allowedCsr);
        Assert.True(allowed.Succeeded, allowed.ErrorMessage);
        using X509Certificate2 allowedCert = X509Certificate2.CreateFromPem(allowed.CertificatePem);
        X509EnhancedKeyUsageExtension leafEku = allowedCert.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Single();
        string[] leafEkuOids = leafEku.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value!).ToArray();
        Assert.Contains(CertificateProfiles.ServerAuthOid, leafEkuOids);
        Assert.DoesNotContain(CertificateProfiles.ClientAuthOid, leafEkuOids);

        KeyPair outsideKey = crypto.KeyGen(256);
        string outsideCsr = crypto.CSRGen(
            outsideKey,
            "api.example.org",
            ["api.example.org"],
            "US", "Washington", "Redmond", "Contoso", "IT", "");
        IssuanceOutcome outside = await caService.IssueCertificateFromCsrAsync(admin.Id, outsideCsr);
        Assert.False(outside.Succeeded);
        Assert.Contains("permitted NameConstraints", outside.ErrorMessage);

        KeyPair excludedKey = crypto.KeyGen(256);
        string excludedCsr = crypto.CSRGen(
            excludedKey,
            "host.blocked.contoso.com",
            ["host.blocked.contoso.com"],
            "US", "Washington", "Redmond", "Contoso", "IT", "");
        IssuanceOutcome excluded = await caService.IssueCertificateFromCsrAsync(admin.Id, excludedCsr);
        Assert.False(excluded.Succeeded);
        Assert.Contains("excluded NameConstraints", excluded.ErrorMessage);
    }

    private async Task<PendingCaEnrollmentRecord> CreatePendingAsync(
        CertificateAuthorityService caService,
        string passphrase)
    {
        return await caService.CreatePendingCaEnrollmentAsync(
            "External Issuing CA",
            "external-issuing.contoso.com",
            "US",
            "Washington",
            "Redmond",
            "Contoso",
            "PKI",
            CertificateKeyFamily.Ecdsa,
            256,
            passphrase,
            requestedPathLengthConstraint: 0,
            crlDistributionPointUrl: "/ca.crl",
            authorityIssuerCertUrl: "/ca.crt");
    }

    private static X509Certificate2 SignPendingCa(
        string csrPem,
        TestCaRoot issuer,
        bool isCa,
        X509KeyUsageFlags keyUsage,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        IEnumerable<System.Security.Cryptography.X509Certificates.X509Extension>? additionalExtensions = null)
    {
        CertificateRequest loaded = CertificateRequest.LoadSigningRequestPem(
            csrPem,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        CertificateRequest request = new(
            loaded.SubjectName,
            loaded.PublicKey,
            HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            isCa,
            hasPathLengthConstraint: isCa,
            pathLengthConstraint: 0,
            critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        X509SubjectKeyIdentifierExtension issuerSki = issuer.Certificate.Extensions
            .OfType<X509SubjectKeyIdentifierExtension>()
            .Single();
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuerSki));

        if (additionalExtensions != null)
        {
            foreach (System.Security.Cryptography.X509Certificates.X509Extension extension in additionalExtensions)
            {
                request.CertificateExtensions.Add(extension);
            }
        }

        return request.Create(
            issuer.Certificate.SubjectName,
            X509SignatureGenerator.CreateForRSA(issuer.Key, RSASignaturePadding.Pkcs1),
            notBefore ?? DateTimeOffset.UtcNow.AddMinutes(-5),
            notAfter ?? DateTimeOffset.UtcNow.AddDays(90),
            RandomNumberGenerator.GetBytes(16));
    }

    private static string Sha256OfCsrPublicKey(string csrPem)
    {
        Pkcs10CertificationRequest csr = Assert.IsType<Pkcs10CertificationRequest>(
            new PemReader(new StringReader(csrPem)).ReadObject());
        Assert.True(csr.Verify());
        byte[] spki = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory
            .CreateSubjectPublicKeyInfo(csr.GetPublicKey())
            .GetDerEncoded();
        return Convert.ToHexString(SHA256.HashData(spki));
    }

    private static ServiceProvider BuildServices(string dbPath, string caDir, string dpDir)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(dpDir));
        services.AddDbContextFactory<CertRoboDbContext>(options =>
            options.UseSqlite($"Data Source={dbPath}"));
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
            StorageDirectory = caDir,
            PassphraseEnvironmentVariable = null
        });
        services.AddScoped<AccountManagementService>();
        services.AddScoped<IssuancePolicyService>();
        services.AddSingleton<CertificateAuthorityService>();
        services.AddSingleton<BackupRestoreService>();

        ServiceProvider provider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true
        });
        using IServiceScope scope = provider.CreateScope();
        CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
        db.EnsureSchemaUpgradedAsync().GetAwaiter().GetResult();
        return provider;
    }

    public void Dispose()
    {
        _services.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_tempRoot, recursive: true);
        }
        catch
        {
        }
    }

    private sealed class TestCaRoot : IDisposable
    {
        public RSA Key { get; }
        public X509Certificate2 Certificate { get; }

        private TestCaRoot(RSA key, X509Certificate2 certificate)
        {
            Key = key;
            Certificate = certificate;
        }

        public static TestCaRoot Create(
            string subject,
            int pathLengthConstraint,
            IEnumerable<System.Security.Cryptography.X509Certificates.X509Extension>? additionalExtensions = null)
        {
            RSA key = RSA.Create(2048);
            CertificateRequest request = new(
                subject,
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                true,
                hasPathLengthConstraint: true,
                pathLengthConstraint,
                critical: true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                critical: true));
            X509SubjectKeyIdentifierExtension ski = new(request.PublicKey, critical: false);
            request.CertificateExtensions.Add(ski);
            request.CertificateExtensions.Add(
                X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(ski));
            if (additionalExtensions != null)
            {
                foreach (System.Security.Cryptography.X509Certificates.X509Extension extension in additionalExtensions)
                {
                    request.CertificateExtensions.Add(extension);
                }
            }

            X509Certificate2 cert = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-2),
                DateTimeOffset.UtcNow.AddYears(5));
            return new TestCaRoot(key, cert);
        }

        public void Dispose()
        {
            Certificate.Dispose();
            Key.Dispose();
        }
    }
}
