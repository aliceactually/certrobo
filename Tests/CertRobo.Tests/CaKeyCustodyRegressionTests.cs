using CertRobo.Data;
using CertRobo.Models;
using CertRobo.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertRobo.Tests;

public sealed class CaKeyCustodyRegressionTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly CryptoFactory _crypto = new();

    public CaKeyCustodyRegressionTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"certrobo-custody-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    [Fact]
    public async Task FirstCa_And_ReplacementMismatches_AreRejectedBeforeSideEffects_WhilePreviousCaRemainsUsable()
    {
        const string secretA = "SyntheticCustodySecret-Alpha!2026";
        const string secretB = "SyntheticCustodySecret-Bravo!2026";

        string dbPath = Path.Combine(_tempRoot, "mismatch.db");
        string caDir = Path.Combine(_tempRoot, "mismatch-ca");
        string passFile = Path.Combine(_tempRoot, "ca.pass");
        await File.WriteAllTextAsync(passFile, secretA + "\n");

        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir, passFilePath: passFile);
        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
        ApplicationUser admin = await BootstrapAdminAsync(sp);

        // 1. First-CA mismatches (create, PEM import, PKCS#12 import, pending external enrollment) against configured persistent custody (secretA)
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            caService.CreateSelfSignedOrIntermediateCaAsync(
                "Mismatched First Root CA",
                "mismatched-first.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                365,
                secretB));

        using ECDsa externalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest extReq = new("CN=Imported B, O=Contoso, C=US", externalKey, HashAlgorithmName.SHA256);
        extReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        extReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using X509Certificate2 extCert = extReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(365));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            caService.ImportCaAsync(
                "Mismatched First Import PEM",
                extCert.ExportCertificatePem(),
                null,
                externalKey.ExportPkcs8PrivateKeyPem(),
                inputKeyPassphrase: null,
                storagePassphrase: secretB));

        byte[] pfxBytes = extCert.Export(X509ContentType.Pkcs12, "BundleImportPass!123")!;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            caService.ImportCaFromPkcs12Async(
                "Mismatched First Import PFX",
                pfxBytes,
                pkcs12Password: "BundleImportPass!123",
                storagePassphrase: secretB));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            caService.CreatePendingCaEnrollmentAsync(
                "Mismatched First Pending CA",
                "mismatched-pending.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                secretB));

        Assert.Null(await caService.GetActiveAuthorityAsync());
        Assert.Empty(await caService.ListAuthoritiesAsync());
        Assert.Null(await caService.GetActivePendingEnrollmentAsync());
        Assert.True(!Directory.Exists(caDir) || Directory.GetFiles(caDir, "*.p8.enc").Length == 0);

        // 2. Create valid Issuer A using configured secretA and issue an unexpired leaf certificate
        CaAuthorityRecord issuerA = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Issuer A",
            "issuer-a.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa,
            256,
            365,
            secretA);

        int keyFilesAfterIssuerA = Directory.GetFiles(caDir, "*.p8.enc").Length;
        Assert.Equal(1, keyFilesAfterIssuerA);

        KeyPair leafKey1 = _crypto.KeyGen(256);
        string csr1 = _crypto.CSRGen(leafKey1, "app1.contoso.com", ["app1.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
        IssuanceOutcome issued1 = await caService.IssueCertificateFromCsrAsync(admin.Id, csr1);
        Assert.True(issued1.Succeeded, issued1.ErrorMessage);

        // 3. Replacement local CA creation, subordinate creation with mismatched parentPassphrase, PEM import, PFX import, and pending external request with secretB must all be rejected
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            caService.CreateSelfSignedOrIntermediateCaAsync(
                "Replacement Issuer B",
                "issuer-b.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                365,
                secretB));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            caService.CreateSelfSignedOrIntermediateCaAsync(
                "Mismatched Subordinate B",
                "sub-b.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                180,
                secretB,
                parentAuthority: issuerA,
                parentPassphrase: secretA));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            caService.ImportCaAsync(
                "Imported B PEM",
                extCert.ExportCertificatePem(),
                null,
                externalKey.ExportPkcs8PrivateKeyPem(),
                inputKeyPassphrase: null,
                storagePassphrase: secretB));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            caService.ImportCaFromPkcs12Async(
                "Imported B PFX",
                pfxBytes,
                pkcs12Password: "BundleImportPass!123",
                storagePassphrase: secretB));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            caService.CreatePendingCaEnrollmentAsync(
                "Mismatched Pending Replacement",
                "pending-b.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                secretB));

        // Verify no orphan key files were left behind and Issuer A remains active and able to sign and refresh CRLs
        Assert.Equal(keyFilesAfterIssuerA, Directory.GetFiles(caDir, "*.p8.enc").Length);
        CaAuthorityRecord? currentActive = await caService.GetActiveAuthorityAsync();
        Assert.NotNull(currentActive);
        Assert.Equal(issuerA.Id, currentActive.Id);

        KeyPair leafKey2 = _crypto.KeyGen(256);
        string csr2 = _crypto.CSRGen(leafKey2, "app2.contoso.com", ["app2.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
        IssuanceOutcome issued2 = await caService.IssueCertificateFromCsrAsync(admin.Id, csr2);
        Assert.True(issued2.Succeeded, issued2.ErrorMessage);

        PublishedCrlRecord? refreshedCrl = await caService.RefreshActiveCrlAsync();
        Assert.NotNull(refreshedCrl);
        Assert.Equal(2, refreshedCrl.CrlNumber);
    }

    [Fact]
    public async Task IncorrectRuntimeUnlock_IsRejected_WithoutReplacingExistingValidUnlock_And_ManualCustodyRequiresUnlockAfterRestart()
    {
        const string secretA = "ValidManualSecret-Alpha!2026";
        const string wrongSecret = "WrongManualSecret-Bravo!2026";

        string dbPath = Path.Combine(_tempRoot, "unlock.db");
        string caDir = Path.Combine(_tempRoot, "unlock-ca");

        ApplicationUser admin;
        using (ServiceProvider sp = BuildServiceProvider(dbPath, caDir))
        {
            CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
            admin = await BootstrapAdminAsync(sp);

            // Unlocking before any CA exists must be rejected
            Assert.Throws<InvalidOperationException>(() => caService.UnlockRuntimePassphrase(secretA));

            await caService.CreateSelfSignedOrIntermediateCaAsync(
                "Manual Custody Root CA",
                "manual-root.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                365,
                secretA);

            // Attempt an invalid runtime unlock while CA is already unlocked with secretA
            Assert.Throws<InvalidOperationException>(() => caService.UnlockRuntimePassphrase(wrongSecret));

            // Existing valid runtime unlock must remain intact and able to sign
            Assert.Equal(secretA, caService.ResolveEffectivePassphrase());
            KeyPair leafKey = _crypto.KeyGen(256);
            string csr = _crypto.CSRGen(leafKey, "still-working.contoso.com", ["still-working.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
            IssuanceOutcome outcome = await caService.IssueCertificateFromCsrAsync(admin.Id, csr);
            Assert.True(outcome.Succeeded, outcome.ErrorMessage);

            // Intentional lock clears runtime unlock
            caService.LockRuntimePassphrase();
            Assert.Null(caService.ResolveEffectivePassphrase());

            // Incorrect unlock while locked is rejected and leaves CA locked
            Assert.Throws<InvalidOperationException>(() => caService.UnlockRuntimePassphrase(wrongSecret));
            Assert.Null(caService.ResolveEffectivePassphrase());

            // Even while locked, attempting to replace the CA using a different passphrase must be rejected because existing CA key on disk uses secretA
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                caService.CreateSelfSignedOrIntermediateCaAsync(
                    "Locked Mismatched Replacement",
                    "locked-mismatch.contoso.com",
                    "US", "WA", "Redmond", "Contoso", "PKI",
                    CertificateKeyFamily.Ecdsa,
                    256,
                    365,
                    wrongSecret));

            // Correct unlock restores signing capability
            caService.UnlockRuntimePassphrase(secretA);
            Assert.Equal(secretA, caService.ResolveEffectivePassphrase());
            PublishedCrlRecord? crl = await caService.RefreshActiveCrlAsync();
            Assert.NotNull(crl);
        }

        // Simulate restart with no persistent custody configured: CA must start in locked state until manually unlocked
        using (ServiceProvider restartedSp = BuildServiceProvider(dbPath, caDir))
        {
            CertificateAuthorityService restartedCa = restartedSp.GetRequiredService<CertificateAuthorityService>();
            Assert.Null(restartedCa.ResolveEffectivePassphrase());

            CaKeyCustodyReport lockedReport = await restartedCa.InspectKeyCustodyAsync();
            Assert.False(lockedReport.HasConfiguredPersistentPassphrase);
            Assert.False(lockedReport.HasEffectivePassphrase);
            Assert.False(lockedReport.ActiveAuthorityDecryptable);

            KeyPair leafKey = _crypto.KeyGen(256);
            string csr = _crypto.CSRGen(leafKey, "locked-after-restart.contoso.com", ["locked-after-restart.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
            IssuanceOutcome lockedIssuance = await restartedCa.IssueCertificateFromCsrAsync(admin.Id, csr);
            Assert.False(lockedIssuance.Succeeded);
            Assert.Contains("locked", lockedIssuance.ErrorMessage, StringComparison.OrdinalIgnoreCase);

            Assert.Throws<InvalidOperationException>(() => restartedCa.UnlockRuntimePassphrase(wrongSecret));
            Assert.Null(restartedCa.ResolveEffectivePassphrase());

            restartedCa.UnlockRuntimePassphrase(secretA);
            CaKeyCustodyReport unlockedReport = await restartedCa.InspectKeyCustodyAsync();
            Assert.True(unlockedReport.IsCustodyHealthy);
            Assert.True(unlockedReport.ActiveAuthorityDecryptable);

            IssuanceOutcome unlockedIssuance = await restartedCa.IssueCertificateFromCsrAsync(admin.Id, csr);
            Assert.True(unlockedIssuance.Succeeded, unlockedIssuance.ErrorMessage);
        }
    }

    [Fact]
    public async Task SamePolicyRotation_And_ConfiguredCustodyRestart_PreservesActiveSigning_HistoricalAssociation_And_BothCrls()
    {
        const string sharedCustodySecret = "SharedConfiguredSecret!2026";
        string dbPath = Path.Combine(_tempRoot, "rotation.db");
        string caDir = Path.Combine(_tempRoot, "rotation-ca");
        string dpDir = Path.Combine(_tempRoot, "rotation-dp");
        string passFile = Path.Combine(_tempRoot, "rotation-ca.pass");
        await File.WriteAllTextAsync(passFile, sharedCustodySecret + "\n");

        int issuerAId;
        int issuerBId;
        int issuerCId;
        string issuerACertPem;
        string issuerALeafPem;
        int issuerALeafId;

        using (ServiceProvider sp1 = BuildServiceProvider(dbPath, caDir, passFilePath: passFile, dpKeysDir: dpDir))
        {
            CertificateAuthorityService caService = sp1.GetRequiredService<CertificateAuthorityService>();
            ApplicationUser admin = await BootstrapAdminAsync(sp1);

            // 1. Create Root Issuer A under sharedCustodySecret and issue a leaf certificate
            CaAuthorityRecord issuerA = await caService.CreateSelfSignedOrIntermediateCaAsync(
                "Contoso Root A",
                "root-a.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Rsa,
                2048,
                365,
                sharedCustodySecret);
            issuerAId = issuerA.Id;
            issuerACertPem = issuerA.IssuerCertificatePem;

            KeyPair leafAKey = _crypto.KeyGen(256);
            string csrA = _crypto.CSRGen(leafAKey, "service-a.contoso.com", ["service-a.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
            IssuanceOutcome issuedA = await caService.IssueCertificateFromCsrAsync(admin.Id, csrA);
            Assert.True(issuedA.Succeeded, issuedA.ErrorMessage);
            issuerALeafPem = issuedA.CertificatePem!;
            issuerALeafId = issuedA.Record!.Id;

            // 2. Create Subordinate Issuer B under sharedCustodySecret and issue a leaf certificate
            CaAuthorityRecord issuerB = await caService.CreateSelfSignedOrIntermediateCaAsync(
                "Contoso Subordinate B",
                "sub-b.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                180,
                sharedCustodySecret,
                parentAuthority: issuerA,
                parentPassphrase: sharedCustodySecret);
            issuerBId = issuerB.Id;

            KeyPair leafBKey = _crypto.KeyGen(256);
            string csrB = _crypto.CSRGen(leafBKey, "service-b.contoso.com", ["service-b.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
            IssuanceOutcome issuedB = await caService.IssueCertificateFromCsrAsync(admin.Id, csrB);
            Assert.True(issuedB.Succeeded, issuedB.ErrorMessage);

            // 3. Replace with Externally Signed Issuing CA C using the same sharedCustodySecret
            PendingCaEnrollmentRecord pendingC = await caService.CreatePendingCaEnrollmentAsync(
                "Contoso External Issuing CA C",
                "ext-c.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                sharedCustodySecret);

            using RSA extParentKey = RSA.Create(2048);
            CertificateRequest extParentReq = new("CN=External Root CA, O=Contoso, C=US", extParentKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            extParentReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
            extParentReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            X509SubjectKeyIdentifierExtension extParentSki = new(extParentReq.PublicKey, false);
            extParentReq.CertificateExtensions.Add(extParentSki);
            extParentReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(extParentSki));
            using X509Certificate2 extParentCert = extParentReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

            CertificateRequest loadedCsr = CertificateRequest.LoadSigningRequestPem(
                pendingC.CsrPem,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
            CertificateRequest signReq = new(loadedCsr.SubjectName, loadedCsr.PublicKey, HashAlgorithmName.SHA256);
            signReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            signReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            signReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(signReq.PublicKey, false));
            signReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(extParentSki));
            using X509Certificate2 signedCertC = signReq.Create(
                extParentCert.SubjectName,
                X509SignatureGenerator.CreateForRSA(extParentKey, RSASignaturePadding.Pkcs1),
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddDays(180),
                [0x01, 0x02, 0x03, 0x04]);

            CaBundleValidationResult staged = await caService.ValidateAndStageSignedCaBundleAsync(
                pendingC.Id,
                null,
                signedCertC.ExportCertificatePem(),
                null,
                extParentCert.ExportCertificatePem());
            Assert.True(staged.IsValid, staged.ErrorMessage);

            CaAuthorityRecord issuerC = await caService.ActivatePendingCaEnrollmentAsync(pendingC.Id);
            issuerCId = issuerC.Id;
        }

        // 4. Recreate service in a fresh container (and also verify in a separate child process) using only persistent passFile
        using (ServiceProvider sp2 = BuildServiceProvider(dbPath, caDir, passFilePath: passFile, dpKeysDir: dpDir))
        {
            CertificateAuthorityService freshCa = sp2.GetRequiredService<CertificateAuthorityService>();
            CaKeyCustodyReport report = await freshCa.InspectKeyCustodyAsync();
            Assert.True(report.IsCustodyHealthy);
            Assert.Equal(3, report.Authorities.Count);
            Assert.All(report.Authorities, a =>
            {
                Assert.True(a.CanDecryptWithEffectivePassphrase);
                Assert.True(a.CanDecryptWithConfiguredPassphrase);
            });

            // Sign new leaf with active Issuer C after restart
            using IServiceScope scope = sp2.CreateScope();
            UserManager<ApplicationUser> userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            ApplicationUser admin = (await userMgr.FindByNameAsync("admin"))!;

            KeyPair leafCKey = _crypto.KeyGen(256);
            string csrC = _crypto.CSRGen(leafCKey, "service-c.contoso.com", ["service-c.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
            IssuanceOutcome issuedC = await freshCa.IssueCertificateFromCsrAsync(admin.Id, csrC);
            Assert.True(issuedC.Succeeded, issuedC.ErrorMessage);
            Assert.Equal(issuerCId, issuedC.Record!.CaAuthorityId);

            // Historical certificate from Issuer A retains its original chain and issuer association
            string? resolvedChainA = await freshCa.ResolveCertificateChainPemAsync(issuerALeafPem);
            Assert.NotNull(resolvedChainA);
            Assert.Contains(issuerACertPem.Trim(), resolvedChainA);

            // Revoke historical certificate on Issuer A and refresh all due CRLs across active (C) and historical (A, B) issuers
            var (revOk, revErr) = await freshCa.RevokeCertificateAsync(issuerALeafId, CrlReason.Superseded, "admin");
            Assert.True(revOk, revErr);

            IReadOnlyList<CrlRefreshOutcome> refreshOutcomes = await freshCa.RefreshDueCrlsAsync(TimeSpan.FromDays(10));
            Assert.Equal(3, refreshOutcomes.Count);
            Assert.All(refreshOutcomes, o => Assert.True(o.Succeeded, o.ErrorMessage));
            Assert.Contains(refreshOutcomes, o => o.CaAuthorityId == issuerAId && o.Succeeded);
            Assert.Contains(refreshOutcomes, o => o.CaAuthorityId == issuerBId && o.Succeeded);
            Assert.Contains(refreshOutcomes, o => o.CaAuthorityId == issuerCId && o.Succeeded);
        }

        // 5. Also verify CLI --verify-ca-custody in a fresh child process
        var (cliExit, cliOut) = await RunCertRoboCliAsync(
            dbPath,
            caDir,
            passFile,
            ["--verify-ca-custody"]);
        Assert.Equal(0, cliExit);
        Assert.Contains("CA key custody check passed.", cliOut);
        Assert.DoesNotContain(sharedCustodySecret, cliOut);
    }

    [Fact]
    public async Task ImportBundlePasswords_MayDifferFromAtRestStorageCustody_WithoutConfusingTheTwo()
    {
        const string storageCustodySecret = "AtRestStorageCustody!2026";
        const string pemImportPassword = "PemBundleTransferPassword!999";
        const string pfxImportPassword = "PfxBundleTransferPassword!888";

        string dbPath = Path.Combine(_tempRoot, "bundle-passwords.db");
        string caDir = Path.Combine(_tempRoot, "bundle-passwords-ca");
        string passFile = Path.Combine(_tempRoot, "bundle-ca.pass");
        await File.WriteAllTextAsync(passFile, storageCustodySecret);

        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir, passFilePath: passFile);
        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();

        // 1. Encrypted PEM private key protected with pemImportPassword, stored at rest with storageCustodySecret
        using RSA rsa1 = RSA.Create(2048);
        CertificateRequest req1 = new("CN=PEM Imported Root CA, O=Contoso, C=US", rsa1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req1.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req1.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using X509Certificate2 cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(365));

        string encryptedInputKeyPem = rsa1.ExportEncryptedPkcs8PrivateKeyPem(
            pemImportPassword,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 10_000));

        // Wrong input key password throws ArgumentException (not confused with storage custody)
        ArgumentException badPemPassEx = await Assert.ThrowsAsync<ArgumentException>(() =>
            caService.ImportCaAsync(
                "PEM Root CA",
                cert1.ExportCertificatePem(),
                null,
                encryptedInputKeyPem,
                inputKeyPassphrase: "WrongInputPassword",
                storagePassphrase: storageCustodySecret));
        Assert.Contains("input key passphrase", badPemPassEx.Message, StringComparison.OrdinalIgnoreCase);

        // Correct input key password + matching storageCustodySecret succeeds
        CaAuthorityRecord importedPemCa = await caService.ImportCaAsync(
            "PEM Root CA",
            cert1.ExportCertificatePem(),
            null,
            encryptedInputKeyPem,
            inputKeyPassphrase: pemImportPassword,
            storagePassphrase: storageCustodySecret);
        Assert.True(importedPemCa.IsActive);

        // 2. PKCS#12 bundle protected with pfxImportPassword, stored at rest with storageCustodySecret
        using ECDsa ec2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest req2 = new("CN=PFX Imported Root CA, O=Contoso, C=US", ec2, HashAlgorithmName.SHA256);
        req2.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req2.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using X509Certificate2 cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(365));
        byte[] pfxBytes = cert2.Export(X509ContentType.Pkcs12, pfxImportPassword)!;

        // Wrong PFX bundle password throws ArgumentException
        ArgumentException badPfxPassEx = await Assert.ThrowsAsync<ArgumentException>(() =>
            caService.ImportCaFromPkcs12Async(
                "PFX Root CA",
                pfxBytes,
                pkcs12Password: "WrongPfxPassword",
                storagePassphrase: storageCustodySecret));
        Assert.Contains("bundle password", badPfxPassEx.Message, StringComparison.OrdinalIgnoreCase);

        // Correct PFX bundle password + matching storageCustodySecret succeeds
        CaAuthorityRecord importedPfxCa = await caService.ImportCaFromPkcs12Async(
            "PFX Root CA",
            pfxBytes,
            pkcs12Password: pfxImportPassword,
            storagePassphrase: storageCustodySecret);
        Assert.True(importedPfxCa.IsActive);

        // Verify both keys on disk are encrypted with storageCustodySecret (not the bundle passwords)
        CaKeyCustodyReport report = await caService.InspectKeyCustodyAsync();
        Assert.True(report.IsCustodyHealthy);
        Assert.Equal(2, report.Authorities.Count);
        Assert.All(report.Authorities, a => Assert.True(a.CanDecryptWithConfiguredPassphrase));
    }

    [Fact]
    public async Task ExistingMixedPassphraseKeys_AreDetected_BlockIncompatibleRotation_And_RecoverViaDocumentedProcedure()
    {
        const string legacySecretA = "LegacyHistoricalSecret-Alpha!2026";
        const string activeSecretB = "LegacyReplacementSecret-Bravo!2026";

        string dbPath = Path.Combine(_tempRoot, "mixed-recovery.db");
        string caDir = Path.Combine(_tempRoot, "mixed-recovery-ca");
        string passFile = Path.Combine(_tempRoot, "target-ca.pass");
        string sourcePassFile = Path.Combine(_tempRoot, "legacy-sources.pass");

        int issuerAId;
        int issuerBId;
        string originalIssuerBKeyPath;

        // 1. Seed a valid Issuer A (with legacySecretA) and an unexpired certificate, then simulate a pre-fix mixed-passphrase
        // database where Issuer B's key on disk was encrypted with activeSecretB while persistent custody is configured with legacySecretA.
        using (ServiceProvider seedSp = BuildServiceProvider(dbPath, caDir))
        {
            CertificateAuthorityService caService = seedSp.GetRequiredService<CertificateAuthorityService>();
            ApplicationUser admin = await BootstrapAdminAsync(seedSp);

            CaAuthorityRecord issuerA = await caService.CreateSelfSignedOrIntermediateCaAsync(
                "Historical Issuer A",
                "historical-a.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                365,
                legacySecretA);
            issuerAId = issuerA.Id;

            KeyPair leafAKey = _crypto.KeyGen(256);
            string csrA = _crypto.CSRGen(leafAKey, "unexpired-a.contoso.com", ["unexpired-a.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
            IssuanceOutcome issuedA = await caService.IssueCertificateFromCsrAsync(admin.Id, csrA);
            Assert.True(issuedA.Succeeded, issuedA.ErrorMessage);

            CaAuthorityRecord issuerB = await caService.CreateSelfSignedOrIntermediateCaAsync(
                "Active Issuer B",
                "active-b.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                365,
                legacySecretA);
            issuerBId = issuerB.Id;
            originalIssuerBKeyPath = issuerB.EncryptedPrivateKeyPath;

            // Re-encrypt Issuer B's key file on disk with activeSecretB to simulate a pre-fix mixed-passphrase state
            byte[] rawEncB = await File.ReadAllBytesAsync(originalIssuerBKeyPath);
            using ECDsa keyB = ECDsa.Create();
            keyB.ImportEncryptedPkcs8PrivateKey(legacySecretA, rawEncB, out _);
            byte[] mixedEncB = keyB.ExportEncryptedPkcs8PrivateKey(
                activeSecretB,
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000));
            await File.WriteAllBytesAsync(originalIssuerBKeyPath, mixedEncB);
        }

        await File.WriteAllTextAsync(passFile, legacySecretA + "\n");

        // 2. In a fresh process with persistent custody = legacySecretA, verify mixed-passphrase state is detected:
        //    - InspectKeyCustodyAsync reports IsCustodyHealthy == false and flags Issuer B
        //    - RefreshDueCrlsAsync reports failure for Issuer B while succeeding for Historical Issuer A
        //    - UnlockRuntimePassphrase rejects both legacySecretA and activeSecretB because neither unlocks all keys
        //    - Rotation/creation is rejected until recovery is performed
        using (ServiceProvider mixedSp = BuildServiceProvider(dbPath, caDir, passFilePath: passFile))
        {
            CertificateAuthorityService mixedCa = mixedSp.GetRequiredService<CertificateAuthorityService>();

            CaKeyCustodyReport badReport = await mixedCa.InspectKeyCustodyAsync();
            Assert.False(badReport.IsCustodyHealthy);
            Assert.False(badReport.ActiveAuthorityDecryptable);
            Assert.True(badReport.Authorities.Single(a => a.CaAuthorityId == issuerAId).CanDecryptWithConfiguredPassphrase);
            Assert.False(badReport.Authorities.Single(a => a.CaAuthorityId == issuerBId).CanDecryptWithConfiguredPassphrase);

            IReadOnlyList<CrlRefreshOutcome> mixedRefresh = await mixedCa.RefreshDueCrlsAsync(TimeSpan.FromDays(10));
            Assert.Contains(mixedRefresh, r => r.CaAuthorityId == issuerAId && r.Succeeded);
            Assert.Contains(mixedRefresh, r => r.CaAuthorityId == issuerBId && !r.Succeeded);

            Assert.Throws<InvalidOperationException>(() => mixedCa.UnlockRuntimePassphrase(legacySecretA));
            Assert.Throws<InvalidOperationException>(() => mixedCa.UnlockRuntimePassphrase(activeSecretB));

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                mixedCa.CreateSelfSignedOrIntermediateCaAsync(
                    "Blocked Issuer C",
                    "blocked-c.contoso.com",
                    "US", "WA", "Redmond", "Contoso", "PKI",
                    CertificateKeyFamily.Ecdsa,
                    256,
                    365,
                    legacySecretA));
        }

        // Verify CLI --verify-ca-custody detects the incompatible key and exits non-zero without printing secrets
        var (verifyFailExit, verifyFailOut) = await RunCertRoboCliAsync(
            dbPath,
            caDir,
            passFile,
            ["--verify-ca-custody"]);
        Assert.NotEqual(0, verifyFailExit);
        Assert.Contains("FAILED", verifyFailOut);
        Assert.DoesNotContain(legacySecretA, verifyFailOut);
        Assert.DoesNotContain(activeSecretB, verifyFailOut);

        // 3. Execute the documented CLI recovery procedure (--reprotect-ca-keys) using disposable source passphrase file
        await File.WriteAllTextAsync(sourcePassFile, activeSecretB + "\n");
        var (reprotectExit, reprotectOut) = await RunCertRoboCliAsync(
            dbPath,
            caDir,
            passFile,
            ["--reprotect-ca-keys", sourcePassFile]);
        Assert.True(reprotectExit == 0, $"CLI reprotect failed ({reprotectExit}): {reprotectOut}");
        Assert.Contains("Re-protected 1 CA authority key(s)", reprotectOut);
        Assert.DoesNotContain(legacySecretA, reprotectOut);
        Assert.DoesNotContain(activeSecretB, reprotectOut);

        // Verify original encrypted key file was NOT overwritten and still decrypts with activeSecretB
        Assert.True(File.Exists(originalIssuerBKeyPath));
        byte[] preservedOriginalBytes = await File.ReadAllBytesAsync(originalIssuerBKeyPath);
        using (ECDsa checkOriginal = ECDsa.Create())
        {
            checkOriginal.ImportEncryptedPkcs8PrivateKey(activeSecretB, preservedOriginalBytes, out _);
        }

        // 4. Verify in a fresh process after recovery that custody is healthy, active signing works, and both CRLs refresh
        var (verifyOkExit, verifyOkOut) = await RunCertRoboCliAsync(
            dbPath,
            caDir,
            passFile,
            ["--verify-ca-custody"]);
        Assert.Equal(0, verifyOkExit);
        Assert.Contains("CA key custody check passed.", verifyOkOut);

        using (ServiceProvider recoveredSp = BuildServiceProvider(dbPath, caDir, passFilePath: passFile))
        {
            CertificateAuthorityService recoveredCa = recoveredSp.GetRequiredService<CertificateAuthorityService>();
            CaKeyCustodyReport healthyReport = await recoveredCa.InspectKeyCustodyAsync();
            Assert.True(healthyReport.IsCustodyHealthy);
            Assert.True(healthyReport.ActiveAuthorityDecryptable);

            CaAuthorityRecord updatedB = (await recoveredCa.GetAuthorityByIdAsync(issuerBId))!;
            Assert.NotEqual(originalIssuerBKeyPath, updatedB.EncryptedPrivateKeyPath);
            Assert.True(File.Exists(updatedB.EncryptedPrivateKeyPath));

            using IServiceScope scope = recoveredSp.CreateScope();
            UserManager<ApplicationUser> userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            ApplicationUser admin = (await userMgr.FindByNameAsync("admin"))!;

            KeyPair postRecoveryLeafKey = _crypto.KeyGen(256);
            string postRecoveryCsr = _crypto.CSRGen(
                postRecoveryLeafKey, "recovered.contoso.com", ["recovered.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
            IssuanceOutcome postRecoveryIssued = await recoveredCa.IssueCertificateFromCsrAsync(admin.Id, postRecoveryCsr);
            Assert.True(postRecoveryIssued.Succeeded, postRecoveryIssued.ErrorMessage);

            IReadOnlyList<CrlRefreshOutcome> postRecoveryCrls = await recoveredCa.RefreshDueCrlsAsync(TimeSpan.FromDays(10));
            Assert.Equal(2, postRecoveryCrls.Count);
            Assert.All(postRecoveryCrls, r => Assert.True(r.Succeeded, r.ErrorMessage));
        }
    }

    private static async Task<(int ExitCode, string CombinedOutput)> RunCertRoboCliAsync(
        string dbPath,
        string caDir,
        string passFilePath,
        IReadOnlyList<string> args)
    {
        string appDll = Path.Combine(AppContext.BaseDirectory, "CertRobo.dll");
        ProcessStartInfo psi = new("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = AppContext.BaseDirectory
        };
        psi.ArgumentList.Add(appDll);
        foreach (string arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        psi.Environment.Remove("CERTROBO_CA_PASSPHRASE");
        psi.Environment["CertRobo__DataDirectory"] = Path.GetDirectoryName(dbPath)!;
        psi.Environment["CertRobo__SqliteFilePath"] = dbPath;
        psi.Environment["CertRobo__CaStorageDirectory"] = caDir;
        psi.Environment["CertRobo__CaPassphraseFile"] = passFilePath;

        using Process proc = Process.Start(psi)!;
        Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync();
        Task<string> stderrTask = proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        string combined = (await stdoutTask) + "\n" + (await stderrTask);
        return (proc.ExitCode, combined);
    }

    private static async Task<ApplicationUser> BootstrapAdminAsync(ServiceProvider sp)
    {
        using IServiceScope scope = sp.CreateScope();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        var (ok, err, admin) = await acct.BootstrapFirstAdminAsync("admin", "AdminSecret!2026", "admin@contoso.com", "*.contoso.com");
        Assert.True(ok, err);
        return admin!;
    }

    private static ServiceProvider BuildServiceProvider(
        string sqlitePath,
        string caStorageDir,
        string? passFilePath = null,
        string? configuredPassphrase = null,
        string? envVarName = null,
        string? dpKeysDir = null)
    {
        ServiceCollection services = new();
        services.AddLogging();
        IDataProtectionBuilder dp = services.AddDataProtection();
        if (!string.IsNullOrEmpty(dpKeysDir))
        {
            Directory.CreateDirectory(dpKeysDir);
            dp.PersistKeysToFileSystem(new DirectoryInfo(dpKeysDir));
        }
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
            PassphraseEnvironmentVariable = envVarName,
            PassphraseFilePath = passFilePath,
            ConfiguredPassphrase = configuredPassphrase
        });

        services.AddScoped<AccountManagementService>();
        services.AddScoped<LegacySettingsMigrationService>();
        services.AddScoped<IssuancePolicyService>();
        services.AddSingleton<CertificateAuthorityService>();
        services.AddSingleton<BackupRestoreService>();

        ServiceProvider sp = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true
        });
        using IServiceScope scope = sp.CreateScope();
        CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
        db.EnsureSchemaUpgradedAsync().GetAwaiter().GetResult();
        return sp;
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_tempRoot))
        {
            try { Directory.Delete(_tempRoot, recursive: true); }
            catch { }
        }
    }
}
