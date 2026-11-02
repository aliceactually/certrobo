using CertRobo.Data;
using CertRobo.Models;
using CertRobo.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertRobo.Tests;

public sealed class CaCrlLifecycleRegressionTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly CryptoFactory _crypto = new();

    public CaCrlLifecycleRegressionTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"certrobo-lifecycle-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    [Fact]
    public async Task RevocationPublication_LockedSigner_MissingIssuer_AndInjectedFailure_ProduceTruthfulOutcomes_SurviveRestart_AndPublishPromptly()
    {
        const string secret = "LifecycleRevocationSecret!2026";
        string dbPath = Path.Combine(_tempRoot, "revocation-durable.db");
        string caDir = Path.Combine(_tempRoot, "revocation-durable-ca");
        string passFile = Path.Combine(_tempRoot, "revocation-durable.pass");
        await File.WriteAllTextAsync(passFile, secret + "\n");

        int caId;
        int cert1Id;
        int cert2Id;
        int cert3Id;
        string cert1SerialHex;
        string cert2SerialHex;
        string cert1Pem;
        string cert2Pem;
        string rootCaPem;

        using (ServiceProvider sp = BuildServiceProvider(dbPath, caDir))
        {
            CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
            ApplicationUser admin = await BootstrapAdminAsync(sp);

            CaAuthorityRecord ca = await caService.CreateSelfSignedOrIntermediateCaAsync(
                "Durable Revocation Root CA",
                "durable-root.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                365,
                secret);
            caId = ca.Id;
            rootCaPem = ca.IssuerCertificatePem;

            IssuanceOutcome issued1 = await IssueLeafAsync(caService, admin.Id, "app1.contoso.com");
            IssuanceOutcome issued2 = await IssueLeafAsync(caService, admin.Id, "app2.contoso.com");
            IssuanceOutcome issued3 = await IssueLeafAsync(caService, admin.Id, "app3.contoso.com");

            cert1Id = issued1.Record!.Id;
            cert2Id = issued2.Record!.Id;
            cert3Id = issued3.Record!.Id;
            cert1SerialHex = issued1.Record.SerialNumberHex;
            cert2SerialHex = issued2.Record.SerialNumberHex;
            cert1Pem = issued1.CertificatePem!;
            cert2Pem = issued2.CertificatePem!;

            // 1. Lock the signer and revoke cert1 + seed a legacy serial
            caService.LockRuntimePassphrase();

            RevocationOutcome lockedRevoke = await caService.RevokeCertificateAsync(
                cert1Id,
                CrlReason.KeyCompromise,
                "admin");
            Assert.False(lockedRevoke.Succeeded);
            Assert.True(lockedRevoke.RevocationAccepted);
            Assert.False(lockedRevoke.CrlPublished);
            Assert.True(lockedRevoke.IsPendingPublication);
            Assert.Equal(RevocationPublicationStatus.PendingSignerLocked, lockedRevoke.PublicationStatus);
            Assert.Contains("locked", lockedRevoke.ErrorMessage, StringComparison.OrdinalIgnoreCase);

            RevocationOutcome lockedSeed = await caService.SeedRevokedSerialAsync(
                "01:02:03:04:AA",
                "legacy-locked.contoso.com",
                CrlReason.Superseded,
                "admin");
            Assert.False(lockedSeed.Succeeded);
            Assert.True(lockedSeed.RevocationAccepted);
            Assert.False(lockedSeed.CrlPublished);
            Assert.Equal(RevocationPublicationStatus.PendingSignerLocked, lockedSeed.PublicationStatus);

            // Previous CRL #1 must still be served and must not contain the unpublished serials yet
            PublishedCrlRecord? servedWhileLocked = await caService.GetLatestCrlAsync();
            Assert.NotNull(servedWhileLocked);
            Assert.Equal(1, servedWhileLocked.CrlNumber);
            Assert.False(CrlContainsSerial(servedWhileLocked.CrlDer, cert1SerialHex));
            Assert.False(CrlContainsSerial(servedWhileLocked.CrlDer, "01020304AA"));

            IReadOnlySet<int> pendingIdsWhileLocked = await caService.GetCertificateIdsWithUnpublishedRevocationsAsync();
            Assert.Contains(cert1Id, pendingIdsWhileLocked);
            Assert.Contains(lockedSeed.CertificateRecord!.Id, pendingIdsWhileLocked);

            // Unlock and trigger RefreshDueCrlsAsync(24h) while CRL #1 is still ~7 days from expiry
            caService.UnlockRuntimePassphrase(secret);
            IReadOnlyList<CrlRefreshOutcome> refreshAfterUnlock = await caService.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
            Assert.Single(refreshAfterUnlock);
            Assert.True(refreshAfterUnlock[0].Succeeded, refreshAfterUnlock[0].ErrorMessage);
            Assert.Equal(2, refreshAfterUnlock[0].PublishedCrl!.CrlNumber);

            PublishedCrlRecord? crlAfterUnlock = await caService.GetLatestCrlAsync();
            Assert.NotNull(crlAfterUnlock);
            Assert.Equal(2, crlAfterUnlock.CrlNumber);
            Assert.True(CrlContainsSerial(crlAfterUnlock.CrlDer, cert1SerialHex, CrlReason.KeyCompromise));
            Assert.True(CrlContainsSerial(crlAfterUnlock.CrlDer, "01020304AA", CrlReason.Superseded));
            Assert.Empty(await caService.GetCertificateIdsWithUnpublishedRevocationsAsync());

            // 2. Inject a publication failure during RevokeCertificateAsync on cert2
            caService.CrlPublicationFaultInjector = _ => throw new IOException("Simulated CRL publication storage failure.");
            RevocationOutcome failedPublish = await caService.RevokeCertificateAsync(
                cert2Id,
                CrlReason.CessationOfOperation,
                "admin");
            caService.CrlPublicationFaultInjector = null;

            Assert.False(failedPublish.Succeeded);
            Assert.True(failedPublish.RevocationAccepted);
            Assert.False(failedPublish.CrlPublished);
            Assert.Equal(RevocationPublicationStatus.PendingPublicationFailed, failedPublish.PublicationStatus);
            Assert.Contains("Simulated CRL publication storage failure", failedPublish.ErrorMessage);

            // Previous CRL #2 remains served; LastCrlNumber was not incremented on the failed attempt
            PublishedCrlRecord? servedAfterFailure = await caService.GetLatestCrlAsync();
            Assert.NotNull(servedAfterFailure);
            Assert.Equal(2, servedAfterFailure.CrlNumber);
            Assert.False(CrlContainsSerial(servedAfterFailure.CrlDer, cert2SerialHex));
            Assert.Equal(2, (await caService.GetActiveAuthorityAsync())!.LastCrlNumber);
            Assert.Contains(cert2Id, await caService.GetCertificateIdsWithUnpublishedRevocationsAsync());
        }

        // 3. Simulate process restart: run --refresh-crls in an isolated child process using configured passFile
        //    even though CRL #2 is still 7 days from expiry.
        var (cliExit, cliOut) = await RunCertRoboCliAsync(dbPath, caDir, passFile, ["--refresh-crls"]);
        Assert.True(cliExit == 0, $"CLI --refresh-crls failed ({cliExit}): {cliOut}");
        Assert.Contains($"Published CRL #3 for CA #{caId}", cliOut);

        using (ServiceProvider postRestartSp = BuildServiceProvider(dbPath, caDir, passFilePath: passFile))
        {
            CertificateAuthorityService postRestartCa = postRestartSp.GetRequiredService<CertificateAuthorityService>();
            PublishedCrlRecord? crl3 = await postRestartCa.GetLatestCrlAsync();
            Assert.NotNull(crl3);
            Assert.Equal(3, crl3.CrlNumber);
            Assert.True(CrlContainsSerial(crl3.CrlDer, cert1SerialHex, CrlReason.KeyCompromise));
            Assert.True(CrlContainsSerial(crl3.CrlDer, cert2SerialHex, CrlReason.CessationOfOperation));
            Assert.Empty(await postRestartCa.GetCertificateIdsWithUnpublishedRevocationsAsync());

            // Independently verify CRL #3 and revoked certificates with OpenSSL
            await VerifyCrlAndLeafWithOpenSslAsync(rootCaPem, null, crl3.CrlPem, cert1Pem, expectRevoked: true);
            await VerifyCrlAndLeafWithOpenSslAsync(rootCaPem, null, crl3.CrlPem, cert2Pem, expectRevoked: true);

            // 4. Missing issuer case: point cert3 at a non-existent CA authority ID and revoke it
            using (IServiceScope dbScope = postRestartSp.CreateScope())
            {
                CertRoboDbContext db = dbScope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
                IssuedCertificateRecord c3 = await db.IssuedCertificates.FirstAsync(c => c.Id == cert3Id);
                c3.CaAuthorityId = 9999;
                await db.SaveChangesAsync();
            }

            RevocationOutcome missingIssuerOutcome = await postRestartCa.RevokeCertificateAsync(
                cert3Id,
                CrlReason.Unspecified,
                "admin");
            Assert.False(missingIssuerOutcome.Succeeded);
            Assert.True(missingIssuerOutcome.RevocationAccepted);
            Assert.False(missingIssuerOutcome.CrlPublished);
            Assert.Equal(RevocationPublicationStatus.PendingIssuerUnavailable, missingIssuerOutcome.PublicationStatus);
            Assert.Contains("9999", missingIssuerOutcome.ErrorMessage);

            // Active CA's CRL #3 remains intact and RefreshDueCrlsAsync surfaces the missing-issuer maintenance error
            Assert.Equal(3, (await postRestartCa.GetLatestCrlAsync())!.CrlNumber);
            IReadOnlyList<CrlRefreshOutcome> missingOutcomes = await postRestartCa.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
            Assert.Contains(missingOutcomes, o => o.CaAuthorityId == 9999 && !o.Succeeded);
        }
    }

    [Fact]
    public async Task ConcurrentRevokeAndRefresh_RepeatedRevocation_AndHistoricalIssuerRevocation_PreserveUpdates_AndMonotonicCrlNumbers()
    {
        const string secret = "HistoricalAndConcurrentSecret!2026";
        string dbPath = Path.Combine(_tempRoot, "concurrent-historical.db");
        string caDir = Path.Combine(_tempRoot, "concurrent-historical-ca");

        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir, configuredPassphrase: secret);
        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
        ApplicationUser admin = await BootstrapAdminAsync(sp);

        // 1. Create Historical Issuer A and issue two leaf certificates
        CaAuthorityRecord issuerA = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Historical Issuer A",
            "issuer-a.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa,
            256,
            365,
            secret);

        IssuanceOutcome leafA1 = await IssueLeafAsync(caService, admin.Id, "a1.contoso.com");
        IssuanceOutcome leafA2 = await IssueLeafAsync(caService, admin.Id, "a2.contoso.com");

        // 2. Replace with Active Issuer B and issue four leaf certificates
        CaAuthorityRecord issuerB = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Active Issuer B",
            "issuer-b.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa,
            256,
            365,
            secret);

        IssuanceOutcome leafB1 = await IssueLeafAsync(caService, admin.Id, "b1.contoso.com");
        IssuanceOutcome leafB2 = await IssueLeafAsync(caService, admin.Id, "b2.contoso.com");
        IssuanceOutcome leafB3 = await IssueLeafAsync(caService, admin.Id, "b3.contoso.com");
        IssuanceOutcome leafB4 = await IssueLeafAsync(caService, admin.Id, "b4.contoso.com");

        // 3. Revoke historical Issuer A's unexpired certificate leafA1 while signer is locked, then unlock and refresh
        caService.LockRuntimePassphrase();
        RevocationOutcome lockedHistRevoke = await caService.RevokeCertificateAsync(
            leafA1.Record!.Id,
            CrlReason.KeyCompromise,
            "admin");
        Assert.True(lockedHistRevoke.RevocationAccepted);
        Assert.False(lockedHistRevoke.CrlPublished);

        caService.UnlockRuntimePassphrase(secret);
        IReadOnlyList<CrlRefreshOutcome> histRefresh = await caService.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
        // Only Historical Issuer A had an unpublished revocation; Active Issuer B's CRL #1 is still current
        Assert.Single(histRefresh);
        Assert.Equal(issuerA.Id, histRefresh[0].CaAuthorityId);
        Assert.True(histRefresh[0].Succeeded);
        Assert.Equal(2, histRefresh[0].PublishedCrl!.CrlNumber);

        PublishedCrlRecord crlA2 = (await caService.GetLatestCrlAsync(caAuthorityId: issuerA.Id))!;
        PublishedCrlRecord crlB1 = (await caService.GetLatestCrlAsync(caAuthorityId: issuerB.Id))!;
        Assert.Equal(2, crlA2.CrlNumber);
        Assert.Equal(1, crlB1.CrlNumber);
        Assert.True(CrlContainsSerial(crlA2.CrlDer, leafA1.Record.SerialNumberHex, CrlReason.KeyCompromise));
        Assert.False(CrlContainsSerial(crlB1.CrlDer, leafA1.Record.SerialNumberHex));

        // Verify Historical Issuer A's CRL #2 with OpenSSL against leafA1 (revoked) and leafA2 (valid)
        await VerifyCrlAndLeafWithOpenSslAsync(issuerA.IssuerCertificatePem, null, crlA2.CrlPem, leafA1.CertificatePem!, expectRevoked: true);
        await VerifyCrlAndLeafWithOpenSslAsync(issuerA.IssuerCertificatePem, null, crlA2.CrlPem, leafA2.CertificatePem!, expectRevoked: false);

        // 4. Repeated revocation updating reason code on leafB1
        RevocationOutcome revB1Initial = await caService.RevokeCertificateAsync(
            leafB1.Record!.Id,
            CrlReason.PrivilegeWithdrawn,
            "admin");
        Assert.True(revB1Initial.Succeeded);
        Assert.Equal(2, revB1Initial.PublishedCrl!.CrlNumber);
        Assert.True(CrlContainsSerial(revB1Initial.PublishedCrl.CrlDer, leafB1.Record.SerialNumberHex, CrlReason.PrivilegeWithdrawn));

        // Repeat revocation of leafB1 with updated reason (KeyCompromise) while locked -> detected as unpublished update
        caService.LockRuntimePassphrase();
        RevocationOutcome revB1UpdatedLocked = await caService.RevokeCertificateAsync(
            leafB1.Record.Id,
            CrlReason.KeyCompromise,
            "admin");
        Assert.True(revB1UpdatedLocked.RevocationAccepted);
        Assert.False(revB1UpdatedLocked.CrlPublished);
        Assert.Contains(leafB1.Record.Id, await caService.GetCertificateIdsWithUnpublishedRevocationsAsync());

        caService.UnlockRuntimePassphrase(secret);
        IReadOnlyList<CrlRefreshOutcome> reasonUpdateRefresh = await caService.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
        Assert.Single(reasonUpdateRefresh);
        Assert.Equal(issuerB.Id, reasonUpdateRefresh[0].CaAuthorityId);
        Assert.Equal(3, reasonUpdateRefresh[0].PublishedCrl!.CrlNumber);
        Assert.True(CrlContainsSerial(reasonUpdateRefresh[0].PublishedCrl!.CrlDer, leafB1.Record.SerialNumberHex, CrlReason.KeyCompromise));

        // 5. Concurrent revocations (leafB2, leafB3, leafB4) and concurrent CRL refreshes
        Task<RevocationOutcome> tRev2 = caService.RevokeCertificateAsync(leafB2.Record!.Id, CrlReason.Superseded, "admin");
        Task<RevocationOutcome> tRev3 = caService.RevokeCertificateAsync(leafB3.Record!.Id, CrlReason.CessationOfOperation, "admin");
        Task<RevocationOutcome> tRev4 = caService.RevokeCertificateAsync(leafB4.Record!.Id, CrlReason.AffiliationChanged, "admin");
        Task<IReadOnlyList<CrlRefreshOutcome>> tDue = caService.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
        Task<PublishedCrlRecord?> tActive = caService.RefreshActiveCrlAsync();

        await Task.WhenAll(tRev2, tRev3, tRev4, tDue, tActive);
        Assert.True((await tRev2).Succeeded);
        Assert.True((await tRev3).Succeeded);
        Assert.True((await tRev4).Succeeded);

        // Verify all CRL numbers persisted for Issuer B are strictly consecutive and monotonic
        using (IServiceScope dbScope = sp.CreateScope())
        {
            CertRoboDbContext db = dbScope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            List<long> crlNumbersB = await db.PublishedCrls
                .Where(c => c.CaAuthorityId == issuerB.Id)
                .OrderBy(c => c.Id)
                .Select(c => c.CrlNumber)
                .ToListAsync();
            Assert.Equal(Enumerable.Range(1, crlNumbersB.Count).Select(i => (long)i), crlNumbersB);
        }

        PublishedCrlRecord finalCrlB = (await caService.GetLatestCrlAsync(caAuthorityId: issuerB.Id))!;
        Assert.True(CrlContainsSerial(finalCrlB.CrlDer, leafB1.Record.SerialNumberHex, CrlReason.KeyCompromise));
        Assert.True(CrlContainsSerial(finalCrlB.CrlDer, leafB2.Record.SerialNumberHex, CrlReason.Superseded));
        Assert.True(CrlContainsSerial(finalCrlB.CrlDer, leafB3.Record.SerialNumberHex, CrlReason.CessationOfOperation));
        Assert.True(CrlContainsSerial(finalCrlB.CrlDer, leafB4.Record.SerialNumberHex, CrlReason.AffiliationChanged));

        await VerifyCrlAndLeafWithOpenSslAsync(issuerB.IssuerCertificatePem, null, finalCrlB.CrlPem, leafB4.CertificatePem!, expectRevoked: true);
    }

    [Fact]
    public async Task SubordinateActivation_EnforcesPathLengthConstraints_AcrossAncestors_AndSupportsSelfIssuedAndTrustAnchorCases_WithOpenSslVerification()
    {
        const string secret = "PathLengthValidationSecret!2026";
        string dbPath = Path.Combine(_tempRoot, "pathlen-comprehensive.db");
        string caDir = Path.Combine(_tempRoot, "pathlen-comprehensive-ca");

        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir, configuredPassphrase: secret);
        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
        ApplicationUser admin = await BootstrapAdminAsync(sp);

        // 1. Trust-anchor case: a self-signed Root CA with pathLenConstraint=0 CAN be activated and CAN issue leaf certificates,
        //    but CANNOT sign a non-self-issued subordinate CA.
        CaAuthorityRecord rootPathZero = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Constrained Root CA (pathLen=0)",
            "root-path0.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Rsa,
            2048,
            365,
            secret,
            pathLengthConstraint: 0);

        IssuanceOutcome rootPathZeroLeaf = await IssueLeafAsync(caService, admin.Id, "direct-leaf.contoso.com");
        Assert.True(rootPathZeroLeaf.Succeeded, rootPathZeroLeaf.ErrorMessage);
        PublishedCrlRecord rootPathZeroCrl = (await caService.GetLatestCrlAsync(caAuthorityId: rootPathZero.Id))!;
        await VerifyCrlAndLeafWithOpenSslAsync(rootPathZero.IssuerCertificatePem, null, rootPathZeroCrl.CrlPem, rootPathZeroLeaf.CertificatePem!, expectRevoked: false);

        int keyFilesBeforeForbiddenSub = Directory.GetFiles(caDir, "*.p8.enc").Length;
        InvalidOperationException rootPathZeroSubEx = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            caService.CreateSelfSignedOrIntermediateCaAsync(
                "Forbidden Sub Under Path0 Root",
                "forbidden-sub.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                180,
                secret,
                parentAuthority: rootPathZero,
                parentPassphrase: secret));
        Assert.Contains("pathLenConstraint=0", rootPathZeroSubEx.Message);
        Assert.Equal(keyFilesBeforeForbiddenSub, Directory.GetFiles(caDir, "*.p8.enc").Length);
        Assert.Equal(rootPathZero.Id, (await caService.GetActiveAuthorityAsync())!.Id);

        // 2. Self-issued rollover intermediate case under a pathLen=0 parent:
        //    Per RFC 5280 Section 4.2.1.9, a self-issued intermediate (Subject DN == Issuer DN, signed by parent key)
        //    does not count against pathLenConstraint=0.
        CaAuthorityRecord selfIssuedRollover = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Self-Issued Rollover CA",
            "root-path0.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa,
            256,
            180,
            secret,
            parentAuthority: rootPathZero,
            parentPassphrase: secret,
            pathLengthConstraint: 0);
        Assert.True(selfIssuedRollover.IsIntermediate);
        Assert.True(selfIssuedRollover.IsActive);

        IssuanceOutcome rolloverLeaf = await IssueLeafAsync(caService, admin.Id, "rollover-leaf.contoso.com");
        Assert.True(rolloverLeaf.Succeeded, rolloverLeaf.ErrorMessage);
        PublishedCrlRecord rolloverCrl = (await caService.GetLatestCrlAsync(caAuthorityId: selfIssuedRollover.Id))!;
        await VerifyCrlAndLeafWithOpenSslAsync(
             rootPem: rootPathZero.IssuerCertificatePem,
             untrustedChainPem: selfIssuedRollover.IssuerCertificatePem,
             crlPem: rolloverCrl.CrlPem,
             leafPem: rolloverLeaf.CertificatePem!,
             expectRevoked: false);

        // 3. Multi-tier constrained chain: Root (pathLen=1) -> Tier1 (non-self-issued, pathLen=0 or pathLen=1)
        CaAuthorityRecord rootPathOne = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Root CA (pathLen=1)",
            "root-path1.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Rsa,
            2048,
            365,
            secret,
            pathLengthConstraint: 1);

        CaAuthorityRecord tier1PathZero = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Tier 1 Intermediate (pathLen=0)",
            "tier1-path0.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa,
            256,
            180,
            secret,
            parentAuthority: rootPathOne,
            parentPassphrase: secret,
            pathLengthConstraint: 0);

        // 3a. Creating a non-self-issued subordinate beneath Tier 1 (pathLen=0) must fail before state changes
        int keyFilesAfterTier1 = Directory.GetFiles(caDir, "*.p8.enc").Length;
        InvalidOperationException tier2Ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            caService.CreateSelfSignedOrIntermediateCaAsync(
                "Forbidden Tier 2 Subordinate",
                "tier2-forbidden.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                90,
                secret,
                parentAuthority: tier1PathZero,
                parentPassphrase: secret));
        Assert.Contains("pathLenConstraint=0", tier2Ex.Message);
        Assert.Equal(keyFilesAfterTier1, Directory.GetFiles(caDir, "*.p8.enc").Length);
        Assert.Equal(tier1PathZero.Id, (await caService.GetActiveAuthorityAsync())!.Id);

        // 3b. Even if Tier 1 had pathLen=1, Root (pathLen=1) still forbids a non-self-issued Tier 2 subordinate!
        //     Also verify via ImportCaAsync and ImportCaFromPkcs12Async, and confirm OpenSSL rejects a leaf under such a chain.
        CaAuthorityRecord tier1PathOne = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Tier 1 Intermediate (pathLen=1 under Root pathLen=1)",
            "tier1-path1.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa,
            256,
            180,
            secret,
            parentAuthority: rootPathOne,
            parentPassphrase: secret,
            pathLengthConstraint: 1);

        InvalidOperationException ancestorLimitEx = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            caService.CreateSelfSignedOrIntermediateCaAsync(
                "Forbidden By Root PathLen=1",
                "tier2-exceeds-root.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                90,
                secret,
                parentAuthority: tier1PathOne,
                parentPassphrase: secret));
        Assert.Contains("Root CA", ancestorLimitEx.Message);
        Assert.Contains("pathLenConstraint=1", ancestorLimitEx.Message);
        Assert.Equal(tier1PathOne.Id, (await caService.GetActiveAuthorityAsync())!.Id);

        // Also construct a raw forbidden subordinate outside CertRobo under tier1PathZero and verify ImportCaAsync & ImportCaFromPkcs12Async reject it,
        // and confirm OpenSSL rejects a leaf signed by that forbidden subordinate.
        using X509Certificate2 rootPathOneCert = X509Certificate2.CreateFromPem(rootPathOne.IssuerCertificatePem);
        using X509Certificate2 tier1ZeroCert = X509Certificate2.CreateFromPem(tier1PathZero.IssuerCertificatePem);
        using ECDsa tier1ZeroKey = ECDsa.Create();
        byte[] tier1ZeroKeyBytes = await File.ReadAllBytesAsync(tier1PathZero.EncryptedPrivateKeyPath);
        tier1ZeroKey.ImportEncryptedPkcs8PrivateKey(secret, tier1ZeroKeyBytes, out _);

        using ECDsa rawSubKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest rawSubReq = new("CN=Raw Forbidden Sub, O=Contoso, C=US", rawSubKey, HashAlgorithmName.SHA256);
        rawSubReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        rawSubReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rawSubReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rawSubReq.PublicKey, false));
        using X509Certificate2 rawSubCert = rawSubReq.Create(
            tier1ZeroCert.SubjectName,
            X509SignatureGenerator.CreateForECDsa(tier1ZeroKey),
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(60),
            [0x31, 0x32, 0x33]);

        string parentChainPem = tier1PathZero.IssuerCertificatePem + "\n" + rootPathOne.IssuerCertificatePem;
        ArgumentException importForbiddenEx = await Assert.ThrowsAsync<ArgumentException>(() =>
            caService.ImportCaAsync(
                "Imported Forbidden Sub",
                rawSubCert.ExportCertificatePem(),
                parentChainPem,
                rawSubKey.ExportPkcs8PrivateKeyPem(),
                null,
                secret));
        Assert.Contains("pathLenConstraint=0", importForbiddenEx.Message);

        using X509Certificate2 rawSubWithKey = rawSubCert.CopyWithPrivateKey(rawSubKey);
        X509Certificate2Collection forbiddenPfxCol = [rawSubWithKey, tier1ZeroCert, rootPathOneCert];
        byte[] forbiddenPfxBytes = forbiddenPfxCol.Export(X509ContentType.Pkcs12, "PfxPass!123")!;
        await Assert.ThrowsAsync<ArgumentException>(() =>
            caService.ImportCaFromPkcs12Async("Imported Forbidden Sub PFX", forbiddenPfxBytes, "PfxPass!123", secret));

        // Independently confirm OpenSSL rejects a leaf under rawSubCert -> tier1ZeroCert (pathLen=0) -> rootPathOneCert
        using ECDsa rawLeafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest rawLeafReq = new("CN=bad-leaf.contoso.com, O=Contoso, C=US", rawLeafKey, HashAlgorithmName.SHA256);
        rawLeafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using X509Certificate2 rawLeafCert = rawLeafReq.Create(
            rawSubCert.SubjectName,
            X509SignatureGenerator.CreateForECDsa(rawSubKey),
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(10),
            [0x41, 0x42, 0x43]);

        string verifyDir = Path.Combine(_tempRoot, "openssl-pathlen");
        Directory.CreateDirectory(verifyDir);
        string rootPath = Path.Combine(verifyDir, "root.pem");
        string untrustedPath = Path.Combine(verifyDir, "untrusted.pem");
        string leafPath = Path.Combine(verifyDir, "leaf.pem");
        await File.WriteAllTextAsync(rootPath, rootPathOne.IssuerCertificatePem);
        await File.WriteAllTextAsync(untrustedPath, rawSubCert.ExportCertificatePem() + "\n" + tier1PathZero.IssuerCertificatePem);
        await File.WriteAllTextAsync(leafPath, rawLeafCert.ExportCertificatePem());
        var (osslExit, osslOut) = await RunProcessAsync("openssl", ["verify", "-CAfile", rootPath, "-untrusted", untrustedPath, leafPath]);
        Assert.NotEqual(0, osslExit);
        Assert.Contains("path length constraint exceeded", osslOut, StringComparison.OrdinalIgnoreCase);

        // 4. Positive multi-tier constrained chain: Root (pathLen=2) -> Tier1 (pathLen=1) -> Tier2 (pathLen=0) -> Leaf
        CaAuthorityRecord rootPathTwo = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Root CA (pathLen=2)",
            "root-path2.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Rsa,
            2048,
            365,
            secret,
            pathLengthConstraint: 2);
        CaAuthorityRecord validTier1 = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Valid Tier 1 (pathLen=1)",
            "valid-tier1.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa,
            256,
            180,
            secret,
            parentAuthority: rootPathTwo,
            parentPassphrase: secret,
            pathLengthConstraint: 1);
        CaAuthorityRecord validTier2 = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Valid Tier 2 (pathLen=0)",
            "valid-tier2.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa,
            256,
            90,
            secret,
            parentAuthority: validTier1,
            parentPassphrase: secret,
            pathLengthConstraint: 0);

        IssuanceOutcome tier2Leaf = await IssueLeafAsync(caService, admin.Id, "tier2-app.contoso.com");
        Assert.True(tier2Leaf.Succeeded, tier2Leaf.ErrorMessage);
        PublishedCrlRecord tier2Crl = (await caService.GetLatestCrlAsync(caAuthorityId: validTier2.Id))!;
        await VerifyCrlAndLeafWithOpenSslAsync(
            rootPem: rootPathTwo.IssuerCertificatePem,
            untrustedChainPem: validTier2.IssuerCertificatePem + "\n" + validTier1.IssuerCertificatePem,
            crlPem: tier2Crl.CrlPem,
            leafPem: tier2Leaf.CertificatePem!,
            expectRevoked: false);
    }

    [Fact]
    public async Task CaImportAndActivation_RejectMissingKeyUsage_AndMissingCrlSign_BeforeStateChanges_WhileValidImportsWork()
    {
        const string secret = "KeyUsageValidationSecret!2026";
        string dbPath = Path.Combine(_tempRoot, "keyusage-comprehensive.db");
        string caDir = Path.Combine(_tempRoot, "keyusage-comprehensive-ca");

        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir, configuredPassphrase: secret);
        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
        ApplicationUser admin = await BootstrapAdminAsync(sp);

        CaAuthorityRecord initialActive = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Initial Working Root CA",
            "initial-root.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa,
            256,
            365,
            secret);
        int keyFileCountBefore = Directory.GetFiles(caDir, "*.p8.enc").Length;

        // 1. Missing CrlSign (KeyUsage = KeyCertSign only) via PEM and PKCS#12
        using ECDsa noCrlSignKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest noCrlSignReq = new("CN=No CrlSign CA, O=Contoso, C=US", noCrlSignKey, HashAlgorithmName.SHA256);
        noCrlSignReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        noCrlSignReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using X509Certificate2 noCrlSignCert = noCrlSignReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(365));

        ArgumentException pemNoCrlEx = await Assert.ThrowsAsync<ArgumentException>(() =>
            caService.ImportCaAsync(
                "No CrlSign PEM",
                noCrlSignCert.ExportCertificatePem(),
                null,
                noCrlSignKey.ExportPkcs8PrivateKeyPem(),
                null,
                secret));
        Assert.Contains("CrlSign", pemNoCrlEx.Message);

        byte[] noCrlSignPfx = noCrlSignCert.Export(X509ContentType.Pkcs12, "PfxPass!123")!;
        ArgumentException pfxNoCrlEx = await Assert.ThrowsAsync<ArgumentException>(() =>
            caService.ImportCaFromPkcs12Async("No CrlSign PFX", noCrlSignPfx, "PfxPass!123", secret));
        Assert.Contains("CrlSign", pfxNoCrlEx.Message);

        // 2. Missing KeyCertSign (KeyUsage = CrlSign only)
        using ECDsa noCertSignKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest noCertSignReq = new("CN=No KeyCertSign CA, O=Contoso, C=US", noCertSignKey, HashAlgorithmName.SHA256);
        noCertSignReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        noCertSignReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign, true));
        using X509Certificate2 noCertSignCert = noCertSignReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(365));

        ArgumentException noCertSignEx = await Assert.ThrowsAsync<ArgumentException>(() =>
            caService.ImportCaAsync(
                "No KeyCertSign PEM",
                noCertSignCert.ExportCertificatePem(),
                null,
                noCertSignKey.ExportPkcs8PrivateKeyPem(),
                null,
                secret));
        Assert.Contains("KeyCertSign", noCertSignEx.Message);

        // 3. Missing KeyUsage extension altogether
        using ECDsa noKuKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest noKuReq = new("CN=No KeyUsage CA, O=Contoso, C=US", noKuKey, HashAlgorithmName.SHA256);
        noKuReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using X509Certificate2 noKuCert = noKuReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(365));

        ArgumentException noKuEx = await Assert.ThrowsAsync<ArgumentException>(() =>
            caService.ImportCaAsync(
                "No KeyUsage PEM",
                noKuCert.ExportCertificatePem(),
                null,
                noKuKey.ExportPkcs8PrivateKeyPem(),
                null,
                secret));
        Assert.Contains("KeyUsage", noKuEx.Message);

        // 4. Intermediate CA whose parent lacks KeyUsage
        using ECDsa interUnderNoKuKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest interUnderNoKuReq = new("CN=Inter Under NoKu Root, O=Contoso, C=US", interUnderNoKuKey, HashAlgorithmName.SHA256);
        interUnderNoKuReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        interUnderNoKuReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using X509Certificate2 interUnderNoKuCert = interUnderNoKuReq.Create(
            noKuCert.SubjectName,
            X509SignatureGenerator.CreateForECDsa(noKuKey),
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(180),
            [0x51, 0x52]);

        ArgumentException parentNoKuEx = await Assert.ThrowsAsync<ArgumentException>(() =>
            caService.ImportCaAsync(
                "Inter Under NoKu Parent",
                interUnderNoKuCert.ExportCertificatePem(),
                noKuCert.ExportCertificatePem(),
                interUnderNoKuKey.ExportPkcs8PrivateKeyPem(),
                null,
                secret));
        Assert.Contains("KeyUsage", parentNoKuEx.Message);

        // Verify zero side effects on disk or active CA
        Assert.Equal(keyFileCountBefore, Directory.GetFiles(caDir, "*.p8.enc").Length);
        Assert.Equal(initialActive.Id, (await caService.GetActiveAuthorityAsync())!.Id);
        IssuanceOutcome stillWorking = await IssueLeafAsync(caService, admin.Id, "still-working.contoso.com");
        Assert.True(stillWorking.Succeeded, stillWorking.ErrorMessage);
    }

    [Fact]
    public async Task Pkcs12Import_RejectsAmbiguousMultiKeyArchivesRegardlessOfOrder_SupportsExplicitThumbprintSelection_AndImportsSingleKeyWithChain()
    {
        const string secret = "Pkcs12SelectionSecret!2026";
        string dbPath = Path.Combine(_tempRoot, "pkcs12-selection.db");
        string caDir = Path.Combine(_tempRoot, "pkcs12-selection-ca");

        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir, configuredPassphrase: secret);
        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();

        using ECDsa key1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest req1 = new("CN=CA Identity One, O=Contoso, C=US", key1, HashAlgorithmName.SHA256);
        req1.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req1.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using X509Certificate2 cert1 = req1.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(365));
        string fp1 = cert1.GetCertHashString(HashAlgorithmName.SHA256);

        using ECDsa key2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest req2 = new("CN=CA Identity Two, O=Contoso, C=US", key2, HashAlgorithmName.SHA256);
        req2.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req2.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using X509Certificate2 cert2 = req2.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(365));
        string fp2 = cert2.GetCertHashString(HashAlgorithmName.SHA256);

        X509Certificate2Collection col12 = [cert1, cert2];
        X509Certificate2Collection col21 = [cert2, cert1];
        byte[] pfxOrder12 = col12.Export(X509ContentType.Pkcs12, "PfxPass!123")!;
        byte[] pfxOrder21 = col21.Export(X509ContentType.Pkcs12, "PfxPass!123")!;

        // 1. Implicit import of a multi-key PFX is rejected in BOTH orderings without side effects
        ArgumentException ex12 = await Assert.ThrowsAsync<ArgumentException>(() =>
            caService.ImportCaFromPkcs12Async("Ambiguous 1-2", pfxOrder12, "PfxPass!123", secret));
        ArgumentException ex21 = await Assert.ThrowsAsync<ArgumentException>(() =>
            caService.ImportCaFromPkcs12Async("Ambiguous 2-1", pfxOrder21, "PfxPass!123", secret));
        Assert.Contains("ambiguous", ex12.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(fp1, ex12.Message);
        Assert.Contains(fp2, ex12.Message);
        Assert.Equal(ex12.Message, ex21.Message);
        Assert.Null(await caService.GetActiveAuthorityAsync());

        // 2. Explicit selection by SHA-256 thumbprint selects the exact same identity regardless of PFX entry ordering
        CaAuthorityRecord selectedFrom12 = await caService.ImportCaFromPkcs12Async(
            "Explicit Identity Two (from 1-2)",
            pfxOrder12,
            "PfxPass!123",
            secret,
            selectedCertificateThumbprintSha256: fp2);
        CaAuthorityRecord selectedFrom21 = await caService.ImportCaFromPkcs12Async(
            "Explicit Identity Two (from 2-1)",
            pfxOrder21,
            "PfxPass!123",
            secret,
            selectedCertificateThumbprintSha256: fp2);
        Assert.Equal(fp2, selectedFrom12.ThumbprintOrSerialHex);
        Assert.Equal(fp2, selectedFrom21.ThumbprintOrSerialHex);

        // 3. Single-key PFX with public chain certificates imports cleanly regardless of whether chain cert is first or last
        using RSA rootKey = RSA.Create(2048);
        CertificateRequest rootReq = new("CN=SingleKey PFX Root CA, O=Contoso, C=US", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        X509SubjectKeyIdentifierExtension rootSki = new(rootReq.PublicKey, false);
        rootReq.CertificateExtensions.Add(rootSki);
        using X509Certificate2 rootCertWithKey = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        using X509Certificate2 rootPublicOnly = X509CertificateLoader.LoadCertificate(rootCertWithKey.RawData);

        using ECDsa interKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest interReq = new("CN=SingleKey PFX Inter CA, O=Contoso, C=US", interKey, HashAlgorithmName.SHA256);
        interReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        interReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        interReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(interReq.PublicKey, false));
        interReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(rootSki));
        using X509Certificate2 interUnsigned = interReq.Create(
            rootCertWithKey.SubjectName,
            X509SignatureGenerator.CreateForRSA(rootKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(180),
            [0x61, 0x62, 0x63]);
        using X509Certificate2 interWithKey = interUnsigned.CopyWithPrivateKey(interKey);
        string interFp = interWithKey.GetCertHashString(HashAlgorithmName.SHA256);

        X509Certificate2Collection chainFirstCol = [rootPublicOnly, interWithKey];
        byte[] chainFirstPfx = chainFirstCol.Export(X509ContentType.Pkcs12, "ChainPfx!123")!;
        CaAuthorityRecord importedSingleKey = await caService.ImportCaFromPkcs12Async(
            "SingleKey With Chain First",
            chainFirstPfx,
            "ChainPfx!123",
            secret);
        Assert.Equal(interFp, importedSingleKey.ThumbprintOrSerialHex);
        Assert.True(importedSingleKey.IsIntermediate);
    }

    [Fact]
    public async Task ReviewFix_EquivalentSerialEncodings_SignPadding_LeadingZeros_AndPreExistingDuplicates_ConvergeAndExposeConflicts()
    {
        const string secret = "Disposable-Test-Secret-Only!2026";
        string dbPath = Path.Combine(_tempRoot, "leading-zero.db");
        string caDir = Path.Combine(_tempRoot, "leading-zero-ca");

        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir, configuredPassphrase: secret);
        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
        ApplicationUser admin = await BootstrapAdminAsync(sp);

        CaAuthorityRecord ca = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Test CA", "ca.contoso.com", "US", "Colorado", "Denver", "Test", "PKI",
            CertificateKeyFamily.Ecdsa, 256, 365, secret);

        // 1. Exact review probe: issue & revoke a certificate, then seed its serial prefixed with "00" and a different reason
        IssuanceOutcome leaf = await IssueLeafAsync(caService, admin.Id, "host.contoso.com");
        RevocationOutcome first = await caService.RevokeCertificateAsync(leaf.Record!.Id, CrlReason.KeyCompromise, "admin");
        Assert.True(first.CrlPublished);

        RevocationOutcome seeded = await caService.SeedRevokedSerialAsync(
            "00" + leaf.Record.SerialNumberHex,
            "host.contoso.com",
            CrlReason.Superseded,
            "admin");
        Assert.True(seeded.CrlPublished);
        Assert.Empty(await caService.GetCertificateIdsWithUnpublishedRevocationsAsync());

        long crlAfterSeed = seeded.PublishedCrl!.CrlNumber;
        Assert.True(CrlContainsSerial(seeded.PublishedCrl.CrlDer, leaf.Record.SerialNumberHex, CrlReason.Superseded));

        // Subsequent refreshes must be no-ops (converged, no permanent pending loop)
        for (int i = 0; i < 2; i++)
        {
            IReadOnlyList<CrlRefreshOutcome> retry = await caService.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
            Assert.Empty(retry);
            Assert.Empty(await caService.GetCertificateIdsWithUnpublishedRevocationsAsync());
            Assert.Equal(crlAfterSeed, (await caService.GetLatestCrlAsync())!.CrlNumber);
        }

        // 2. ASN.1 DER sign-padding ("00:80:AB:CD" vs "80:AB:CD") and odd-nibble/leading-zero ("0003E9" vs "3E9")
        RevocationOutcome signPadded1 = await caService.SeedRevokedSerialAsync(
            "00:80:AB:CD",
            "signpadded.contoso.com",
            CrlReason.KeyCompromise,
            "admin");
        Assert.True(signPadded1.CrlPublished);
        Assert.Equal("80ABCD", signPadded1.CertificateRecord!.SerialNumberHex);

        RevocationOutcome signPadded2 = await caService.SeedRevokedSerialAsync(
            "80ABCD",
            "signpadded.contoso.com",
            CrlReason.CessationOfOperation,
            "admin");
        Assert.True(signPadded2.CrlPublished);
        Assert.Equal(signPadded1.CertificateRecord.Id, signPadded2.CertificateRecord!.Id);
        Assert.Empty(await caService.GetCertificateIdsWithUnpublishedRevocationsAsync());

        // 3. Pre-existing agreeing duplicate rows in database ("03E9" and "0003E9" with same reason & timestamp)
        DateTimeOffset agreedRevokedAt = new(2026, 11, 2, 12, 0, 0, TimeSpan.Zero);
        using (IServiceScope scope = sp.CreateScope())
        {
            CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            db.IssuedCertificates.AddRange(
                new IssuedCertificateRecord
                {
                    CaAuthorityId = ca.Id,
                    SerialNumberHex = "03E9",
                    SerialNumberValue = 1001,
                    ProfileId = "legacy-imported",
                    CommonName = "dup1.contoso.com",
                    SubjectAlternativeNamesCsv = "dup1.contoso.com",
                    SubjectDistinguishedName = "CN=dup1.contoso.com",
                    IssuerDistinguishedName = "CN=ca.contoso.com",
                    KeyAlgorithm = "LEGACY",
                    KeySizeBits = 0,
                    ThumbprintSha256 = "LEGACY-03E9",
                    NotBeforeUtc = ca.NotBeforeUtc,
                    NotAfterUtc = ca.NotAfterUtc,
                    RequestedByUserId = "legacy",
                    RequestedByUserName = "admin",
                    Status = IssuanceStatus.Revoked,
                    CreatedAtUtc = agreedRevokedAt,
                    RevokedAtUtc = agreedRevokedAt,
                    RevocationReasonCode = CrlReason.KeyCompromise,
                    RevokedByUserName = "admin"
                },
                new IssuedCertificateRecord
                {
                    CaAuthorityId = ca.Id,
                    SerialNumberHex = "0003E9",
                    SerialNumberValue = 1001,
                    ProfileId = "legacy-imported",
                    CommonName = "dup1.contoso.com",
                    SubjectAlternativeNamesCsv = "dup1.contoso.com",
                    SubjectDistinguishedName = "CN=dup1.contoso.com",
                    IssuerDistinguishedName = "CN=ca.contoso.com",
                    KeyAlgorithm = "LEGACY",
                    KeySizeBits = 0,
                    ThumbprintSha256 = "LEGACY-0003E9",
                    NotBeforeUtc = ca.NotBeforeUtc,
                    NotAfterUtc = ca.NotAfterUtc,
                    RequestedByUserId = "legacy",
                    RequestedByUserName = "admin",
                    Status = IssuanceStatus.Revoked,
                    CreatedAtUtc = agreedRevokedAt,
                    RevokedAtUtc = agreedRevokedAt,
                    RevocationReasonCode = CrlReason.KeyCompromise,
                    RevokedByUserName = "admin"
                });
            await db.SaveChangesAsync();
        }

        IReadOnlyList<CrlRefreshOutcome> agreedRefresh = await caService.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
        Assert.Single(agreedRefresh);
        Assert.True(agreedRefresh[0].Succeeded, agreedRefresh[0].ErrorMessage);

        // Verify the generated CRL has no duplicate serial entries and subsequent refresh converges
        X509Crl parsedAgreedCrl = new X509CrlParser().ReadCrl(agreedRefresh[0].PublishedCrl!.CrlDer);
        var crlEntries = parsedAgreedCrl.GetRevokedCertificates();
        int countFor03E9 = crlEntries.Cast<X509CrlEntry>().Count(e => e.SerialNumber.Equals(new BigInteger(1, [0x03, 0xE9])));
        Assert.Equal(1, countFor03E9);
        Assert.Empty(await caService.GetCertificateIdsWithUnpublishedRevocationsAsync());
        Assert.Empty(await caService.RefreshDueCrlsAsync(TimeSpan.FromHours(24)));

        // 4. Pre-existing CONFLICTING duplicate rows in database ("04B0" with KeyCompromise vs "0004B0" with Superseded)
        int conflictId1;
        int conflictId2;
        using (IServiceScope scope = sp.CreateScope())
        {
            CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            IssuedCertificateRecord c1 = new()
            {
                CaAuthorityId = ca.Id,
                SerialNumberHex = "04B0",
                SerialNumberValue = 1200,
                ProfileId = "legacy-imported",
                CommonName = "conflict.contoso.com",
                SubjectAlternativeNamesCsv = "conflict.contoso.com",
                SubjectDistinguishedName = "CN=conflict.contoso.com",
                IssuerDistinguishedName = "CN=ca.contoso.com",
                KeyAlgorithm = "LEGACY",
                KeySizeBits = 0,
                ThumbprintSha256 = "LEGACY-04B0",
                NotBeforeUtc = ca.NotBeforeUtc,
                NotAfterUtc = ca.NotAfterUtc,
                RequestedByUserId = "legacy",
                RequestedByUserName = "admin",
                Status = IssuanceStatus.Revoked,
                CreatedAtUtc = agreedRevokedAt,
                RevokedAtUtc = agreedRevokedAt,
                RevocationReasonCode = CrlReason.KeyCompromise,
                RevokedByUserName = "admin"
            };
            IssuedCertificateRecord c2 = new()
            {
                CaAuthorityId = ca.Id,
                SerialNumberHex = "0004B0",
                SerialNumberValue = 1200,
                ProfileId = "legacy-imported",
                CommonName = "conflict.contoso.com",
                SubjectAlternativeNamesCsv = "conflict.contoso.com",
                SubjectDistinguishedName = "CN=conflict.contoso.com",
                IssuerDistinguishedName = "CN=ca.contoso.com",
                KeyAlgorithm = "LEGACY",
                KeySizeBits = 0,
                ThumbprintSha256 = "LEGACY-0004B0",
                NotBeforeUtc = ca.NotBeforeUtc,
                NotAfterUtc = ca.NotAfterUtc,
                RequestedByUserId = "legacy",
                RequestedByUserName = "admin",
                Status = IssuanceStatus.Revoked,
                CreatedAtUtc = agreedRevokedAt,
                RevokedAtUtc = agreedRevokedAt,
                RevocationReasonCode = CrlReason.Superseded,
                RevokedByUserName = "admin"
            };
            db.IssuedCertificates.AddRange(c1, c2);
            await db.SaveChangesAsync();
            conflictId1 = c1.Id;
            conflictId2 = c2.Id;
        }

        long crlBeforeConflict = (await caService.GetLatestCrlAsync())!.CrlNumber;
        IReadOnlySet<int> unpublishedWithConflict = await caService.GetCertificateIdsWithUnpublishedRevocationsAsync();
        Assert.Contains(conflictId1, unpublishedWithConflict);
        Assert.Contains(conflictId2, unpublishedWithConflict);

        // Retries must expose the conflict without advancing CRL numbers
        for (int i = 0; i < 2; i++)
        {
            IReadOnlyList<CrlRefreshOutcome> conflictRefresh = await caService.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
            Assert.Single(conflictRefresh);
            Assert.False(conflictRefresh[0].Succeeded);
            Assert.Contains("Conflicting revocation records", conflictRefresh[0].ErrorMessage);
            Assert.Contains("04B0", conflictRefresh[0].ErrorMessage);
            Assert.Equal(crlBeforeConflict, (await caService.GetLatestCrlAsync())!.CrlNumber);
        }

        // Reconciling the conflicting serial via SeedRevokedSerialAsync aligns revocation metadata without deleting either row and converges
        RevocationOutcome reconciled = await caService.SeedRevokedSerialAsync(
            "00:04:B0",
            "conflict.contoso.com",
            CrlReason.KeyCompromise,
            "admin");
        Assert.True(reconciled.CrlPublished);
        Assert.Equal(crlBeforeConflict + 1, reconciled.PublishedCrl!.CrlNumber);
        Assert.Empty(await caService.GetCertificateIdsWithUnpublishedRevocationsAsync());
        Assert.Empty(await caService.RefreshDueCrlsAsync(TimeSpan.FromHours(24)));

        using (IServiceScope checkScope = sp.CreateScope())
        {
            CertRoboDbContext checkDb = checkScope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            Assert.NotNull(await checkDb.IssuedCertificates.FindAsync(conflictId1));
            Assert.NotNull(await checkDb.IssuedCertificates.FindAsync(conflictId2));
        }
    }

    [Fact]
    public async Task ReviewFix_RealDatabasePersistenceFailure_OnOneIssuer_DoesNotContaminateOtherIssuerRefresh()
    {
        const string secret = "Disposable-Test-Secret-Only!2026";
        string dbPath = Path.Combine(_tempRoot, "failure-isolation.db");
        string caDir = Path.Combine(_tempRoot, "failure-isolation-ca");

        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir, configuredPassphrase: secret);
        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
        ApplicationUser admin = await BootstrapAdminAsync(sp);

        CaAuthorityRecord a = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "CA A", "a.contoso.com", "US", "Colorado", "Denver", "Test", "PKI",
            CertificateKeyFamily.Ecdsa, 256, 365, secret);
        IssuanceOutcome leafA = await IssueLeafAsync(caService, admin.Id, "a1.contoso.com");

        CaAuthorityRecord b = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "CA B", "b.contoso.com", "US", "Colorado", "Denver", "Test", "PKI",
            CertificateKeyFamily.Ecdsa, 256, 365, secret);
        IssuanceOutcome leafB = await IssueLeafAsync(caService, admin.Id, "b1.contoso.com");

        caService.LockRuntimePassphrase();
        Assert.True((await caService.RevokeCertificateAsync(leafA.Record!.Id, CrlReason.KeyCompromise, "admin")).IsPendingPublication);
        Assert.True((await caService.RevokeCertificateAsync(leafB.Record!.Id, CrlReason.KeyCompromise, "admin")).IsPendingPublication);
        caService.UnlockRuntimePassphrase(secret);

        using (IServiceScope scope = sp.CreateScope())
        {
            CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
#pragma warning disable EF1002
            await db.Database.ExecuteSqlRawAsync(
                $"CREATE TRIGGER fail_first_issuer BEFORE INSERT ON PublishedCrls WHEN NEW.CaAuthorityId = {a.Id} BEGIN SELECT RAISE(ABORT, 'synthetic issuer-specific failure'); END;");
#pragma warning restore EF1002
        }

        // Issuer A fails persistence, but Issuer B must succeed in its isolated context and advance to CRL #2
        IReadOnlyList<CrlRefreshOutcome> results = await caService.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
        Assert.False(results.Single(x => x.CaAuthorityId == a.Id).Succeeded);
        Assert.True(results.Single(x => x.CaAuthorityId == b.Id).Succeeded, results.Single(x => x.CaAuthorityId == b.Id).ErrorMessage);
        Assert.Equal(1, (await caService.GetLatestCrlAsync(caAuthorityId: a.Id))!.CrlNumber);
        Assert.Equal(2, (await caService.GetLatestCrlAsync(caAuthorityId: b.Id))!.CrlNumber);

        IReadOnlySet<int> stillPending = await caService.GetCertificateIdsWithUnpublishedRevocationsAsync();
        Assert.Contains(leafA.Record.Id, stillPending);
        Assert.DoesNotContain(leafB.Record.Id, stillPending);

        using (IServiceScope scope = sp.CreateScope())
        {
            CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            await db.Database.ExecuteSqlRawAsync("DROP TRIGGER fail_first_issuer;");
        }

        IReadOnlyList<CrlRefreshOutcome> retry = await caService.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
        Assert.Single(retry);
        Assert.Equal(a.Id, retry[0].CaAuthorityId);
        Assert.True(retry[0].Succeeded, retry[0].ErrorMessage);
        Assert.Equal(2, (await caService.GetLatestCrlAsync(caAuthorityId: a.Id))!.CrlNumber);
        Assert.Equal(2, (await caService.GetLatestCrlAsync(caAuthorityId: b.Id))!.CrlNumber);
        Assert.Empty(await caService.GetCertificateIdsWithUnpublishedRevocationsAsync());
    }

    [Fact]
    public async Task ReviewFix_BackgroundService_WakesPromptlyOnPendingRevocationAndUnlock_AfterCleanScan()
    {
        const string secret = "BackgroundServiceWakeSecret!2026";
        string dbPath = Path.Combine(_tempRoot, "bg-wake.db");
        string caDir = Path.Combine(_tempRoot, "bg-wake-ca");

        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir);
        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
        ApplicationUser admin = await BootstrapAdminAsync(sp);

        CaAuthorityRecord ca = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Background Wake CA", "wake.contoso.com", "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa, 256, 365, secret);
        IssuanceOutcome leaf1 = await IssueLeafAsync(caService, admin.Id, "wake1.contoso.com");
        IssuanceOutcome leaf2 = await IssueLeafAsync(caService, admin.Id, "wake2.contoso.com");

        var logger = sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<CrlRefreshBackgroundService>>();
        using CrlRefreshBackgroundService bgService = new(
            caService,
            logger,
            checkIntervalOverride: TimeSpan.FromMinutes(30),
            pendingRetryIntervalOverride: TimeSpan.FromMilliseconds(100));

        await bgService.StartAsync(CancellationToken.None);
        try
        {
            // 1. Wait for the initial clean scan to complete; the background service is now parked in its 30-minute wait
            await bgService.WaitForCompletedScanCountAsync(1, TimeSpan.FromSeconds(5));
            Assert.Equal(1, (await caService.GetLatestCrlAsync(caAuthorityId: ca.Id))!.CrlNumber);

            // 2. Lock the signer and revoke leaf1 AFTER the clean scan has already entered its 30-minute wait
            caService.LockRuntimePassphrase();
            RevocationOutcome lockedRevoke = await caService.RevokeCertificateAsync(
                leaf1.Record!.Id,
                CrlReason.KeyCompromise,
                "admin");
            Assert.True(lockedRevoke.IsPendingPublication);

            // The pending revocation wakes the background service from its 30-minute sleep immediately
            long afterPendingScan = await bgService.WaitForCompletedScanCountAsync(2, TimeSpan.FromSeconds(5));
            Assert.True(afterPendingScan >= 2);
            Assert.Equal(1, (await caService.GetLatestCrlAsync(caAuthorityId: ca.Id))!.CrlNumber);

            // 3. Unlocking the signer signals the background service to publish CRL #2 immediately
            caService.UnlockRuntimePassphrase(secret);
            PublishedCrlRecord crl2 = await WaitForCrlNumberAsync(caService, ca.Id, expectedCrlNumber: 2, bgService, TimeSpan.FromSeconds(5));
            Assert.Equal(2, crl2.CrlNumber);
            Assert.True(CrlContainsSerial(crl2.CrlDer, leaf1.Record.SerialNumberHex, CrlReason.KeyCompromise));
            Assert.Empty(await caService.GetCertificateIdsWithUnpublishedRevocationsAsync());

            // Wait for the background service to settle into its clean 30-minute sleep
            long settledScanCount = bgService.CompletedScanCount;
            await Task.Delay(150);
            if (bgService.CompletedScanCount > settledScanCount)
            {
                await Task.Delay(150);
            }

            // 4. Also verify a transient publication failure arriving after a clean scan wakes the 30-minute sleep
            //    and retries automatically on the short pendingRetryInterval once the transient fault clears
            int faultCount = 0;
            caService.CrlPublicationFaultInjector = _ =>
            {
                if (Interlocked.Increment(ref faultCount) <= 2)
                {
                    throw new IOException("Transient CRL fault.");
                }
            };

            RevocationOutcome transientOutcome = await caService.RevokeCertificateAsync(
                leaf2.Record!.Id,
                CrlReason.Superseded,
                "admin");
            Assert.True(transientOutcome.IsPendingPublication);

            PublishedCrlRecord crl3 = await WaitForCrlNumberAsync(caService, ca.Id, expectedCrlNumber: 3, bgService, TimeSpan.FromSeconds(5));
            caService.CrlPublicationFaultInjector = null;

            Assert.Equal(3, crl3.CrlNumber);
            Assert.True(CrlContainsSerial(crl3.CrlDer, leaf2.Record.SerialNumberHex, CrlReason.Superseded));
            Assert.Empty(await caService.GetCertificateIdsWithUnpublishedRevocationsAsync());
        }
        finally
        {
            caService.CrlPublicationFaultInjector = null;
            await bgService.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task ReviewFollowup_RevokeAndSeed_PreserveAllEquivalentSerialLedgerRecords_IncludingOnPublicationFailure()
    {
        const string secret = "Disposable-Test-Secret-Only!2026";
        string dbPath = Path.Combine(_tempRoot, "preserve-ledger.db");
        string caDir = Path.Combine(_tempRoot, "preserve-ledger-ca");

        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir, configuredPassphrase: secret);
        CertificateAuthorityService service = sp.GetRequiredService<CertificateAuthorityService>();
        ApplicationUser admin = await BootstrapAdminAsync(sp);

        CaAuthorityRecord ca = await service.CreateSelfSignedOrIntermediateCaAsync(
            "Test CA", "ca.contoso.com", "US", "Colorado", "Denver", "Test", "PKI",
            CertificateKeyFamily.Ecdsa, 256, 365, secret);

        IssuanceOutcome leaf = await IssueLeafAsync(service, admin.Id, "host.contoso.com");
        IssuanceOutcome otherRealLeaf = await IssueLeafAsync(service, admin.Id, "other-certificate.contoso.com");

        int duplicateId;
        using (IServiceScope scope = sp.CreateScope())
        {
            CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            IssuedCertificateRecord duplicate = new()
            {
                CaAuthorityId = ca.Id,
                SerialNumberHex = "00" + leaf.Record!.SerialNumberHex,
                SerialNumberValue = leaf.Record.SerialNumberValue,
                ProfileId = otherRealLeaf.Record!.ProfileId,
                CommonName = "other-certificate.contoso.com",
                SubjectAlternativeNamesCsv = "other-certificate.contoso.com",
                SubjectDistinguishedName = "CN=other-certificate.contoso.com",
                IssuerDistinguishedName = leaf.Record.IssuerDistinguishedName,
                KeyAlgorithm = otherRealLeaf.Record.KeyAlgorithm,
                KeySizeBits = otherRealLeaf.Record.KeySizeBits,
                ThumbprintSha256 = "DIFFERENT-HISTORICAL-RECORD",
                CertificatePem = otherRealLeaf.CertificatePem!,
                ChainPem = otherRealLeaf.Record.ChainPem,
                NotBeforeUtc = otherRealLeaf.Record.NotBeforeUtc,
                NotAfterUtc = otherRealLeaf.Record.NotAfterUtc,
                RequestedByUserId = admin.Id,
                RequestedByUserName = "other-operator",
                Status = IssuanceStatus.Issued
            };
            db.IssuedCertificates.Add(duplicate);
            await db.SaveChangesAsync();
            duplicateId = duplicate.Id;
        }

        // 1. Revoke first record while CRL publication fails -> both ledger records must remain intact
        service.CrlPublicationFaultInjector = _ => throw new IOException("Simulated CRL failure on revoke.");
        RevocationOutcome failedRevoke = await service.RevokeCertificateAsync(leaf.Record!.Id, CrlReason.KeyCompromise, "admin");
        service.CrlPublicationFaultInjector = null;

        Assert.True(failedRevoke.RevocationAccepted);
        Assert.False(failedRevoke.CrlPublished);
        Assert.True(failedRevoke.IsPendingPublication);

        using (IServiceScope checkScope1 = sp.CreateScope())
        {
            CertRoboDbContext checkDb = checkScope1.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            IssuedCertificateRecord? preservedPrimary = await checkDb.IssuedCertificates.FindAsync(leaf.Record.Id);
            IssuedCertificateRecord? preservedDuplicate = await checkDb.IssuedCertificates.FindAsync(duplicateId);
            Assert.NotNull(preservedPrimary);
            Assert.NotNull(preservedDuplicate);
            Assert.Equal("host.contoso.com", preservedPrimary.CommonName);
            Assert.Equal("other-certificate.contoso.com", preservedDuplicate.CommonName);
            Assert.Equal("other-operator", preservedDuplicate.RequestedByUserName);
            Assert.Equal("DIFFERENT-HISTORICAL-RECORD", preservedDuplicate.ThumbprintSha256);
            Assert.Equal(otherRealLeaf.CertificatePem, preservedDuplicate.CertificatePem);
        }

        // 2. Revoke first record with CRL publication succeeding (exact ReviewProbe_RevokeMustPreserveEquivalentSerialLedgerRecords check)
        RevocationOutcome outcome = await service.RevokeCertificateAsync(leaf.Record.Id, CrlReason.KeyCompromise, "admin");
        Assert.True(outcome.RevocationAccepted);
        Assert.True(outcome.CrlPublished);

        using (IServiceScope checkScope2 = sp.CreateScope())
        {
            CertRoboDbContext checkDb = checkScope2.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            IssuedCertificateRecord? preservedDuplicate = await checkDb.IssuedCertificates.FindAsync(duplicateId);
            Assert.NotNull(preservedDuplicate);
            Assert.Equal("other-certificate.contoso.com", preservedDuplicate.CommonName);
            Assert.Equal("other-operator", preservedDuplicate.RequestedByUserName);
            Assert.Equal(otherRealLeaf.CertificatePem, preservedDuplicate.CertificatePem);
        }

        // 3. Seed equivalent serial with publication failure, then with publication success -> both ledger records remain preserved
        service.CrlPublicationFaultInjector = _ => throw new IOException("Simulated CRL failure on seed.");
        RevocationOutcome failedSeed = await service.SeedRevokedSerialAsync(
            "00" + leaf.Record.SerialNumberHex,
            "host.contoso.com",
            CrlReason.Superseded,
            "admin");
        service.CrlPublicationFaultInjector = null;
        Assert.True(failedSeed.RevocationAccepted);
        Assert.False(failedSeed.CrlPublished);

        RevocationOutcome succeededSeed = await service.SeedRevokedSerialAsync(
            "00" + leaf.Record.SerialNumberHex,
            "host.contoso.com",
            CrlReason.Superseded,
            "admin");
        Assert.True(succeededSeed.RevocationAccepted);
        Assert.True(succeededSeed.CrlPublished);
        Assert.Empty(await service.GetCertificateIdsWithUnpublishedRevocationsAsync());

        using (IServiceScope checkScope3 = sp.CreateScope())
        {
            CertRoboDbContext checkDb = checkScope3.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            IssuedCertificateRecord? preservedPrimary = await checkDb.IssuedCertificates.FindAsync(leaf.Record.Id);
            IssuedCertificateRecord? preservedDuplicate = await checkDb.IssuedCertificates.FindAsync(duplicateId);
            Assert.NotNull(preservedPrimary);
            Assert.NotNull(preservedDuplicate);
            Assert.Equal("host.contoso.com", preservedPrimary.CommonName);
            Assert.Equal("other-certificate.contoso.com", preservedDuplicate.CommonName);
            Assert.Equal("other-operator", preservedDuplicate.RequestedByUserName);
            Assert.Equal(otherRealLeaf.CertificatePem, preservedDuplicate.CertificatePem);
            Assert.Equal(IssuanceStatus.Revoked, preservedPrimary.Status);
            Assert.Equal(IssuanceStatus.Revoked, preservedDuplicate.Status);
            Assert.Equal(CrlReason.Superseded, preservedPrimary.RevocationReasonCode);
            Assert.Equal(CrlReason.Superseded, preservedDuplicate.RevocationReasonCode);
        }
    }

    [Fact]
    public async Task ReviewFollowup_PostSaveFailures_InPassphraseFile_AndContextOrQueryStage_ReturnPendingOutcome_SignalWorker_AndPreserveCancellation()
    {
        const string secret = "Disposable-Test-Secret-Only!2026";
        string dbPath = Path.Combine(_tempRoot, "unreadable-passphrase.db");
        string caDir = Path.Combine(_tempRoot, "unreadable-passphrase-ca");
        string passFile = Path.Combine(_tempRoot, "unreadable.pass");
        await File.WriteAllTextAsync(passFile, secret);

        FaultInjectingDbContextFactory? faultDbFactory = null;
        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir, passFilePath: passFile, wrapDbFactory: options =>
        {
            faultDbFactory = new FaultInjectingDbContextFactory(options);
            return faultDbFactory;
        });

        CertificateAuthorityService service = sp.GetRequiredService<CertificateAuthorityService>();
        ApplicationUser admin = await BootstrapAdminAsync(sp);

        await service.CreateSelfSignedOrIntermediateCaAsync(
            "Test CA", "ca.contoso.com", "US", "Colorado", "Denver", "Test", "PKI",
            CertificateKeyFamily.Ecdsa, 256, 365, secret);

        IssuanceOutcome leaf1 = await IssueLeafAsync(service, admin.Id, "host1.contoso.com");
        IssuanceOutcome leaf2 = await IssueLeafAsync(service, admin.Id, "host2.contoso.com");
        IssuanceOutcome leaf3 = await IssueLeafAsync(service, admin.Id, "host3.contoso.com");

        // Drain any initial wake signal
        await service.WaitForCrlRefreshSignalAsync(TimeSpan.FromMilliseconds(50));

        // 1. Passphrase-resolution stage failure (unreadable passphrase file on Unix)
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(passFile, UnixFileMode.None);
            try
            {
                RevocationOutcome unreadableRevoke = await service.RevokeCertificateAsync(
                    leaf1.Record!.Id,
                    CrlReason.KeyCompromise,
                    "admin");
                Assert.False(unreadableRevoke.Succeeded);
                Assert.True(unreadableRevoke.RevocationAccepted);
                Assert.False(unreadableRevoke.CrlPublished);
                Assert.True(unreadableRevoke.IsPendingPublication);
                Assert.Equal(RevocationPublicationStatus.PendingPublicationFailed, unreadableRevoke.PublicationStatus);
                Assert.True(await service.WaitForCrlRefreshSignalAsync(TimeSpan.FromMilliseconds(250)));

                RevocationOutcome unreadableSeed = await service.SeedRevokedSerialAsync(
                    "01:AA:BB:CC",
                    "legacy-unreadable.contoso.com",
                    CrlReason.Superseded,
                    "admin");
                Assert.False(unreadableSeed.Succeeded);
                Assert.True(unreadableSeed.RevocationAccepted);
                Assert.False(unreadableSeed.CrlPublished);
                Assert.Equal(RevocationPublicationStatus.PendingPublicationFailed, unreadableSeed.PublicationStatus);
                Assert.True(await service.WaitForCrlRefreshSignalAsync(TimeSpan.FromMilliseconds(250)));

                // RefreshDueCrlsAsync reports the passphrase-read error per authority without throwing
                IReadOnlyList<CrlRefreshOutcome> unreadableRefresh = await service.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
                Assert.Single(unreadableRefresh);
                Assert.False(unreadableRefresh[0].Succeeded);
            }
            finally
            {
                File.SetUnixFileMode(passFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            using (IServiceScope checkScope = sp.CreateScope())
            {
                CertRoboDbContext checkDb = checkScope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
                IssuedCertificateRecord saved = (await checkDb.IssuedCertificates.FindAsync(leaf1.Record!.Id))!;
                Assert.Equal(IssuanceStatus.Revoked, saved.Status);
            }

            PublishedCrlRecord currentBeforeRetry = (await service.GetLatestCrlAsync())!;
            Assert.False(CrlContainsSerial(currentBeforeRetry.CrlDer, leaf1.Record!.SerialNumberHex));

            IReadOnlyList<CrlRefreshOutcome> recoveredRefresh = await service.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
            Assert.Single(recoveredRefresh);
            Assert.True(recoveredRefresh[0].Succeeded, recoveredRefresh[0].ErrorMessage);
            Assert.True(CrlContainsSerial(recoveredRefresh[0].PublishedCrl!.CrlDer, leaf1.Record.SerialNumberHex, CrlReason.KeyCompromise));
            Assert.True(CrlContainsSerial(recoveredRefresh[0].PublishedCrl!.CrlDer, "01AABBCC", CrlReason.Superseded));
        }

        // 2. Context / query stage failure after saving revocation (when TryPublishRevocationCrlCoreAsync opens crlDb)
        await service.WaitForCrlRefreshSignalAsync(TimeSpan.FromMilliseconds(50));
        Assert.NotNull(faultDbFactory);
        // Context #1 in RevokeCertificateAsync saves the revocation; Context #2 in TryPublishRevocationCrlCoreAsync throws
        faultDbFactory!.FailOnContextCreationNumber = 2;
        try
        {
            RevocationOutcome contextFailOutcome = await service.RevokeCertificateAsync(
                leaf2.Record!.Id,
                CrlReason.AffiliationChanged,
                "admin");
            Assert.False(contextFailOutcome.Succeeded);
            Assert.True(contextFailOutcome.RevocationAccepted);
            Assert.False(contextFailOutcome.CrlPublished);
            Assert.Equal(RevocationPublicationStatus.PendingPublicationFailed, contextFailOutcome.PublicationStatus);
            Assert.Contains("Simulated post-save DbContext creation failure", contextFailOutcome.ErrorMessage);
            Assert.True(await service.WaitForCrlRefreshSignalAsync(TimeSpan.FromMilliseconds(250)));
        }
        finally
        {
            faultDbFactory.FailOnContextCreationNumber = 0;
        }

        using (IServiceScope checkScope2 = sp.CreateScope())
        {
            CertRoboDbContext checkDb = checkScope2.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            IssuedCertificateRecord saved2 = (await checkDb.IssuedCertificates.FindAsync(leaf2.Record!.Id))!;
            Assert.Equal(IssuanceStatus.Revoked, saved2.Status);
        }

        IReadOnlyList<CrlRefreshOutcome> retryAfterContextFault = await service.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
        Assert.Single(retryAfterContextFault);
        Assert.True(retryAfterContextFault[0].Succeeded, retryAfterContextFault[0].ErrorMessage);
        Assert.True(CrlContainsSerial(retryAfterContextFault[0].PublishedCrl!.CrlDer, leaf2.Record!.SerialNumberHex, CrlReason.AffiliationChanged));

        // 3. Cancellation semantics during post-save publication: OperationCanceledException is propagated while still signaling worker
        await service.WaitForCrlRefreshSignalAsync(TimeSpan.FromMilliseconds(50));
        using CancellationTokenSource cts = new();
        service.CrlPublicationFaultInjector = _ =>
        {
            cts.Cancel();
            cts.Token.ThrowIfCancellationRequested();
        };
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                service.RevokeCertificateAsync(leaf3.Record!.Id, CrlReason.CessationOfOperation, "admin", cts.Token));
            Assert.True(await service.WaitForCrlRefreshSignalAsync(TimeSpan.FromMilliseconds(250)));
        }
        finally
        {
            service.CrlPublicationFaultInjector = null;
        }

        IReadOnlyList<CrlRefreshOutcome> retryAfterCancel = await service.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
        Assert.Single(retryAfterCancel);
        Assert.True(retryAfterCancel[0].Succeeded, retryAfterCancel[0].ErrorMessage);
        Assert.True(CrlContainsSerial(retryAfterCancel[0].PublishedCrl!.CrlDer, leaf3.Record!.SerialNumberHex, CrlReason.CessationOfOperation));
    }

    private sealed class FaultInjectingDbContextFactory(DbContextOptions<CertRoboDbContext> options)
        : IDbContextFactory<CertRoboDbContext>
    {
        private int _creationCount;
        private int _failOnCreationNumber;

        public int FailOnContextCreationNumber
        {
            get => _failOnCreationNumber;
            set
            {
                _creationCount = 0;
                _failOnCreationNumber = value;
            }
        }

        public CertRoboDbContext CreateDbContext()
        {
            if (_failOnCreationNumber > 0 && Interlocked.Increment(ref _creationCount) == _failOnCreationNumber)
            {
                throw new InvalidOperationException("Simulated post-save DbContext creation failure.");
            }
            return new CertRoboDbContext(options);
        }

        public Task<CertRoboDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(CreateDbContext());
        }
    }

    private static async Task<PublishedCrlRecord> WaitForCrlNumberAsync(
        CertificateAuthorityService caService,
        int caAuthorityId,
        long expectedCrlNumber,
        CrlRefreshBackgroundService bgService,
        TimeSpan timeout)
    {
        Stopwatch sw = Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            PublishedCrlRecord? latest = await caService.GetLatestCrlAsync(caAuthorityId: caAuthorityId);
            if (latest != null && latest.CrlNumber >= expectedCrlNumber)
            {
                return latest;
            }

            long currentScans = bgService.CompletedScanCount;
            TimeSpan remaining = timeout - sw.Elapsed;
            if (remaining <= TimeSpan.Zero)
            {
                break;
            }

            await bgService.WaitForCompletedScanCountAsync(currentScans + 1, remaining);
        }

        PublishedCrlRecord? finalCrl = await caService.GetLatestCrlAsync(caAuthorityId: caAuthorityId);
        Assert.NotNull(finalCrl);
        Assert.Equal(expectedCrlNumber, finalCrl.CrlNumber);
        return finalCrl;
    }

    private async Task<IssuanceOutcome> IssueLeafAsync(
        CertificateAuthorityService caService,
        string userId,
        string domain)
    {
        KeyPair kp = _crypto.KeyGen(256);
        string csr = _crypto.CSRGen(kp, domain, [domain], "US", "WA", "Redmond", "Contoso", "IT", "");
        return await caService.IssueCertificateFromCsrAsync(userId, csr);
    }

    private static bool CrlContainsSerial(byte[] crlDer, string serialHex, int? expectedReasonCode = null)
    {
        X509Crl crl = new X509CrlParser().ReadCrl(crlDer);
        BigInteger serial = new(1, Convert.FromHexString(serialHex));
        X509CrlEntry? entry = crl.GetRevokedCertificate(serial);
        if (entry == null)
        {
            return false;
        }

        if (expectedReasonCode.HasValue)
        {
            Asn1OctetString? ext = entry.GetExtensionValue(X509Extensions.ReasonCode);
            int actualReason = ext != null
                ? DerEnumerated.GetInstance(Asn1Object.FromByteArray(ext.GetOctets())).Value.IntValueExact
                : CrlReason.Unspecified;
            return actualReason == expectedReasonCode.Value;
        }

        return true;
    }

    private async Task VerifyCrlAndLeafWithOpenSslAsync(
        string rootPem,
        string? untrustedChainPem,
        string crlPem,
        string leafPem,
        bool expectRevoked)
    {
        string dir = Path.Combine(_tempRoot, $"ossl-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        string rootPath = Path.Combine(dir, "root.pem");
        string crlPath = Path.Combine(dir, "ca.crl.pem");
        string leafPath = Path.Combine(dir, "leaf.pem");
        string crlVerifyCaPath = Path.Combine(dir, "crl-issuer-chain.pem");

        await File.WriteAllTextAsync(rootPath, rootPem);
        await File.WriteAllTextAsync(crlPath, crlPem);
        await File.WriteAllTextAsync(leafPath, leafPem);
        await File.WriteAllTextAsync(
            crlVerifyCaPath,
            string.IsNullOrWhiteSpace(untrustedChainPem) ? rootPem : untrustedChainPem + "\n" + rootPem);

        var (crlExit, crlOut) = await RunProcessAsync("openssl", ["crl", "-in", crlPath, "-CAfile", crlVerifyCaPath, "-noout"]);
        Assert.True(crlExit == 0, $"OpenSSL crl verify failed ({crlExit}): {crlOut}");
        Assert.Contains("verify OK", crlOut, StringComparison.OrdinalIgnoreCase);

        List<string> verifyArgs = ["verify", "-crl_check", "-CAfile", rootPath, "-CRLfile", crlPath];
        if (!string.IsNullOrWhiteSpace(untrustedChainPem))
        {
            string untrustedPath = Path.Combine(dir, "untrusted.pem");
            await File.WriteAllTextAsync(untrustedPath, untrustedChainPem);
            verifyArgs.Add("-untrusted");
            verifyArgs.Add(untrustedPath);
        }
        verifyArgs.Add(leafPath);

        var (verExit, verOut) = await RunProcessAsync("openssl", verifyArgs);
        if (expectRevoked)
        {
            Assert.NotEqual(0, verExit);
            Assert.Contains("certificate revoked", verOut, StringComparison.OrdinalIgnoreCase);
        }
        else
        {
            Assert.True(verExit == 0, $"OpenSSL verify failed ({verExit}): {verOut}");
            Assert.Contains("OK", verOut);
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
        return (proc.ExitCode, (await stdoutTask) + "\n" + (await stderrTask));
    }

    private static async Task<(int ExitCode, string CombinedOutput)> RunProcessAsync(
        string fileName,
        IReadOnlyList<string> args)
    {
        ProcessStartInfo psi = new(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (string arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        using Process proc = Process.Start(psi)!;
        Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync();
        Task<string> stderrTask = proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        return (proc.ExitCode, (await stdoutTask) + "\n" + (await stderrTask));
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
        Func<DbContextOptions<CertRoboDbContext>, IDbContextFactory<CertRoboDbContext>>? wrapDbFactory = null)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection();
        services.AddDbContextFactory<CertRoboDbContext>(options =>
            options.UseSqlite($"Data Source={sqlitePath}"));
        if (wrapDbFactory != null)
        {
            ServiceDescriptor existingFactory = services.Single(d => d.ServiceType == typeof(IDbContextFactory<CertRoboDbContext>));
            services.Remove(existingFactory);
            services.AddSingleton<IDbContextFactory<CertRoboDbContext>>(_ =>
            {
                DbContextOptionsBuilder<CertRoboDbContext> builder = new();
                builder.UseSqlite($"Data Source={sqlitePath}");
                return wrapDbFactory(builder.Options);
            });
        }
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
            PassphraseEnvironmentVariable = null,
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
