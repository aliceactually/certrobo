using CertRobo.Data;
using CertRobo.Models;
using CertRobo.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertRobo.Tests;

public sealed class LocalSubordinateHierarchyRegressionTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly CryptoFactory _crypto = new();

    public LocalSubordinateHierarchyRegressionTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"certrobo-subordinate-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    [Fact]
    public async Task ParentSerialAllocation_AdvancesAndPersistsParentCounter_PreventsLedgerCollision_HandlesConcurrency_AndFailureRetry_WithoutTouchingUnrelatedIssuers()
    {
        const string secret = "SubordinateSerialSecret!2026";
        string dbPath = Path.Combine(_tempRoot, "parent-serials.db");
        string caDir = Path.Combine(_tempRoot, "parent-serials-ca");

        using ServiceProvider sp = BuildServiceProvider(dbPath, caDir, publicBaseUrl: "http://pki.contoso.com");
        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
        ApplicationUser admin = await BootstrapAdminAsync(sp);

        // 1. Create an unrelated CA first and issue one leaf under it so its LastAllocatedSerial is 1001
        CaAuthorityRecord unrelatedCa = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Unrelated Root CA",
            "unrelated-root.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa,
            256,
            365,
            secret);
        Assert.Equal(1000L, unrelatedCa.LastAllocatedSerial);

        IssuanceOutcome unrelatedLeaf = await IssueLeafAsync(caService, admin.Id, "unrelated.contoso.com");
        Assert.True(unrelatedLeaf.Succeeded, unrelatedLeaf.ErrorMessage);

        // 2. Create the target Parent Root CA (pathLen=2)
        CaAuthorityRecord parentRoot = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Parent Root CA",
            "parent-root.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Rsa,
            2048,
            3650,
            secret,
            pathLengthConstraint: 2);
        Assert.Equal(1000L, parentRoot.LastAllocatedSerial);

        // Capture a stale snapshot of parentRoot (LastAllocatedSerial == 1000) before issuing a leaf and seeding a higher ledger row
        CaAuthorityRecord staleParentSnapshot = new()
        {
            Id = parentRoot.Id,
            Name = parentRoot.Name,
            IssuerCertificatePem = parentRoot.IssuerCertificatePem,
            ChainCertificatesPem = parentRoot.ChainCertificatesPem,
            EncryptedPrivateKeyPath = parentRoot.EncryptedPrivateKeyPath,
            CrlDistributionPointUrl = parentRoot.CrlDistributionPointUrl,
            AuthorityIssuerCertUrl = parentRoot.AuthorityIssuerCertUrl,
            LastAllocatedSerial = 1000L,
            NotBeforeUtc = parentRoot.NotBeforeUtc,
            NotAfterUtc = parentRoot.NotAfterUtc
        };

        // Issue a leaf under parentRoot (advances parentRoot to 1001) and insert an existing ledger row at SerialNumberValue = 1005
        IssuanceOutcome parentLeaf = await IssueLeafAsync(caService, admin.Id, "root-issued.contoso.com");
        Assert.True(parentLeaf.Succeeded, parentLeaf.ErrorMessage);
        Assert.Equal(1001L, parentLeaf.Record!.SerialNumberValue);

        using (IServiceScope scope = sp.CreateScope())
        {
            CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            db.IssuedCertificates.Add(new IssuedCertificateRecord
            {
                CaAuthorityId = parentRoot.Id,
                SerialNumberValue = 1005L,
                SerialNumberHex = Convert.ToHexString(CertificateAuthorityService.AllocatePositiveSerialBytes(1005L)),
                ProfileId = "legacy-imported",
                CommonName = "legacy.contoso.com",
                SubjectAlternativeNamesCsv = "legacy.contoso.com",
                SubjectDistinguishedName = "CN=legacy.contoso.com",
                IssuerDistinguishedName = "CN=parent-root.contoso.com",
                KeyAlgorithm = "RSA",
                KeySizeBits = 2048,
                ThumbprintSha256 = "00",
                RequestedByUserId = admin.Id,
                RequestedByUserName = admin.UserName!,
                Status = IssuanceStatus.Issued,
                NotBeforeUtc = DateTimeOffset.UtcNow.AddDays(-1),
                NotAfterUtc = DateTimeOffset.UtcNow.AddDays(30),
                CreatedAtUtc = DateTimeOffset.UtcNow
            });
            await db.SaveChangesAsync();
        }

        // 3. Create Subordinate #1 passing staleParentSnapshot (which still had LastAllocatedSerial=1000 in memory).
        //    It must consult the authoritative database state, allocate 1006, and persist 1006 on parentRoot.
        CaAuthorityRecord sub1 = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Subordinate CA 1",
            "sub1.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa,
            256,
            1825,
            secret,
            parentAuthority: staleParentSnapshot,
            parentPassphrase: secret,
            pathLengthConstraint: 0);

        Assert.Equal(1006L, staleParentSnapshot.LastAllocatedSerial);
        CaAuthorityRecord persistedParentAfterSub1 = (await caService.GetAuthorityByIdAsync(parentRoot.Id))!;
        Assert.Equal(1006L, persistedParentAfterSub1.LastAllocatedSerial);
        Assert.Equal(1006L, ExtractSerialCounter(sub1.IssuerCertificatePem));

        // 4. Pre-signing failure (wrong passphrase and forbidden pathLen=0 subordinate under sub1) must not alter parentRoot or unrelatedCa serials
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            caService.CreateSelfSignedOrIntermediateCaAsync(
                "Forbidden Sub Under Sub1",
                "forbidden-under-sub1.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                365,
                secret,
                parentAuthority: sub1,
                parentPassphrase: secret));
        Assert.Equal(1000L, (await caService.GetAuthorityByIdAsync(sub1.Id))!.LastAllocatedSerial);
        Assert.Equal(1006L, (await caService.GetAuthorityByIdAsync(parentRoot.Id))!.LastAllocatedSerial);
        Assert.Equal(1001L, (await caService.GetAuthorityByIdAsync(unrelatedCa.Id))!.LastAllocatedSerial);

        // 5. Post-signing persistence failure followed by retry:
        //    Inject a fault in PersistAndActivateCaCoreAsync after signing Subordinate #2 (serial 1007).
        //    Then retry Subordinate #2 creation and verify it gets serial 1008 (never reusing 1007), while unrelatedCa stays at 1001.
        caService.CaPersistenceFaultInjector = _ => throw new IOException("Simulated persistence fault after subordinate signing.");
        await Assert.ThrowsAsync<IOException>(() =>
            caService.CreateSelfSignedOrIntermediateCaAsync(
                "Subordinate CA 2 (Failed Attempt)",
                "sub2-failed.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                1825,
                secret,
                parentAuthority: parentRoot,
                parentPassphrase: secret));
        caService.CaPersistenceFaultInjector = null;

        Assert.Equal(1007L, (await caService.GetAuthorityByIdAsync(parentRoot.Id))!.LastAllocatedSerial);
        Assert.Equal(1001L, (await caService.GetAuthorityByIdAsync(unrelatedCa.Id))!.LastAllocatedSerial);

        CaAuthorityRecord sub2Retry = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Subordinate CA 2 (Retry)",
            "sub2.contoso.com",
            "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa,
            256,
            1825,
            secret,
            parentAuthority: parentRoot,
            parentPassphrase: secret,
            pathLengthConstraint: 0);
        Assert.Equal(1008L, (await caService.GetAuthorityByIdAsync(parentRoot.Id))!.LastAllocatedSerial);
        Assert.Equal(1008L, ExtractSerialCounter(sub2Retry.IssuerCertificatePem));

        // 6. Concurrent subordinate CA creations under parentRoot: all serials must be distinct and strictly monotonic
        Task<CaAuthorityRecord>[] concurrentSubTasks = Enumerable.Range(1, 4).Select(i =>
            caService.CreateSelfSignedOrIntermediateCaAsync(
                $"Concurrent Sub {i}",
                $"concurrent-sub-{i}.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                365,
                secret,
                parentAuthority: parentRoot,
                parentPassphrase: secret,
                pathLengthConstraint: 0)).ToArray();

        CaAuthorityRecord[] concurrentSubs = await Task.WhenAll(concurrentSubTasks);
        HashSet<string> allSubSerialHexes = concurrentSubs
            .Append(sub1)
            .Append(sub2Retry)
            .Select(s => ExtractSerialHex(s.IssuerCertificatePem))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Equal(6, allSubSerialHexes.Count);
        Assert.DoesNotContain(parentLeaf.Record.SerialNumberHex, allSubSerialHexes);
        Assert.Equal(1012L, (await caService.GetAuthorityByIdAsync(parentRoot.Id))!.LastAllocatedSerial);
        Assert.Equal(1001L, (await caService.GetAuthorityByIdAsync(unrelatedCa.Id))!.LastAllocatedSerial);
    }

    [Fact]
    public async Task ParentCrlMaintenance_RetainsAndRefreshesLocalParentCrl_AcrossMultiTierHierarchy_Restarts_Expiration_AndOpenSslCrlCheckAll()
    {
        const string secret = "ParentCrlMaintenanceSecret!2026";
        string dbPath = Path.Combine(_tempRoot, "parent-crl-maint.db");
        string caDir = Path.Combine(_tempRoot, "parent-crl-maint-ca");
        string passFile = Path.Combine(_tempRoot, "parent-crl-maint.pass");
        await File.WriteAllTextAsync(passFile, secret + "\n");

        int rootId;
        int tier1Id;
        int tier2Id;
        string rootPem;
        string tier1Pem;
        string tier2Pem;
        string tier2SerialHex;
        string leafPem;

        using (ServiceProvider sp = BuildServiceProvider(dbPath, caDir, passFilePath: passFile, publicBaseUrl: "http://pki.contoso.com"))
        {
            CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
            ApplicationUser admin = await BootstrapAdminAsync(sp);

            // 1. Provision 3-tier local hierarchy: Root (#1, pathLen=2) -> Tier 1 (#2, pathLen=1) -> Tier 2 (#3, pathLen=0)
            CaAuthorityRecord rootCa = await caService.CreateSelfSignedOrIntermediateCaAsync(
                "Local Root CA",
                "root.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Rsa,
                2048,
                3650,
                secret,
                pathLengthConstraint: 2);
            rootId = rootCa.Id;
            rootPem = rootCa.IssuerCertificatePem;

            CaAuthorityRecord tier1Ca = await caService.CreateSelfSignedOrIntermediateCaAsync(
                "Local Tier 1 Intermediate CA",
                "tier1.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                1825,
                secret,
                parentAuthority: rootCa,
                parentPassphrase: secret,
                pathLengthConstraint: 1);
            tier1Id = tier1Ca.Id;
            tier1Pem = tier1Ca.IssuerCertificatePem;

            CaAuthorityRecord tier2Ca = await caService.CreateSelfSignedOrIntermediateCaAsync(
                "Local Tier 2 Issuing CA",
                "tier2.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                900,
                secret,
                parentAuthority: tier1Ca,
                parentPassphrase: secret,
                pathLengthConstraint: 0);
            tier2Id = tier2Ca.Id;
            tier2Pem = tier2Ca.IssuerCertificatePem;
            tier2SerialHex = ExtractSerialHex(tier2Pem);

            // Even before any leaf certificates are issued, Root (#1) and Tier 1 (#2) must require CRL maintenance
            // because each has an unexpired locally issued subordinate CA.
            CaKeyCustodyReport report = await caService.InspectKeyCustodyAsync();
            Assert.True(report.IsCustodyHealthy);
            Assert.True(report.Authorities.Single(a => a.CaAuthorityId == rootId).RequiresCrlMaintenance);
            Assert.True(report.Authorities.Single(a => a.CaAuthorityId == tier1Id).RequiresCrlMaintenance);
            Assert.True(report.Authorities.Single(a => a.CaAuthorityId == tier2Id).RequiresCrlMaintenance);

            IssuanceOutcome leafOutcome = await IssueLeafAsync(caService, admin.Id, "fullchain-app.contoso.com");
            Assert.True(leafOutcome.Succeeded, leafOutcome.ErrorMessage);
            leafPem = leafOutcome.CertificatePem!;
        }

        // 2. Simulate service restart: verify --verify-ca-custody and RefreshDueCrlsAsync maintain all 3 tiers
        using (ServiceProvider postRestartSp = BuildServiceProvider(dbPath, caDir, passFilePath: passFile, publicBaseUrl: "http://pki.contoso.com"))
        {
            CertificateAuthorityService caService = postRestartSp.GetRequiredService<CertificateAuthorityService>();

            CaKeyCustodyReport restartReport = await caService.InspectKeyCustodyAsync();
            Assert.All(restartReport.Authorities, a => Assert.True(a.RequiresCrlMaintenance));

            // Advance window so all 3 CRLs are due, and verify all 3 refresh to CRL #2
            IReadOnlyList<CrlRefreshOutcome> refreshed = await caService.RefreshDueCrlsAsync(TimeSpan.FromDays(10));
            Assert.Equal(3, refreshed.Count);
            Assert.All(refreshed, o =>
            {
                Assert.True(o.Succeeded, o.ErrorMessage);
                Assert.Equal(2L, o.PublishedCrl!.CrlNumber);
            });

            PublishedCrlRecord rootCrl = (await caService.GetLatestCrlAsync(caAuthorityId: rootId))!;
            PublishedCrlRecord tier1Crl = (await caService.GetLatestCrlAsync(caAuthorityId: tier1Id))!;
            PublishedCrlRecord tier2Crl = (await caService.GetLatestCrlAsync(caAuthorityId: tier2Id))!;

            // 3. Verify complete 3-tier chain with OpenSSL `verify -crl_check_all` (including controlled `-attime` checks)
            await VerifyFullChainWithOpenSslCrlCheckAllAsync(
                rootPem,
                [tier2Pem, tier1Pem],
                [rootCrl.CrlPem, tier1Crl.CrlPem, tier2Crl.CrlPem],
                leafPem,
                expectSuccess: true,
                atTimeUtc: DateTimeOffset.UtcNow.AddHours(1));

            // If evaluated at a timestamp after the parent/tier CRLs' nextUpdate (e.g., +10 days when CRL validity is 7 days),
            // OpenSSL `-crl_check_all -attime` must reject the chain with "CRL has expired"
            await VerifyFullChainWithOpenSslCrlCheckAllAsync(
                rootPem,
                [tier2Pem, tier1Pem],
                [rootCrl.CrlPem, tier1Crl.CrlPem, tier2Crl.CrlPem],
                leafPem,
                expectSuccess: false,
                expectedFailureSubstring: "CRL has expired",
                atTimeUtc: DateTimeOffset.UtcNow.AddDays(10));

            // 4. Revoke Tier 2 subordinate CA on Tier 1 parent CA and verify OpenSSL `-crl_check_all` rejects the chain
            RevocationOutcome subRevoke = await caService.SeedRevokedSerialAsync(
                tier2SerialHex,
                "tier2.contoso.com",
                CrlReason.CACompromise,
                "admin",
                targetCaAuthorityId: tier1Id);
            Assert.True(subRevoke.Succeeded, subRevoke.ErrorMessage);
            Assert.Equal(3L, subRevoke.PublishedCrl!.CrlNumber);

            await VerifyFullChainWithOpenSslCrlCheckAllAsync(
                rootPem,
                [tier2Pem, tier1Pem],
                [rootCrl.CrlPem, subRevoke.PublishedCrl.CrlPem, tier2Crl.CrlPem],
                leafPem,
                expectSuccess: false);

            // 5. Also verify that an externally signed Issuing CA does NOT mistake its external parent/root for a local authority,
            //    and that once local subordinates expire (with no unexpired leaf certs), parent RequiresCrlMaintenance becomes false.
            using RSA extRootKey = RSA.Create(2048);
            CertificateRequest extRootReq = new("CN=External Root CA, O=External, C=US", extRootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            extRootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
            extRootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            X509SubjectKeyIdentifierExtension extRootSki = new(extRootReq.PublicKey, false);
            extRootReq.CertificateExtensions.Add(extRootSki);
            extRootReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(extRootSki));
            using X509Certificate2 extRootCert = extRootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(3650));

            PendingCaEnrolmentRecord pendingExt = await caService.CreatePendingCaEnrolmentAsync(
                "Externally Signed CA",
                "ext-issuing.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                secret);
            CertificateRequest loadedCsr = CertificateRequest.LoadSigningRequestPem(
                pendingExt.CsrPem,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
            CertificateRequest signExt = new(loadedCsr.SubjectName, loadedCsr.PublicKey, HashAlgorithmName.SHA256);
            signExt.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            signExt.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            signExt.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(signExt.PublicKey, false));
            signExt.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(extRootSki));
            using X509Certificate2 signedExtCert = signExt.Create(
                extRootCert.SubjectName,
                X509SignatureGenerator.CreateForRSA(extRootKey, RSASignaturePadding.Pkcs1),
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddDays(365),
                [0x01, 0x09, 0x09]);

            CaBundleValidationResult staged = await caService.ValidateAndStageSignedCaBundleAsync(
                pendingExt.Id,
                null,
                signedExtCert.ExportCertificatePem(),
                null,
                extRootCert.ExportCertificatePem());
            Assert.True(staged.IsValid, staged.ErrorMessage);
            CaAuthorityRecord activeExtCa = await caService.ActivatePendingCaEnrolmentAsync(pendingExt.Id);

            // Mark Tier 1, Tier 2, and their issued certificates as expired in SQLite -> Root (#1) now has no unexpired subordinates or leaf certs
            using (IServiceScope scope = postRestartSp.CreateScope())
            {
                CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
                DateTimeOffset expiredPast = DateTimeOffset.UtcNow.AddDays(-10);
                foreach (CaAuthorityRecord sub in await db.CaAuthorities.Where(c => c.Id == tier1Id || c.Id == tier2Id).ToListAsync())
                {
                    sub.NotAfterUtc = expiredPast;
                }
                foreach (IssuedCertificateRecord cert in await db.IssuedCertificates.ToListAsync())
                {
                    cert.NotAfterUtc = expiredPast;
                }
                await db.SaveChangesAsync();
            }

            CaKeyCustodyReport afterSubExpiry = await caService.InspectKeyCustodyAsync();
            Assert.Equal(4, afterSubExpiry.Authorities.Count); // Only the 4 local CAs, never the external root
            Assert.False(afterSubExpiry.Authorities.Single(a => a.CaAuthorityId == rootId).RequiresCrlMaintenance);
            Assert.False(afterSubExpiry.Authorities.Single(a => a.CaAuthorityId == tier1Id).RequiresCrlMaintenance);
            Assert.False(afterSubExpiry.Authorities.Single(a => a.CaAuthorityId == tier2Id).RequiresCrlMaintenance);
            Assert.True(afterSubExpiry.Authorities.Single(a => a.CaAuthorityId == activeExtCa.Id).RequiresCrlMaintenance);
        }
    }

    [Fact]
    public async Task SubordinateCaExtensions_EmbedStableParentAiaAndCdpUrls_DistinguishedFromChildConfig_AndReachableViaHttpEndpoints()
    {
        const string secret = "SubordinateExtensionsSecret!2026";
        string tempDir = Path.Combine(_tempRoot, "sub-ext-webapp");
        Directory.CreateDirectory(tempDir);

        await using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("CertRobo:DataDirectory", tempDir);
            builder.UseSetting("CertRobo:SqliteFilePath", Path.Combine(tempDir, "certrobo.db"));
            builder.UseSetting("CertRobo:CaStorageDirectory", Path.Combine(tempDir, "ca"));
            builder.UseSetting("CertRobo:CaPassphrase", secret);
            builder.UseSetting("CertRobo:PublicBaseUrl", "http://pki.contoso.com");
        });

        CaAuthorityRecord rootCa;
        CaAuthorityRecord subCa;
        IssuanceOutcome childLeaf;

        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            var (_, _, admin) = await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*.contoso.com");
            CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();

            rootCa = await caService.CreateSelfSignedOrIntermediateCaAsync(
                "Contoso Root CA",
                "root-ca.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Rsa,
                2048,
                3650,
                secret,
                crlDistributionPointUrl: "http://pki.contoso.com/ca.crl",
                authorityIssuerCertUrl: "http://pki.contoso.com/ca.crt",
                pathLengthConstraint: 1);

            subCa = await caService.CreateSelfSignedOrIntermediateCaAsync(
                "Contoso Issuing Intermediate CA",
                "issuing-ca.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa,
                384,
                1825,
                secret,
                crlDistributionPointUrl: "http://pki.contoso.com/ca.crl",
                authorityIssuerCertUrl: "http://pki.contoso.com/ca.crt",
                parentAuthority: rootCa,
                parentPassphrase: secret,
                pathLengthConstraint: 0);

            KeyPair kp = _crypto.KeyGen(256);
            string csr = _crypto.CSRGen(kp, "portal.contoso.com", ["portal.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
            childLeaf = await caService.IssueCertificateFromCsrAsync(admin!.Id, csr);
            Assert.True(childLeaf.Succeeded, childLeaf.ErrorMessage);
        }

        // 1. Verify parent vs child publication URLs on records and inside X.509 DER extensions
        Assert.Equal($"http://pki.contoso.com/authorities/{rootCa.Id}/ca.crl", rootCa.CrlDistributionPointUrl);
        Assert.Equal($"http://pki.contoso.com/authorities/{rootCa.Id}/issuer.crt", rootCa.AuthorityIssuerCertUrl);
        Assert.Equal($"http://pki.contoso.com/authorities/{subCa.Id}/ca.crl", subCa.CrlDistributionPointUrl);
        Assert.Equal($"http://pki.contoso.com/authorities/{subCa.Id}/issuer.crt", subCa.AuthorityIssuerCertUrl);

        // Subordinate CA certificate must embed PARENT's stable URLs (/authorities/1/ca.crl and /authorities/1/issuer.crt)
        var (subCdpUrls, subAiaUrls) = ExtractCdpAndAiaUrls(subCa.IssuerCertificatePem);
        Assert.Equal([$"http://pki.contoso.com/authorities/{rootCa.Id}/ca.crl"], subCdpUrls);
        Assert.Equal([$"http://pki.contoso.com/authorities/{rootCa.Id}/issuer.crt"], subAiaUrls);

        // Leaf certificate issued by Subordinate CA must embed CHILD's stable URLs (/authorities/2/ca.crl and /authorities/2/issuer.crt)
        var (leafCdpUrls, leafAiaUrls) = ExtractCdpAndAiaUrls(childLeaf.CertificatePem!);
        Assert.Equal([$"http://pki.contoso.com/authorities/{subCa.Id}/ca.crl"], leafCdpUrls);
        Assert.Equal([$"http://pki.contoso.com/authorities/{subCa.Id}/issuer.crt"], leafAiaUrls);

        // Self-signed Root CA certificate must not contain CDP or AIA extensions
        var (rootCdpUrls, rootAiaUrls) = ExtractCdpAndAiaUrls(rootCa.IssuerCertificatePem);
        Assert.Empty(rootCdpUrls);
        Assert.Empty(rootAiaUrls);

        // 2. Verify HTTP reachability and DER validity of parent AIA/CDP URLs embedded in the subordinate certificate,
        //    and verify /rootca.crt remains unchanged (PEM trust anchor only).
        using HttpClient client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        string parentAiaPath = new Uri(subAiaUrls[0]).PathAndQuery;
        string parentCdpPath = new Uri(subCdpUrls[0]).PathAndQuery;

        byte[] parentIssuerDer = await client.GetByteArrayAsync(parentAiaPath);
        using X509Certificate2 fetchedParentCert = X509CertificateLoader.LoadCertificate(parentIssuerDer);
        Assert.Equal(rootCa.ThumbprintOrSerialHex, fetchedParentCert.GetCertHashString(HashAlgorithmName.SHA256));

        byte[] parentCrlDer = await client.GetByteArrayAsync(parentCdpPath);
        X509Crl parsedParentCrl = new X509CrlParser().ReadCrl(parentCrlDer);
        Org.BouncyCastle.X509.X509Certificate bcRoot = new X509CertificateParser().ReadCertificate(parentIssuerDer);
        parsedParentCrl.Verify(bcRoot.GetPublicKey());

        HttpResponseMessage rootCaEndpoint = await client.GetAsync("/rootca.crt");
        Assert.Equal(HttpStatusCode.OK, rootCaEndpoint.StatusCode);
        string rootCaEndpointPem = await rootCaEndpoint.Content.ReadAsStringAsync();
        Assert.Equal(rootCa.IssuerCertificatePem.Trim(), rootCaEndpointPem.Trim());
        Assert.DoesNotContain(subCa.IssuerCertificatePem.Trim(), rootCaEndpointPem);

        // 3. Also verify that when no HTTP PublicBaseUrl or HTTP URL is configured (relative paths only),
        //    subordinate creation succeeds cleanly and omits non-URI relative paths from X.509 AIA/CDP extensions.
        using ServiceProvider relativeSp = BuildServiceProvider(
            Path.Combine(_tempRoot, "relative-only.db"),
            Path.Combine(_tempRoot, "relative-only-ca"),
            publicBaseUrl: "");
        CertificateAuthorityService relativeCaService = relativeSp.GetRequiredService<CertificateAuthorityService>();
        CaAuthorityRecord relRoot = await relativeCaService.CreateSelfSignedOrIntermediateCaAsync(
            "Relative Root", "rel-root.contoso.com", "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa, 256, 365, secret);
        CaAuthorityRecord relSub = await relativeCaService.CreateSelfSignedOrIntermediateCaAsync(
            "Relative Sub", "rel-sub.contoso.com", "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa, 256, 180, secret,
            crlDistributionPointUrl: "/ca.crl",
            authorityIssuerCertUrl: "/ca.crt",
            parentAuthority: relRoot,
            parentPassphrase: secret);
        var (relSubCdp, relSubAia) = ExtractCdpAndAiaUrls(relSub.IssuerCertificatePem);
        Assert.Empty(relSubCdp);
        Assert.Empty(relSubAia);

        // 4. Verify custom external parent CDP/AIA URLs are preserved on the subordinate certificate
        //    while the child authority's own publication configuration uses the child's stable URLs.
        CaAuthorityRecord customExtRoot = await relativeCaService.CreateSelfSignedOrIntermediateCaAsync(
            "Custom External URL Root", "custom-root.contoso.com", "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa, 256, 365, secret,
            crlDistributionPointUrl: "http://external-cdp.contoso.com/custom-root.crl",
            authorityIssuerCertUrl: "http://external-aia.contoso.com/custom-root.cer");
        CaAuthorityRecord customChildSub = await relativeCaService.CreateSelfSignedOrIntermediateCaAsync(
            "Custom Child Sub", "custom-sub.contoso.com", "US", "WA", "Redmond", "Contoso", "PKI",
            CertificateKeyFamily.Ecdsa, 256, 180, secret,
            crlDistributionPointUrl: "http://pki.contoso.com/ca.crl",
            authorityIssuerCertUrl: "http://pki.contoso.com/ca.crt",
            parentAuthority: customExtRoot,
            parentPassphrase: secret);
        var (customSubCdp, customSubAia) = ExtractCdpAndAiaUrls(customChildSub.IssuerCertificatePem);
        Assert.Equal(["http://external-cdp.contoso.com/custom-root.crl"], customSubCdp);
        Assert.Equal(["http://external-aia.contoso.com/custom-root.cer"], customSubAia);
        Assert.Equal($"http://pki.contoso.com/authorities/{customChildSub.Id}/ca.crl", customChildSub.CrlDistributionPointUrl);
        Assert.Equal($"http://pki.contoso.com/authorities/{customChildSub.Id}/issuer.crt", customChildSub.AuthorityIssuerCertUrl);
    }

    private static (IReadOnlyList<string> CdpUrls, IReadOnlyList<string> AiaUrls) ExtractCdpAndAiaUrls(string certPem)
    {
        using X509Certificate2 dotNetCert = X509Certificate2.CreateFromPem(certPem);
        Org.BouncyCastle.X509.X509Certificate bcCert = new X509CertificateParser().ReadCertificate(dotNetCert.RawData);

        List<string> cdpUrls = [];
        Asn1OctetString? cdpOctets = bcCert.GetExtensionValue(X509Extensions.CrlDistributionPoints);
        if (cdpOctets != null)
        {
            CrlDistPoint distPoint = CrlDistPoint.GetInstance(Asn1Object.FromByteArray(cdpOctets.GetOctets()));
            foreach (DistributionPoint dp in distPoint.GetDistributionPoints())
            {
                if (dp.DistributionPointName?.Type == DistributionPointName.FullName)
                {
                    GeneralNames gns = GeneralNames.GetInstance(dp.DistributionPointName.Name);
                    foreach (GeneralName gn in gns.GetNames())
                    {
                        if (gn.TagNo == GeneralName.UniformResourceIdentifier)
                        {
                            cdpUrls.Add(DerIA5String.GetInstance(gn.Name).GetString());
                        }
                    }
                }
            }
        }

        List<string> aiaUrls = [];
        Asn1OctetString? aiaOctets = bcCert.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
        if (aiaOctets != null)
        {
            AuthorityInformationAccess aia = AuthorityInformationAccess.GetInstance(Asn1Object.FromByteArray(aiaOctets.GetOctets()));
            foreach (AccessDescription ad in aia.GetAccessDescriptions())
            {
                if (ad.AccessMethod.Equals(AccessDescription.IdADCAIssuers)
                    && ad.AccessLocation.TagNo == GeneralName.UniformResourceIdentifier)
                {
                    aiaUrls.Add(DerIA5String.GetInstance(ad.AccessLocation.Name).GetString());
                }
            }
        }

        return (cdpUrls, aiaUrls);
    }

    private static string ExtractSerialHex(string certPem)
    {
        using X509Certificate2 cert = X509Certificate2.CreateFromPem(certPem);
        return Convert.ToHexString(cert.GetSerialNumber().Reverse().ToArray());
    }

    private static long ExtractSerialCounter(string certPem)
    {
        using X509Certificate2 cert = X509Certificate2.CreateFromPem(certPem);
        byte[] serialBigEndian = cert.GetSerialNumber().Reverse().ToArray();
        Assert.Equal(12, serialBigEndian.Length);
        byte[] counterBytes = new byte[8];
        Buffer.BlockCopy(serialBigEndian, 0, counterBytes, 0, 8);
        if (counterBytes[0] == 0x01 && counterBytes[1] == 0x00)
        {
            counterBytes[0] = 0x00;
        }
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(counterBytes);
        }
        return BitConverter.ToInt64(counterBytes, 0);
    }

    private async Task<IssuanceOutcome> IssueLeafAsync(
        CertificateAuthorityService caService,
        string userId,
        string commonName)
    {
        KeyPair kp = _crypto.KeyGen(256);
        string csr = _crypto.CSRGen(
            kp, commonName, [commonName], "US", "WA", "Redmond", "Contoso", "IT", "");
        return await caService.IssueCertificateFromCsrAsync(userId, csr);
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
        string? passFilePath = null,
        string publicBaseUrl = "http://pki.contoso.com")
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
            PassphraseEnvironmentVariable = null,
            PassphraseFilePath = passFilePath,
            PublicBaseUrl = publicBaseUrl
        });

        services.AddScoped<AccountManagementService>();
        services.AddScoped<IssuancePolicyService>();
        services.AddSingleton<CertificateAuthorityService>();
        services.AddSingleton<BackupRestoreService>();

        ServiceProvider sp = services.BuildServiceProvider();
        using IServiceScope scope = sp.CreateScope();
        CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
        db.EnsureSchemaUpgradedAsync().GetAwaiter().GetResult();
        return sp;
    }

    private async Task VerifyFullChainWithOpenSslCrlCheckAllAsync(
        string rootPem,
        IReadOnlyList<string> untrustedIntermediatesPem,
        IReadOnlyList<string> crlsPem,
        string leafPem,
        bool expectSuccess,
        string expectedFailureSubstring = "certificate revoked",
        DateTimeOffset? atTimeUtc = null)
    {
        string dir = Path.Combine(_tempRoot, $"ossl-all-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        string rootFile = Path.Combine(dir, "root.pem");
        string untrustedFile = Path.Combine(dir, "untrusted.pem");
        string crlFile = Path.Combine(dir, "crls.pem");
        string leafFile = Path.Combine(dir, "leaf.pem");

        await File.WriteAllTextAsync(rootFile, rootPem);
        await File.WriteAllTextAsync(untrustedFile, string.Join("\n", untrustedIntermediatesPem));
        await File.WriteAllTextAsync(crlFile, string.Join("\n", crlsPem));
        await File.WriteAllTextAsync(leafFile, leafPem);

        ProcessStartInfo psi = new("openssl")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        psi.ArgumentList.Add("verify");
        psi.ArgumentList.Add("-crl_check_all");
        if (atTimeUtc.HasValue)
        {
            psi.ArgumentList.Add("-attime");
            psi.ArgumentList.Add(atTimeUtc.Value.ToUnixTimeSeconds().ToString());
        }
        psi.ArgumentList.Add("-CAfile");
        psi.ArgumentList.Add(rootFile);
        psi.ArgumentList.Add("-untrusted");
        psi.ArgumentList.Add(untrustedFile);
        psi.ArgumentList.Add("-CRLfile");
        psi.ArgumentList.Add(crlFile);
        psi.ArgumentList.Add(leafFile);

        using Process proc = Process.Start(psi)!;
        string stdout = await proc.StandardOutput.ReadToEndAsync();
        string stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        string combined = stdout + "\n" + stderr;

        if (expectSuccess)
        {
            Assert.True(proc.ExitCode == 0, $"Expected OpenSSL -crl_check_all to succeed, but failed ({proc.ExitCode}): {combined}");
            Assert.Contains("OK", combined);
        }
        else
        {
            Assert.NotEqual(0, proc.ExitCode);
            Assert.Contains(expectedFailureSubstring, combined, StringComparison.OrdinalIgnoreCase);
        }
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
