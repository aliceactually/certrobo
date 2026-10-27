using CertRobo.Data;
using CertRobo.Models;
using CertRobo.Services;
using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertRobo.Tests;

public class StandaloneCaAndIdentityTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly string _sqliteFilePath;
    private readonly string _caStorageDir;
    private readonly string _dpKeysDir;
    private ServiceProvider _serviceProvider;
    private readonly CryptoFactory _crypto = new();

    public StandaloneCaAndIdentityTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"certrobo-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
        _sqliteFilePath = Path.Combine(_tempRoot, "certrobo.db");
        _caStorageDir = Path.Combine(_tempRoot, "ca");
        _dpKeysDir = Path.Combine(_tempRoot, "dp");
        _serviceProvider = BuildServiceProvider(_sqliteFilePath, _caStorageDir);
    }

    private static ServiceProvider BuildServiceProvider(string sqlitePath, string caStorageDir)
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
        db.Database.EnsureCreated();
        return sp;
    }

    [Fact]
    public async Task SqliteRuntime_MeetsSecurityPatchFloor()
    {
        // CVE-2025-6965 was fixed in 3.50.2. Check the loaded engine, not package metadata.
        await using SqliteConnection connection = new("Data Source=:memory:");
        await connection.OpenAsync();
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT sqlite_version()";
        string versionText = (string)(await command.ExecuteScalarAsync())!;

        Assert.True(Version.TryParse(versionText, out Version? version), $"Unrecognised SQLite version: {versionText}");
        Assert.True(version >= new Version(3, 50, 2), $"SQLite {versionText} is below the CVE-2025-6965 patch floor (3.50.2).");
    }

    [Fact]
    public async Task FirstAdminBootstrap_AllowsExactlyOneInitialAdmin_UnderConcurrency()
    {
        Task<(bool Succeeded, string? ErrorMessage, ApplicationUser? User)>[] tasks =
            Enumerable.Range(1, 5).Select(async i =>
            {
                using IServiceScope scope = _serviceProvider.CreateScope();
                AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
                return await acct.BootstrapFirstAdminAsync($"admin{i}", "StrongPass1234", $"admin{i}@contoso.com", "*.contoso.com");
            }).ToArray();

        var results = await Task.WhenAll(tasks);
        Assert.Equal(1, results.Count(r => r.Succeeded));
        Assert.Equal(4, results.Count(r => !r.Succeeded));

        using IServiceScope verifyScope = _serviceProvider.CreateScope();
        AccountManagementService verifyAcct = verifyScope.ServiceProvider.GetRequiredService<AccountManagementService>();
        Assert.False(await verifyAcct.IsBootstrapRequiredAsync());
    }

    [Fact]
    public async Task AccountDisable_And_PasswordReset_RotateSecurityStamp_AndBlockIssuance()
    {
        using IServiceScope scope = _serviceProvider.CreateScope();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        IssuancePolicyService policy = scope.ServiceProvider.GetRequiredService<IssuancePolicyService>();
        UserManager<ApplicationUser> userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var (ok, _, user) = await acct.CreateUserAsync(
            "alice",
            "InitialPass1234",
            "alice@contoso.com",
            [AppRoles.Issuer],
            ["*.contoso.com"]);
        Assert.True(ok);
        Assert.NotNull(user);

        string initialStamp = user.SecurityStamp!;
        KeyPair kp = _crypto.KeyGen(256);
        string csr = _crypto.CSRGen(kp, "web.contoso.com", ["web.contoso.com"], "US", "Washington", "Redmond", "Contoso", "IT", "it@contoso.com");

        // Allowed while active and matching security stamp
        PolicyEvaluationResult allowedEval = await policy.EvaluateCsrRequestAsync(user.Id, csr, expectedSecurityStamp: initialStamp);
        Assert.True(allowedEval.IsAllowed);

        // Disable account -> rotates security stamp & blocks issuance
        await acct.SetUserDisabledAsync(user.Id, isDisabled: true);
        PolicyEvaluationResult disabledEval = await policy.EvaluateCsrRequestAsync(user.Id, csr);
        Assert.False(disabledEval.IsAllowed);
        Assert.Contains("disabled", disabledEval.DenialReason, StringComparison.OrdinalIgnoreCase);

        // Reset password -> re-enables account & rotates security stamp so old session stamp is rejected
        var (resetOk, _) = await acct.ResetPasswordAsync("alice", "NewResetPass1234");
        Assert.True(resetOk);

        PolicyEvaluationResult staleStampEval = await policy.EvaluateCsrRequestAsync(user.Id, csr, expectedSecurityStamp: initialStamp);
        Assert.False(staleStampEval.IsAllowed);
        Assert.Contains("invalidated", staleStampEval.DenialReason, StringComparison.OrdinalIgnoreCase);

        ApplicationUser reloaded = (await userMgr.FindByNameAsync("alice"))!;
        Assert.True(await userMgr.CheckPasswordAsync(reloaded, "NewResetPass1234"));
        PolicyEvaluationResult freshStampEval = await policy.EvaluateCsrRequestAsync(user.Id, csr, expectedSecurityStamp: reloaded.SecurityStamp);
        Assert.True(freshStampEval.IsAllowed);
    }

    [Fact]
    public async Task PolicyBoundary_RejectsTamperedCsr_UnsupportedSan_CaBasicConstraints_AndForbiddenDomains()
    {
        using IServiceScope scope = _serviceProvider.CreateScope();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        IssuancePolicyService policy = scope.ServiceProvider.GetRequiredService<IssuancePolicyService>();

        var (_, _, user) = await acct.CreateUserAsync(
            "devops",
            "DevOpsPass1234",
            null,
            [AppRoles.Issuer],
            ["*.dev.contoso.com"]);

        KeyPair kp = _crypto.KeyGen(256);

        // 1. Forbidden domain (prod.contoso.com when only *.dev.contoso.com is allowed)
        string forbiddenCsr = _crypto.CSRGen(
            kp, "prod.contoso.com", ["prod.contoso.com"], "US", "Washington", "Redmond", "Contoso", "IT", "");
        PolicyEvaluationResult forbiddenEval = await policy.EvaluateCsrRequestAsync(user!.Id, forbiddenCsr);
        Assert.False(forbiddenEval.IsAllowed);
        Assert.Contains("prod.contoso.com", forbiddenEval.DenialReason);

        // 2. Mixed SANs (one allowed, one forbidden)
        string mixedCsr = _crypto.CSRGen(
            kp, "api.dev.contoso.com", ["api.dev.contoso.com", "secret.corp.contoso.com"], "US", "Washington", "Redmond", "Contoso", "IT", "");
        PolicyEvaluationResult mixedEval = await policy.EvaluateCsrRequestAsync(user.Id, mixedCsr);
        Assert.False(mixedEval.IsAllowed);
        Assert.Contains("secret.corp.contoso.com", mixedEval.DenialReason);

        // 3. Tampered CSR signature (flip byte in signature area at the end of CSR DER)
        Pkcs10CertificationRequest validDecoded = new(Convert.FromBase64String(
            string.Concat(forbiddenCsr.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Where(l => !l.StartsWith("-----")))));
        byte[] der = validDecoded.GetEncoded();
        der[^5] ^= 0xFF;
        string tamperedPem = "-----BEGIN CERTIFICATE REQUEST-----\n"
            + Convert.ToBase64String(der)
            + "\n-----END CERTIFICATE REQUEST-----";
        var (tamperedValid, tamperedErr, _) = IssuancePolicyService.ParseAndValidateCsr(tamperedPem);
        Assert.False(tamperedValid);
        Assert.Contains("signature", tamperedErr, StringComparison.OrdinalIgnoreCase);

        // 4. Unsupported SAN type (IP address SAN instead of DNS SAN)
        var pairParams = kp.ToAsymmetricCipherKeyPair();
        X509Name subject = new("CN=api.dev.contoso.com,C=US,ST=Washington,L=Redmond,O=Contoso");
        GeneralNames ipSan = new(new GeneralName(GeneralName.IPAddress, "10.0.0.1"));
        Dictionary<DerObjectIdentifier, Org.BouncyCastle.Asn1.X509.X509Extension> ipExts = new()
        {
            [X509Extensions.SubjectAlternativeName] = new(false, new DerOctetString(ipSan))
        };
        Pkcs10CertificationRequest ipCsrObj = new(
            new Asn1SignatureFactory("SHA256withECDSA", pairParams.Private, new SecureRandom()),
            subject,
            pairParams.Public,
            new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(new X509Extensions(ipExts)))));
        string ipCsrPem = "-----BEGIN CERTIFICATE REQUEST-----\n" + Convert.ToBase64String(ipCsrObj.GetEncoded()) + "\n-----END CERTIFICATE REQUEST-----";
        var (ipValid, ipErr, _) = IssuancePolicyService.ParseAndValidateCsr(ipCsrPem);
        Assert.False(ipValid);
        Assert.Contains("Unsupported Subject Alternative Name", ipErr);

        // 5. CSR requesting CA=true BasicConstraints
        Dictionary<DerObjectIdentifier, Org.BouncyCastle.Asn1.X509.X509Extension> caExts = new()
        {
            [X509Extensions.BasicConstraints] = new(true, new DerOctetString(new BasicConstraints(true)))
        };
        Pkcs10CertificationRequest caCsrObj = new(
            new Asn1SignatureFactory("SHA256withECDSA", pairParams.Private, new SecureRandom()),
            subject,
            pairParams.Public,
            new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(new X509Extensions(caExts)))));
        string caCsrPem = "-----BEGIN CERTIFICATE REQUEST-----\n" + Convert.ToBase64String(caCsrObj.GetEncoded()) + "\n-----END CERTIFICATE REQUEST-----";
        var (caValid, caErr, _) = IssuancePolicyService.ParseAndValidateCsr(caCsrPem);
        Assert.False(caValid);
        Assert.Contains("CA BasicConstraints", caErr);
    }

    [Fact]
    public async Task IntermediateChain_CrossAlgorithmIssuance_Export_ConcurrentSerials_Revocation_And_Restore()
    {
        using IServiceScope scope = _serviceProvider.CreateScope();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
        BackupRestoreService backupService = scope.ServiceProvider.GetRequiredService<BackupRestoreService>();

        var (_, _, admin) = await acct.BootstrapFirstAdminAsync("admin", "AdminSecret1234", "admin@contoso.com", "*.contoso.com");
        Assert.NotNull(admin);

        // 1. Create Root CA (RSA 4096) and Subordinate Intermediate CA (ECDSA P-384)
        string caPassphrase = "CaVaultPassphrase!2026";
        CaAuthorityRecord rootCa = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Contoso Root CA",
            "root.contoso.com",
            "US",
            "Washington",
            "Redmond",
            "Contoso Corporation",
            "PKI",
            CertificateKeyFamily.Rsa,
            4096,
            3650,
            caPassphrase);
        Assert.False(rootCa.IsIntermediate);

        CaAuthorityRecord intermediateCa = await caService.CreateSelfSignedOrIntermediateCaAsync(
            "Contoso Issuing Intermediate CA",
            "issuing.contoso.com",
            "US",
            "Washington",
            "Redmond",
            "Contoso Corporation",
            "PKI",
            CertificateKeyFamily.Ecdsa,
            384,
            1825,
            caPassphrase,
            crlDistributionPointUrl: "http://pki.contoso.com/ca.crl",
            authorityIssuerCertUrl: "http://pki.contoso.com/ca.crt",
            parentAuthority: rootCa,
            parentPassphrase: caPassphrase);
        Assert.True(intermediateCa.IsIntermediate);

        // Verify initial CRL #1 was published for intermediate CA before any leaf issuance
        PublishedCrlRecord? initialCrl = await caService.GetLatestCrlAsync();
        Assert.NotNull(initialCrl);
        Assert.Equal(1, initialCrl.CrlNumber);

        // 2. Issue both RSA 2048 and ECDSA P-256 leaf certificates under the ECDSA P-384 Intermediate CA
        KeyPair rsaLeafKey = _crypto.KeyGen(2048);
        string rsaCsr = _crypto.CSRGen(
            rsaLeafKey, "rsa-app.contoso.com", ["rsa-app.contoso.com", "contoso.com"], "US", "Washington", "Redmond", "Contoso Corporation", "IT", "");
        IssuanceOutcome rsaOutcome = await caService.IssueCertificateFromCsrAsync(admin.Id, rsaCsr);
        Assert.True(rsaOutcome.Succeeded, rsaOutcome.ErrorMessage);

        // Verify RSA leaf has DigitalSignature | KeyEncipherment and is NOT a CA
        using X509Certificate2 rsaLeafCert = X509Certificate2.CreateFromPem(rsaOutcome.CertificatePem);
        var rsaKu = rsaLeafCert.Extensions.OfType<X509KeyUsageExtension>().Single();
        Assert.True(rsaKu.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature));
        Assert.True(rsaKu.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment));
        Assert.False(rsaLeafCert.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority);

        // Verify PkcsBuilder.Export with 3-cert chain (leaf + intermediate + root)
        Tuple<string, byte[]>? exportZip = PkcsBuilder.Export(
            rsaOutcome.CertificatePem!,
            rsaLeafKey.Private,
            rootCaCertPath: null,
            chainPemContent: rsaOutcome.Record!.ChainPem);
        Assert.NotNull(exportZip);
        using (MemoryStream zipMs = new(exportZip.Item2))
        using (ZipArchive zip = new(zipMs, ZipArchiveMode.Read))
        {
            ZipArchiveEntry chainedP12 = zip.GetEntry("rsa-app.contoso.com-chained.p12")!;
            using MemoryStream p12Ms = new();
            chainedP12.Open().CopyTo(p12Ms);
            X509Certificate2Collection p12Certs = X509CertificateLoader.LoadPkcs12Collection(p12Ms.ToArray(), null);
            Assert.Equal(3, p12Certs.Count); // leaf + intermediate + root
        }

        // 3. Concurrent issuance: 8 parallel requests must allocate strictly unique positive serials
        Task<IssuanceOutcome>[] concurrentTasks = Enumerable.Range(1, 8).Select(async idx =>
        {
            KeyPair ecKey = _crypto.KeyGen(256);
            string csr = _crypto.CSRGen(
                ecKey, $"node{idx}.contoso.com", [$"node{idx}.contoso.com"], "US", "Washington", "Redmond", "Contoso Corporation", "IT", "");
            return await caService.IssueCertificateFromCsrAsync(admin.Id, csr);
        }).ToArray();

        IssuanceOutcome[] concurrentOutcomes = await Task.WhenAll(concurrentTasks);
        Assert.All(concurrentOutcomes, o => Assert.True(o.Succeeded, o.ErrorMessage));
        HashSet<string> serialHexes = concurrentOutcomes.Select(o => o.Record!.SerialNumberHex).ToHashSet();
        Assert.Equal(8, serialHexes.Count);

        // 4. Revoke the RSA leaf certificate and verify CRL #2 contains its serial number and validates against Intermediate CA
        var (revOk, revErr) = await caService.RevokeCertificateAsync(rsaOutcome.Record.Id, CrlReason.KeyCompromise, "admin");
        Assert.True(revOk, revErr);

        PublishedCrlRecord? updatedCrl = await caService.GetLatestCrlAsync();
        Assert.NotNull(updatedCrl);
        Assert.Equal(2, updatedCrl.CrlNumber);

        X509Crl parsedCrl = new X509CrlParser().ReadCrl(updatedCrl.CrlDer);
        Org.BouncyCastle.X509.X509Certificate bcInterCert = new X509CertificateParser().ReadCertificate(
            X509Certificate2.CreateFromPem(intermediateCa.IssuerCertificatePem).RawData);
        parsedCrl.Verify(bcInterCert.GetPublicKey());

        BigInteger revokedSerialBigInt = new(1, Convert.FromHexString(rsaOutcome.Record.SerialNumberHex));
        X509CrlEntry crlEntry = parsedCrl.GetRevokedCertificate(revokedSerialBigInt);
        Assert.NotNull(crlEntry);

        // 4a. Independently verify intermediate chain, leaf certificate, and revoked CRL using system OpenSSL CLI
        string opensslVerifyDir = Path.Combine(_tempRoot, "openssl-verify");
        Directory.CreateDirectory(opensslVerifyDir);
        string rootPemPath = Path.Combine(opensslVerifyDir, "root.pem");
        string interPemPath = Path.Combine(opensslVerifyDir, "inter.pem");
        string leafPemPath = Path.Combine(opensslVerifyDir, "leaf.pem");
        string crlPemPath = Path.Combine(opensslVerifyDir, "ca.crl.pem");
        string chainPlusCrlPath = Path.Combine(opensslVerifyDir, "chain-crl.pem");

        await File.WriteAllTextAsync(rootPemPath, rootCa.IssuerCertificatePem);
        await File.WriteAllTextAsync(interPemPath, intermediateCa.IssuerCertificatePem);
        await File.WriteAllTextAsync(leafPemPath, rsaOutcome.CertificatePem);
        await File.WriteAllTextAsync(crlPemPath, updatedCrl.CrlPem);
        await File.WriteAllTextAsync(chainPlusCrlPath, intermediateCa.IssuerCertificatePem + "\n" + updatedCrl.CrlPem);

        // Verify unrevoked node1 leaf passes OpenSSL chain verification
        string unrevokedLeafPath = Path.Combine(opensslVerifyDir, "node1.pem");
        await File.WriteAllTextAsync(unrevokedLeafPath, concurrentOutcomes[0].CertificatePem);
        var (exitOk, outOk) = await RunProcessAsync("openssl", $"verify -CAfile \"{rootPemPath}\" -untrusted \"{interPemPath}\" \"{unrevokedLeafPath}\"");
        Assert.Equal(0, exitOk);
        Assert.Contains("OK", outOk);

        // Verify CRL signature using OpenSSL
        var (crlExit, crlOut) = await RunProcessAsync("openssl", $"crl -in \"{crlPemPath}\" -CAfile \"{interPemPath}\" -noout");
        Assert.Equal(0, crlExit);
        Assert.Contains("verify OK", crlOut, StringComparison.OrdinalIgnoreCase);

        // Verify revoked RSA leaf is flagged as revoked by OpenSSL when -crl_check is enabled
        var (revVerifyExit, revVerifyOut) = await RunProcessAsync(
            "openssl",
            $"verify -crl_check -CAfile \"{rootPemPath}\" -untrusted \"{interPemPath}\" -CRLfile \"{crlPemPath}\" \"{leafPemPath}\"");
        Assert.NotEqual(0, revVerifyExit);
        Assert.Contains("certificate revoked", revVerifyOut, StringComparison.OrdinalIgnoreCase);

        // 5. Consistent Backup & Restore to a clean directory, then verify serial & CRL continuity after restart
        byte[] backupBytes = await backupService.CreateConsistentBackupArchiveAsync(_sqliteFilePath, _dpKeysDir);

        string restoredRoot = Path.Combine(_tempRoot, "restored");
        string restoredDbPath = Path.Combine(restoredRoot, "certrobo.db");
        string restoredCaDir = Path.Combine(restoredRoot, "ca");
        string restoredDpDir = Path.Combine(restoredRoot, "dp");

        BackupRestoreService.RestoreBackupArchive(backupBytes, restoredDbPath, restoredCaDir, restoredDpDir);

        using ServiceProvider restoredSp = BuildServiceProvider(restoredDbPath, restoredCaDir);
        CertificateAuthorityService restoredCaService = restoredSp.GetRequiredService<CertificateAuthorityService>();
        restoredCaService.UnlockRuntimePassphrase(caPassphrase);

        PublishedCrlRecord? restoredCrl = await restoredCaService.GetLatestCrlAsync();
        Assert.NotNull(restoredCrl);
        Assert.Equal(2, restoredCrl.CrlNumber);

        PublishedCrlRecord? postRestoreCrl = await restoredCaService.RefreshActiveCrlAsync();
        Assert.NotNull(postRestoreCrl);
        Assert.Equal(3, postRestoreCrl.CrlNumber);

        // 6. Verify that no private key or passphrase appears in any SQLite database record
        using (IServiceScope auditScope = _serviceProvider.CreateScope())
        {
            CertRoboDbContext db = auditScope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            List<IssuedCertificateRecord> allIssued = await db.IssuedCertificates.ToListAsync();
            Assert.NotEmpty(allIssued);
            foreach (IssuedCertificateRecord rec in allIssued)
            {
                Assert.DoesNotContain("PRIVATE KEY", rec.CertificatePem);
                Assert.DoesNotContain("PRIVATE KEY", rec.ChainPem);
                Assert.DoesNotContain(caPassphrase, rec.CertificatePem);
            }

            List<CaAuthorityRecord> allCas = await db.CaAuthorities.ToListAsync();
            foreach (CaAuthorityRecord caRec in allCas)
            {
                Assert.DoesNotContain("PRIVATE KEY", caRec.IssuerCertificatePem);
                Assert.DoesNotContain(caPassphrase, caRec.EncryptedPrivateKeyPath);
                byte[] encryptedFileBytes = await File.ReadAllBytesAsync(caRec.EncryptedPrivateKeyPath);
                string rawAscii = System.Text.Encoding.ASCII.GetString(encryptedFileBytes);
                Assert.DoesNotContain("BEGIN PRIVATE KEY", rawAscii);
            }
        }
    }

    [Fact]
    public async Task CaImport_ValidatesKeyMatch_BasicConstraints_And_Pkcs12Chain()
    {
        using IServiceScope scope = _serviceProvider.CreateScope();
        CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();

        // Generate synthetic Root CA + Intermediate CA outside CertRobo, then import via PEM and PKCS#12
        using RSA extRootKey = RSA.Create(2048);
        CertificateRequest extRootReq = new("CN=External Root CA, O=Contoso, C=US", extRootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        extRootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        extRootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        X509SubjectKeyIdentifierExtension rootSki = new(extRootReq.PublicKey, false);
        extRootReq.CertificateExtensions.Add(rootSki);
        using X509Certificate2 extRootCert = extRootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

        using ECDsa extInterKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest extInterReq = new("CN=External Intermediate CA, O=Contoso, C=US", extInterKey, HashAlgorithmName.SHA256);
        extInterReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        extInterReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        extInterReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(extInterReq.PublicKey, false));
        extInterReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(rootSki));
        using X509Certificate2 extInterCert = extInterReq.Create(
            extRootCert.SubjectName,
            X509SignatureGenerator.CreateForRSA(extRootKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddDays(180),
            [0x0A, 0x0B, 0x0C]);

        // 1. Mismatched private key must be rejected
        using ECDsa wrongInterKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            caService.ImportCaAsync(
                "Bad Key Import",
                extInterCert.ExportCertificatePem(),
                extRootCert.ExportCertificatePem(),
                wrongInterKey.ExportPkcs8PrivateKeyPem(),
                null,
                "VaultPass!123"));

        // 2. Non-CA leaf certificate must be rejected when imported as CA
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest nonCaReq = new("CN=leaf.contoso.com", leafKey, HashAlgorithmName.SHA256);
        nonCaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using X509Certificate2 nonCaCert = nonCaReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(10));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            caService.ImportCaAsync(
                "Non-CA Import",
                nonCaCert.ExportCertificatePem(),
                null,
                leafKey.ExportPkcs8PrivateKeyPem(),
                null,
                "VaultPass!123"));

        // 3. Valid PKCS#12 Intermediate CA + Root chain import succeeds
        using X509Certificate2 interWithKey = extInterCert.CopyWithPrivateKey(extInterKey);
        using X509Certificate2 rootPublicCopy = X509CertificateLoader.LoadCertificate(extRootCert.RawData);
        X509Certificate2Collection p12Col = [interWithKey, rootPublicCopy];
        byte[] p12Bytes = p12Col.Export(X509ContentType.Pkcs12, "ImportPass!123")!;

        CaAuthorityRecord importedCa = await caService.ImportCaFromPkcs12Async(
            "Imported Intermediate CA",
            p12Bytes,
            "ImportPass!123",
            "StoragePass!123",
            initialSerialFloor: 5000,
            initialCrlNumberFloor: 42);

        Assert.True(importedCa.IsIntermediate);
        Assert.Equal(5000, importedCa.LastAllocatedSerial);
        Assert.Contains("BEGIN CERTIFICATE", importedCa.ChainCertificatesPem);

        // Initial CRL must start at 42 + 1 = 43
        PublishedCrlRecord? initialImportedCrl = await caService.GetLatestCrlAsync();
        Assert.NotNull(initialImportedCrl);
        Assert.Equal(43, initialImportedCrl.CrlNumber);

        // Seed a legacy revoked serial and verify CRL #44 contains it
        var (seedOk, seedErr) = await caService.SeedRevokedSerialAsync(
            "01:A2:B3:C4:D5",
            "legacy.contoso.com",
            CrlReason.KeyCompromise,
            "admin");
        Assert.True(seedOk, seedErr);

        PublishedCrlRecord? seededCrl = await caService.GetLatestCrlAsync();
        Assert.NotNull(seededCrl);
        Assert.Equal(44, seededCrl.CrlNumber);

        X509Crl parsedSeededCrl = new X509CrlParser().ReadCrl(seededCrl.CrlDer);
        X509CrlEntry seededEntry = parsedSeededCrl.GetRevokedCertificate(new BigInteger(1, Convert.FromHexString("01A2B3C4D5")));
        Assert.NotNull(seededEntry);
    }

    [Fact]
    public async Task LegacySettingsMigration_InspectsAdGroups_And_ImportsSubjectDefaults_WithoutGuessingAccounts()
    {
        using IServiceScope scope = _serviceProvider.CreateScope();
        LegacySettingsMigrationService migration = scope.ServiceProvider.GetRequiredService<LegacySettingsMigrationService>();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();

        string xmlContent = """
            <CertRobo>
                <Server>ca.contoso.com\Contoso Certificate Authority</Server>
                <Template256>CertRoboECDSA256</Template256>
                <Template384>CertRoboECDSA384</Template384>
                <Template2048>CertRoboRSA2048</Template2048>
                <Template4096>CertRoboRSA4096</Template4096>
                <Groups>
                    <Group>
                        <Name>CONTOSO\Web Server Admins</Name>
                        <Domains>
                            <Domain>contoso.com</Domain>
                            <Domain>*.contoso.com</Domain>
                        </Domains>
                    </Group>
                    <Group>
                        <Name>CONTOSO\DevOps Team</Name>
                        <Domains>
                            <Domain>*.dev.contoso.com</Domain>
                        </Domains>
                    </Group>
                </Groups>
                <Defaults>
                    <Country>CA</Country>
                    <StateOrProvince>British Columbia</StateOrProvince>
                    <Locality>Vancouver</Locality>
                    <Organisation>Example Corp</Organisation>
                    <OrganisationalUnit>Security</OrganisationalUnit>
                    <EmailAddress>pki@example.org</EmailAddress>
                </Defaults>
            </CertRobo>
            """;

        string tempXmlPath = Path.Combine(_tempRoot, "legacy-settings.xml");
        await File.WriteAllTextAsync(tempXmlPath, xmlContent);

        LegacySettingsInspectionReport report = await migration.InspectAndOptionallyImportDefaultsAsync(
            tempXmlPath,
            importSubjectDefaults: true);

        Assert.Equal(@"ca.contoso.com\Contoso Certificate Authority", report.LegacyAdcsServer);
        Assert.Equal(2, report.GroupMappings.Count);
        Assert.Equal(@"CONTOSO\Web Server Admins", report.GroupMappings[0].LegacyAdGroupName);
        Assert.Contains("contoso.com", report.GroupMappings[0].CanonicalDomainPatterns);
        Assert.Contains("*.contoso.com", report.GroupMappings[0].CanonicalDomainPatterns);

        string worksheet = report.FormatWorksheetText();
        Assert.Contains(@"CONTOSO\DevOps Team", worksheet);
        Assert.Contains("*.dev.contoso.com", worksheet);

        // Verify SubjectDefaultsConfig was updated in DB with full State/Province & Locality names and 2-letter Country
        SubjectDefaultsConfig savedDefaults = await acct.GetSubjectDefaultsAsync();
        Assert.Equal("CA", savedDefaults.Country);
        Assert.Equal("British Columbia", savedDefaults.StateOrProvince);
        Assert.Equal("Vancouver", savedDefaults.Locality);
        Assert.Equal("Example Corp", savedDefaults.Organisation);
        Assert.Equal("Security", savedDefaults.OrganisationalUnit);
        Assert.Equal("pki@example.org", savedDefaults.EmailAddress);

        // Verify no local accounts were guessed/created from the AD groups
        IReadOnlyList<UserSummaryDto> users = await acct.ListUsersAsync();
        Assert.Empty(users);
    }

    private static async Task<(int ExitCode, string CombinedOutput)> RunProcessAsync(string fileName, string arguments)
    {
        using System.Diagnostics.Process proc = new();
        proc.StartInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        proc.Start();
        string stdout = await proc.StandardOutput.ReadToEndAsync();
        string stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        return (proc.ExitCode, stdout + "\n" + stderr);
    }

    public void Dispose()
    {
        _serviceProvider.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (Directory.Exists(_tempRoot))
        {
            try { Directory.Delete(_tempRoot, recursive: true); }
            catch { }
        }
    }
}
