using CertRobo.Data;
using CertRobo.Models;
using CertRobo.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertRobo.Tests;

public static class TestChildProcessEntryPoint
{
    public const string ChildModeArg = "--certrobo-parser-child";

    public static async Task<int> Main(string[] args)
    {
        if (args.Length >= 2 && string.Equals(args[0], ChildModeArg, StringComparison.Ordinal))
        {
            string caseId = args[1];
            try
            {
                await ParserSafetyRegressionTests.ExecuteIsolatedChildCaseAsync(caseId);
                Console.Out.WriteLine($"CHILD_OK:{caseId}");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"CHILD_FAIL:{caseId}:{ex}");
                return 2;
            }
        }

        return 0;
    }
}

public sealed class ParserSafetyRegressionTests
{
    [Theory]
    [InlineData("deep-csr-16kb")]
    [InlineData("deep-csr-extension-san")]
    [InlineData("deep-cms-bundle")]
    [InlineData("deep-encapsulated-cmc-octetstring")]
    [InlineData("deep-ces-wstep-token")]
    [InlineData("wide-fanout-cms-bundle")]
    [InlineData("ber-indefinite-deep-csr")]
    [InlineData("deep-private-key-import")]
    [InlineData("deep-pkcs12-import")]
    public async Task MalformedAndDeepAsn1Inputs_InBoundedChildProcess_ExitCleanlyWithoutCrash_AndPreserveSubsequentValidWork(
        string caseId)
    {
        string testAssemblyPath = typeof(ParserSafetyRegressionTests).Assembly.Location;
        Assert.True(File.Exists(testAssemblyPath), $"Test assembly not found at {testAssemblyPath}");

        ProcessStartInfo psi = new("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(testAssemblyPath);
        psi.ArgumentList.Add(TestChildProcessEntryPoint.ChildModeArg);
        psi.ArgumentList.Add(caseId);
        // Bound child process heap (256 MiB) so unbounded allocation fails fast inside the disposable child.
        psi.Environment["DOTNET_GCHeapHardLimit"] = "0x10000000";

        using Process proc = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start disposable child process.");

        using CancellationTokenSource cts = new(TimeSpan.FromSeconds(20));
        Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync(cts.Token);
        Task<string> stderrTask = proc.StandardError.ReadToEndAsync(cts.Token);

        try
        {
            await proc.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            Assert.Fail($"Child process timed out (>20s) while running parser case '{caseId}'.");
        }

        string stdout = await stdoutTask;
        string stderr = await stderrTask;

        Assert.True(
            proc.ExitCode == 0,
            $"Child process for '{caseId}' exited with code {proc.ExitCode}.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");
        Assert.Contains($"CHILD_OK:{caseId}", stdout);
    }

    [Fact]
    public void BouncyCastleAssembly_IsAtLeast270_AndEnforcesDefaultConstructedTagDepthLimit()
    {
        FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(typeof(Asn1InputStream).Assembly.Location);
        Assert.NotNull(fvi.FileVersion);
        Assert.True(
            Version.TryParse(fvi.FileVersion, out Version? bcVersion) && bcVersion >= new Version(2, 7, 0),
            $"Expected BouncyCastle.Cryptography FileVersion >= 2.7.0, found {fvi.FileVersion}");

        // Depth 80 exceeds BouncyCastle 2.7.0's default constructed-tag depth limit of 64.
        byte[] depth80Der = BuildNestedDerSequences(80);
        Asn1Exception ex = Assert.Throws<Asn1Exception>(() => Asn1Object.FromByteArray(depth80Der));
        Assert.Contains("maximum nested construction level reached", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ServerSideSizeAndCountLimits_RejectOversizedInputsBeforeExpensiveDecode()
    {
        // 1. Oversized CSR PEM (> 32 KiB)
        string oversizedCsrPem = "-----BEGIN CERTIFICATE REQUEST-----\n"
            + new string('A', IssuancePolicyService.MaxCsrPemLength + 1024)
            + "\n-----END CERTIFICATE REQUEST-----";
        var (csrOk, csrErr, _) = IssuancePolicyService.ParseAndValidateCsr(oversizedCsrPem);
        Assert.False(csrOk);
        Assert.Contains("exceeds the maximum permitted length", csrErr, StringComparison.OrdinalIgnoreCase);

        // 2. Oversized CSR DER (> 16 KiB inside a < 32 KiB PEM)
        byte[] oversizedCsrDer = new byte[IssuancePolicyService.MaxCsrDerBytes + 512];
        oversizedCsrDer[0] = 0x30;
        string oversizedDerCsrPem = WrapPem("CERTIFICATE REQUEST", oversizedCsrDer);
        Assert.True(oversizedDerCsrPem.Length <= IssuancePolicyService.MaxCsrPemLength);
        var (derCsrOk, derCsrErr, _) = IssuancePolicyService.ParseAndValidateCsr(oversizedDerCsrPem);
        Assert.False(derCsrOk);
        Assert.Contains("exceeds the maximum permitted decoded size", derCsrErr, StringComparison.OrdinalIgnoreCase);

        // 3. Multiple PEM objects in CSR input
        CryptoFactory crypto = new();
        KeyPair kp = crypto.KeyGen(256);
        string validCsr = crypto.CSRGen(
            kp, "app.contoso.com", ["app.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
        var (multiOk, multiErr, _) = IssuancePolicyService.ParseAndValidateCsr(validCsr + "\n" + validCsr);
        Assert.False(multiOk);
        Assert.Contains("single certificate signing request", multiErr, StringComparison.OrdinalIgnoreCase);

        // 4. CSR with excessive SAN count (> 128)
        string[] tooManySans = Enumerable.Range(1, IssuancePolicyService.MaxCsrDnsSanEntries + 5)
            .Select(i => $"host{i}.contoso.com")
            .ToArray();
        string manySanCsr = crypto.CSRGen(
            kp, "host1.contoso.com", tooManySans, "US", "WA", "Redmond", "Contoso", "IT", "");
        var (sanOk, sanErr, _) = IssuancePolicyService.ParseAndValidateCsr(manySanCsr);
        Assert.False(sanOk);
        Assert.Contains("too many Subject Alternative Name entries", sanErr, StringComparison.OrdinalIgnoreCase);

        // 5. Oversized bundle raw bytes (> 512 KiB) and text (> 1 MiB)
        byte[] oversizedRawBundle = new byte[CaChainAndConstraintValidator.MaxBundleRawBytes + 1];
        ArgumentException rawBundleEx = Assert.Throws<ArgumentException>(() =>
            CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(oversizedRawBundle, null, "test raw bundle"));
        Assert.Contains("exceeds the maximum permitted size", rawBundleEx.Message, StringComparison.OrdinalIgnoreCase);

        string oversizedTextBundle = new('A', CaChainAndConstraintValidator.MaxBundleTextLength + 1);
        ArgumentException textBundleEx = Assert.Throws<ArgumentException>(() =>
            CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(null, oversizedTextBundle, "test text bundle"));
        Assert.Contains("exceeds the maximum permitted length", textBundleEx.Message, StringComparison.OrdinalIgnoreCase);

        // 6. Bundle with > 32 certificates
        using ECDsa certKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest certReq = new("CN=Bundle Test,O=Contoso,C=US", certKey, HashAlgorithmName.SHA256);
        using X509Certificate2 sampleCert = certReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(10));
        string singleCertPem = sampleCert.ExportCertificatePem();
        string thirtyThreeCertsPem = string.Join("\n", Enumerable.Repeat(singleCertPem, CaChainAndConstraintValidator.MaxCertificatesPerBundle + 1));
        ArgumentException countEx = Assert.Throws<ArgumentException>(() =>
            CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(null, thirtyThreeCertsPem, "many certs bundle"));
        Assert.Contains("exceeds the maximum permitted certificate count", countEx.Message, StringComparison.OrdinalIgnoreCase);

        // 7. Oversized CES WSTEP HTTP response (> 2 MiB)
        string tempRoot = Path.Combine(Path.GetTempPath(), $"certrobo-ces-size-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);
        try
        {
            await using ServiceProvider sp = BuildDisposableServices(tempRoot);
            CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
            PendingCaEnrollmentRecord pending = await caService.CreatePendingCaEnrollmentAsync(
                "CES Size Test CA",
                "ces-size.contoso.com",
                "US", "WA", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa, 256, "TestVaultPass!2026");

            string hugePayload = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body>"
                + new string('X', AdCsCesEnrollmentService.MaxCesResponseBytes + 4096)
                + "</s:Body></s:Envelope>";

            AdCsCesEnrollmentService ces = new(
                sp.GetRequiredService<IDbContextFactory<CertRoboDbContext>>(),
                caService,
                sp.GetRequiredService<IDataProtectionProvider>(),
                _ => new StaticResponseHttpHandler(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(hugePayload, Encoding.UTF8, "application/soap+xml")
                }));

            await ces.SaveConfigAsync(
                isEnabled: true,
                endpointUrl: "https://ces.example.test/service.svc/CES",
                certificateTemplate: "SubCA",
                authenticationMode: "UsernamePassword",
                username: @"CONTOSO\svc",
                newPassword: "TestPassword1234",
                clearSavedPassword: false,
                clientCertificatePem: "",
                newClientPrivateKeyPem: null,
                clearSavedClientKey: false,
                customServerTlsTrustPem: "",
                defaultParentChainTrustPem: "",
                requestTimeoutSeconds: 10);

            AdCsCesOperationResult cesRes = await ces.QueryPendingStatusAsync(pending.Id, explicitRequestId: "42");
            Assert.False(cesRes.Succeeded);
            Assert.Equal(AdCsCesOutcomeKind.ValidationFailure, cesRes.OutcomeKind);
            Assert.Contains("exceeded the maximum permitted size", cesRes.SummaryMessage, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(tempRoot, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task NestedCmcEncapsulatedCertificates_WithinBounds_AreExtracted_AndVerifiedWithOpenSsl()
    {
        using RSA rootKey = RSA.Create(2048);
        CertificateRequest rootReq = new("CN=Nested CMC Root CA,O=Contoso,C=US", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        X509SubjectKeyIdentifierExtension rootSki = new(rootReq.PublicKey, false);
        rootReq.CertificateExtensions.Add(rootSki);
        rootReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(rootSki));
        using X509Certificate2 rootCert = rootReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(2));

        using ECDsa interKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest interReq = new("CN=Nested CMC Issuing CA,O=Contoso,C=US", interKey, HashAlgorithmName.SHA256);
        interReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        interReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
        interReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(interReq.PublicKey, false));
        interReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(rootSki));
        using X509Certificate2 interCert = interReq.Create(
            rootCert.SubjectName,
            X509SignatureGenerator.CreateForRSA(rootKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(180),
            [0x01, 0x02, 0x03, 0x04]);

        // Build a CMS SignedData whose encapsulated content is a CMC-like SEQUENCE containing the certificates
        X509CertificateParser bcParser = new();
        Asn1Object interAsn1 = Asn1Object.FromByteArray(interCert.RawData);
        Asn1Object rootAsn1 = Asn1Object.FromByteArray(rootCert.RawData);
        DerSequence cmcInnerPayload = new(
            new DerSequence(),
            new DerTaggedObject(true, 0, new DerSequence(interAsn1, rootAsn1)));

        CmsSignedDataGenerator cmsGen = new();
        CmsSignedData outerCms = cmsGen.Generate(
            new CmsProcessableByteArray(cmcInnerPayload.GetDerEncoded()),
            encapsulate: true);
        byte[] outerCmsDer = outerCms.GetEncoded();

        List<X509Certificate2> extracted = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
            outerCmsDer, null, "nested CMC response");
        try
        {
            Assert.Equal(2, extracted.Count);
            Assert.Contains(extracted, c => c.Thumbprint == interCert.Thumbprint);
            Assert.Contains(extracted, c => c.Thumbprint == rootCert.Thumbprint);
        }
        finally
        {
            foreach (X509Certificate2 c in extracted) c.Dispose();
        }

        // Also verify P7B export and leaf issuance with independent OpenSSL CLI checks
        string tempDir = Path.Combine(Path.GetTempPath(), $"certrobo-openssl-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            string bundlePem = interCert.ExportCertificatePem() + "\n" + rootCert.ExportCertificatePem() + "\n";
            byte[] p7bDer = PkcsBuilder.BuildPkcs7DerFromPemBundle(bundlePem);
            string p7bPath = Path.Combine(tempDir, "chain.p7b");
            await File.WriteAllBytesAsync(p7bPath, p7bDer);

            var (p7bExit, p7bOut, p7bErr) = await RunOpenSslAsync("pkcs7", "-inform", "DER", "-in", p7bPath, "-print_certs", "-noout");
            Assert.True(p7bExit == 0, $"OpenSSL pkcs7 failed: {p7bErr}");

            // Issue a leaf and verify with openssl verify -crl_check
            await using ServiceProvider sp = BuildDisposableServices(tempDir);
            using IServiceScope scope = sp.CreateScope();
            AccountManagementService accounts = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            var (_, _, admin) = await accounts.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*.contoso.com");
            CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
            CaAuthorityRecord ca = await caService.ImportCaAsync(
                "Imported CMC Issuing CA",
                interCert.ExportCertificatePem(),
                rootCert.ExportCertificatePem(),
                interKey.ExportPkcs8PrivateKeyPem(),
                inputKeyPassphrase: null,
                storagePassphrase: "TestVaultPass!2026");

            CryptoFactory crypto = new();
            KeyPair leafKey = crypto.KeyGen(256);
            string leafCsr = crypto.CSRGen(
                leafKey, "cmc-leaf.contoso.com", ["cmc-leaf.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
            IssuanceOutcome issued = await caService.IssueCertificateFromCsrAsync(admin!.Id, leafCsr);
            Assert.True(issued.Succeeded, issued.ErrorMessage);

            PublishedCrlRecord? crl = await caService.GetLatestCrlAsync(caAuthorityId: ca.Id);
            Assert.NotNull(crl);

            string rootPath = Path.Combine(tempDir, "root.pem");
            string interPath = Path.Combine(tempDir, "inter.pem");
            string leafPath = Path.Combine(tempDir, "leaf.pem");
            string crlPath = Path.Combine(tempDir, "ca.crl.pem");
            await File.WriteAllTextAsync(rootPath, rootCert.ExportCertificatePem());
            await File.WriteAllTextAsync(interPath, interCert.ExportCertificatePem());
            await File.WriteAllTextAsync(leafPath, issued.CertificatePem!);
            await File.WriteAllTextAsync(crlPath, crl!.CrlPem);

            var (verExit, verOut, verErr) = await RunOpenSslAsync(
                "verify", "-crl_check", "-CAfile", rootPath, "-untrusted", interPath, "-CRLfile", crlPath, leafPath);
            Assert.True(verExit == 0, $"OpenSSL verify failed: {verOut} {verErr}");
            Assert.Contains("OK", verOut);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    internal static async Task ExecuteIsolatedChildCaseAsync(string caseId)
    {
        switch (caseId)
        {
            case "deep-csr-16kb":
                {
                    // ~12.2 KB malformed CSR containing 3,100 nested constructed SEQUENCE tags (~16.5 KB PEM; the Opus audit crash scenario)
                    byte[] deepDer = BuildNestedDerSequences(3100);
                    Assert.True(deepDer.Length >= 12_000 && deepDer.Length <= IssuancePolicyService.MaxCsrDerBytes);
                    string pem = WrapPem("CERTIFICATE REQUEST", deepDer);

                    var (isValid, err, result) = IssuancePolicyService.ParseAndValidateCsr(pem);
                    Assert.False(isValid);
                    Assert.Null(result);
                    Assert.Equal("The CSR provided could not be decoded", err);

                    Assert.Throws<ArgumentException>(() => DomainPolicyEvaluator.GetDomainsFromCsr(pem));
                    break;
                }

            case "deep-csr-extension-san":
                {
                    // Valid outer PKCS#10 CSR whose SAN extension OCTET STRING encapsulates deeply nested ASN.1 (depth 200)
                    CryptoFactory crypto = new();
                    KeyPair kp = crypto.KeyGen(256);
                    var cipherPair = kp.ToAsymmetricCipherKeyPair();
                    byte[] deepInner = BuildNestedDerSequences(200);
                    Dictionary<DerObjectIdentifier, Org.BouncyCastle.Asn1.X509.X509Extension> exts = new()
                    {
                        [X509Extensions.SubjectAlternativeName] = new(false, new DerOctetString(deepInner))
                    };
                    Pkcs10CertificationRequest craftedCsr = new(
                        new Asn1SignatureFactory("SHA256withECDSA", cipherPair.Private, new SecureRandom()),
                        new X509Name("CN=deep-ext.contoso.com,C=US,ST=WA,L=Redmond,O=Contoso"),
                        cipherPair.Public,
                        new DerSet(new AttributePkcs(
                            PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                            new DerSet(new X509Extensions(exts)))));

                    string pem = WrapPem("CERTIFICATE REQUEST", craftedCsr.GetEncoded());
                    var (isValid, err, result) = IssuancePolicyService.ParseAndValidateCsr(pem);
                    Assert.False(isValid);
                    Assert.Null(result);
                    Assert.Equal("The CSR provided could not be decoded", err);
                    break;
                }

            case "deep-cms-bundle":
                {
                    // Deeply nested ASN.1 fed to TryExtractCertificatesFromCmsDer and ParseCertificatesFromAnyInput (DER & PEM PKCS7)
                    byte[] deepDer5000 = BuildNestedDerSequences(5000);
                    byte[] deepDer45 = BuildNestedDerSequences(45); // Below BC's 64 limit, above CertRobo's 32 traversal limit

                    List<X509Certificate2> target = [];
                    Assert.False(CaChainAndConstraintValidator.TryExtractCertificatesFromCmsDer(deepDer5000, target));
                    Assert.False(CaChainAndConstraintValidator.TryExtractCertificatesFromCmsDer(deepDer45, target));
                    Assert.Empty(target);

                    Assert.Throws<ArgumentException>(() =>
                        CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(deepDer5000, null, "deep binary bundle"));
                    Assert.Throws<ArgumentException>(() =>
                        CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(null, WrapPem("PKCS7", deepDer45), "deep PKCS7 PEM"));
                    Assert.Throws<ArgumentException>(() =>
                        CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(null, WrapPem("CERTIFICATE", deepDer45), "deep CERT PEM"));
                    break;
                }

            case "deep-encapsulated-cmc-octetstring":
                {
                    // Multi-layer CMS/CMC ContentInfo OCTET STRING wrapping where each layer has shallow ASN.1 depth (~3)
                    // so BouncyCastle's per-decode depth resets, testing CertRobo's cumulative traversal depth guard.
                    byte[] payload = BuildNestedDerSequences(4);
                    DerObjectIdentifier idData = CmsObjectIdentifiers.Data;
                    for (int layer = 0; layer < 25; layer++)
                    {
                        DerSequence contentInfo = new(
                            idData,
                            new DerTaggedObject(true, 0, new DerOctetString(payload)));
                        payload = contentInfo.GetDerEncoded();
                    }

                    CmsSignedDataGenerator cmsGen = new();
                    CmsSignedData outerCms = cmsGen.Generate(new CmsProcessableByteArray(payload), encapsulate: true);
                    byte[] outerDer = outerCms.GetEncoded();

                    List<X509Certificate2> target = [];
                    Assert.False(CaChainAndConstraintValidator.TryExtractCertificatesFromCmsDer(outerDer, target));
                    Assert.Empty(target);
                    break;
                }

            case "deep-ces-wstep-token":
                {
                    string tempRoot = Path.Combine(Path.GetTempPath(), $"certrobo-child-ces-{Guid.NewGuid():N}");
                    Directory.CreateDirectory(tempRoot);
                    try
                    {
                        await using ServiceProvider sp = BuildDisposableServices(tempRoot);
                        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
                        PendingCaEnrollmentRecord pending = await caService.CreatePendingCaEnrollmentAsync(
                            "Child CES CA",
                            "child-ces.contoso.com",
                            "US", "WA", "Redmond", "Contoso", "PKI",
                            CertificateKeyFamily.Ecdsa, 256, "TestVaultPass!2026");

                        byte[] deepTokenBytes = BuildNestedDerSequences(3000);
                        string deepTokenB64 = Convert.ToBase64String(deepTokenBytes);
                        string rstrXml = $$"""
                        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                                    xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
                                    xmlns:wstep="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
                                    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                          <s:Body>
                            <wst:RequestSecurityTokenResponseCollection>
                              <wst:RequestSecurityTokenResponse>
                                <wst:TokenType>{{AdCsCesEnrollmentService.X509v3TokenTypeUri}}</wst:TokenType>
                                <wstep:DispositionMessage xml:lang="en-US">Issued</wstep:DispositionMessage>
                                <wstep:RequestID>101</wstep:RequestID>
                                <wst:RequestedSecurityToken>
                                  <wsse:BinarySecurityToken ValueType="{{AdCsCesEnrollmentService.X509v3TokenTypeUri}}"
                                                            EncodingType="{{AdCsCesEnrollmentService.Base64EncodingTypeUri}}">{{deepTokenB64}}</wsse:BinarySecurityToken>
                                </wst:RequestedSecurityToken>
                              </wst:RequestSecurityTokenResponse>
                            </wst:RequestSecurityTokenResponseCollection>
                          </s:Body>
                        </s:Envelope>
                        """;

                        AdCsCesEnrollmentService ces = new(
                            sp.GetRequiredService<IDbContextFactory<CertRoboDbContext>>(),
                            caService,
                            sp.GetRequiredService<IDataProtectionProvider>(),
                            _ => new StaticResponseHttpHandler(new HttpResponseMessage(HttpStatusCode.OK)
                            {
                                Content = new StringContent(rstrXml, Encoding.UTF8, "application/soap+xml")
                            }));

                        await ces.SaveConfigAsync(
                            isEnabled: true,
                            endpointUrl: "https://ces.example.test/service.svc/CES",
                            certificateTemplate: "SubCA",
                            authenticationMode: "UsernamePassword",
                            username: @"CONTOSO\svc",
                            newPassword: "TestPassword1234",
                            clearSavedPassword: false,
                            clientCertificatePem: "",
                            newClientPrivateKeyPem: null,
                            clearSavedClientKey: false,
                            customServerTlsTrustPem: "",
                            defaultParentChainTrustPem: "",
                            requestTimeoutSeconds: 10);

                        AdCsCesOperationResult result = await ces.QueryPendingStatusAsync(pending.Id, explicitRequestId: "101");
                        Assert.False(result.Succeeded);
                        Assert.Equal(AdCsCesOutcomeKind.ValidationFailure, result.OutcomeKind);
                        Assert.Contains("could not be parsed safely", result.SummaryMessage, StringComparison.OrdinalIgnoreCase);
                    }
                    finally
                    {
                        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
                        try { Directory.Delete(tempRoot, recursive: true); } catch { }
                    }
                    break;
                }

            case "wide-fanout-cms-bundle":
                {
                    // Wide ASN.1 sequence with > 8,192 nodes inside encapsulated CMS content
                    byte[] wideSeq = BuildWideDerSequence(10_000);
                    CmsSignedDataGenerator cmsGen = new();
                    CmsSignedData outerCms = cmsGen.Generate(new CmsProcessableByteArray(wideSeq), encapsulate: true);
                    byte[] outerDer = outerCms.GetEncoded();

                    List<X509Certificate2> target = [];
                    Assert.False(CaChainAndConstraintValidator.TryExtractCertificatesFromCmsDer(outerDer, target));
                    Assert.Empty(target);
                    break;
                }

            case "ber-indefinite-deep-csr":
                {
                    // BER indefinite-length nested SEQUENCEs (0x30 0x80 ... 0x00 0x00) at depth 3000
                    byte[] berIndef = BuildBerIndefiniteNestedSequences(3000);
                    string pem = WrapPem("CERTIFICATE REQUEST", berIndef);
                    var (isValid, err, result) = IssuancePolicyService.ParseAndValidateCsr(pem);
                    Assert.False(isValid);
                    Assert.Null(result);
                    Assert.Equal("The CSR provided could not be decoded", err);
                    break;
                }

            case "deep-private-key-import":
                {
                    byte[] deepDer = BuildNestedDerSequences(3000);
                    string keyPem = WrapPem("PRIVATE KEY", deepDer);
                    CryptoFactory crypto = new();
                    Assert.Throws<ArgumentException>(() => crypto.DerivePublicKey(keyPem));
                    PkcsBuilder builder = new();
                    Assert.Throws<ArgumentException>(() => builder.PrivateKey = keyPem);
                    Assert.Null(PkcsBuilder.Export(WrapPem("CERTIFICATE", deepDer), keyPem));
                    break;
                }

            case "deep-pkcs12-import":
                {
                    string tempRoot = Path.Combine(Path.GetTempPath(), $"certrobo-child-p12-{Guid.NewGuid():N}");
                    Directory.CreateDirectory(tempRoot);
                    try
                    {
                        await using ServiceProvider sp = BuildDisposableServices(tempRoot);
                        CertificateAuthorityService caService = sp.GetRequiredService<CertificateAuthorityService>();
                        byte[] deepDer = BuildNestedDerSequences(3000);
                        await Assert.ThrowsAsync<ArgumentException>(() =>
                            caService.ImportCaFromPkcs12Async("Malformed P12 CA", deepDer, "pass", "TestVaultPass!2026"));
                    }
                    finally
                    {
                        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
                        try { Directory.Delete(tempRoot, recursive: true); } catch { }
                    }
                    break;
                }

            default:
                throw new ArgumentException($"Unknown child test case '{caseId}'.");
        }

        // Verify that after rejecting the hostile input, the same process still validates a legitimate CSR and certificate bundle.
        CryptoFactory validCrypto = new();
        KeyPair validKey = validCrypto.KeyGen(256);
        string validCsr = validCrypto.CSRGen(
            validKey,
            "post-reject.contoso.com",
            ["post-reject.contoso.com"],
            "US", "Washington", "Redmond", "Contoso", "IT", "");
        var (postValid, postErr, postParsed) = IssuancePolicyService.ParseAndValidateCsr(validCsr);
        Assert.True(postValid, postErr);
        Assert.NotNull(postParsed);
        Assert.Equal("post-reject.contoso.com", postParsed!.CommonName);
    }

    internal static byte[] BuildNestedDerSequences(int depth)
    {
        byte[] current = [0x05, 0x00]; // ASN.1 NULL
        for (int i = 0; i < depth; i++)
        {
            current = WrapDerTag(0x30, current);
        }
        return current;
    }

    private static byte[] BuildWideDerSequence(int elementCount)
    {
        using MemoryStream body = new(elementCount * 2);
        for (int i = 0; i < elementCount; i++)
        {
            body.WriteByte(0x05);
            body.WriteByte(0x00);
        }
        return WrapDerTag(0x30, body.ToArray());
    }

    private static byte[] BuildBerIndefiniteNestedSequences(int depth)
    {
        byte[] result = new byte[depth * 4 + 2];
        int offset = 0;
        for (int i = 0; i < depth; i++)
        {
            result[offset++] = 0x30;
            result[offset++] = 0x80;
        }
        result[offset++] = 0x05;
        result[offset++] = 0x00;
        for (int i = 0; i < depth; i++)
        {
            result[offset++] = 0x00;
            result[offset++] = 0x00;
        }
        return result;
    }

    private static byte[] WrapDerTag(byte tag, byte[] content)
    {
        int len = content.Length;
        byte[] lenBytes;
        if (len < 128)
        {
            lenBytes = [(byte)len];
        }
        else if (len <= 0xFF)
        {
            lenBytes = [0x81, (byte)len];
        }
        else if (len <= 0xFFFF)
        {
            lenBytes = [0x82, (byte)(len >> 8), (byte)(len & 0xFF)];
        }
        else
        {
            lenBytes = [0x83, (byte)(len >> 16), (byte)((len >> 8) & 0xFF), (byte)(len & 0xFF)];
        }

        byte[] wrapped = new byte[1 + lenBytes.Length + len];
        wrapped[0] = tag;
        Buffer.BlockCopy(lenBytes, 0, wrapped, 1, lenBytes.Length);
        Buffer.BlockCopy(content, 0, wrapped, 1 + lenBytes.Length, len);
        return wrapped;
    }

    private static string WrapPem(string type, byte[] der)
    {
        return $"-----BEGIN {type}-----\n"
            + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)
            + $"\n-----END {type}-----";
    }

    private static ServiceProvider BuildDisposableServices(string tempRoot)
    {
        string dbPath = Path.Combine(tempRoot, "certrobo.db");
        string caDir = Path.Combine(tempRoot, "ca");
        string dpDir = Path.Combine(tempRoot, "dp");
        Directory.CreateDirectory(caDir);
        Directory.CreateDirectory(dpDir);

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
            PassphraseEnvironmentVariable = null,
            ConfiguredPassphrase = "TestVaultPass!2026"
        });
        services.AddScoped<AccountManagementService>();
        services.AddScoped<IssuancePolicyService>();
        services.AddSingleton<CertificateAuthorityService>();

        ServiceProvider provider = services.BuildServiceProvider();
        using IServiceScope scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<CertRoboDbContext>()
            .EnsureSchemaUpgradedAsync().GetAwaiter().GetResult();
        return provider;
    }

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunOpenSslAsync(params string[] args)
    {
        ProcessStartInfo psi = new("openssl")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (string arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        using Process proc = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start openssl.");
        string stdOut = await proc.StandardOutput.ReadToEndAsync();
        string stdErr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        return (proc.ExitCode, stdOut, stdErr);
    }

    private sealed class StaticResponseHttpHandler(HttpResponseMessage response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(response);
        }
    }
}
