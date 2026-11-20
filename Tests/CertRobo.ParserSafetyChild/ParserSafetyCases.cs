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

using Xunit;

namespace CertRobo.Tests;

public static class ParserSafetyCases
{
    public static async Task ExecuteIsolatedChildCaseAsync(string caseId)
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
                        PendingCaEnrolmentRecord pending = await caService.CreatePendingCaEnrolmentAsync(
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

    public static byte[] BuildNestedDerSequences(int depth)
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

    public static string WrapPem(string type, byte[] der)
    {
        return $"-----BEGIN {type}-----\n"
            + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)
            + $"\n-----END {type}-----";
    }

    public static ServiceProvider BuildDisposableServices(string tempRoot)
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

    public sealed class StaticResponseHttpHandler(HttpResponseMessage response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(response);
        }
    }
}
