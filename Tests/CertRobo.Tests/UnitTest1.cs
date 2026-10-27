using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace CertRobo.Tests;

public class BaselineCryptoAndPolicyTests
{
    private readonly CryptoFactory _crypto = new();

    [Theory]
    [InlineData(256, "ECDSA")]
    [InlineData(384, "ECDSA")]
    [InlineData(2048, "RSA")]
    [InlineData(4096, "RSA")]
    public void KeyGen_And_DerivePublicKey_RoundTrip(int keyBits, string expectedType)
    {
        KeyPair pair = _crypto.KeyGen(keyBits);
        Assert.Equal(expectedType, pair.Type());

        string derivedPub = _crypto.DerivePublicKey(pair.Private);
        Assert.Equal(pair.Public, derivedPub);
    }

    [Theory]
    [InlineData(256)]
    [InlineData(384)]
    [InlineData(2048)]
    public void CSRGen_CreatesValidSignedCsr_AndExtractsDomains(int keyBits)
    {
        KeyPair pair = _crypto.KeyGen(keyBits);
        string[] sans = ["app.contoso.com", "api.contoso.com"];
        string csrPem = _crypto.CSRGen(
            pair,
            commonName: "app.contoso.com",
            subjectAlternativeNames: sans,
            countryCode: "US",
            stateOrProvinceName: "Washington",
            localityName: "Redmond",
            organization: "Contoso Corporation",
            organizationalUnit: "IT",
            emailAddress: "it@contoso.com");

        Pkcs10CertificationRequest decoded = Assert.IsType<Pkcs10CertificationRequest>(
            new PemReader(new StringReader(csrPem)).ReadObject());

        Assert.True(decoded.Verify());

        List<string> extractedDomains = DomainPolicyEvaluator.GetDomainsFromCsr(csrPem);
        Assert.Equal(2, extractedDomains.Count);
        Assert.Contains("app.contoso.com", extractedDomains, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("api.contoso.com", extractedDomains, StringComparer.OrdinalIgnoreCase);
    }

    [Theory]
    // Wildcard pattern *.contoso.com matches subdomains, wildcard requests, AND the apex contoso.com
    [InlineData("sub.contoso.com", "*.contoso.com", true)]
    [InlineData("deep.sub.contoso.com", "*.contoso.com", true)]
    [InlineData("*.contoso.com", "*.contoso.com", true)]
    [InlineData("contoso.com", "*.contoso.com", true)]
    [InlineData("CONTOSO.COM.", "*.contoso.com", true)]
    [InlineData("evilcontoso.com", "*.contoso.com", false)]
    [InlineData("other.org", "*.contoso.com", false)]
    // Bare domain pattern contoso.com matches ONLY exact apex
    [InlineData("contoso.com", "contoso.com", true)]
    [InlineData("sub.contoso.com", "contoso.com", false)]
    [InlineData("*.contoso.com", "contoso.com", false)]
    // Global wildcard * matches everything
    [InlineData("anything.example.org", "*", true)]
    [InlineData("*.anything.example.org", "*", true)]
    public void DomainMatchesPattern_PreservesExistingWildcardAndApexSemantics(
        string requestedDomain, string allowedPattern, bool expectedMatch)
    {
        Assert.Equal(expectedMatch, DomainPolicyEvaluator.DomainMatchesPattern(requestedDomain, allowedPattern));
    }

    [Fact]
    public void PkcsBuilder_Export_ProducesValidArchiveWithChainedCertAndPkcs12()
    {
        using RSA caKey = RSA.Create(2048);
        CertificateRequest caReq = new(
            "CN=Test Root CA, O=ContosoTest, C=US",
            caKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using X509Certificate2 caCert = caReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));

        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest leafReq = new(
            "CN=web.contoso.com, O=ContosoTest, C=US",
            leafKey,
            HashAlgorithmName.SHA256);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        X509SignatureGenerator caSigGen = X509SignatureGenerator.CreateForRSA(caKey, RSASignaturePadding.Pkcs1);
        using X509Certificate2 leafCert = leafReq.Create(
            caCert.SubjectName,
            caSigGen,
            DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddDays(7),
            [0x01, 0x02, 0x03, 0x04]);

        string caPem = caCert.ExportCertificatePem() + "\n";
        string leafPem = leafCert.ExportCertificatePem() + "\n";
        string leafKeyPem = leafKey.ExportPkcs8PrivateKeyPem() + "\n";

        string tempCaPath = Path.Combine(Path.GetTempPath(), $"certrobo-test-ca-{Guid.NewGuid():N}.crt");
        try
        {
            File.WriteAllText(tempCaPath, caPem);

            Tuple<string, byte[]>? export = PkcsBuilder.Export(leafPem, leafKeyPem, tempCaPath);
            Assert.NotNull(export);
            Assert.Equal("web.contoso.com.zip", export.Item1);

            using MemoryStream ms = new(export.Item2);
            using ZipArchive archive = new(ms, ZipArchiveMode.Read);

            string[] entryNames = archive.Entries.Select(e => e.FullName).ToArray();
            Assert.Contains("web.contoso.com.crt", entryNames);
            Assert.Contains("web.contoso.com-chained.crt", entryNames);
            Assert.Contains("web.contoso.com.key", entryNames);
            Assert.Contains("web.contoso.com.pem", entryNames);
            Assert.Contains("web.contoso.com-chained.pem", entryNames);
            Assert.Contains("web.contoso.com.p12", entryNames);
            Assert.Contains("web.contoso.com-chained.p12", entryNames);

            ZipArchiveEntry p12Entry = archive.GetEntry("web.contoso.com-chained.p12")!;
            using MemoryStream p12Stream = new();
            p12Entry.Open().CopyTo(p12Stream);
            X509Certificate2Collection p12Col = X509CertificateLoader.LoadPkcs12Collection(
                p12Stream.ToArray(),
                password: null);
            Assert.Equal(2, p12Col.Count);
        }
        finally
        {
            if (File.Exists(tempCaPath))
            {
                File.Delete(tempCaPath);
            }
        }
    }
}
