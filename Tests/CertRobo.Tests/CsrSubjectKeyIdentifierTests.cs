using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertRobo.Services;

namespace CertRobo.Tests;

public class CsrSubjectKeyIdentifierTests
{
    // Deliberately unrelated to the key: the CA must compute its own identifier.
    internal const string RequestedIdentifier = "0102030405060708090A0B0C0D0E0F1011121314";
    private const string ValidSki = "0414" + RequestedIdentifier;

    [Theory]
    [InlineData(2048)]
    [InlineData(256)]
    [InlineData(384)]
    public void DeviceCsr_WithSubjectKeyIdentifier_IsAccepted(int keyBits)
    {
        string csr = CreateDeviceCsr(keyBits);

        var (valid, error, request) = IssuancePolicyService.ParseAndValidateCsr(csr);

        Assert.True(valid, error);
        Assert.NotNull(request);
        Assert.Equal(keyBits, request.Profile.KeyBits);
        Assert.Equal(new[] { "storage.example.com", "node0.example.com", "node1.example.com" },
            request.CanonicalDnsIdentities);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0400")] // Empty OCTET STRING
    [InlineData("020101")] // INTEGER instead of OCTET STRING
    [InlineData("040201")] // Truncated value
    [InlineData("0401010500")] // Trailing ASN.1 object
    public void MalformedSubjectKeyIdentifier_IsRejected(string encodedSki)
    {
        var (valid, error, _) = IssuancePolicyService.ParseAndValidateCsr(
            CreateDeviceCsr(encodedSki: encodedSki));

        Assert.False(valid);
        Assert.NotNull(error);
    }

    [Fact]
    public void CriticalSubjectKeyIdentifier_IsRejected()
    {
        var (valid, error, _) = IssuancePolicyService.ParseAndValidateCsr(
            CreateDeviceCsr(criticalSki: true));

        Assert.False(valid);
        Assert.Contains("non-critical", error);
    }

    [Fact]
    public void SubjectKeyIdentifier_DoesNotPermitUnknownExtensions()
    {
        var (valid, error, _) = IssuancePolicyService.ParseAndValidateCsr(
            CreateDeviceCsr(extraOid: "1.2.3.4.5"));

        Assert.False(valid);
        Assert.Contains("unsupported extension OID '1.2.3.4.5'", error);
    }

    [Fact]
    public void SubjectKeyIdentifier_DoesNotPermitCaRequests()
    {
        var (valid, error, _) = IssuancePolicyService.ParseAndValidateCsr(
            CreateDeviceCsr(requestCa: true));

        Assert.False(valid);
        Assert.Contains("CA BasicConstraints", error);
    }

    [Fact]
    public void SubjectKeyIdentifier_DoesNotBypassSignatureVerification()
    {
        string pem = CreateDeviceCsr();
        byte[] der = Convert.FromBase64String(string.Concat(pem.Split('\n')
            .Where(line => !line.StartsWith("-----"))));
        der[^1] ^= 1;
        var (valid, error, _) = IssuancePolicyService.ParseAndValidateCsr(
            PemEncoding.WriteString("CERTIFICATE REQUEST", der));

        Assert.False(valid);
        Assert.Contains("signature", error, StringComparison.OrdinalIgnoreCase);
    }

    internal static string CreateDeviceCsr(int keyBits = 384, string encodedSki = ValidSki,
        bool criticalSki = false, string? extraOid = null, bool requestCa = false)
    {
        using AsymmetricAlgorithm key = keyBits == 2048
            ? RSA.Create(keyBits)
            : ECDsa.Create(keyBits == 256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
        const string subject = "CN=storage.example.com,O=Example,C=US";
        CertificateRequest request = key is RSA rsa
            ? new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            : new(subject, (ECDsa)key, HashAlgorithmName.SHA256);
        SubjectAlternativeNameBuilder sans = new();
        foreach (string dns in new[] { "storage.example.com", "node0.example.com", "node1.example.com" })
            sans.AddDnsName(dns);
        request.CertificateExtensions.Add(sans.Build());
        request.CertificateExtensions.Add(new X509Extension("2.5.29.14",
            Convert.FromHexString(encodedSki), criticalSki));
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(requestCa, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
        {
            new("1.3.6.1.5.5.7.3.1"), new("1.3.6.1.5.5.7.3.2"), new("2.5.29.37.0")
        }, false));
        if (extraOid != null)
            request.CertificateExtensions.Add(new X509Extension(extraOid, new byte[] { 5, 0 }, false));
        return request.CreateSigningRequestPem();
    }
}
