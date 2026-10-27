using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace CertRobo.Models;

public enum CertificateKeyFamily
{
    Rsa,
    Ecdsa
}

public sealed record CertificateProfileDefinition(
    string ProfileId,
    string DisplayName,
    CertificateKeyFamily KeyFamily,
    int KeyBits,
    int DefaultValidityDays,
    int MaxValidityDays,
    X509KeyUsageFlags KeyUsages,
    IReadOnlyList<string> ExtendedKeyUsageOids,
    bool RequireDnsSan = true,
    bool AllowCommonName = true);

public static class CertificateProfiles
{
    public const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    public const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";

    public const string EcdsaP256ServerId = "tls-server-ecdsa-256";
    public const string EcdsaP384ServerId = "tls-server-ecdsa-384";
    public const string Rsa2048ServerId = "tls-server-rsa-2048";
    public const string Rsa4096ServerId = "tls-server-rsa-4096";

    public static readonly IReadOnlyDictionary<string, CertificateProfileDefinition> All =
        new Dictionary<string, CertificateProfileDefinition>(StringComparer.OrdinalIgnoreCase)
        {
            [EcdsaP256ServerId] = new(
                EcdsaP256ServerId,
                "TLS Server — ECDSA P-256",
                CertificateKeyFamily.Ecdsa,
                256,
                DefaultValidityDays: 365,
                MaxValidityDays: 825,
                KeyUsages: X509KeyUsageFlags.DigitalSignature,
                ExtendedKeyUsageOids: [ServerAuthOid, ClientAuthOid]),
            [EcdsaP384ServerId] = new(
                EcdsaP384ServerId,
                "TLS Server — ECDSA P-384",
                CertificateKeyFamily.Ecdsa,
                384,
                DefaultValidityDays: 365,
                MaxValidityDays: 825,
                KeyUsages: X509KeyUsageFlags.DigitalSignature,
                ExtendedKeyUsageOids: [ServerAuthOid, ClientAuthOid]),
            [Rsa2048ServerId] = new(
                Rsa2048ServerId,
                "TLS Server — RSA 2048",
                CertificateKeyFamily.Rsa,
                2048,
                DefaultValidityDays: 365,
                MaxValidityDays: 825,
                KeyUsages: X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                ExtendedKeyUsageOids: [ServerAuthOid, ClientAuthOid]),
            [Rsa4096ServerId] = new(
                Rsa4096ServerId,
                "TLS Server — RSA 4096",
                CertificateKeyFamily.Rsa,
                4096,
                DefaultValidityDays: 365,
                MaxValidityDays: 825,
                KeyUsages: X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                ExtendedKeyUsageOids: [ServerAuthOid, ClientAuthOid])
        };

    public static CertificateProfileDefinition? ResolveForKey(CertificateKeyFamily family, int keyBits)
    {
        return (family, keyBits) switch
        {
            (CertificateKeyFamily.Ecdsa, 256) => All[EcdsaP256ServerId],
            (CertificateKeyFamily.Ecdsa, 384) => All[EcdsaP384ServerId],
            (CertificateKeyFamily.Rsa, 2048) => All[Rsa2048ServerId],
            (CertificateKeyFamily.Rsa, 4096) => All[Rsa4096ServerId],
            _ => null
        };
    }
}
