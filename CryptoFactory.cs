using ICSharpCode.SharpZipLib.Zip;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Text;

namespace CertRobo;

public class PkcsBuilder
{
    private static readonly char[] newline = ['\n', '\r'];

    private string? _cert;
    private string? _key;

    public PkcsBuilder() { }

    public PkcsBuilder(string certificate, string privateKey)
    {
        _cert = certificate;
        _key = privateKey;
    }

    public string? Certificate
    {
        get => _cert;
        set
        {
            if (value != null)
            {
                string cn = "";
                try
                {
                    X509Certificate cert = ParseFirstCertificate(value);
                    cn = ExtractCommonName(cert);
                }
                catch
                {
                    throw new ArgumentException("Certificate could not be parsed");
                }
                if (cn == string.Empty)
                {
                    throw new ArgumentException("Certificate does not contain a Common Name");
                }
            }
            _cert = value;
        }
    }

    public string? PrivateKey
    {
        get => _key;
        set
        {
            if (value != null)
            {
                try
                {
                    string t = string.Empty;
                    foreach (string s in value.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----")))
                    {
                        t += s;
                    }
                    PrivateKeyFactory.CreateKey(Convert.FromBase64String(t));
                }
                catch
                {
                    throw new ArgumentException("Private key could not be parsed");
                }
            }
            _key = value;
        }
    }

    public string CN
    {
        get
        {
            if (_cert == null)
            {
                return string.Empty;
            }
            X509Certificate cert = ParseFirstCertificate(_cert);
            return ExtractCommonName(cert);
        }
    }

    public static bool CertKeyCheck(string certificate, string privateKey)
    {
        if (string.IsNullOrWhiteSpace(certificate) || string.IsNullOrWhiteSpace(privateKey))
        {
            return false;
        }

        string k = string.Empty;
        foreach (string s in privateKey.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----")))
        {
            k += s;
        }
        AsymmetricKeyParameter privateParam = PrivateKeyFactory.CreateKey(Convert.FromBase64String(k));
        X509Certificate cert = ParseFirstCertificate(certificate);
        AsymmetricKeyParameter publicParam = cert.GetPublicKey();

        if (privateParam is RsaPrivateCrtKeyParameters privRsa && publicParam is RsaKeyParameters pubRsa)
        {
            if (privRsa.Modulus.Equals(pubRsa.Modulus) && privRsa.PublicExponent.Equals(pubRsa.Exponent))
            {
                return true;
            }
        }
        else if (privateParam is ECPrivateKeyParameters privEc && publicParam is ECPublicKeyParameters pubEc)
        {
            ECPoint q = privEc.Parameters.G.Multiply(privEc.D);
            ECPublicKeyParameters derived = new(privEc.AlgorithmName, q, privEc.PublicKeyParamSet);
            if (derived.Q.Equals(pubEc.Q))
            {
                return true;
            }
        }
        else if (privateParam is Ed25519PrivateKeyParameters privEd && publicParam is Ed25519PublicKeyParameters pubEd)
        {
            if (pubEd.GetEncoded().SequenceEqual(privEd.GeneratePublicKey().GetEncoded()))
            {
                return true;
            }
        }
        return false;
    }

    public static Tuple<string, byte[]>? Export(
        string certificate,
        string privateKey,
        string? rootCaCertPath = null,
        string? chainPemContent = null)
    {
        X509Certificate cert;
        try
        {
            cert = ParseFirstCertificate(certificate);
        }
        catch
        {
            return null;
        }

        string resolvedChainPem;
        if (!string.IsNullOrWhiteSpace(chainPemContent))
        {
            resolvedChainPem = chainPemContent;
        }
        else
        {
            string resolvedRootPath = rootCaCertPath
                ?? (File.Exists("static/rootca.crt") ? "static/rootca.crt" : "static/rootca.crt.example");
            if (!File.Exists(resolvedRootPath))
            {
                return null;
            }
            resolvedChainPem = File.ReadAllText(resolvedRootPath);
        }

        IList<X509Certificate> chainCerts;
        try
        {
            chainCerts = ParseCertificateBundle(resolvedChainPem);
            if (chainCerts.Count == 0)
            {
                return null;
            }
        }
        catch
        {
            return null;
        }

        // Verify that the leaf certificate is signed by the first certificate in the chain (either intermediate or root)
        // and that each subsequent certificate in the chain is signed by the next.
        bool chainValid = true;
        try
        {
            cert.Verify(chainCerts[0].GetPublicKey());
            for (int i = 0; i < chainCerts.Count - 1; i++)
            {
                chainCerts[i].Verify(chainCerts[i + 1].GetPublicKey());
            }
            if (chainCerts[^1].SubjectDN.Equivalent(chainCerts[^1].IssuerDN, inOrder: false))
            {
                chainCerts[^1].Verify(chainCerts[^1].GetPublicKey());
            }
        }
        catch
        {
            chainValid = false;
        }

        string cn = ExtractCommonName(cert);
        if (string.IsNullOrEmpty(cn))
        {
            cn = "certificate";
        }

        string normalizedLeafPem = NormalizePemEnding(ExportCertificateToPem(cert));

        // Separate intermediate CA(s) from the self-signed trust anchor root CA so TLS server-chain files
        // (-chained.crt / -chained.pem) carry leaf + intermediate(s) without indiscriminately inserting the trust root,
        // while providing the trust root separately (rootca.crt) and carrying the full chain in PKCS#12 / PKCS#7 bundles.
        bool hasExplicitTrustAnchor = chainCerts.Count > 0
            && chainCerts[^1].SubjectDN.Equivalent(chainCerts[^1].IssuerDN, inOrder: false);

        IList<X509Certificate> tlsServerChainIssuers = hasExplicitTrustAnchor
            ? chainCerts.Take(chainCerts.Count - 1).ToList()
            : chainCerts;

        X509Certificate trustAnchorRootCert = chainCerts[^1];

        StringBuilder tlsChainPemBuilder = new();
        foreach (X509Certificate issuerCert in tlsServerChainIssuers)
        {
            tlsChainPemBuilder.Append(NormalizePemEnding(ExportCertificateToPem(issuerCert)));
        }
        string normalizedTlsChainIssuersPem = tlsChainPemBuilder.ToString();
        string normalizedRootAnchorPem = NormalizePemEnding(ExportCertificateToPem(trustAnchorRootCert));

        using MemoryStream output = new();
        using (ZipOutputStream zipStream = new(output))
        {
            zipStream.IsStreamOwner = false;

            // Base64 leaf
            zipStream.PutNextEntry(new ZipEntry(cn + ".crt"));
            zipStream.Write(Encoding.ASCII.GetBytes(normalizedLeafPem));

            // PKCS #7 leaf (.p7b)
            byte[] leafP7b = BuildPkcs7Der([cert]);
            zipStream.PutNextEntry(new ZipEntry(cn + ".p7b"));
            zipStream.Write(leafP7b);

            if (chainValid)
            {
                // TLS server chain: leaf + intermediate(s), excluding the self-signed trust anchor.
                zipStream.PutNextEntry(new ZipEntry(cn + "-chained.crt"));
                zipStream.Write(Encoding.ASCII.GetBytes(normalizedLeafPem));
                if (!string.IsNullOrEmpty(normalizedTlsChainIssuersPem))
                {
                    zipStream.Write(Encoding.ASCII.GetBytes(normalizedTlsChainIssuersPem));
                }

                // Separate trust root certificate
                zipStream.PutNextEntry(new ZipEntry("rootca.crt"));
                zipStream.Write(Encoding.ASCII.GetBytes(normalizedRootAnchorPem));

                if (tlsServerChainIssuers.Count > 0)
                {
                    zipStream.PutNextEntry(new ZipEntry("ca-chain.crt"));
                    zipStream.Write(Encoding.ASCII.GetBytes(normalizedTlsChainIssuersPem));
                }

                // PKCS #7 chained (.p7b): leaf + intermediate(s) + root
                List<X509Certificate> fullP7bCerts = [cert, .. chainCerts];
                byte[] chainedP7b = BuildPkcs7Der(fullP7bCerts);
                zipStream.PutNextEntry(new ZipEntry(cn + "-chained.p7b"));
                zipStream.Write(chainedP7b);
            }

            if (!string.IsNullOrWhiteSpace(privateKey))
            {
                string k = "";
                foreach (string s in privateKey.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----")))
                {
                    k += s;
                }
                AsymmetricKeyParameter p = PrivateKeyFactory.CreateKey(Convert.FromBase64String(k));
                if (p is RsaPrivateCrtKeyParameters or ECPrivateKeyParameters or Ed25519PrivateKeyParameters)
                {
                    if (CertKeyCheck(certificate, privateKey))
                    {
                        string normalizedKeyPem = NormalizePemEnding(privateKey);

                        zipStream.PutNextEntry(new ZipEntry(cn + ".key"));
                        zipStream.Write(Encoding.ASCII.GetBytes(normalizedKeyPem));

                        zipStream.PutNextEntry(new ZipEntry(cn + ".pem"));
                        zipStream.Write(Encoding.ASCII.GetBytes(normalizedLeafPem));
                        zipStream.Write(Encoding.ASCII.GetBytes(normalizedKeyPem));

                        if (chainValid)
                        {
                            zipStream.PutNextEntry(new ZipEntry(cn + "-chained.pem"));
                            zipStream.Write(Encoding.ASCII.GetBytes(normalizedLeafPem));
                            if (!string.IsNullOrEmpty(normalizedTlsChainIssuersPem))
                            {
                                zipStream.Write(Encoding.ASCII.GetBytes(normalizedTlsChainIssuersPem));
                            }
                            zipStream.Write(Encoding.ASCII.GetBytes(normalizedKeyPem));
                        }

                        // PKCS #12 leaf
                        Pkcs12StoreBuilder builder = new();
                        builder.SetUseDerEncoding(true);
                        Pkcs12Store store = builder.Build();
                        store.SetKeyEntry(string.Empty, new AsymmetricKeyEntry(p), [new X509CertificateEntry(cert)]);
                        byte[] pkcs;
                        using (MemoryStream stream = new())
                        {
                            store.Save(stream, null, new SecureRandom());
                            pkcs = stream.ToArray();
                        }
                        zipStream.PutNextEntry(new ZipEntry(cn + ".p12"));
                        zipStream.Write(pkcs);

                        // PKCS #12 chained (leaf + all chain certificates in order)
                        if (chainValid)
                        {
                            builder = new();
                            builder.SetUseDerEncoding(true);
                            store = builder.Build();
                            List<X509CertificateEntry> certEntries = [new X509CertificateEntry(cert)];
                            certEntries.AddRange(chainCerts.Select(c => new X509CertificateEntry(c)));
                            store.SetKeyEntry(string.Empty, new AsymmetricKeyEntry(p), certEntries.ToArray());
                            using (MemoryStream stream = new())
                            {
                                store.Save(stream, null, new SecureRandom());
                                pkcs = stream.ToArray();
                            }
                            zipStream.PutNextEntry(new ZipEntry(cn + "-chained.p12"));
                            zipStream.Write(pkcs);
                        }
                    }
                }
            }

            zipStream.Finish();
        }

        return new Tuple<string, byte[]>(cn + ".zip", output.ToArray());
    }

    public static byte[] BuildPkcs7Der(IEnumerable<X509Certificate> certificates)
    {
        CmsSignedDataGenerator gen = new();
        foreach (X509Certificate c in certificates)
        {
            gen.AddCertificate(c);
        }
        CmsSignedData signedData = gen.Generate(new CmsProcessableByteArray([]), encapsulate: false);
        return signedData.GetEncoded();
    }

    public static byte[] BuildPkcs7DerFromPemBundle(string pemBundle)
    {
        IList<X509Certificate> certs = ParseCertificateBundle(pemBundle);
        if (certs.Count == 0)
        {
            throw new ArgumentException("No certificates found in PEM bundle.");
        }
        return BuildPkcs7Der(certs);
    }

    private static string ExportCertificateToPem(X509Certificate cert)
    {
        using StringWriter sw = new();
        PemWriter pw = new(sw);
        pw.WriteObject(cert);
        pw.Writer.Flush();
        return sw.ToString().Replace("\r\n", "\n");
    }

    private static X509Certificate ParseFirstCertificate(string pem)
    {
        IList<X509Certificate> certs = ParseCertificateBundle(pem);
        return certs.FirstOrDefault() ?? throw new ArgumentException("Certificate could not be parsed");
    }

    private static IList<X509Certificate> ParseCertificateBundle(string pem)
    {
        List<X509Certificate> list = [];
        using StringReader sr = new(pem);
        PemReader reader = new(sr);
        object? obj;
        while ((obj = reader.ReadObject()) != null)
        {
            if (obj is X509Certificate c)
            {
                list.Add(c);
            }
        }
        return list;
    }

    private static string ExtractCommonName(X509Certificate cert)
    {
        var oids = cert.SubjectDN.GetOidList();
        var values = cert.SubjectDN.GetValueList();
        for (int i = 0; i < oids.Count; i++)
        {
            if (X509Name.CN.Equals(oids[i]))
            {
                return ((string)values[i]!).Trim();
            }
        }
        return string.Empty;
    }

    private static string NormalizePemEnding(string pem)
    {
        return pem.EndsWith('\n') ? pem : pem + "\n";
    }
}

public class KeyPair(string publicKey, string privateKey)
{
    private static readonly char[] newline = ['\n', '\r'];

    public string Public { get; } = publicKey;

    public string Private { get; } = privateKey;

    public string Type()
    {
        AsymmetricKeyParameter privateParam;
        try
        {
            privateParam = ToAsymmetricCipherKeyPair().Private;
        }
        catch (Exception)
        {
            throw new ArgumentException("Could not parse key pair");
        }
        if (privateParam is ECPrivateKeyParameters)
        {
            return "ECDSA";
        }
        else if (privateParam is RsaPrivateCrtKeyParameters)
        {
            return "RSA";
        }
        else
        {
            throw new ArgumentException("Could not parse key pair");
        }
    }

    public AsymmetricCipherKeyPair ToAsymmetricCipherKeyPair()
    {
        AsymmetricKeyParameter publicKey;
        AsymmetricKeyParameter privateKey;
        try
        {
            string t = "";
            foreach (string s in Public.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----")))
            {
                t += s;
            }
            publicKey = PublicKeyFactory.CreateKey(Convert.FromBase64String(t));
        }
        catch (Exception)
        {
            throw new ArgumentException("Could not parse public key.");
        }
        try
        {
            string t = "";
            foreach (string s in Private.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----")))
            {
                t += s;
            }
            privateKey = PrivateKeyFactory.CreateKey(Convert.FromBase64String(t));
        }
        catch (Exception)
        {
            throw new ArgumentException("Could not parse private key.");
        }
        try
        {
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }
        catch (Exception)
        {
            throw new ArgumentException("Could not construct keypair from provided keys.");
        }
    }
}

public class CryptoFactory
{
    private static readonly char[] newline = ['\n', '\r'];

    public string CSRGen(
        KeyPair pair,
        string commonName,
        string[] subjectAlternativeNames,
        string countryCode,
        string stateOrProvinceName,
        string localityName,
        string organization,
        string organizationalUnit,
        string emailAddress)
    {
        IDictionary<DerObjectIdentifier, string> values = new Dictionary<DerObjectIdentifier, string>
        {
            [X509Name.CN] = commonName,
            [X509Name.C] = countryCode,
            [X509Name.ST] = stateOrProvinceName,
            [X509Name.L] = localityName,
            [X509Name.O] = organization,
            [X509Name.OU] = organizationalUnit,
            [X509Name.E] = emailAddress
        };
        IList<DerObjectIdentifier> keys =
        [
            X509Name.CN,
            X509Name.C,
            X509Name.ST,
            X509Name.L,
            X509Name.O,
            X509Name.OU,
            X509Name.E
        ];
        X509Name issuerDN = new(keys, values);

        Dictionary<DerObjectIdentifier, X509Extension> extensions = [];
        if (subjectAlternativeNames.Length > 0)
        {
            GeneralNames san = new(subjectAlternativeNames.Select(n => new GeneralName(GeneralName.DnsName, n)).ToArray());
            Asn1OctetString bytes = new DerOctetString(san);
            extensions.Add(X509Extensions.SubjectAlternativeName, new X509Extension(false, bytes));
        }

        ISignatureFactory sig;
        if (pair.Type() == "RSA")
        {
            sig = new Asn1SignatureFactory("SHA256withRSA", pair.ToAsymmetricCipherKeyPair().Private, new SecureRandom());
        }
        else if (pair.Type() == "ECDSA")
        {
            sig = new Asn1SignatureFactory("SHA256withECDSA", pair.ToAsymmetricCipherKeyPair().Private, new SecureRandom());
        }
        else
        {
            throw new ArgumentException("Could not determine key type");
        }

        Pkcs10CertificationRequest req = new(
            sig,
            issuerDN,
            pair.ToAsymmetricCipherKeyPair().Public,
            new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(new X509Extensions(extensions)))));

        return "-----BEGIN CERTIFICATE REQUEST-----\r\n"
            + StringChunker(Convert.ToBase64String(req.GetEncoded()), 64)
            + "\r\n-----END CERTIFICATE REQUEST-----";
    }

    private static string StringChunker(string input, int length)
    {
        string output = "";
        int i = 0;
        while (i < input.Length)
        {
            if (i + length > input.Length)
            {
                length = input.Length - i;
            }
            output += string.Concat(input.AsSpan(i, length), "\n");
            i += length;
        }
        return output[..^1];
    }

    public KeyPair KeyGen(int keySizeInBits)
    {
        SecureRandom random = new();
        KeyGenerationParameters keyParams = new(random, keySizeInBits);

        return keySizeInBits switch
        {
            256 or 384 or 521 or 2048 or 4096 => KeyGen(keyParams),
            _ => throw new ArgumentException("Invalid key size")
        };
    }

    private static KeyPair KeyGen(KeyGenerationParameters keyParams)
    {
        AsymmetricCipherKeyPair thisKey;

        if (keyParams.Strength is 256 or 384 or 521)
        {
            ECKeyPairGenerator keygen = new();
            keygen.Init(keyParams);
            thisKey = keygen.GenerateKeyPair();
        }
        else if (keyParams.Strength is 2048 or 4096)
        {
            RsaKeyPairGenerator keygen = new();
            keygen.Init(keyParams);
            thisKey = keygen.GenerateKeyPair();
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(keyParams));
        }

        byte[] publicBytes = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(thisKey.Public).ToAsn1Object().GetDerEncoded();
        string publicString =
            "-----BEGIN PUBLIC KEY-----\n"
            + StringChunker(Convert.ToBase64String(publicBytes, 0, publicBytes.Length, Base64FormattingOptions.None), 64)
            + "\n-----END PUBLIC KEY-----";

        byte[] privateBytes = PrivateKeyInfoFactory.CreatePrivateKeyInfo(thisKey.Private).ToAsn1Object().GetDerEncoded();
        string privateString =
            "-----BEGIN PRIVATE KEY-----\n"
            + StringChunker(Convert.ToBase64String(privateBytes, 0, privateBytes.Length, Base64FormattingOptions.None), 64)
            + "\n-----END PRIVATE KEY-----";

        return new KeyPair(publicString, privateString);
    }

    public string DerivePublicKey(string privateKey)
    {
        if (string.IsNullOrWhiteSpace(privateKey))
        {
            return string.Empty;
        }
        string k = "";
        foreach (string s in privateKey.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----")))
        {
            k += s;
        }
        AsymmetricKeyParameter privateParam;
        try
        {
            byte[] privateBytes = Convert.FromBase64String(k);
            privateParam = PrivateKeyFactory.CreateKey(privateBytes);
        }
        catch (Exception)
        {
            throw new ArgumentException("The private key provided could not be decoded");
        }

        AsymmetricCipherKeyPair keyPair;
        if (privateParam is RsaPrivateCrtKeyParameters rsa)
        {
            RsaKeyParameters kp = new(false, rsa.Modulus, rsa.PublicExponent);
            keyPair = new AsymmetricCipherKeyPair(kp, privateParam);
        }
        else if (privateParam is ECPrivateKeyParameters ec)
        {
            ECPoint q = ec.Parameters.G.Multiply(ec.D);
            ECPublicKeyParameters kp = new(ec.AlgorithmName, q, ec.PublicKeyParamSet);
            keyPair = new AsymmetricCipherKeyPair(kp, ec);
        }
        else if (privateParam is Ed25519PrivateKeyParameters ed)
        {
            Ed25519PublicKeyParameters kp = ed.GeneratePublicKey();
            keyPair = new AsymmetricCipherKeyPair(kp, privateParam);
        }
        else
        {
            throw new ArgumentException("The key provided could not be decoded");
        }

        byte[] publicBytes = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).ToAsn1Object().GetDerEncoded();
        return "-----BEGIN PUBLIC KEY-----\n"
            + StringChunker(Convert.ToBase64String(publicBytes, 0, publicBytes.Length, Base64FormattingOptions.None), 64)
            + "\n-----END PUBLIC KEY-----";
    }
}
