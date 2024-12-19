using ICSharpCode.SharpZipLib.Zip;
using Microsoft.PowerShell;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Operators;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Xml.Linq;

namespace CertRobo
{
    public class PkcsBuilder
    {
    static readonly char[] newline = ([ '\n', '\r' ]);

    string? _cert;
    string? _key;

        public PkcsBuilder() { }

        public PkcsBuilder(string certificate, string privateKey)
        {
            _cert = certificate;
            _key = privateKey;
        }

        public string? Certificate
        {
            get { return _cert; }
            set
            {
                if (value != null)
                {
                    string cn = "";
                    try
                    {
                        string c = "";
                        foreach (string s in value.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----"))) { c += s; }
                        X509Certificate cert = new(Convert.FromBase64String(c));
                        foreach (string s in cert.SubjectDN.ToString().Split(',')) { if (s.StartsWith("CN=")) { cn = s.Split('=').Last(); } }
                    }
                    catch { throw new ArgumentException("Certificate could not be parsed"); }
                    if (cn == string.Empty) { throw new ArgumentException("Certificate does not contain a Common Name"); }
                }
                _cert = value;
            }
        }

        public string? PrivateKey
        {
            get { return _key; }
            set
            {
                if (value != null)
                {
                    try
                    {
                        string t = string.Empty;
                        foreach (string s in value.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----"))) { t += s; }
                        PrivateKeyFactory.CreateKey(Convert.FromBase64String(t));
                    }
                    catch { throw new ArgumentException("Private key could not be parsed"); }
                }
                _key = value;
            }
        }

        public string CN
        {
            get
            {
                if (_cert == null) { return string.Empty; }
                string c = string.Empty;
                foreach (string s in _cert.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----"))) { c += s; }
                X509Certificate cert = new(Convert.FromBase64String(c));
                foreach (string s in cert.SubjectDN.ToString().Split(',')) { if (s.StartsWith("CN=")) { return s.Split('=').Last(); } }
                // This will only happen if the certificate lacks a CN, which is certainly some kind of user error, but...
                return string.Empty;
            }
        }
        private static bool CertKeyCheck(string certificate, string privateKey)
        {
            if (certificate == null || privateKey == null) { return false; }
            string k = string.Empty;
            foreach (string s in privateKey.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----"))) { k += s; }
            AsymmetricKeyParameter privateParam = PrivateKeyFactory.CreateKey(Convert.FromBase64String(k));
            string c = string.Empty;
            foreach (string s in certificate.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----"))) { c += s; }
            X509Certificate cert = new(Convert.FromBase64String(c));
            AsymmetricKeyParameter publicParam = cert.GetPublicKey();

            if (privateParam is RsaPrivateCrtKeyParameters privRsa && publicParam is RsaKeyParameters pubRsa)
            {
                if (privRsa.Modulus.Equals(pubRsa.Modulus) && privRsa.PublicExponent.Equals(pubRsa.Exponent)) { return true; }
            }
            else if (privateParam is ECPrivateKeyParameters privEc && publicParam is ECPublicKeyParameters pubEc)
            {
                ECPoint q = privEc.Parameters.G.Multiply(privEc.D);
                ECPublicKeyParameters derived = new(privEc.AlgorithmName, q, privEc.PublicKeyParamSet);
                if (derived.Q.Equals(pubEc.Q)) { return true; }
            }
            else if (privateParam is Ed25519PrivateKeyParameters privEd && publicParam is Ed25519PublicKeyParameters pubEd)
            {
                if (pubEd.GetEncoded().SequenceEqual(privEd.GeneratePublicKey().GetEncoded())) { return true; }
            }
            return false;
        }

        public static Tuple<string, byte[]>? Export(string certificate, string privateKey)
        {
            // Determine what we have, if we have anything. Start with the certificate itself and radiate out.
            string c = "";
            foreach (string s in certificate.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----"))) { c += s; }

            // Test the certificate and abort if needed.
            X509Certificate cert;
            try { cert = new(Convert.FromBase64String(c)); }
            catch { return null; }

            // Fetch the root certificate from static
            string r = "";
            foreach (string s in File.ReadAllText("static/rootca.crt").Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----"))) { r += s; }
            X509Certificate root;
            string rootAlgo;
            try 
            { 
                root = new(Convert.FromBase64String(r));
                rootAlgo = root.SubjectPublicKeyInfo.Algorithm.Algorithm.GetID();
            }
            catch { return null; }

            // Let's find out if this certificate was signed by the root
            bool chain = true;
            try { cert.Verify(root.GetPublicKey()); }
            catch { chain = false; }

            string cn = "";
            foreach (string s in cert.SubjectDN.ToString().Split(',')) { if (s.StartsWith("CN=")) { cn = s.Split('=').Last(); } }
            MemoryStream output = new();
            ZipOutputStream zipStream = new(output);

            // Base64
            zipStream.PutNextEntry(new ZipEntry(cn + ".crt"));
            zipStream.Write(Encoding.ASCII.GetBytes(certificate));
            
            // Base64, chained
            if (chain)
            {
                zipStream.PutNextEntry(new ZipEntry(cn + "-chained.crt"));
                zipStream.Write(Encoding.ASCII.GetBytes(certificate));
                zipStream.Write(File.ReadAllBytes("static/rootca.crt"));
            }
            
            if (privateKey != string.Empty)
            {
                string k = "";
                foreach (string s in privateKey.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----"))) { k += s; }
                AsymmetricKeyParameter p = PrivateKeyFactory.CreateKey(Convert.FromBase64String(k));
                if (p is RsaPrivateCrtKeyParameters || p is ECPrivateKeyParameters || p is Ed25519PrivateKeyParameters)
                {
                    if (CertKeyCheck(certificate, privateKey))
                    {
                        // Base64, with key
                        zipStream.PutNextEntry(new ZipEntry(cn + ".key"));
                        zipStream.Write(Encoding.ASCII.GetBytes(privateKey));
                        zipStream.PutNextEntry(new ZipEntry(cn + ".pem"));
                        zipStream.Write(Encoding.ASCII.GetBytes(certificate));
                        zipStream.Write(Encoding.ASCII.GetBytes(privateKey));

                        // Base64, with key, chained
                        if (chain)
                        {
                            zipStream.PutNextEntry(new ZipEntry(cn + "-chained.pem"));
                            zipStream.Write(Encoding.ASCII.GetBytes(certificate));
                            zipStream.Write(File.ReadAllBytes("static/rootca.crt"));
                            zipStream.Write(Encoding.ASCII.GetBytes(privateKey));
                        }

                        // PKCS #12
                        Pkcs12StoreBuilder builder = new();
                        builder.SetUseDerEncoding(true);
                        Pkcs12Store store = builder.Build();
                        store.SetKeyEntry(string.Empty, new AsymmetricKeyEntry(p), new X509CertificateEntry[] { new(cert) });
                        byte[] pkcs;
                        using (MemoryStream stream = new())
                        {
                            store.Save(stream, null, new SecureRandom());
                            pkcs = stream.ToArray();
                        }
                        zipStream.PutNextEntry(new ZipEntry(cn + ".p12"));
                        zipStream.Write(pkcs);

                        // PKCS #12, chained
                        if (chain)
                        {
                            builder = new();
                            builder.SetUseDerEncoding(true);
                            store = builder.Build();
                            store.SetKeyEntry(string.Empty, new AsymmetricKeyEntry(p), new X509CertificateEntry[] { new(cert), new(root) });
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
            zipStream.Close();
            return new Tuple<string, byte[]>((cn + ".zip"), output.ToArray());
        }
    }

    public class KeyPair(string publicKey, string privateKey)
    {
        static readonly char[] newline = (['\n', '\r']);

        public string Public { get; } = publicKey;

        public string Private { get; } = privateKey;

        public string Type()
        {
            AsymmetricKeyParameter privateParam;
            try { privateParam = ToAsymmetricCipherKeyPair().Private; }
            catch (Exception) { throw new ArgumentException("Could not parse key pair"); }
            if (privateParam.GetType().ToString() == "Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters") { return "ECDSA"; }
            else if (privateParam.GetType().ToString() == "Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters") { return "RSA"; }
            else { throw new ArgumentException("Could not parse key pair"); }
        }

        public AsymmetricCipherKeyPair ToAsymmetricCipherKeyPair()
        {
            AsymmetricKeyParameter publicKey;
            AsymmetricKeyParameter privateKey;
            try
            {
                string t = "";
                foreach (string s in Public.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----"))) { t += s; }
                publicKey = PublicKeyFactory.CreateKey(Convert.FromBase64String(t));
            }
            catch (Exception) { throw new ArgumentException("Could not parse public key."); }
            try
            {
                string t = "";
                foreach (string s in Private.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----"))) { t += s; }
                privateKey = PrivateKeyFactory.CreateKey(Convert.FromBase64String(t));
            }
            catch (Exception) { throw new ArgumentException("Could not parse private key."); }
            try { return new AsymmetricCipherKeyPair(publicKey, privateKey); }
            catch (Exception) { throw new ArgumentException("Could not construct keypair from provided keys."); }
        }
    }

    public class CryptoFactory
    {
        static private readonly char[] newline = (['\n', '\r']);
        static private readonly XDocument settings = XDocument.Load("static/settings.xml");

        public string CSRGen(KeyPair pair, string commonName, string[] subjectAlternativeNames, string countryCode,
            string stateOrProvinceName, string localityName, string organization, string organizationalUnit, string emailAddress)
        {

            IDictionary<DerObjectIdentifier,string> values = new Dictionary<DerObjectIdentifier, string>
            {
                [X509Name.CN] = commonName,
                [X509Name.C] = countryCode,
                [X509Name.ST] = stateOrProvinceName,
                [X509Name.L] = localityName,
                [X509Name.O] = organization,
                [X509Name.OU] = organizationalUnit,
                [X509Name.E] = emailAddress
            };
            IList<DerObjectIdentifier> keys = new List<DerObjectIdentifier>()
            {
                X509Name.CN,
                X509Name.C,
                X509Name.ST,
                X509Name.L,
                X509Name.O,
                X509Name.OU,
                X509Name.E
            };
            X509Name issuerDN = new(keys, values);

            Dictionary<DerObjectIdentifier, X509Extension> extensions = [];
            if (subjectAlternativeNames.Length > 0)
            {
                GeneralNames san = new(subjectAlternativeNames.Select(n => new GeneralName(GeneralName.DnsName, n)).ToArray());
                Asn1OctetString bytes = new DerOctetString(san);
                extensions.Add(X509Extensions.SubjectAlternativeName, new X509Extension(false, bytes));
            }

            ISignatureFactory sig;
            if (pair.Type() == "RSA") { sig = new Asn1SignatureFactory("SHA256withRSA", pair.ToAsymmetricCipherKeyPair().Private, new SecureRandom()); }
            else if (pair.Type() == "ECDSA") { sig = new Asn1SignatureFactory("SHA256withECDSA", pair.ToAsymmetricCipherKeyPair().Private, new SecureRandom()); }
            else { throw new ArgumentException("Could not determine key type"); }

            Pkcs10CertificationRequest req = new(sig, issuerDN, pair.ToAsymmetricCipherKeyPair().Public,
                new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(new X509Extensions(extensions)))));
            return "-----BEGIN CERTIFICATE REQUEST-----\r\n" + StringChunker(Convert.ToBase64String(req.GetEncoded()), 64) + "\r\n-----END CERTIFICATE REQUEST-----";
        }

        private static string StringChunker(string input, int length)
        {
            string output = "";
            int i = 0;
            while (i < input.Length)
            {
                if (i + length > input.Length) { length = input.Length - i; }
                output += string.Concat(input.AsSpan(i, length), "\n");
                i += length;
            }
            return output[..^1];
        }

        public KeyPair KeyGen(int keySizeInBits)
        {
            SecureRandom random = new();
            KeyGenerationParameters keyParams = new(random, keySizeInBits);

            // NISTP-521 is supported, but since it's not Suite B compliant it's not exposed in the UI. No harm leaving it in here for future use.
            return keySizeInBits switch
            {
                256 or 384 or 521 or 2048 or 4096 => KeyGen(keyParams),
                _ => throw new ArgumentException("Invalid key size")
            };
        }

        private static KeyPair KeyGen(KeyGenerationParameters keyParams)
        {
            AsymmetricCipherKeyPair thisKey;

            if (keyParams.Strength == 256 || keyParams.Strength == 384 || keyParams.Strength == 521)
            {
                ECKeyPairGenerator keygen = new();
                keygen.Init(keyParams);
                thisKey = keygen.GenerateKeyPair();
            }
            else if (keyParams.Strength == 2048 || keyParams.Strength == 4096)
            {
                RsaKeyPairGenerator keygen = new();
                keygen.Init(keyParams);
                thisKey = keygen.GenerateKeyPair();
            }
            else { throw new ArgumentOutOfRangeException(nameof(keyParams)); }

            byte[] publicBytes = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(thisKey.Public).ToAsn1Object().GetDerEncoded();
            string publicString =
                "-----BEGIN PUBLIC KEY-----\n"
                + StringChunker(Convert.ToBase64String(publicBytes, 0, publicBytes.Length, Base64FormattingOptions.None), 64)
                + "\n-----END PUBLIC KEY-----";

            byte[] privateBytes = PrivateKeyInfoFactory.CreatePrivateKeyInfo(thisKey.Private).ToAsn1Object().GetDerEncoded();
            string privateString;
            privateString =
                "-----BEGIN PRIVATE KEY-----\n"
                + StringChunker(Convert.ToBase64String(privateBytes, 0, privateBytes.Length, Base64FormattingOptions.None), 64)
                + "\n-----END PRIVATE KEY-----";

            return new KeyPair(publicString, privateString);
        }

        public string DerivePublicKey(string privateKey)
        {
            string k = "";
            foreach (string s in privateKey.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----"))) { k += s; }
            AsymmetricKeyParameter privateParam;
            try
            {
                byte[] privateBytes = Convert.FromBase64String(k);
                privateParam = PrivateKeyFactory.CreateKey(privateBytes);
            }
            catch (Exception) { throw new ArgumentException("The private key provided could not be decoded"); }

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
                try { throw new NotSupportedException($"The key type {k.GetType().Name} is not supported"); }
                catch { throw new ArgumentException("The key provided could not be decoded"); }
            }

            byte[] publicBytes = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).ToAsn1Object().GetDerEncoded();
            string publicString =
                "-----BEGIN PUBLIC KEY-----\n"
                + StringChunker(Convert.ToBase64String(publicBytes, 0, publicBytes.Length, Base64FormattingOptions.None), 64)
                + "\n-----END PUBLIC KEY-----";

            return publicString;
        }

        public static string RequestCert(string csr)
        {
            // TODO: Convert.TryFromBase64String fails where Convert.FromBase64String in a try block succeeds. Not sure why. Is this input validation good enough?
            string c = "";
            foreach (string s in csr.Split(newline, StringSplitOptions.RemoveEmptyEntries).Where(s => !s.StartsWith("-----"))) { c += s; }
            try { Convert.FromBase64String(c); }
            catch { throw new ArgumentException("The CSR provided could not be decoded from base64"); }

            string request = Path.GetTempFileName();
            StreamWriter requestStream = File.CreateText(request);
            requestStream.Write(c);
            requestStream.Close();
            string response = Path.GetTempFileName();

            InitialSessionState state = InitialSessionState.CreateDefault();
            state.ExecutionPolicy = ExecutionPolicy.Unrestricted;
            PowerShell shell = PowerShell.Create(state);
            
            XElement root = settings.Root ?? new XElement("null");
            if (root.Value.Equals("null")) { return string.Empty; }
            string server = Enumerable.FirstOrDefault(root.Elements("Server"), new XElement("null")).Value;
            string template = Enumerable.FirstOrDefault(root.Elements("Template"), new XElement("null")).Value;
            if (server.Equals(string.Empty) || template.Equals(string.Empty)) { return string.Empty; }

            // If we got this far, we should have everything we need to do this successfully...
            shell.AddScript("certreq -f -q -submit -attrib \"CertificateTemplate:" + template + "\" -config \"" + server + "\" " + request + " " + response, true);

            IEnumerable<PSObject> result = shell.Invoke();
            if (shell.HadErrors)
            {
                string error = "";
                foreach (PSObject obj in result)
                {
                    // This cast should never actually result in a null being returned, but since the compiler does not know that, we need to validate it to avoid a null dereference warning
                    string? thisErr = obj.BaseObject.ToString();
                    if (!object.Equals(thisErr, null)) { error += obj.ToString().Trim() + "\r\n"; }
                    else { error += "An error occurred, but a null reference exception was encountered while attempting to retrieve the error details\r\n"; }
                }
                throw new InvalidOperationException("An exception was thrown by Certreq while attempting to issue the certificate: \"" + error.TrimEnd() + "\"");
            }

            StreamReader responseStream = File.OpenText(response);
            string output = responseStream.ReadToEnd();
            responseStream.Close();
            File.Delete(request);
            File.Delete(response);

            return output;
        }
    }
}
