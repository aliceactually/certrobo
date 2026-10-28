using CertRobo.Models;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace CertRobo.Services;

public sealed record CaChainElementSummary(
    string Role,
    string Subject,
    string Issuer,
    string SerialNumberHex,
    string ThumbprintSha256,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc,
    int? PathLengthConstraint);

public sealed record CaActivationPreviewSummary(
    string Subject,
    string Issuer,
    string SerialNumberHex,
    string ThumbprintSha256,
    string SubjectKeyIdentifierHex,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc,
    DateTimeOffset UsableChainNotBeforeUtc,
    DateTimeOffset UsableChainNotAfterUtc,
    int? PathLengthConstraint,
    string KeyUsageSummary,
    IReadOnlyList<string> EffectivePermittedEkuOids,
    IReadOnlyList<string> PermittedDnsSubtrees,
    IReadOnlyList<string> ExcludedDnsSubtrees,
    IReadOnlyList<CaChainElementSummary> ChainElements,
    IReadOnlyList<string> MaterialDifferencesFromCsr);

public sealed record CaBundleValidationResult(
    bool IsValid,
    string? ErrorMessage,
    string? ValidatedIssuerCertificatePem,
    string? ValidatedOrderedChainPem,
    CaActivationPreviewSummary? Summary);

public sealed record ActiveChainPolicyRestrictions(
    DateTimeOffset UsableNotBeforeUtc,
    DateTimeOffset UsableNotAfterUtc,
    IReadOnlyList<string>? EffectivePermittedEkuOids,
    IReadOnlyList<IReadOnlyList<string>> PerCaPermittedDnsSubtrees,
    IReadOnlyList<string> CumulativeExcludedDnsSubtrees);

/// <summary>
/// Shared parser and validator for externally signed issuing CA certificates, chains,
/// PKCS#7/PEM/DER bundles, and RFC 5280 chain restrictions (pathLen, EKU, NameConstraints, validity).
/// </summary>
public static class CaChainAndConstraintValidator
{
    public const string AnyExtendedKeyUsageOid = "2.5.29.37.0";
    public const string MsAppPoliciesOid = "1.3.6.1.4.1.311.21.10";
    public const string MsCertTemplateNameOid = "1.3.6.1.4.1.311.20.2";
    public const string MsCertTemplateInfoOid = "1.3.6.1.4.1.311.21.7";

    private static readonly HashSet<string> SupportedCriticalCaExtensionOids = new(StringComparer.Ordinal)
    {
        "2.5.29.19", // BasicConstraints
        "2.5.29.15", // KeyUsage
        "2.5.29.37", // ExtendedKeyUsage
        "2.5.29.30", // NameConstraints
        "2.5.29.14", // SubjectKeyIdentifier
        "2.5.29.35", // AuthorityKeyIdentifier
        "2.5.29.17", // SubjectAlternativeName
        "2.5.29.31", // CRLDistributionPoints
        "1.3.6.1.5.5.7.1.1", // AuthorityInfoAccess
        MsAppPoliciesOid
    };

    /// <summary>
    /// Parses one or more X.509 certificates from PEM (CERTIFICATE or PKCS7/CMS blocks),
    /// Base64 text, binary DER X.509, or binary DER PKCS#7/CMS (.p7b) bundles.
    /// Rejects private key material or PKCS#12 archives in the external signed-certificate completion flow.
    /// </summary>
    public static List<X509Certificate2> ParseCertificatesFromAnyInput(
        byte[]? rawBytes,
        string? textInput,
        string inputLabel)
    {
        List<X509Certificate2> results = [];

        if (rawBytes is { Length: > 0 })
        {
            ParseFromBytes(rawBytes, inputLabel, results);
        }

        if (!string.IsNullOrWhiteSpace(textInput))
        {
            ParseFromText(textInput, inputLabel, results);
        }

        return DeduplicateCertificates(results);
    }

    private static void ParseFromBytes(byte[] data, string inputLabel, List<X509Certificate2> results)
    {
        // Check if the bytes are actually UTF-8/ASCII text containing PEM or Base64
        if (LooksLikePemOrBase64Text(data, out string? asText) && !string.IsNullOrWhiteSpace(asText))
        {
            ParseFromText(asText, inputLabel, results);
            return;
        }

        // Try binary PKCS#7 / CMS first or binary DER certificate
        if (TryExtractCertificatesFromCmsDer(data, results))
        {
            return;
        }

        try
        {
            X509Certificate2 single = X509CertificateLoader.LoadCertificate(data);
            results.Add(single);
            return;
        }
        catch
        {
            // Check if the user accidentally uploaded a PKCS#12 (.p12/.pfx) archive
        }

        throw new ArgumentException($"Could not parse any X.509 certificates from {inputLabel} (supported formats: PEM, DER, and certificate-only PKCS #7 / P7B).");
    }

    private static void ParseFromText(string text, string inputLabel, List<X509Certificate2> results)
    {
        if (text.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"{inputLabel} contains a private key. External CA enrolment uses the locally generated key; use 'Import Existing Issuing CA' to import external private keys.");
        }

        bool foundPemBlock = false;

        // 1. Extract all -----BEGIN CERTIFICATE----- blocks
        MatchCollection certMatches = Regex.Matches(
            text,
            @"-----BEGIN\s+(?:X509\s+)?CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n\t ]+?)\s*-----END\s+(?:X509\s+)?CERTIFICATE-----",
            RegexOptions.CultureInvariant);

        foreach (Match m in certMatches)
        {
            foundPemBlock = true;
            string b64 = Regex.Replace(m.Groups[1].Value, @"\s+", "");
            byte[] der;
            try
            {
                der = Convert.FromBase64String(b64);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException($"Invalid Base64 in CERTIFICATE PEM block of {inputLabel}: {ex.Message}");
            }

            try
            {
                results.Add(X509CertificateLoader.LoadCertificate(der));
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"Malformed X.509 certificate in {inputLabel}: {ex.Message}");
            }
        }

        // 2. Extract all -----BEGIN PKCS7----- or -----BEGIN CMS----- blocks
        MatchCollection pkcs7Matches = Regex.Matches(
            text,
            @"-----BEGIN\s+(?:PKCS7|PKCS\s*#7|CMS)-----\s*([A-Za-z0-9+/=\r\n\t ]+?)\s*-----END\s+(?:PKCS7|PKCS\s*#7|CMS)-----",
            RegexOptions.CultureInvariant);

        foreach (Match m in pkcs7Matches)
        {
            foundPemBlock = true;
            string b64 = Regex.Replace(m.Groups[1].Value, @"\s+", "");
            byte[] cmsDer;
            try
            {
                cmsDer = Convert.FromBase64String(b64);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException($"Invalid Base64 in PKCS#7 PEM block of {inputLabel}: {ex.Message}");
            }

            if (!TryExtractCertificatesFromCmsDer(cmsDer, results))
            {
                throw new ArgumentException($"Could not extract certificates from PKCS #7 / P7B block in {inputLabel}.");
            }
        }

        if (foundPemBlock)
        {
            return;
        }

        if (text.Contains("-----BEGIN ", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"{inputLabel} contains an unsupported PEM block type (expected CERTIFICATE or PKCS7).");
        }

        // 3. Try raw Base64 (without PEM headers) of either DER certificate or DER PKCS#7
        string cleanedBase64 = Regex.Replace(text.Trim(), @"\s+", "");
        if (cleanedBase64.Length > 0)
        {
            byte[] rawDer;
            try
            {
                rawDer = Convert.FromBase64String(cleanedBase64);
            }
            catch (FormatException)
            {
                throw new ArgumentException($"Could not parse {inputLabel} as PEM or Base64-encoded DER/PKCS#7.");
            }

            if (TryExtractCertificatesFromCmsDer(rawDer, results))
            {
                return;
            }

            try
            {
                results.Add(X509CertificateLoader.LoadCertificate(rawDer));
                return;
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"Could not parse Base64 data in {inputLabel} as an X.509 certificate or PKCS #7 bundle: {ex.Message}");
            }
        }
    }

    public static bool TryExtractCertificatesFromCmsDer(byte[] derBytes, List<X509Certificate2> target)
    {
        // First try BouncyCastle CmsSignedData (handles standard PKCS#7, degenerate certs-only P7B, and CMC SignedData)
        try
        {
            CmsSignedData cms = new(derBytes);
            var certStore = cms.GetCertificates();
            var matches = certStore.EnumerateMatches(null);
            int countBefore = target.Count;
            foreach (BcX509Certificate bcCert in matches)
            {
                target.Add(X509CertificateLoader.LoadCertificate(bcCert.GetEncoded()));
            }

            // Also check if the encapsulated content itself is a nested CMC / PKCS#7 or X.509 cert
            if (cms.SignedContent != null)
            {
                using MemoryStream contentStream = new();
                cms.SignedContent.Write(contentStream);
                byte[] innerBytes = contentStream.ToArray();
                if (innerBytes.Length > 0)
                {
                    InspectCmcOrInnerAsn1ForCertificates(innerBytes, target);
                }
            }

            if (target.Count > countBefore)
            {
                return true;
            }
        }
        catch
        {
            // Fallback to BouncyCastle X509CertificateParser.ReadCertificates (which also parses PKCS#7 cert streams)
        }

        try
        {
            var bcCerts = new X509CertificateParser().ReadCertificates(derBytes);
            if (bcCerts is { Count: > 0 })
            {
                foreach (BcX509Certificate bcCert in bcCerts)
                {
                    target.Add(X509CertificateLoader.LoadCertificate(bcCert.GetEncoded()));
                }
                return true;
            }
        }
        catch
        {
            // Not a valid CMS/PKCS#7 structure
        }

        return false;
    }

    private static void InspectCmcOrInnerAsn1ForCertificates(byte[] bytes, List<X509Certificate2> target)
    {
        try
        {
            Asn1Object obj = Asn1Object.FromByteArray(bytes);
            ExtractCertificatesFromAsn1Recursive(obj, target);
        }
        catch
        {
            // Ignore non-ASN.1 inner payload
        }
    }

    private static void ExtractCertificatesFromAsn1Recursive(Asn1Object obj, List<X509Certificate2> target)
    {
        if (obj is Asn1Sequence seq)
        {
            try
            {
                if (seq.Count == 3
                    && seq[0] is Asn1Sequence
                    && seq[1] is Asn1Sequence
                    && seq[2] is DerBitString)
                {
                    X509CertificateStructure certStruct = X509CertificateStructure.GetInstance(seq);
                    if (certStruct.Version >= 1 && certStruct.Subject != null && certStruct.Issuer != null)
                    {
                        target.Add(X509CertificateLoader.LoadCertificate(certStruct.GetDerEncoded()));
                        return;
                    }
                }
            }
            catch
            {
                // Continue traversing children
            }

            foreach (Asn1Encodable item in seq)
            {
                ExtractCertificatesFromAsn1Recursive(item.ToAsn1Object(), target);
            }
        }
        else if (obj is Asn1Set set)
        {
            foreach (Asn1Encodable item in set)
            {
                ExtractCertificatesFromAsn1Recursive(item.ToAsn1Object(), target);
            }
        }
        else if (obj is Asn1TaggedObject tagged)
        {
            ExtractCertificatesFromAsn1Recursive(tagged.GetExplicitBaseObject().ToAsn1Object(), target);
        }
    }

    private static bool LooksLikePemOrBase64Text(byte[] bytes, out string? text)
    {
        text = null;
        if (bytes.Length == 0)
        {
            return false;
        }

        // DER ASN.1 SEQUENCE always starts with 0x30
        if (bytes[0] == 0x30)
        {
            return false;
        }

        for (int i = 0; i < Math.Min(bytes.Length, 128); i++)
        {
            byte b = bytes[i];
            if (b < 0x09 || (b > 0x0D && b < 0x20))
            {
                return false;
            }
        }

        text = Encoding.UTF8.GetString(bytes);
        return true;
    }

    public static List<X509Certificate2> DeduplicateCertificates(IEnumerable<X509Certificate2> certs)
    {
        List<X509Certificate2> unique = [];
        HashSet<string> seenThumbprints = new(StringComparer.OrdinalIgnoreCase);

        foreach (X509Certificate2 c in certs)
        {
            string sha256 = c.GetCertHashString(HashAlgorithmName.SHA256);
            if (seenThumbprints.Add(sha256))
            {
                unique.Add(c);
            }
            else
            {
                c.Dispose();
            }
        }

        return unique;
    }

    /// <summary>
    /// Validates a signed issuing CA certificate and its parent/root chain against a pending PKCS#10 CSR and private key.
    /// Enforces key match, CA BasicConstraints, KeyCertSign|CrlSign, validity periods, unambiguous cryptographic signature chain
    /// to an explicitly supplied root trust anchor, path-length limits for leaf issuance, EKU constraints, NameConstraints,
    /// and critical extension safety.
    /// </summary>
    public static CaBundleValidationResult ValidateSignedCaAndBuildActivationSummary(
        string csrPem,
        AsymmetricAlgorithm pendingPrivateKey,
        IReadOnlyList<X509Certificate2> primaryCertCandidates,
        IReadOnlyList<X509Certificate2> additionalChainCandidates,
        DateTimeOffset? validationTimeUtc = null)
    {
        DateTimeOffset now = validationTimeUtc ?? DateTimeOffset.UtcNow;

        if (primaryCertCandidates.Count == 0 && additionalChainCandidates.Count == 0)
        {
            return new(false, "No certificates were provided for validation.", null, null, null);
        }

        Pkcs10CertificationRequest decodedCsr;
        byte[] expectedSpkiDer;
        try
        {
            decodedCsr = (new PemReader(new StringReader(csrPem)).ReadObject() as Pkcs10CertificationRequest)
                ?? throw new ArgumentException("Pending CSR could not be decoded.");
            if (!decodedCsr.Verify())
            {
                return new(false, "Pending CSR self-signature verification failed.", null, null, null);
            }
            expectedSpkiDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(decodedCsr.GetPublicKey()).GetDerEncoded();
        }
        catch (Exception ex)
        {
            return new(false, $"Failed to decode pending CSR: {ex.Message}", null, null, null);
        }

        byte[] privateKeySpkiDer = ExportPublicKeySpki(pendingPrivateKey);
        if (!expectedSpkiDer.SequenceEqual(privateKeySpkiDer))
        {
            return new(false, "Pending private key does not match the pending CSR public key.", null, null, null);
        }

        // Pool all unique certificates from primary and chain inputs
        List<X509Certificate2> allCerts = [];
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        foreach (X509Certificate2 c in primaryCertCandidates.Concat(additionalChainCandidates))
        {
            string fp = c.GetCertHashString(HashAlgorithmName.SHA256);
            if (seen.Add(fp))
            {
                allCerts.Add(c);
            }
        }

        // 1. Find the certificate whose public key matches the pending private key
        List<X509Certificate2> matchingKeyCerts = allCerts
            .Where(c => c.PublicKey.ExportSubjectPublicKeyInfo().SequenceEqual(expectedSpkiDer))
            .ToList();

        if (matchingKeyCerts.Count == 0)
        {
            return new(
                false,
                "None of the supplied certificates match the pending CA private key. Ensure you uploaded the certificate issued for the current pending CSR.",
                null,
                null,
                null);
        }
        if (matchingKeyCerts.Count > 1)
        {
            return new(
                false,
                $"The supplied bundle contains {matchingKeyCerts.Count} different certificates for the pending CA public key. Select exactly one signed CA certificate to avoid ambiguous activation.",
                null,
                null,
                null);
        }

        X509Certificate2 candidateCaCert = matchingKeyCerts[0];

        // Reject self-signed certificate in external CA completion workflow
        if (IsSelfSignedCryptographically(candidateCaCert))
        {
            return new(
                false,
                "The supplied certificate is self-signed. External CA enrolment requires a subordinate CA certificate signed by an external parent CA.",
                null,
                null,
                null);
        }

        // 2. Verify BasicConstraints on candidate issuing CA
        X509BasicConstraintsExtension? caBc = candidateCaCert.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault();

        if (caBc == null || !caBc.CertificateAuthority)
        {
            return new(
                false,
                $"Certificate '{candidateCaCert.Subject}' is not a valid CA certificate (BasicConstraints CA=true is required).",
                null,
                null,
                null);
        }
        if (!caBc.Critical)
        {
            return new(
                false,
                $"CA certificate '{candidateCaCert.Subject}' BasicConstraints extension must be critical for CA use under RFC 5280.",
                null,
                null,
                null);
        }

        // 3. Verify KeyUsage on candidate issuing CA
        X509KeyUsageExtension? caKu = candidateCaCert.Extensions
            .OfType<X509KeyUsageExtension>()
            .FirstOrDefault();

        if (caKu == null)
        {
            return new(
                false,
                $"CA certificate '{candidateCaCert.Subject}' is missing the required KeyUsage extension (KeyCertSign and CrlSign are required).",
                null,
                null,
                null);
        }

        if ((caKu.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0)
        {
            return new(
                false,
                $"CA certificate '{candidateCaCert.Subject}' KeyUsage ({caKu.KeyUsages}) does not include KeyCertSign.",
                null,
                null,
                null);
        }

        if ((caKu.KeyUsages & X509KeyUsageFlags.CrlSign) == 0)
        {
            return new(
                false,
                $"CA certificate '{candidateCaCert.Subject}' KeyUsage ({caKu.KeyUsages}) does not include CrlSign, which CertRobo requires to publish CRLs.",
                null,
                null,
                null);
        }

        // 4. Verify validity window of candidate issuing CA
        DateTimeOffset caNotBefore = candidateCaCert.NotBefore.ToUniversalTime();
        DateTimeOffset caNotAfter = candidateCaCert.NotAfter.ToUniversalTime();
        if (now < caNotBefore)
        {
            return new(
                false,
                $"CA certificate '{candidateCaCert.Subject}' is not yet valid (NotBefore: {caNotBefore:yyyy-MM-dd HH:mm:ss} UTC).",
                null,
                null,
                null);
        }
        if (now > caNotAfter)
        {
            return new(
                false,
                $"CA certificate '{candidateCaCert.Subject}' has expired (NotAfter: {caNotAfter:yyyy-MM-dd HH:mm:ss} UTC).",
                null,
                null,
                null);
        }

        // 5. Resolve unambiguous cryptographic signature chain up to an explicitly supplied self-signed Root CA trust anchor
        string candidateThumbprint = candidateCaCert.GetCertHashString(HashAlgorithmName.SHA256);
        List<X509Certificate2> otherCerts = allCerts
            .Where(c => !c.GetCertHashString(HashAlgorithmName.SHA256).Equals(candidateThumbprint, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (otherCerts.Count == 0)
        {
            return new(
                false,
                "Parent/root CA certificate chain is missing. Supply the signing parent and root CA certificate(s) to verify the chain.",
                candidateCaCert.ExportCertificatePem() + "\n",
                null,
                null);
        }

        var (chainResolved, chainError, orderedChain) = ResolveUnambiguousCryptographicChain(candidateCaCert, otherCerts);
        if (!chainResolved || orderedChain == null)
        {
            return new(
                false,
                chainError ?? "Failed to resolve a valid signature chain to an explicitly supplied root CA trust anchor.",
                candidateCaCert.ExportCertificatePem() + "\n",
                null,
                null);
        }

        // orderedChain[0] is candidateCaCert, orderedChain[1] is immediate parent, ..., orderedChain[^1] is self-signed Root CA
        // 6. Validate validity periods, BasicConstraints, KeyUsage, pathLengthConstraint, and extensions across the entire chain
        int nonSelfIssuedIntermediateCountBelow = 1; // candidateCaCert itself is 1 non-self-issued intermediate CA when it issues leaf certs!
        for (int i = 1; i < orderedChain.Count; i++)
        {
            X509Certificate2 ancestor = orderedChain[i];
            bool isRoot = i == orderedChain.Count - 1;
            string roleName = isRoot ? "Root CA" : $"Parent Intermediate CA #{i}";

            DateTimeOffset ancNotBefore = ancestor.NotBefore.ToUniversalTime();
            DateTimeOffset ancNotAfter = ancestor.NotAfter.ToUniversalTime();
            if (now < ancNotBefore)
            {
                return new(
                    false,
                    $"{roleName} '{ancestor.Subject}' is not yet valid (NotBefore: {ancNotBefore:yyyy-MM-dd HH:mm:ss} UTC).",
                    null,
                    null,
                    null);
            }
            if (now > ancNotAfter)
            {
                return new(
                    false,
                    $"{roleName} '{ancestor.Subject}' has expired (NotAfter: {ancNotAfter:yyyy-MM-dd HH:mm:ss} UTC).",
                    null,
                    null,
                    null);
            }

            X509BasicConstraintsExtension? ancBc = ancestor.Extensions
                .OfType<X509BasicConstraintsExtension>()
                .FirstOrDefault();

            if (ancBc == null || !ancBc.CertificateAuthority)
            {
                return new(
                    false,
                    $"{roleName} '{ancestor.Subject}' is not a valid CA certificate (BasicConstraints CA=true is missing).",
                    null,
                    null,
                    null);
            }
            if (!ancBc.Critical)
            {
                return new(
                    false,
                    $"{roleName} '{ancestor.Subject}' BasicConstraints extension is not critical as required for CA use under RFC 5280.",
                    null,
                    null,
                    null);
            }

            if (ancBc.HasPathLengthConstraint && ancBc.PathLengthConstraint < nonSelfIssuedIntermediateCountBelow)
            {
                return new(
                    false,
                    $"{roleName} '{ancestor.Subject}' has BasicConstraints pathLenConstraint={ancBc.PathLengthConstraint}, which is exceeded when '{candidateCaCert.Subject}' acts as an issuing intermediate CA (requires pathLenConstraint >= {nonSelfIssuedIntermediateCountBelow}).",
                    null,
                    null,
                    null);
            }

            X509KeyUsageExtension? ancKu = ancestor.Extensions
                .OfType<X509KeyUsageExtension>()
                .FirstOrDefault();

            if (ancKu != null && (ancKu.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0)
            {
                return new(
                    false,
                    $"{roleName} '{ancestor.Subject}' KeyUsage ({ancKu.KeyUsages}) does not allow KeyCertSign.",
                    null,
                    null,
                    null);
            }

            if (!IsSelfIssued(ancestor))
            {
                nonSelfIssuedIntermediateCountBelow++;
            }
        }

        // 7. Inspect critical extensions, EKU constraints, and NameConstraints before asking the
        // platform chain builder, so unsupported restrictions produce an actionable error.
        var (restrictionsOk, restrictionsError, restrictions, displayPermittedDns, displayExcludedDns) =
            EvaluateChainExtensionsAndRestrictions(orderedChain);

        if (!restrictionsOk || restrictions == null)
        {
            return new(false, restrictionsError ?? "CA chain contains unsupported restrictions.", null, null, null);
        }

        // 8. Also verify via .NET X509Chain with CustomRootTrust (never trusting OS store)
        using (X509Chain dotNetChain = new())
        {
            dotNetChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            dotNetChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            dotNetChain.ChainPolicy.VerificationTime = now.UtcDateTime;

            for (int i = 1; i < orderedChain.Count - 1; i++)
            {
                dotNetChain.ChainPolicy.ExtraStore.Add(orderedChain[i]);
            }
            dotNetChain.ChainPolicy.CustomTrustStore.Add(orderedChain[^1]);

            if (!dotNetChain.Build(candidateCaCert))
            {
                string statuses = string.Join(", ", dotNetChain.ChainStatus.Select(s => $"{s.Status}: {s.StatusInformation}"));
                return new(
                    false,
                    $"X.509 chain validation failed: {statuses}",
                    null,
                    null,
                    null);
            }
        }

        // 9. Build ordered chain PEM (excluding index 0 which is candidateCaCert itself)
        StringBuilder chainPemBuilder = new();
        for (int i = 1; i < orderedChain.Count; i++)
        {
            chainPemBuilder.AppendLine(orderedChain[i].ExportCertificatePem().Trim());
        }

        string issuerCertPem = candidateCaCert.ExportCertificatePem().Trim() + "\n";
        string orderedChainPem = chainPemBuilder.ToString();

        // 10. Compute material differences between CSR and returned signed CA certificate
        List<string> differences = ComputeMaterialDifferencesFromCsr(
            decodedCsr,
            candidateCaCert,
            caBc,
            caKu,
            restrictions,
            displayPermittedDns,
            displayExcludedDns);

        List<CaChainElementSummary> elementSummaries = [];
        for (int i = 0; i < orderedChain.Count; i++)
        {
            X509Certificate2 c = orderedChain[i];
            X509BasicConstraintsExtension? bc = c.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            string role = i == 0
                ? "Issuing Intermediate CA"
                : (i == orderedChain.Count - 1 ? "Root CA (Trust Anchor)" : $"Intermediate CA #{i}");

            elementSummaries.Add(new CaChainElementSummary(
                role,
                c.Subject,
                c.Issuer,
                c.SerialNumber,
                c.GetCertHashString(HashAlgorithmName.SHA256),
                c.NotBefore.ToUniversalTime(),
                c.NotAfter.ToUniversalTime(),
                bc is { HasPathLengthConstraint: true } ? bc.PathLengthConstraint : null));
        }

        string skiHex = candidateCaCert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault()?.SubjectKeyIdentifier
            ?? candidateCaCert.GetCertHashString(HashAlgorithmName.SHA256);

        CaActivationPreviewSummary summary = new(
            Subject: candidateCaCert.Subject,
            Issuer: candidateCaCert.Issuer,
            SerialNumberHex: candidateCaCert.SerialNumber,
            ThumbprintSha256: candidateCaCert.GetCertHashString(HashAlgorithmName.SHA256),
            SubjectKeyIdentifierHex: skiHex,
            NotBeforeUtc: caNotBefore,
            NotAfterUtc: caNotAfter,
            UsableChainNotBeforeUtc: restrictions.UsableNotBeforeUtc,
            UsableChainNotAfterUtc: restrictions.UsableNotAfterUtc,
            PathLengthConstraint: caBc.HasPathLengthConstraint ? caBc.PathLengthConstraint : null,
            KeyUsageSummary: caKu.KeyUsages.ToString(),
            EffectivePermittedEkuOids: restrictions.EffectivePermittedEkuOids ?? [],
            PermittedDnsSubtrees: displayPermittedDns,
            ExcludedDnsSubtrees: displayExcludedDns,
            ChainElements: elementSummaries,
            MaterialDifferencesFromCsr: differences);

        return new(true, null, issuerCertPem, orderedChainPem, summary);
    }

    private static (bool Succeeded, string? ErrorMessage, List<X509Certificate2>? OrderedChain) ResolveUnambiguousCryptographicChain(
        X509Certificate2 leafCaCert,
        IReadOnlyList<X509Certificate2> candidateAncestors)
    {
        List<List<X509Certificate2>> validChainsToRoot = [];
        List<string> verifyFailureReasons = [];

        void Walk(List<X509Certificate2> currentPath, HashSet<string> visitedThumbprints)
        {
            X509Certificate2 current = currentPath[^1];

            // Find all candidate parents that cryptographically signed `current`
            List<X509Certificate2> matchingParents = [];
            foreach (X509Certificate2 candidateParent in candidateAncestors)
            {
                string parentFp = candidateParent.GetCertHashString(HashAlgorithmName.SHA256);
                if (visitedThumbprints.Contains(parentFp))
                {
                    continue;
                }

                // Check AKI/SKI if both present with KeyIdentifier
                if (!IsAkiCompatibleWithParentSki(current, candidateParent))
                {
                    continue;
                }

                if (VerifySignatureCryptographically(current, candidateParent, out string? sigErr))
                {
                    matchingParents.Add(candidateParent);
                }
                else if (current.IssuerName.RawData.SequenceEqual(candidateParent.SubjectName.RawData) && sigErr != null)
                {
                    verifyFailureReasons.Add($"Signature verification failed for '{current.Subject}' against candidate issuer '{candidateParent.Subject}': {sigErr}");
                }
            }

            foreach (X509Certificate2 parent in matchingParents)
            {
                string parentFp = parent.GetCertHashString(HashAlgorithmName.SHA256);
                List<X509Certificate2> nextPath = [.. currentPath, parent];
                HashSet<string> nextVisited = new(visitedThumbprints, StringComparer.OrdinalIgnoreCase) { parentFp };

                if (IsSelfIssued(parent))
                {
                    if (VerifySignatureCryptographically(parent, parent, out string? rootSigErr))
                    {
                        validChainsToRoot.Add(nextPath);
                    }
                    else
                    {
                        verifyFailureReasons.Add($"Root CA '{parent.Subject}' failed self-signature verification: {rootSigErr}");
                    }
                }
                else
                {
                    Walk(nextPath, nextVisited);
                }
            }
        }

        string startFp = leafCaCert.GetCertHashString(HashAlgorithmName.SHA256);
        Walk([leafCaCert], new HashSet<string>(StringComparer.OrdinalIgnoreCase) { startFp });

        if (validChainsToRoot.Count == 0)
        {
            if (verifyFailureReasons.Count > 0)
            {
                return (false, string.Join(" ", verifyFailureReasons.Distinct()), null);
            }
            return (
                false,
                $"Could not build a complete cryptographic signature chain from '{leafCaCert.Subject}' (Issuer: '{leafCaCert.Issuer}') to a self-signed root CA trust anchor in the supplied bundle.",
                null);
        }

        if (validChainsToRoot.Count > 1)
        {
            return (
                false,
                $"Supplied certificate bundle contains {validChainsToRoot.Count} ambiguous certification paths for '{leafCaCert.Subject}'. Provide only the authoritative signing chain.",
                null);
        }

        return (true, null, validChainsToRoot[0]);
    }

    public static (
        bool IsValid,
        string? ErrorMessage,
        ActiveChainPolicyRestrictions? Restrictions,
        List<string> DisplayPermittedDns,
        List<string> DisplayExcludedDns)
        EvaluateChainExtensionsAndRestrictions(IReadOnlyList<X509Certificate2> orderedChain)
    {
        DateTimeOffset maxNotBefore = orderedChain.Max(c => c.NotBefore.ToUniversalTime());
        DateTimeOffset minNotAfter = orderedChain.Min(c => c.NotAfter.ToUniversalTime());

        HashSet<string>? effectivePermittedEkus = null;
        List<IReadOnlyList<string>> perCaPermittedDns = [];
        List<string> displayPermittedDns = [];
        List<string> cumulativeExcludedDns = [];

        X509CertificateParser bcParser = new();

        foreach (X509Certificate2 cert in orderedChain)
        {
            BcX509Certificate bcCert = bcParser.ReadCertificate(cert.RawData);

            // 1. Check for unsupported critical extensions
            foreach (System.Security.Cryptography.X509Certificates.X509Extension ext in cert.Extensions)
            {
                string oid = ext.Oid?.Value ?? string.Empty;
                if (ext.Critical && !SupportedCriticalCaExtensionOids.Contains(oid))
                {
                    string friendly = ext.Oid?.FriendlyName ?? oid;
                    return (
                        false,
                        $"Certificate '{cert.Subject}' contains an unsupported critical extension '{friendly}' ({oid}) that CertRobo cannot safely enforce.",
                        null,
                        [],
                        []);
                }
            }

            // 2. Check ExtendedKeyUsage (2.5.29.37) and Microsoft Application Policies (1.3.6.1.4.1.311.21.10)
            HashSet<string>? certEkus = ExtractCaEkuConstraintOids(cert);
            if (certEkus != null && !certEkus.Contains(AnyExtendedKeyUsageOid))
            {
                if (effectivePermittedEkus == null)
                {
                    effectivePermittedEkus = new HashSet<string>(certEkus, StringComparer.Ordinal);
                }
                else
                {
                    effectivePermittedEkus.IntersectWith(certEkus);
                }
            }

            // 3. Check NameConstraints (2.5.29.30)
            Asn1OctetString? ncOctets = bcCert.GetExtensionValue(X509Extensions.NameConstraints);
            if (ncOctets != null)
            {
                NameConstraints nc;
                try
                {
                    nc = NameConstraints.GetInstance(Asn1Object.FromByteArray(ncOctets.GetOctets()));
                }
                catch (Exception ex)
                {
                    return (
                        false,
                        $"Certificate '{cert.Subject}' contains a malformed NameConstraints extension: {ex.Message}",
                        null,
                        [],
                        []);
                }

                List<string> caPermittedDns = [];
                if (nc.PermittedSubtrees != null)
                {
                    foreach (Asn1Encodable item in nc.PermittedSubtrees)
                    {
                        GeneralSubtree subtree = GeneralSubtree.GetInstance(item);
                        var (subtreeOk, subtreeErr, dnsPattern) = ValidateAndExtractDnsSubtree(cert.Subject, "permitted", subtree);
                        if (!subtreeOk || dnsPattern == null)
                        {
                            return (false, subtreeErr, null, [], []);
                        }
                        caPermittedDns.Add(dnsPattern);
                        if (!displayPermittedDns.Contains(dnsPattern, StringComparer.OrdinalIgnoreCase))
                        {
                            displayPermittedDns.Add(dnsPattern);
                        }
                    }

                    if (caPermittedDns.Count == 0)
                    {
                        return (
                            false,
                            $"Certificate '{cert.Subject}' contains an empty PermittedSubtrees sequence in NameConstraints.",
                            null,
                            [],
                            []);
                    }

                    perCaPermittedDns.Add(caPermittedDns);
                }

                if (nc.ExcludedSubtrees != null)
                {
                    foreach (Asn1Encodable item in nc.ExcludedSubtrees)
                    {
                        GeneralSubtree subtree = GeneralSubtree.GetInstance(item);
                        var (subtreeOk, subtreeErr, dnsPattern) = ValidateAndExtractDnsSubtree(cert.Subject, "excluded", subtree);
                        if (!subtreeOk || dnsPattern == null)
                        {
                            return (false, subtreeErr, null, [], []);
                        }
                        if (!cumulativeExcludedDns.Contains(dnsPattern, StringComparer.OrdinalIgnoreCase))
                        {
                            cumulativeExcludedDns.Add(dnsPattern);
                        }
                    }
                }
            }
        }

        // Verify that if EKU constraints are present on the chain, TLS Server Authentication (1.3.6.1.5.5.7.3.1) is permitted
        if (effectivePermittedEkus != null && !effectivePermittedEkus.Contains(CertificateProfiles.ServerAuthOid))
        {
            string allowedList = effectivePermittedEkus.Count == 0
                ? "(none)"
                : string.Join(", ", effectivePermittedEkus);
            return (
                false,
                $"CA chain restricts Extended Key Usage to [{allowedList}], which does not permit TLS Server Authentication ({CertificateProfiles.ServerAuthOid}) required by CertRobo profiles.",
                null,
                [],
                []);
        }

        // Verify that if multiple CAs in the chain have PermittedSubtrees, they are not mutually disjoint
        if (perCaPermittedDns.Count > 1)
        {
            List<string> cumulativeIntersections = [.. perCaPermittedDns[0]];
            for (int i = 1; i < perCaPermittedDns.Count; i++)
            {
                List<string> nextIntersections = [];
                foreach (string existing in cumulativeIntersections)
                {
                    foreach (string next in perCaPermittedDns[i])
                    {
                        if (TryIntersectDnsSubtrees(existing, next, out string? intersection)
                            && intersection != null
                            && !nextIntersections.Contains(intersection, StringComparer.OrdinalIgnoreCase))
                        {
                            nextIntersections.Add(intersection);
                        }
                    }
                }

                if (nextIntersections.Count == 0)
                {
                    return (
                        false,
                        "CA chain contains mutually disjoint DNS NameConstraints across ancestor CAs, leaving no valid DNS namespace for leaf issuance.",
                        null,
                        [],
                        []);
                }
                cumulativeIntersections = nextIntersections;
            }
        }

        ActiveChainPolicyRestrictions result = new(
            UsableNotBeforeUtc: maxNotBefore,
            UsableNotAfterUtc: minNotAfter,
            EffectivePermittedEkuOids: effectivePermittedEkus?.OrderBy(x => x, StringComparer.Ordinal).ToList(),
            PerCaPermittedDnsSubtrees: perCaPermittedDns,
            CumulativeExcludedDnsSubtrees: cumulativeExcludedDns);

        return (true, null, result, displayPermittedDns, cumulativeExcludedDns);
    }

    /// <summary>
    /// Evaluates whether a list of canonical leaf DNS identities (including wildcards) is permitted by
    /// the active CA chain's NameConstraints.
    /// </summary>
    public static (bool IsAllowed, string? DenialReason) ValidateIdentitiesAgainstChainNameConstraints(
        IReadOnlyList<string> canonicalDnsIdentities,
        ActiveChainPolicyRestrictions chainRestrictions)
    {
        foreach (string identity in canonicalDnsIdentities)
        {
            // 1. Check every CA's PermittedSubtrees (must match at least one subtree in each CA that specifies PermittedSubtrees)
            for (int caIdx = 0; caIdx < chainRestrictions.PerCaPermittedDnsSubtrees.Count; caIdx++)
            {
                IReadOnlyList<string> caPermitted = chainRestrictions.PerCaPermittedDnsSubtrees[caIdx];
                bool matchesPermitted = caPermitted.Any(subtree => DoesDnsIdentitySatisfyPermittedSubtree(identity, subtree));
                if (!matchesPermitted)
                {
                    return (
                        false,
                        $"Requested DNS identity '{identity}' is not within the issuing CA chain's permitted NameConstraints ({string.Join(", ", caPermitted)}).");
                }
            }

            // 2. Check ExcludedSubtrees (must not match or overlap any excluded subtree)
            foreach (string excluded in chainRestrictions.CumulativeExcludedDnsSubtrees)
            {
                if (DoesDnsIdentityMatchOrOverlapExcludedSubtree(identity, excluded))
                {
                    return (
                        false,
                        $"Requested DNS identity '{identity}' is forbidden by the issuing CA chain's excluded NameConstraints ('{excluded}').");
                }
            }
        }

        return (true, null);
    }

    public static bool DoesDnsIdentitySatisfyPermittedSubtree(string identity, string permittedSubtree)
    {
        string normId = identity.Trim().TrimEnd('.').ToLowerInvariant();
        string normTree = permittedSubtree.Trim().TrimEnd('.').ToLowerInvariant();

        if (string.IsNullOrEmpty(normId) || string.IsNullOrEmpty(normTree))
        {
            return false;
        }

        bool isWildcard = normId.StartsWith("*.");
        string hostPart = isWildcard ? normId[2..] : normId;

        if (normTree.StartsWith('.'))
        {
            string baseDomain = normTree[1..]; // e.g. "contoso.com" for ".contoso.com"
            if (isWildcard)
            {
                // *.contoso.com or *.sub.contoso.com expands to labels under .contoso.com
                return hostPart.Equals(baseDomain, StringComparison.OrdinalIgnoreCase)
                    || hostPart.EndsWith(normTree, StringComparison.OrdinalIgnoreCase);
            }

            return normId.EndsWith(normTree, StringComparison.OrdinalIgnoreCase)
                && normId.Length > normTree.Length;
        }
        else
        {
            // Standard RFC 5280: zero or more labels added to the left of normTree
            return hostPart.Equals(normTree, StringComparison.OrdinalIgnoreCase)
                || hostPart.EndsWith("." + normTree, StringComparison.OrdinalIgnoreCase);
        }
    }

    public static bool DoesDnsIdentityMatchOrOverlapExcludedSubtree(string identity, string excludedSubtree)
    {
        string normId = identity.Trim().TrimEnd('.').ToLowerInvariant();
        string normEx = excludedSubtree.Trim().TrimEnd('.').ToLowerInvariant();

        if (string.IsNullOrEmpty(normId) || string.IsNullOrEmpty(normEx))
        {
            return false;
        }

        // If the identity directly falls inside the excluded subtree, it's forbidden
        if (DoesDnsIdentitySatisfyPermittedSubtree(normId, normEx))
        {
            return true;
        }

        // Additionally, if the requested identity is a wildcard *.hostPart, check if the excluded subtree
        // is a subdomain underneath hostPart (e.g., wildcard *.contoso.com overlaps excluded admin.contoso.com)
        if (normId.StartsWith("*."))
        {
            string hostPart = normId[2..];
            string cleanEx = normEx.StartsWith('.') ? normEx[1..] : normEx;
            if (cleanEx.EndsWith("." + hostPart, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryIntersectDnsSubtrees(
        string subtreeA,
        string subtreeB,
        out string? intersection)
    {
        intersection = null;
        string a = subtreeA.ToLowerInvariant();
        string b = subtreeB.ToLowerInvariant();
        string cleanA = a.TrimStart('.');
        string cleanB = b.TrimStart('.');

        if (cleanA.Equals(cleanB, StringComparison.OrdinalIgnoreCase))
        {
            // A leading dot excludes the apex and is therefore the narrower intersection.
            intersection = a.StartsWith('.') || b.StartsWith('.') ? "." + cleanA : cleanA;
            return true;
        }

        if (cleanA.EndsWith("." + cleanB, StringComparison.OrdinalIgnoreCase))
        {
            intersection = a;
            return true;
        }

        if (cleanB.EndsWith("." + cleanA, StringComparison.OrdinalIgnoreCase))
        {
            intersection = b;
            return true;
        }

        return false;
    }

    private static (bool IsValid, string? ErrorMessage, string? CanonicalDnsSubtree) ValidateAndExtractDnsSubtree(
        string certSubject,
        string subtreeKind,
        GeneralSubtree subtree)
    {
        if (subtree.Minimum != null && subtree.Minimum.IntValueExact != 0)
        {
            return (
                false,
                $"Certificate '{certSubject}' contains a NameConstraints {subtreeKind} subtree with non-zero minimum ({subtree.Minimum}), which is invalid under RFC 5280.",
                null);
        }

        if (subtree.Maximum != null)
        {
            return (
                false,
                $"Certificate '{certSubject}' contains a NameConstraints {subtreeKind} subtree with a maximum distance ({subtree.Maximum}), which is invalid under RFC 5280.",
                null);
        }

        GeneralName baseName = subtree.Base;
        if (baseName.TagNo != GeneralName.DnsName)
        {
            string tagDesc = baseName.TagNo switch
            {
                GeneralName.Rfc822Name => "rfc822Name (email)",
                GeneralName.DirectoryName => "directoryName (X.500 DN)",
                GeneralName.UniformResourceIdentifier => "uniformResourceIdentifier (URI)",
                GeneralName.IPAddress => "iPAddress",
                _ => $"GeneralName tag {baseName.TagNo}"
            };

            return (
                false,
                $"Certificate '{certSubject}' contains a NameConstraints {subtreeKind} subtree of type '{tagDesc}', which CertRobo cannot safely enforce. Only dNSName NameConstraints subtrees are supported.",
                null);
        }

        string rawDns = DerIA5String.GetInstance(baseName.Name).GetString().Trim().TrimEnd('.');
        if (string.IsNullOrWhiteSpace(rawDns))
        {
            return (
                false,
                $"Certificate '{certSubject}' contains an empty dNSName in NameConstraints {subtreeKind} subtrees (universal DNS exclusion/constraint is not usable for leaf issuance).",
                null);
        }

        bool leadingDot = rawDns.StartsWith('.');
        string hostPart = leadingDot ? rawDns[1..] : rawDns;
        if (string.IsNullOrWhiteSpace(hostPart) || hostPart.Contains('*'))
        {
            return (
                false,
                $"Certificate '{certSubject}' contains an invalid dNSName subtree '{rawDns}' in NameConstraints.",
                null);
        }

        try
        {
            IdnMapping idn = new();
            hostPart = idn.GetAscii(hostPart).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return (
                false,
                $"Certificate '{certSubject}' contains a malformed internationalized dNSName subtree '{rawDns}' in NameConstraints.",
                null);
        }

        if (Uri.CheckHostName(hostPart) != UriHostNameType.Dns)
        {
            return (
                false,
                $"Certificate '{certSubject}' contains an invalid dNSName subtree '{rawDns}' in NameConstraints.",
                null);
        }

        return (true, null, leadingDot ? "." + hostPart : hostPart);
    }

    public static HashSet<string>? ExtractCaEkuConstraintOids(X509Certificate2 cert)
    {
        HashSet<string>? combined = null;

        X509EnhancedKeyUsageExtension? ekuExt = cert.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();

        if (ekuExt != null)
        {
            combined = new HashSet<string>(
                ekuExt.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value!).Where(v => !string.IsNullOrEmpty(v)),
                StringComparer.Ordinal);
        }

        // Also check Microsoft Application Policies (1.3.6.1.4.1.311.21.10) if present on an AD CS-issued certificate
        System.Security.Cryptography.X509Certificates.X509Extension? msAppPol = cert.Extensions
            .FirstOrDefault(e => e.Oid?.Value == MsAppPoliciesOid);

        if (msAppPol != null)
        {
            try
            {
                Asn1Sequence seq = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(msAppPol.RawData));
                HashSet<string> appPolicyOids = new(StringComparer.Ordinal);
                foreach (Asn1Encodable item in seq)
                {
                    if (item is Asn1Sequence policyInfo && policyInfo.Count > 0 && policyInfo[0] is DerObjectIdentifier policyOid)
                    {
                        appPolicyOids.Add(policyOid.Id);
                    }
                }

                if (appPolicyOids.Count == 0)
                {
                    return [];
                }

                if (!appPolicyOids.Contains(AnyExtendedKeyUsageOid))
                {
                    if (combined == null)
                    {
                        combined = appPolicyOids;
                    }
                    else if (!combined.Contains(AnyExtendedKeyUsageOid))
                    {
                        combined.IntersectWith(appPolicyOids);
                    }
                    else
                    {
                        combined = appPolicyOids;
                    }
                }
                else
                {
                    combined ??= appPolicyOids;
                }
            }
            catch
            {
                return [];
            }
        }

        return combined;
    }

    private static List<string> ComputeMaterialDifferencesFromCsr(
        Pkcs10CertificationRequest csr,
        X509Certificate2 issuedCaCert,
        X509BasicConstraintsExtension actualBc,
        X509KeyUsageExtension actualKu,
        ActiveChainPolicyRestrictions restrictions,
        IReadOnlyList<string> permittedDns,
        IReadOnlyList<string> excludedDns)
    {
        List<string> diffs = [];
        CertificationRequestInfo info = csr.GetCertificationRequestInfo();

        // 1. Compare Subject DN (canonicalized RDN comparison)
        BcX509Certificate bcCert = new X509CertificateParser().ReadCertificate(issuedCaCert.RawData);
        if (!info.Subject.Equivalent(bcCert.SubjectDN, inOrder: false))
        {
            diffs.Add($"Subject DN changed by parent CA: requested '{info.Subject}', issued '{bcCert.SubjectDN}'.");
        }

        // Extract requested BasicConstraints and KeyUsage from CSR attributes
        int? requestedPathLen = null;
        bool requestedBcPresent = false;
        X509KeyUsageFlags? requestedKu = null;

        if (info.Attributes != null)
        {
            foreach (Asn1Encodable attr in info.Attributes)
            {
                AttributePkcs pkcsAttr = AttributePkcs.GetInstance(attr);
                if (PkcsObjectIdentifiers.Pkcs9AtExtensionRequest.Equals(pkcsAttr.AttrType))
                {
                    foreach (Asn1Encodable extSet in pkcsAttr.AttrValues)
                    {
                        X509Extensions exts = X509Extensions.GetInstance(extSet);
                        Org.BouncyCastle.Asn1.X509.X509Extension bcExt = exts.GetExtension(X509Extensions.BasicConstraints);
                        if (bcExt != null)
                        {
                            requestedBcPresent = true;
                            BasicConstraints reqBc = BasicConstraints.GetInstance(Asn1OctetString.GetInstance(bcExt.Value).GetOctets());
                            requestedPathLen = reqBc.PathLenConstraint != null ? reqBc.PathLenConstraint.IntValueExact : null;
                        }

                        Org.BouncyCastle.Asn1.X509.X509Extension kuExt = exts.GetExtension(X509Extensions.KeyUsage);
                        if (kuExt != null)
                        {
                            var rawKuExt = new System.Security.Cryptography.X509Certificates.X509Extension(
                                X509Extensions.KeyUsage.Id,
                                Asn1OctetString.GetInstance(kuExt.Value).GetOctets(),
                                kuExt.IsCritical);
                            X509KeyUsageExtension parsedReqKu = new(rawKuExt, kuExt.IsCritical);
                            requestedKu = parsedReqKu.KeyUsages;
                        }
                    }
                }
            }
        }

        // 2. Compare BasicConstraints pathLenConstraint
        int? actualPathLen = actualBc.HasPathLengthConstraint ? actualBc.PathLengthConstraint : null;
        if (requestedBcPresent && requestedPathLen != actualPathLen)
        {
            string reqStr = requestedPathLen.HasValue ? $"pathLenConstraint={requestedPathLen.Value}" : "unconstrained pathLen";
            string actStr = actualPathLen.HasValue ? $"pathLenConstraint={actualPathLen.Value}" : "unconstrained pathLen";
            diffs.Add($"BasicConstraints path length modified by parent template: requested {reqStr}, issued with {actStr}.");
        }

        // 3. Compare KeyUsage
        if (requestedKu.HasValue && requestedKu.Value != actualKu.KeyUsages)
        {
            diffs.Add($"KeyUsage modified by parent template: requested '{requestedKu.Value}', issued with '{actualKu.KeyUsages}'.");
        }

        // 4. Note EKU restrictions if added by parent CA / chain
        if (restrictions.EffectivePermittedEkuOids is { Count: > 0 })
        {
            diffs.Add($"Chain restricts Extended Key Usage to: {string.Join(", ", restrictions.EffectivePermittedEkuOids)}.");
        }

        // 5. Note NameConstraints if present on issued CA or parent chain
        if (permittedDns.Count > 0)
        {
            diffs.Add($"Chain enforces Permitted DNS NameConstraints: {string.Join(", ", permittedDns)}.");
        }
        if (excludedDns.Count > 0)
        {
            diffs.Add($"Chain enforces Excluded DNS NameConstraints: {string.Join(", ", excludedDns)}.");
        }

        // 6. Note if a parent/root certificate expires earlier than the issued CA certificate
        DateTimeOffset caNotAfter = issuedCaCert.NotAfter.ToUniversalTime();
        if (restrictions.UsableNotAfterUtc < caNotAfter)
        {
            diffs.Add($"Parent/root chain expires at {restrictions.UsableNotAfterUtc:yyyy-MM-dd HH:mm:ss} UTC, which is earlier than the issued CA certificate ({caNotAfter:yyyy-MM-dd HH:mm:ss} UTC). Leaf lifetimes will be bounded to {restrictions.UsableNotAfterUtc:yyyy-MM-dd HH:mm:ss} UTC.");
        }

        return diffs;
    }

    public static bool IsSelfIssued(X509Certificate2 cert)
    {
        return cert.SubjectName.RawData.SequenceEqual(cert.IssuerName.RawData);
    }

    public static bool IsSelfSignedCryptographically(X509Certificate2 cert)
    {
        if (!IsSelfIssued(cert))
        {
            return false;
        }
        return VerifySignatureCryptographically(cert, cert, out _);
    }

    public static bool VerifySignatureCryptographically(
        X509Certificate2 child,
        X509Certificate2 issuer,
        out string? errorMessage)
    {
        try
        {
            X509CertificateParser parser = new();
            BcX509Certificate bcChild = parser.ReadCertificate(child.RawData);
            BcX509Certificate bcIssuer = parser.ReadCertificate(issuer.RawData);
            bcChild.Verify(bcIssuer.GetPublicKey());
            errorMessage = null;
            return true;
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            return false;
        }
    }

    private static bool IsAkiCompatibleWithParentSki(X509Certificate2 child, X509Certificate2 parent)
    {
        X509AuthorityKeyIdentifierExtension? childAki = child.Extensions
            .OfType<X509AuthorityKeyIdentifierExtension>()
            .FirstOrDefault();

        X509SubjectKeyIdentifierExtension? parentSki = parent.Extensions
            .OfType<X509SubjectKeyIdentifierExtension>()
            .FirstOrDefault();

        if (childAki?.KeyIdentifier is { Length: > 0 } akiBytes && parentSki?.SubjectKeyIdentifierBytes is { Length: > 0 } skiBytes)
        {
            return akiBytes.Span.SequenceEqual(skiBytes.Span);
        }

        return true;
    }

    private static byte[] ExportPublicKeySpki(AsymmetricAlgorithm key)
    {
        return key switch
        {
            RSA rsa => rsa.ExportSubjectPublicKeyInfo(),
            ECDsa ecdsa => ecdsa.ExportSubjectPublicKeyInfo(),
            _ => throw new NotSupportedException($"Unsupported key type {key.GetType().Name}")
        };
    }
}
