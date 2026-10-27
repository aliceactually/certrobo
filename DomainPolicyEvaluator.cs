using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace CertRobo;

/// <summary>
/// Evaluates domain authorization patterns and extracts/validates CSR identities.
/// Preserves existing CertRobo domain pattern semantics where '*.contoso.com' matches
/// subdomains (including wildcard certificates like '*.contoso.com') AND the apex 'contoso.com'.
/// </summary>
public static class DomainPolicyEvaluator
{
    public static bool DomainMatchesPattern(string domain, string pattern)
    {
        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(pattern))
        {
            return false;
        }

        string canonicalDomain = CanonicalizeDomainPatternOrIdentity(domain);
        string canonicalPattern = CanonicalizeDomainPatternOrIdentity(pattern);
        if (string.IsNullOrEmpty(canonicalDomain) || string.IsNullOrEmpty(canonicalPattern))
        {
            return false;
        }

        if (canonicalPattern == "*")
        {
            return true;
        }

        if (canonicalPattern.StartsWith("*."))
        {
            string suffix = canonicalPattern[1..]; // e.g. ".contoso.com"
            return canonicalDomain.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
                || canonicalDomain.Equals(suffix[1..], StringComparison.OrdinalIgnoreCase);
        }

        return canonicalDomain.Equals(canonicalPattern, StringComparison.OrdinalIgnoreCase);
    }

    public static string CanonicalizeDomainPatternOrIdentity(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        string trimmed = input.Trim().TrimEnd('.');
        if (trimmed == "*")
        {
            return "*";
        }

        bool isWildcard = false;
        string hostPart = trimmed;
        if (trimmed.StartsWith("*."))
        {
            isWildcard = true;
            hostPart = trimmed[2..];
        }

        if (string.IsNullOrEmpty(hostPart))
        {
            return string.Empty;
        }

        try
        {
            IdnMapping idn = new();
            hostPart = idn.GetAscii(hostPart);
        }
        catch (ArgumentException)
        {
            return string.Empty;
        }

        hostPart = hostPart.ToLowerInvariant();
        return isWildcard ? "*." + hostPart : hostPart;
    }

    public static bool ValidateFqdn(string input)
    {
        if (Uri.CheckHostName(input) == UriHostNameType.Dns)
        {
            if (input.Split('.').Length > 2)
            {
                return true;
            }
        }
        return false;
    }

    public static bool IsValidEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return false;
        }
        try
        {
            email = Regex.Replace(email, @"(@)(.+)$", DomainMapper, RegexOptions.None, TimeSpan.FromMilliseconds(200));

            string DomainMapper(Match match)
            {
                IdnMapping idn = new();
                string domainName = idn.GetAscii(match.Groups[2].Value);
                return match.Groups[1].Value + domainName;
            }
        }
        catch (RegexMatchTimeoutException) { return false; }
        catch (ArgumentException) { return false; }

        try
        {
            return Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250));
        }
        catch (RegexMatchTimeoutException) { return false; }
    }

    public static List<string> GetDomainsFromCsr(string csrPem)
    {
        List<string> domains = new();
        Pkcs10CertificationRequest? decoded = new PemReader(new StringReader(csrPem)).ReadObject() as Pkcs10CertificationRequest
            ?? throw new ArgumentException("Could not decode CSR PEM.");

        CertificationRequestInfo info = decoded.GetCertificationRequestInfo();

        var oids = info.Subject.GetOidList();
        var values = info.Subject.GetValueList();
        for (int i = 0; i < oids.Count; i++)
        {
            if (X509Name.CN.Equals(oids[i]))
            {
                string cn = (string)values[i]!;
                if (!string.IsNullOrWhiteSpace(cn))
                {
                    domains.Add(cn);
                }
            }
        }

        Asn1Set attributes = info.Attributes;
        if (attributes != null)
        {
            foreach (Asn1Encodable attr in attributes)
            {
                AttributePkcs pkcsAttr = AttributePkcs.GetInstance(attr);
                if (PkcsObjectIdentifiers.Pkcs9AtExtensionRequest.Equals(pkcsAttr.AttrType))
                {
                    foreach (Asn1Encodable extSet in pkcsAttr.AttrValues)
                    {
                        X509Extensions extensions = X509Extensions.GetInstance(extSet);
                        X509Extension sanExt = extensions.GetExtension(X509Extensions.SubjectAlternativeName);
                        if (sanExt != null)
                        {
                            GeneralNames sans = GeneralNames.GetInstance(Asn1OctetString.GetInstance(sanExt.Value).GetOctets());
                            foreach (GeneralName gn in sans.GetNames())
                            {
                                if (gn.TagNo == GeneralName.DnsName)
                                {
                                    domains.Add(gn.Name.ToString()!);
                                }
                            }
                        }
                    }
                }
            }
        }
        return domains.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
