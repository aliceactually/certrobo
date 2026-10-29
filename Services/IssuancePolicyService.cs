using CertRobo.Data;
using CertRobo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using PemObject = Org.BouncyCastle.Utilities.IO.Pem.PemObject;

namespace CertRobo.Services;

public sealed record ValidatedCsrRequest(
    Pkcs10CertificationRequest DecodedCsr,
    AsymmetricKeyParameter PublicKey,
    CertificateProfileDefinition Profile,
    string CommonName,
    IReadOnlyList<string> CanonicalDnsIdentities,
    X509Name SubjectName);

public sealed record PolicyEvaluationResult(
    bool IsAllowed,
    string? DenialReason,
    ValidatedCsrRequest? ValidatedRequest,
    ApplicationUser? User);

/// <summary>
/// Server-side policy and CSR validation boundary.
/// Verifies user account status, SecurityStamp/roles, CSR signature, key type/size,
/// requested extensions/SAN types, and domain authorization rules.
/// </summary>
public sealed class IssuancePolicyService(
    UserManager<ApplicationUser> userManager,
    CertRoboDbContext dbContext)
{
    public const int MaxCsrPemLength = 32 * 1024;
    public const int MaxCsrDerBytes = 16 * 1024;
    public const int MaxCsrSubjectRdns = 32;
    public const int MaxCsrAttributes = 16;
    public const int MaxCsrExtensions = 16;
    public const int MaxCsrDnsSanEntries = 128;

    public async Task<PolicyEvaluationResult> EvaluateCsrRequestAsync(
        string? userId,
        string? csrPem,
        string? explicitProfileId = null,
        string? expectedSecurityStamp = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userId))
        {
            return new(false, "User authentication is required.", null, null);
        }

        ApplicationUser? user = await userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return new(false, "Authenticated user record was not found.", null, null);
        }

        if (user.IsDisabled || (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTimeOffset.UtcNow))
        {
            return new(false, "User account is disabled or locked out.", null, user);
        }

        if (!string.IsNullOrEmpty(expectedSecurityStamp)
            && !string.Equals(user.SecurityStamp, expectedSecurityStamp, StringComparison.Ordinal))
        {
            return new(false, "User session has been invalidated. Please sign in again.", null, user);
        }

        IList<string> userRoles = await userManager.GetRolesAsync(user);
        bool isIssuerOrAdmin = userRoles.Any(r =>
            r.Equals(AppRoles.Issuer, StringComparison.OrdinalIgnoreCase)
            || r.Equals(AppRoles.Administrator, StringComparison.OrdinalIgnoreCase));

        if (!isIssuerOrAdmin)
        {
            return new(false, "User does not have permission to request certificates.", null, user);
        }

        var (csrValid, csrError, validatedCsr) = ParseAndValidateCsr(csrPem, explicitProfileId);
        if (!csrValid || validatedCsr == null)
        {
            return new(false, csrError ?? "CSR validation failed.", null, user);
        }

        // Gather applicable DomainPermissionRules for this user and their roles
        List<DomainPermissionRule> rules = await dbContext.DomainPermissionRules
            .Where(r =>
                (r.SubjectType == "User" && r.SubjectValue == user.Id)
                || (r.SubjectType == "Role" && userRoles.Contains(r.SubjectValue)))
            .ToListAsync(cancellationToken);

        // Filter rules that allow the resolved profile
        List<DomainPermissionRule> profileMatchingRules = rules
            .Where(r => r.AllowedProfileId == "*"
                     || r.AllowedProfileId.Equals(validatedCsr.Profile.ProfileId, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (profileMatchingRules.Count == 0)
        {
            return new(
                false,
                $"You are not authorised to request certificates for profile '{validatedCsr.Profile.ProfileId}'.",
                validatedCsr,
                user);
        }

        List<string> deniedDomains = validatedCsr.CanonicalDnsIdentities
            .Where(domain => !profileMatchingRules.Any(rule =>
                DomainPolicyEvaluator.DomainMatchesPattern(domain, rule.DomainPattern)))
            .ToList();

        if (deniedDomains.Count > 0)
        {
            return new(
                false,
                "You are not authorised to request certificates for: " + string.Join(", ", deniedDomains),
                validatedCsr,
                user);
        }

        return new(true, null, validatedCsr, user);
    }

    public static (bool IsValid, string? ErrorMessage, ValidatedCsrRequest? Result) ParseAndValidateCsr(
        string? csrPem,
        string? explicitProfileId = null)
    {
        if (string.IsNullOrWhiteSpace(csrPem))
        {
            return (false, "You must provide a CSR before requesting a certificate", null);
        }

        if (csrPem.Length > MaxCsrPemLength)
        {
            return (false, $"The CSR provided exceeds the maximum permitted length ({MaxCsrPemLength} characters)", null);
        }

        Pkcs10CertificationRequest decoded;
        try
        {
            using StringReader sr = new(csrPem);
            PemReader pemReader = new(sr);
            PemObject? pemObj = pemReader.ReadPemObject();
            if (pemObj == null
                || (!string.Equals(pemObj.Type, "CERTIFICATE REQUEST", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(pemObj.Type, "NEW CERTIFICATE REQUEST", StringComparison.OrdinalIgnoreCase)))
            {
                return (false, "The CSR provided could not be decoded", null);
            }

            if (pemObj.Content is not { Length: > 0 } || pemObj.Content.Length > MaxCsrDerBytes)
            {
                return (false, $"The CSR provided exceeds the maximum permitted decoded size ({MaxCsrDerBytes} bytes)", null);
            }

            if (pemReader.ReadPemObject() != null)
            {
                return (false, "The CSR provided must contain a single certificate signing request", null);
            }

            decoded = new Pkcs10CertificationRequest(pemObj.Content);
        }
        catch (Exception)
        {
            return (false, "The CSR provided could not be decoded", null);
        }

        AsymmetricKeyParameter publicKey;
        try
        {
            publicKey = decoded.GetPublicKey();
            if (publicKey == null)
            {
                return (false, "The CSR provided could not be decoded", null);
            }
        }
        catch (Exception)
        {
            return (false, "The CSR provided could not be decoded", null);
        }

        // Verify the CSR proof-of-possession signature
        try
        {
            if (!decoded.Verify(publicKey))
            {
                return (false, "CSR signature verification failed", null);
            }
        }
        catch (Exception)
        {
            return (false, "CSR signature verification failed", null);
        }

        CertificateKeyFamily keyFamily;
        int keyBits;
        if (publicKey is RsaKeyParameters rsa)
        {
            keyFamily = CertificateKeyFamily.Rsa;
            keyBits = rsa.Modulus.BitLength;
            if (keyBits != 2048 && keyBits != 4096)
            {
                return (false, $"The CSR provided uses an unsupported RSA key length ({keyBits})", null);
            }
        }
        else if (publicKey is ECPublicKeyParameters ec)
        {
            keyFamily = CertificateKeyFamily.Ecdsa;
            keyBits = ec.Parameters.N.BitLength;
            if (keyBits != 256 && keyBits != 384)
            {
                return (false, $"The CSR provided uses an unsupported EC key length ({keyBits})", null);
            }
        }
        else if (publicKey is Ed25519PublicKeyParameters)
        {
            return (false, "The CSR provided uses ED25519, which is not supported", null);
        }
        else
        {
            return (false, "The CSR provided uses an unsupported algorithm", null);
        }

        CertificateProfileDefinition? profile;
        if (!string.IsNullOrWhiteSpace(explicitProfileId))
        {
            if (!CertificateProfiles.All.TryGetValue(explicitProfileId, out profile))
            {
                return (false, $"Unknown certificate profile '{explicitProfileId}'", null);
            }
            if (profile.KeyFamily != keyFamily || profile.KeyBits != keyBits)
            {
                return (false, $"CSR key ({keyFamily} {keyBits}) does not match profile '{profile.ProfileId}'", null);
            }
        }
        else
        {
            profile = CertificateProfiles.ResolveForKey(keyFamily, keyBits);
            if (profile == null)
            {
                return (false, "No certificate profile matches the CSR key algorithm and size", null);
            }
        }

        CertificationRequestInfo info;
        X509Name subject;
        List<string> rawDnsNames = [];
        string commonName = string.Empty;

        try
        {
            info = decoded.GetCertificationRequestInfo();
            subject = info.Subject ?? throw new ArgumentException("CSR subject is missing.");

            // Extract and validate CN
            var oids = subject.GetOidList();
            var values = subject.GetValueList();
            if (oids.Count > MaxCsrSubjectRdns || values.Count != oids.Count)
            {
                return (false, $"CSR subject contains too many relative distinguished names (maximum {MaxCsrSubjectRdns})", null);
            }

            for (int i = 0; i < oids.Count; i++)
            {
                if (X509Name.CN.Equals(oids[i]))
                {
                    string cnVal = ((string)values[i]!).Trim();
                    if (!string.IsNullOrEmpty(cnVal))
                    {
                        if (string.IsNullOrEmpty(commonName))
                        {
                            commonName = cnVal;
                        }
                        rawDnsNames.Add(cnVal);
                    }
                }
                else if (X509Name.C.Equals(oids[i]))
                {
                    string countryVal = ((string)values[i]!).Trim();
                    if (!string.IsNullOrEmpty(countryVal) && countryVal.Length != 2)
                    {
                        return (false, "Subject Country (C) must be a two-letter ISO 3166 country code", null);
                    }
                }
            }

            // Inspect attributes and requested extensions; reject unsupported extensions (like CA BasicConstraints) and non-DNS SANs
            Asn1Set? attributes = info.Attributes;
            if (attributes != null)
            {
                if (attributes.Count > MaxCsrAttributes)
                {
                    return (false, $"CSR contains too many attributes (maximum {MaxCsrAttributes})", null);
                }

                foreach (Asn1Encodable attr in attributes)
                {
                    AttributePkcs pkcsAttr = AttributePkcs.GetInstance(attr);
                    if (PkcsObjectIdentifiers.Pkcs9AtExtensionRequest.Equals(pkcsAttr.AttrType))
                    {
                        if (pkcsAttr.AttrValues.Count > MaxCsrExtensions)
                        {
                            return (false, $"CSR contains too many extension attribute values (maximum {MaxCsrExtensions})", null);
                        }

                        foreach (Asn1Encodable extSet in pkcsAttr.AttrValues)
                        {
                            X509Extensions extensions = X509Extensions.GetInstance(extSet);
                            List<DerObjectIdentifier> extOids = extensions.ExtensionOids.Cast<DerObjectIdentifier>().ToList();
                            if (extOids.Count > MaxCsrExtensions)
                            {
                                return (false, $"CSR contains too many requested extensions (maximum {MaxCsrExtensions})", null);
                            }

                            foreach (DerObjectIdentifier extOid in extOids)
                            {
                                if (X509Extensions.SubjectAlternativeName.Equals(extOid))
                                {
                                    X509Extension sanExt = extensions.GetExtension(extOid);
                                    byte[] sanOctets = Asn1OctetString.GetInstance(sanExt.Value).GetOctets();
                                    if (sanOctets.Length == 0 || sanOctets.Length > MaxCsrDerBytes)
                                    {
                                        return (false, "The CSR provided could not be decoded", null);
                                    }

                                    GeneralNames sans = GeneralNames.GetInstance(Asn1Object.FromByteArray(sanOctets));
                                    GeneralName[] sanEntries = sans.GetNames();
                                    if (sanEntries.Length > MaxCsrDnsSanEntries
                                        || rawDnsNames.Count + sanEntries.Length > MaxCsrDnsSanEntries + 1)
                                    {
                                        return (false, $"CSR contains too many Subject Alternative Name entries (maximum {MaxCsrDnsSanEntries})", null);
                                    }

                                    foreach (GeneralName gn in sanEntries)
                                    {
                                        if (gn.TagNo != GeneralName.DnsName)
                                        {
                                            return (false, $"Unsupported Subject Alternative Name type (tag {gn.TagNo}); only DNS names are permitted", null);
                                        }
                                        string dnsVal = DerIA5String.GetInstance(gn.Name).GetString().Trim();
                                        if (string.IsNullOrWhiteSpace(dnsVal))
                                        {
                                            return (false, "Subject Alternative Name contains an empty DNS name", null);
                                        }
                                        rawDnsNames.Add(dnsVal);
                                    }
                                }
                                else if (X509Extensions.BasicConstraints.Equals(extOid))
                                {
                                    X509Extension bcExt = extensions.GetExtension(extOid);
                                    byte[] bcOctets = Asn1OctetString.GetInstance(bcExt.Value).GetOctets();
                                    if (bcOctets.Length == 0 || bcOctets.Length > MaxCsrDerBytes)
                                    {
                                        return (false, "The CSR provided could not be decoded", null);
                                    }

                                    BasicConstraints bc = BasicConstraints.GetInstance(Asn1Object.FromByteArray(bcOctets));
                                    if (bc.IsCA())
                                    {
                                        return (false, "CSR requests CA BasicConstraints, which is forbidden for leaf issuance", null);
                                    }
                                }
                                else if (X509Extensions.KeyUsage.Equals(extOid) || X509Extensions.ExtendedKeyUsage.Equals(extOid))
                                {
                                    X509Extension kuOrEkuExt = extensions.GetExtension(extOid);
                                    byte[] extOctets = Asn1OctetString.GetInstance(kuOrEkuExt.Value).GetOctets();
                                    if (extOctets.Length == 0 || extOctets.Length > MaxCsrDerBytes)
                                    {
                                        return (false, "The CSR provided could not be decoded", null);
                                    }
                                    _ = Asn1Object.FromByteArray(extOctets);
                                }
                                else
                                {
                                    return (false, $"CSR contains unsupported extension OID '{extOid.Id}'", null);
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (Exception)
        {
            return (false, "The CSR provided could not be decoded", null);
        }

        if (rawDnsNames.Count == 0)
        {
            return (false, "CSR does not contain any Common Name or DNS Subject Alternative Name", null);
        }

        List<string> canonicalNames = [];
        foreach (string rawName in rawDnsNames)
        {
            if (!IsValidRequestedDnsIdentity(rawName, out string canonical))
            {
                return (false, $"Requested DNS identity '{rawName}' is invalid", null);
            }
            if (!canonicalNames.Contains(canonical, StringComparer.OrdinalIgnoreCase))
            {
                canonicalNames.Add(canonical);
            }
        }

        string canonicalCn = string.IsNullOrEmpty(commonName)
            ? canonicalNames[0]
            : DomainPolicyEvaluator.CanonicalizeDomainPatternOrIdentity(commonName);

        return (true, null, new ValidatedCsrRequest(
            decoded,
            publicKey,
            profile,
            canonicalCn,
            canonicalNames,
            subject));
    }

    public static bool IsValidRequestedDnsIdentity(string rawName, out string canonical)
    {
        canonical = DomainPolicyEvaluator.CanonicalizeDomainPatternOrIdentity(rawName);
        if (string.IsNullOrEmpty(canonical) || canonical == "*")
        {
            return false;
        }

        string hostToValidate = canonical.StartsWith("*.") ? canonical[2..] : canonical;
        if (hostToValidate.Contains('*'))
        {
            return false;
        }

        if (Uri.CheckHostName(hostToValidate) != UriHostNameType.Dns)
        {
            return false;
        }

        // Require at least two labels (e.g., example.com or sub.example.com)
        string[] labels = hostToValidate.Split('.');
        if (labels.Length < 2 || labels.Any(string.IsNullOrWhiteSpace))
        {
            return false;
        }

        return true;
    }
}
