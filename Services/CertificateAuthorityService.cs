using CertRobo.Data;
using CertRobo.Models;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace CertRobo.Services;

public sealed class CaKeyCustodyOptions
{
    public string StorageDirectory { get; set; } = Path.Combine("App_Data", "ca");
    public string? PassphraseEnvironmentVariable { get; set; } = "CERTROBO_CA_PASSPHRASE";
    public string? PassphraseFilePath { get; set; }
    public string? ConfiguredPassphrase { get; set; }
    public int CrlValidityHours { get; set; } = 168; // 7 days
    public bool AutoCreateDevelopmentCaIfEmpty { get; set; }
}

public sealed record IssuanceOutcome(
    bool Succeeded,
    string? ErrorMessage,
    IssuedCertificateRecord? Record,
    string? CertificatePem,
    string? FullChainPem);

/// <summary>
/// Manages CA lifecycle (creation, import, encrypted key custody, unlock state),
/// serial allocation, leaf certificate signing, post-issuance verification,
/// revocation, and X.509 v2 CRL signing/publication.
/// </summary>
public sealed class CertificateAuthorityService
{
    private static readonly SemaphoreSlim SigningAndSerialLock = new(1, 1);

    private readonly IDbContextFactory<CertRoboDbContext> _dbFactory;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly CaKeyCustodyOptions _options;

    private string? _runtimeUnlockedPassphrase;

    public CertificateAuthorityService(
        IDbContextFactory<CertRoboDbContext> dbFactory,
        IServiceScopeFactory scopeFactory,
        CaKeyCustodyOptions options)
    {
        _dbFactory = dbFactory;
        _scopeFactory = scopeFactory;
        _options = options;
    }

    public void UnlockRuntimePassphrase(string passphrase)
    {
        if (string.IsNullOrWhiteSpace(passphrase))
        {
            throw new ArgumentException("Passphrase cannot be empty.", nameof(passphrase));
        }
        _runtimeUnlockedPassphrase = passphrase;
    }

    public void LockRuntimePassphrase()
    {
        _runtimeUnlockedPassphrase = null;
    }

    public string? ResolveEffectivePassphrase()
    {
        if (!string.IsNullOrEmpty(_runtimeUnlockedPassphrase))
        {
            return _runtimeUnlockedPassphrase;
        }

        if (!string.IsNullOrEmpty(_options.PassphraseEnvironmentVariable))
        {
            string? envVal = Environment.GetEnvironmentVariable(_options.PassphraseEnvironmentVariable);
            if (!string.IsNullOrWhiteSpace(envVal))
            {
                return envVal.Trim();
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.PassphraseFilePath) && File.Exists(_options.PassphraseFilePath))
        {
            string fileVal = File.ReadAllText(_options.PassphraseFilePath).Trim();
            if (!string.IsNullOrEmpty(fileVal))
            {
                return fileVal;
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ConfiguredPassphrase))
        {
            return _options.ConfiguredPassphrase;
        }

        return null;
    }

    public async Task<CaAuthorityRecord?> GetActiveAuthorityAsync(CancellationToken cancellationToken = default)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        return await db.CaAuthorities
            .OrderByDescending(c => c.Id)
            .FirstOrDefaultAsync(c => c.IsActive, cancellationToken);
    }

    /// <summary>
    /// Creates a new Root or Intermediate CA with encrypted PKCS#8 private key storage and publishes its initial CRL #1.
    /// </summary>
    public async Task<CaAuthorityRecord> CreateSelfSignedOrIntermediateCaAsync(
        string caName,
        string subjectCommonName,
        string country,
        string stateOrProvince,
        string locality,
        string organization,
        string organizationalUnit,
        CertificateKeyFamily keyFamily,
        int keyBits,
        int validityDays,
        string passphrase,
        string crlDistributionPointUrl = "/ca.crl",
        string authorityIssuerCertUrl = "/ca.crt",
        CaAuthorityRecord? parentAuthority = null,
        string? parentPassphrase = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(passphrase))
        {
            throw new ArgumentException("A non-empty passphrase is required to protect the CA signing key.", nameof(passphrase));
        }

        await SigningAndSerialLock.WaitAsync(cancellationToken);
        try
        {
            using AsymmetricAlgorithm subjectKey = CreateDotNetAsymmetricKey(keyFamily, keyBits);
            X500DistinguishedName subjectDn = BuildX500DistinguishedName(
                subjectCommonName, country, stateOrProvince, locality, organization, organizationalUnit);

            CertificateRequest certReq = CreateCertificateRequestForKey(subjectDn, subjectKey);

            // CA BasicConstraints (critical)
            bool isIntermediate = parentAuthority != null;
            certReq.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(
                    certificateAuthority: true,
                    hasPathLengthConstraint: isIntermediate,
                    pathLengthConstraint: isIntermediate ? 0 : 0,
                    critical: true));

            // CA KeyUsage: KeyCertSign | CrlSign | DigitalSignature (critical)
            certReq.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
                    critical: true));

            // Subject Key Identifier
            X509SubjectKeyIdentifierExtension skiExt = new(certReq.PublicKey, critical: false);
            certReq.CertificateExtensions.Add(skiExt);

            DateTimeOffset now = DateTimeOffset.UtcNow;
            DateTimeOffset notBefore = now.AddMinutes(-5);
            DateTimeOffset notAfter = now.AddDays(validityDays);

            X509Certificate2 issuedCaCert;
            string chainPem = string.Empty;

            if (parentAuthority == null)
            {
                certReq.CertificateExtensions.Add(
                    X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(skiExt));
                issuedCaCert = certReq.CreateSelfSigned(notBefore, notAfter);
            }
            else
            {
                using X509Certificate2 parentCert = X509Certificate2.CreateFromPem(parentAuthority.IssuerCertificatePem);
                using AsymmetricAlgorithm parentKey = LoadEncryptedKey(
                    parentAuthority.EncryptedPrivateKeyPath,
                    parentPassphrase ?? passphrase);

                if (notAfter > parentCert.NotAfter.ToUniversalTime())
                {
                    notAfter = parentCert.NotAfter.ToUniversalTime();
                }

                X509SubjectKeyIdentifierExtension? parentSki = parentCert.Extensions
                    .OfType<X509SubjectKeyIdentifierExtension>()
                    .FirstOrDefault();

                if (parentSki != null)
                {
                    certReq.CertificateExtensions.Add(
                        X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(parentSki));
                }

                byte[] serialBytes = AllocatePositiveSerialBytes(parentAuthority.LastAllocatedSerial + 1);
                X509SignatureGenerator sigGen = CreateSignatureGenerator(parentKey);
                using X509Certificate2 signedCert = certReq.Create(
                    parentCert.SubjectName,
                    sigGen,
                    notBefore,
                    notAfter,
                    serialBytes);

                issuedCaCert = CopyWithPrivateKey(signedCert, subjectKey);
                chainPem = string.IsNullOrWhiteSpace(parentAuthority.ChainCertificatesPem)
                    ? parentAuthority.IssuerCertificatePem.Trim() + "\n"
                    : parentAuthority.IssuerCertificatePem.Trim() + "\n" + parentAuthority.ChainCertificatesPem.Trim() + "\n";
            }

            using (issuedCaCert)
            {
                string certPem = issuedCaCert.ExportCertificatePem() + "\n";
                byte[] encryptedPkcs8 = subjectKey.ExportEncryptedPkcs8PrivateKey(
                    passphrase,
                    new PbeParameters(
                        PbeEncryptionAlgorithm.Aes256Cbc,
                        HashAlgorithmName.SHA256,
                        iterationCount: 100_000));

                return await PersistAndActivateCaCoreAsync(
                    caName,
                    isIntermediate,
                    certPem,
                    chainPem,
                    encryptedPkcs8,
                    passphrase,
                    crlDistributionPointUrl,
                    authorityIssuerCertUrl,
                    initialSerialFloor: 1000,
                    initialCrlNumberFloor: 0,
                    cancellationToken);
            }
        }
        finally
        {
            SigningAndSerialLock.Release();
        }
    }

    /// <summary>
    /// Imports an existing CA identity (Root or Intermediate) from PEM or PKCS#12, validates key/cert match,
    /// CA BasicConstraints, and KeyCertSign/CrlSign usages, encrypts the key at rest, and publishes an initial CRL.
    /// </summary>
    public async Task<CaAuthorityRecord> ImportCaAsync(
        string caName,
        string issuerCertPem,
        string? chainCertsPem,
        string privateKeyPem,
        string? inputKeyPassphrase,
        string storagePassphrase,
        string crlDistributionPointUrl = "/ca.crl",
        string authorityIssuerCertUrl = "/ca.crt",
        long initialSerialFloor = 1000,
        long initialCrlNumberFloor = 0,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(storagePassphrase))
        {
            throw new ArgumentException("A non-empty storage passphrase is required to protect the imported CA key.", nameof(storagePassphrase));
        }

        await SigningAndSerialLock.WaitAsync(cancellationToken);
        try
        {
            using X509Certificate2 cert = X509Certificate2.CreateFromPem(issuerCertPem);
            using AsymmetricAlgorithm key = ImportPrivateKeyFromPem(cert, privateKeyPem, inputKeyPassphrase);

            ValidateCaCertificateAndKeyMatch(cert, key, chainCertsPem, out bool isIntermediate, out string normalizedChainPem);

            byte[] encryptedPkcs8 = key.ExportEncryptedPkcs8PrivateKey(
                storagePassphrase,
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    iterationCount: 100_000));

            return await PersistAndActivateCaCoreAsync(
                caName,
                isIntermediate,
                cert.ExportCertificatePem() + "\n",
                normalizedChainPem,
                encryptedPkcs8,
                storagePassphrase,
                crlDistributionPointUrl,
                authorityIssuerCertUrl,
                initialSerialFloor,
                initialCrlNumberFloor,
                cancellationToken);
        }
        finally
        {
            SigningAndSerialLock.Release();
        }
    }

    public async Task<CaAuthorityRecord> ImportCaFromPkcs12Async(
        string caName,
        byte[] pkcs12Bytes,
        string? pkcs12Password,
        string storagePassphrase,
        string crlDistributionPointUrl = "/ca.crl",
        string authorityIssuerCertUrl = "/ca.crt",
        long initialSerialFloor = 1000,
        long initialCrlNumberFloor = 0,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(storagePassphrase))
        {
            throw new ArgumentException("A non-empty storage passphrase is required.", nameof(storagePassphrase));
        }

        await SigningAndSerialLock.WaitAsync(cancellationToken);
        try
        {
            X509Certificate2Collection collection = X509CertificateLoader.LoadPkcs12Collection(
                pkcs12Bytes,
                pkcs12Password,
                X509KeyStorageFlags.Exportable);

            X509Certificate2? caCertWithKey = collection.FirstOrDefault(c => c.HasPrivateKey)
                ?? throw new ArgumentException("PKCS#12 archive does not contain a certificate with a private key.");

            using AsymmetricAlgorithm key = ExtractExportablePrivateKey(caCertWithKey);

            StringBuilder extraChainBuilder = new();
            foreach (X509Certificate2 other in collection)
            {
                if (!other.Thumbprint.Equals(caCertWithKey.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    extraChainBuilder.AppendLine(other.ExportCertificatePem());
                }
            }

            ValidateCaCertificateAndKeyMatch(
                caCertWithKey,
                key,
                extraChainBuilder.ToString(),
                out bool isIntermediate,
                out string normalizedChainPem);

            byte[] encryptedPkcs8 = key.ExportEncryptedPkcs8PrivateKey(
                storagePassphrase,
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    iterationCount: 100_000));

            return await PersistAndActivateCaCoreAsync(
                caName,
                isIntermediate,
                caCertWithKey.ExportCertificatePem() + "\n",
                normalizedChainPem,
                encryptedPkcs8,
                storagePassphrase,
                crlDistributionPointUrl,
                authorityIssuerCertUrl,
                initialSerialFloor,
                initialCrlNumberFloor,
                cancellationToken);
        }
        finally
        {
            SigningAndSerialLock.Release();
        }
    }

    /// <summary>
    /// Evaluates user/policy authorization and CSR validity at the service boundary, allocates a unique positive serial,
    /// signs a leaf certificate using the active CA, validates the resulting certificate and chain, and records it in the ledger.
    /// </summary>
    public async Task<IssuanceOutcome> IssueCertificateFromCsrAsync(
        string? requestingUserId,
        string? csrPem,
        string? explicitProfileId = null,
        int? requestedValidityDays = null,
        string? expectedSecurityStamp = null,
        CancellationToken cancellationToken = default)
    {
        PolicyEvaluationResult eval;
        await using (AsyncServiceScope policyScope = _scopeFactory.CreateAsyncScope())
        {
            IssuancePolicyService policyService = policyScope.ServiceProvider.GetRequiredService<IssuancePolicyService>();
            eval = await policyService.EvaluateCsrRequestAsync(
                requestingUserId,
                csrPem,
                explicitProfileId,
                expectedSecurityStamp,
                cancellationToken);
        }

        if (!eval.IsAllowed || eval.ValidatedRequest == null || eval.User == null)
        {
            await RecordDeniedOrFailedAttemptAsync(
                eval.User?.Id ?? requestingUserId ?? "anonymous",
                eval.User?.UserName ?? "anonymous",
                eval.ValidatedRequest,
                IssuanceStatus.Denied,
                eval.DenialReason ?? "Policy check failed.",
                cancellationToken);

            return new(false, eval.DenialReason ?? "Request denied.", null, null, null);
        }

        ValidatedCsrRequest req = eval.ValidatedRequest;
        ApplicationUser user = eval.User;

        await SigningAndSerialLock.WaitAsync(cancellationToken);
        try
        {
            await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            CaAuthorityRecord? ca = await db.CaAuthorities
                .OrderByDescending(c => c.Id)
                .FirstOrDefaultAsync(c => c.IsActive, cancellationToken);

            if (ca == null)
            {
                return new(false, "No active Certificate Authority is configured.", null, null, null);
            }

            string? passphrase = ResolveEffectivePassphrase();
            if (string.IsNullOrEmpty(passphrase))
            {
                return new(false, "CA signing key is locked. An administrator must unlock the CA or configure the passphrase.", null, null, null);
            }

            // Ensure an initial CRL has been published before issuing certificates referencing it
            bool hasCrl = await db.PublishedCrls.AnyAsync(c => c.CaAuthorityId == ca.Id, cancellationToken);
            if (!hasCrl)
            {
                await GenerateAndPersistCrlInternalAsync(db, ca, passphrase, cancellationToken);
            }

            // Allocate positive serial monotonically above both CA's LastAllocatedSerial and any existing ledger record
            long maxLedgerSerial = await db.IssuedCertificates
                .Where(c => c.CaAuthorityId == ca.Id)
                .Select(c => (long?)c.SerialNumberValue)
                .MaxAsync(cancellationToken) ?? 1000L;

            long nextSerial = Math.Max(ca.LastAllocatedSerial, maxLedgerSerial) + 1;
            ca.LastAllocatedSerial = nextSerial;
            byte[] serialBytes = AllocatePositiveSerialBytes(nextSerial);
            string serialHex = Convert.ToHexString(serialBytes);

            // Reserve pending record before signing so crashes cannot produce untracked serial reuse
            IssuedCertificateRecord ledgerEntry = new()
            {
                CaAuthorityId = ca.Id,
                SerialNumberValue = nextSerial,
                SerialNumberHex = serialHex,
                ProfileId = req.Profile.ProfileId,
                CommonName = req.CommonName,
                SubjectAlternativeNamesCsv = string.Join(",", req.CanonicalDnsIdentities),
                SubjectDistinguishedName = req.SubjectName.ToString(),
                IssuerDistinguishedName = string.Empty,
                KeyAlgorithm = req.Profile.KeyFamily.ToString().ToUpperInvariant(),
                KeySizeBits = req.Profile.KeyBits,
                ThumbprintSha256 = string.Empty,
                RequestedByUserId = user.Id,
                RequestedByUserName = user.UserName ?? user.Id,
                Status = IssuanceStatus.Pending,
                CreatedAtUtc = DateTimeOffset.UtcNow
            };

            db.IssuedCertificates.Add(ledgerEntry);
            await db.SaveChangesAsync(cancellationToken);

            try
            {
                using X509Certificate2 issuerCert = X509Certificate2.CreateFromPem(ca.IssuerCertificatePem);
                using AsymmetricAlgorithm issuerKey = LoadEncryptedKey(ca.EncryptedPrivateKeyPath, passphrase);

                DateTimeOffset now = DateTimeOffset.UtcNow;
                if (now > issuerCert.NotAfter.ToUniversalTime())
                {
                    throw new InvalidOperationException("Active CA certificate has expired.");
                }

                int effectiveDays = requestedValidityDays ?? req.Profile.DefaultValidityDays;
                effectiveDays = Math.Clamp(effectiveDays, 1, req.Profile.MaxValidityDays);

                DateTimeOffset notBefore = now.AddMinutes(-5);
                if (notBefore < issuerCert.NotBefore.ToUniversalTime())
                {
                    notBefore = issuerCert.NotBefore.ToUniversalTime();
                }

                DateTimeOffset notAfter = now.AddDays(effectiveDays);
                if (notAfter > issuerCert.NotAfter.ToUniversalTime())
                {
                    notAfter = issuerCert.NotAfter.ToUniversalTime();
                }

                if (notAfter <= notBefore)
                {
                    throw new InvalidOperationException("Computed certificate validity window is invalid relative to issuer validity.");
                }

                using X509Certificate2 signedLeaf = SignLeafCertificate(
                    req,
                    issuerCert,
                    issuerKey,
                    serialBytes,
                    notBefore,
                    notAfter,
                    ca.CrlDistributionPointUrl,
                    ca.AuthorityIssuerCertUrl);

                // Post-issuance verification: verify public key, identities, basic constraints, KU/EKU, validity, and chain
                ValidateIssuedLeafCertificate(signedLeaf, req, issuerCert, ca.ChainCertificatesPem, notBefore, notAfter);

                string leafPem = signedLeaf.ExportCertificatePem() + "\n";
                string issuerChainPem = BuildOrderedCertificateChainPem(ca);

                ledgerEntry.IssuerDistinguishedName = issuerCert.Subject;
                ledgerEntry.ThumbprintSha256 = signedLeaf.GetCertHashString(HashAlgorithmName.SHA256);
                ledgerEntry.CertificatePem = leafPem;
                ledgerEntry.ChainPem = issuerChainPem;
                ledgerEntry.NotBeforeUtc = notBefore;
                ledgerEntry.NotAfterUtc = notAfter;
                ledgerEntry.Status = IssuanceStatus.Issued;

                await db.SaveChangesAsync(cancellationToken);

                string fullBundlePem = leafPem + issuerChainPem;
                return new(true, null, ledgerEntry, leafPem, fullBundlePem);
            }
            catch (Exception ex)
            {
                ledgerEntry.Status = IssuanceStatus.Failed;
                ledgerEntry.FailureOrDenialReason = ex.Message;
                await db.SaveChangesAsync(cancellationToken);
                return new(false, $"Certificate signing failed: {ex.Message}", ledgerEntry, null, null);
            }
        }
        finally
        {
            SigningAndSerialLock.Release();
        }
    }

    public async Task<(bool Succeeded, string? ErrorMessage)> RevokeCertificateAsync(
        int certificateId,
        int revocationReasonCode,
        string revokedByUserName,
        CancellationToken cancellationToken = default)
    {
        await SigningAndSerialLock.WaitAsync(cancellationToken);
        try
        {
            await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            IssuedCertificateRecord? certRecord = await db.IssuedCertificates
                .FirstOrDefaultAsync(c => c.Id == certificateId, cancellationToken);

            if (certRecord == null)
            {
                return (false, "Certificate record not found.");
            }

            if (certRecord.Status != IssuanceStatus.Issued && certRecord.Status != IssuanceStatus.Revoked)
            {
                return (false, $"Certificate in status '{certRecord.Status}' cannot be revoked.");
            }

            certRecord.Status = IssuanceStatus.Revoked;
            certRecord.RevokedAtUtc ??= DateTimeOffset.UtcNow;
            certRecord.RevocationReasonCode = revocationReasonCode;
            certRecord.RevokedByUserName = revokedByUserName;
            await db.SaveChangesAsync(cancellationToken);

            if (certRecord.CaAuthorityId.HasValue)
            {
                CaAuthorityRecord? ca = await db.CaAuthorities
                    .FirstOrDefaultAsync(c => c.Id == certRecord.CaAuthorityId.Value, cancellationToken);

                string? passphrase = ResolveEffectivePassphrase();
                if (ca != null && !string.IsNullOrEmpty(passphrase))
                {
                    await GenerateAndPersistCrlInternalAsync(db, ca, passphrase, cancellationToken);
                }
            }

            return (true, null);
        }
        finally
        {
            SigningAndSerialLock.Release();
        }
    }

    /// <summary>
    /// Seeds an already-revoked serial number from an imported legacy CA so CRL continuity is preserved,
    /// and refreshes the active CA's CRL if unlocked.
    /// </summary>
    public async Task<(bool Succeeded, string? ErrorMessage)> SeedRevokedSerialAsync(
        string serialNumberHex,
        string? commonName,
        int revocationReasonCode,
        string revokedByUserName,
        DateTimeOffset? revokedAtUtc = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(serialNumberHex))
        {
            return (false, "Serial number (hex) is required.");
        }

        string cleanHex = serialNumberHex.Trim().Replace(":", "").Replace(" ", "").ToUpperInvariant();
        if (cleanHex.Length % 2 != 0)
        {
            cleanHex = "0" + cleanHex;
        }

        byte[] serialBytes;
        try
        {
            serialBytes = Convert.FromHexString(cleanHex);
            BigInteger bi = new(1, serialBytes);
            if (bi.CompareTo(BigInteger.Zero) <= 0)
            {
                return (false, "Serial number must represent a positive integer.");
            }
        }
        catch (FormatException)
        {
            return (false, "Serial number must be valid hexadecimal.");
        }

        await SigningAndSerialLock.WaitAsync(cancellationToken);
        try
        {
            await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            CaAuthorityRecord? ca = await db.CaAuthorities
                .OrderByDescending(c => c.Id)
                .FirstOrDefaultAsync(c => c.IsActive, cancellationToken);

            if (ca == null)
            {
                return (false, "No active CA is configured.");
            }

            IssuedCertificateRecord? existing = await db.IssuedCertificates
                .FirstOrDefaultAsync(c => c.CaAuthorityId == ca.Id && c.SerialNumberHex == cleanHex, cancellationToken);

            DateTimeOffset effectiveRevokedAt = revokedAtUtc ?? DateTimeOffset.UtcNow;

            if (existing != null)
            {
                existing.Status = IssuanceStatus.Revoked;
                existing.RevokedAtUtc ??= effectiveRevokedAt;
                existing.RevocationReasonCode = revocationReasonCode;
                existing.RevokedByUserName = revokedByUserName;
            }
            else
            {
                IssuedCertificateRecord seeded = new()
                {
                    CaAuthorityId = ca.Id,
                    SerialNumberHex = cleanHex,
                    SerialNumberValue = 0,
                    ProfileId = "legacy-imported",
                    CommonName = string.IsNullOrWhiteSpace(commonName) ? "legacy-revoked" : commonName.Trim(),
                    SubjectAlternativeNamesCsv = string.IsNullOrWhiteSpace(commonName) ? "" : commonName.Trim(),
                    SubjectDistinguishedName = string.IsNullOrWhiteSpace(commonName) ? "" : $"CN={commonName.Trim()}",
                    IssuerDistinguishedName = string.Empty,
                    KeyAlgorithm = "LEGACY",
                    KeySizeBits = 0,
                    ThumbprintSha256 = "LEGACY-" + cleanHex,
                    RequestedByUserId = "legacy-migration",
                    RequestedByUserName = revokedByUserName,
                    Status = IssuanceStatus.Revoked,
                    CreatedAtUtc = effectiveRevokedAt,
                    RevokedAtUtc = effectiveRevokedAt,
                    RevocationReasonCode = revocationReasonCode,
                    RevokedByUserName = revokedByUserName
                };
                db.IssuedCertificates.Add(seeded);
            }

            await db.SaveChangesAsync(cancellationToken);

            string? passphrase = ResolveEffectivePassphrase();
            if (!string.IsNullOrEmpty(passphrase))
            {
                await GenerateAndPersistCrlInternalAsync(db, ca, passphrase, cancellationToken);
            }

            return (true, null);
        }
        finally
        {
            SigningAndSerialLock.Release();
        }
    }

    public async Task<PublishedCrlRecord?> RefreshActiveCrlAsync(CancellationToken cancellationToken = default)
    {
        await SigningAndSerialLock.WaitAsync(cancellationToken);
        try
        {
            await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            CaAuthorityRecord? ca = await db.CaAuthorities
                .OrderByDescending(c => c.Id)
                .FirstOrDefaultAsync(c => c.IsActive, cancellationToken);

            if (ca == null)
            {
                return null;
            }

            string? passphrase = ResolveEffectivePassphrase();
            if (string.IsNullOrEmpty(passphrase))
            {
                throw new InvalidOperationException("Cannot refresh CRL while CA signing key is locked.");
            }

            return await GenerateAndPersistCrlInternalAsync(db, ca, passphrase, cancellationToken);
        }
        finally
        {
            SigningAndSerialLock.Release();
        }
    }

    public async Task<PublishedCrlRecord?> GetLatestCrlAsync(CancellationToken cancellationToken = default)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        CaAuthorityRecord? ca = await db.CaAuthorities
            .OrderByDescending(c => c.Id)
            .FirstOrDefaultAsync(c => c.IsActive, cancellationToken);

        if (ca == null)
        {
            return null;
        }

        return await db.PublishedCrls
            .Where(c => c.CaAuthorityId == ca.Id)
            .OrderByDescending(c => c.CrlNumber)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<IssuedCertificateRecord>> SearchCertificatesAsync(
        string? searchQuery = null,
        IssuanceStatus? statusFilter = null,
        CancellationToken cancellationToken = default)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        IQueryable<IssuedCertificateRecord> query = db.IssuedCertificates.AsQueryable();

        if (statusFilter.HasValue)
        {
            query = query.Where(c => c.Status == statusFilter.Value);
        }

        if (!string.IsNullOrWhiteSpace(searchQuery))
        {
            string term = searchQuery.Trim().ToLowerInvariant();
            query = query.Where(c =>
                c.CommonName.ToLower().Contains(term)
                || c.SerialNumberHex.ToLower().Contains(term)
                || c.SubjectAlternativeNamesCsv.ToLower().Contains(term)
                || c.RequestedByUserName.ToLower().Contains(term));
        }

        return await query
            .OrderByDescending(c => c.Id)
            .Take(250)
            .ToListAsync(cancellationToken);
    }

    private async Task<CaAuthorityRecord> PersistAndActivateCaCoreAsync(
        string caName,
        bool isIntermediate,
        string issuerCertPem,
        string chainCertsPem,
        byte[] encryptedPkcs8Bytes,
        string passphrase,
        string crlDistributionPointUrl,
        string authorityIssuerCertUrl,
        long initialSerialFloor,
        long initialCrlNumberFloor,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_options.StorageDirectory);
        string keyFileName = $"ca-key-{Guid.NewGuid():N}.p8.enc";
        string keyFilePath = Path.Combine(_options.StorageDirectory, keyFileName);
        await File.WriteAllBytesAsync(keyFilePath, encryptedPkcs8Bytes, cancellationToken);
        RestrictFilePermissionsIfUnix(keyFilePath);

        using X509Certificate2 cert = X509Certificate2.CreateFromPem(issuerCertPem);
        string skiHex = cert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault()?.SubjectKeyIdentifier
            ?? cert.GetCertHashString(HashAlgorithmName.SHA256);

        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        List<CaAuthorityRecord> previousActive = await db.CaAuthorities.Where(c => c.IsActive).ToListAsync(cancellationToken);
        foreach (CaAuthorityRecord prev in previousActive)
        {
            prev.IsActive = false;
        }

        CaAuthorityRecord record = new()
        {
            Name = caName.Trim(),
            IsActive = true,
            IsIntermediate = isIntermediate,
            IssuerCertificatePem = issuerCertPem,
            ChainCertificatesPem = chainCertsPem,
            SubjectKeyIdentifierHex = skiHex,
            ThumbprintOrSerialHex = cert.GetCertHashString(HashAlgorithmName.SHA256),
            EncryptedPrivateKeyPath = keyFilePath,
            CrlDistributionPointUrl = crlDistributionPointUrl,
            AuthorityIssuerCertUrl = authorityIssuerCertUrl,
            LastAllocatedSerial = Math.Max(1000L, initialSerialFloor),
            LastCrlNumber = Math.Max(0L, initialCrlNumberFloor),
            NotBeforeUtc = cert.NotBefore.ToUniversalTime(),
            NotAfterUtc = cert.NotAfter.ToUniversalTime(),
            CreatedAtUtc = DateTimeOffset.UtcNow
        };

        db.CaAuthorities.Add(record);
        await db.SaveChangesAsync(cancellationToken);

        _runtimeUnlockedPassphrase = passphrase;

        // Publish initial CRL #1 immediately so CDP works before any certificate is issued
        await GenerateAndPersistCrlInternalAsync(db, record, passphrase, cancellationToken);

        // Also update static/rootca.crt if writable so static/legacy links see the current trust chain
        await WritePublicTrustFilesAsync(record, cancellationToken);

        return record;
    }

    private async Task<PublishedCrlRecord> GenerateAndPersistCrlInternalAsync(
        CertRoboDbContext db,
        CaAuthorityRecord ca,
        string passphrase,
        CancellationToken cancellationToken)
    {
        using X509Certificate2 issuerDotNetCert = X509Certificate2.CreateFromPem(ca.IssuerCertificatePem);
        using AsymmetricAlgorithm issuerDotNetKey = LoadEncryptedKey(ca.EncryptedPrivateKeyPath, passphrase);

        BcX509Certificate bcIssuerCert = new X509CertificateParser().ReadCertificate(issuerDotNetCert.RawData);
        AsymmetricKeyParameter bcSigningKey = ConvertDotNetPrivateKeyToBouncyCastle(issuerDotNetKey);

        long maxExistingCrl = await db.PublishedCrls
            .Where(c => c.CaAuthorityId == ca.Id)
            .Select(c => (long?)c.CrlNumber)
            .MaxAsync(cancellationToken) ?? 0L;

        long nextCrlNumber = Math.Max(ca.LastCrlNumber, maxExistingCrl) + 1;
        ca.LastCrlNumber = nextCrlNumber;

        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset thisUpdate = now.AddMinutes(-1);
        DateTimeOffset nextUpdate = now.AddHours(Math.Max(1, _options.CrlValidityHours));

        X509V2CrlGenerator crlGen = new();
        crlGen.SetIssuerDN(bcIssuerCert.SubjectDN);
        crlGen.SetThisUpdate(thisUpdate.UtcDateTime);
        crlGen.SetNextUpdate(nextUpdate.UtcDateTime);

        List<IssuedCertificateRecord> revokedCerts = await db.IssuedCertificates
            .Where(c => c.CaAuthorityId == ca.Id && c.Status == IssuanceStatus.Revoked)
            .OrderBy(c => c.SerialNumberValue)
            .ToListAsync(cancellationToken);

        foreach (IssuedCertificateRecord revoked in revokedCerts)
        {
            BigInteger serialBigInt = new(1, Convert.FromHexString(revoked.SerialNumberHex));
            DateTime revDate = (revoked.RevokedAtUtc ?? now).UtcDateTime;
            int reason = revoked.RevocationReasonCode ?? CrlReason.Unspecified;
            crlGen.AddCrlEntry(serialBigInt, revDate, reason);
        }

        crlGen.AddExtension(
            X509Extensions.AuthorityKeyIdentifier,
            critical: false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(bcIssuerCert));

        crlGen.AddExtension(
            X509Extensions.CrlNumber,
            critical: false,
            new CrlNumber(BigInteger.ValueOf(nextCrlNumber)));

        string sigAlgorithm = bcSigningKey switch
        {
            RsaPrivateCrtKeyParameters => "SHA256withRSA",
            ECPrivateKeyParameters ecKey when ecKey.Parameters.N.BitLength >= 384 => "SHA384withECDSA",
            ECPrivateKeyParameters => "SHA256withECDSA",
            _ => throw new NotSupportedException("Unsupported CA signing key algorithm for CRL generation.")
        };

        ISignatureFactory sigFactory = new Asn1SignatureFactory(sigAlgorithm, bcSigningKey, new SecureRandom());
        X509Crl bcCrl = crlGen.Generate(sigFactory);

        // Verify the CRL signature against the issuer public key
        bcCrl.Verify(bcIssuerCert.GetPublicKey());

        byte[] crlDer = bcCrl.GetEncoded();
        string crlPem = "-----BEGIN X509 CRL-----\n"
            + ChunkBase64(Convert.ToBase64String(crlDer), 64)
            + "\n-----END X509 CRL-----\n";

        PublishedCrlRecord crlRecord = new()
        {
            CaAuthorityId = ca.Id,
            CrlNumber = nextCrlNumber,
            CrlDer = crlDer,
            CrlPem = crlPem,
            ThisUpdateUtc = thisUpdate,
            NextUpdateUtc = nextUpdate,
            CreatedAtUtc = now
        };

        db.PublishedCrls.Add(crlRecord);
        await db.SaveChangesAsync(cancellationToken);
        return crlRecord;
    }

    private async Task RecordDeniedOrFailedAttemptAsync(
        string userId,
        string userName,
        ValidatedCsrRequest? validatedCsr,
        IssuanceStatus status,
        string reason,
        CancellationToken cancellationToken)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        IssuedCertificateRecord record = new()
        {
            CaAuthorityId = null,
            SerialNumberValue = 0,
            SerialNumberHex = $"DENIED-{Guid.NewGuid():N}"[..24],
            ProfileId = validatedCsr?.Profile.ProfileId ?? "unknown",
            CommonName = validatedCsr?.CommonName ?? "invalid",
            SubjectAlternativeNamesCsv = validatedCsr != null ? string.Join(",", validatedCsr.CanonicalDnsIdentities) : string.Empty,
            SubjectDistinguishedName = validatedCsr?.SubjectName.ToString() ?? string.Empty,
            IssuerDistinguishedName = string.Empty,
            KeyAlgorithm = validatedCsr?.Profile.KeyFamily.ToString().ToUpperInvariant() ?? "UNKNOWN",
            KeySizeBits = validatedCsr?.Profile.KeyBits ?? 0,
            ThumbprintSha256 = string.Empty,
            RequestedByUserId = userId,
            RequestedByUserName = userName,
            Status = status,
            FailureOrDenialReason = reason,
            CreatedAtUtc = DateTimeOffset.UtcNow
        };
        db.IssuedCertificates.Add(record);
        await db.SaveChangesAsync(cancellationToken);
    }

    public static string BuildOrderedCertificateChainPem(CaAuthorityRecord ca)
    {
        StringBuilder sb = new();
        sb.AppendLine(ca.IssuerCertificatePem.Trim());
        if (!string.IsNullOrWhiteSpace(ca.ChainCertificatesPem))
        {
            sb.AppendLine(ca.ChainCertificatesPem.Trim());
        }
        return sb.ToString();
    }

    private static async Task WritePublicTrustFilesAsync(CaAuthorityRecord ca, CancellationToken cancellationToken)
    {
        try
        {
            if (Directory.Exists("static"))
            {
                string orderedChain = BuildOrderedCertificateChainPem(ca);
                await File.WriteAllTextAsync(Path.Combine("static", "rootca.crt"), orderedChain, cancellationToken);
            }
        }
        catch
        {
            // Non-fatal if static directory is read-only in a container or test runner
        }
    }

    private static X509Certificate2 SignLeafCertificate(
        ValidatedCsrRequest req,
        X509Certificate2 issuerCert,
        AsymmetricAlgorithm issuerKey,
        byte[] serialBytes,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        string crlDistributionPointUrl,
        string authorityIssuerCertUrl)
    {
        byte[] spkiDer = SubjectPublicKeyInfoFactory
            .CreateSubjectPublicKeyInfo(req.PublicKey)
            .GetDerEncoded();

        using AsymmetricAlgorithm subjectDotNetPublicKey = ImportSubjectPublicKey(req.Profile.KeyFamily, spkiDer);
        X500DistinguishedName subjectDn = ConvertBouncyCastleNameToX500(req.SubjectName, req.CommonName);

        CertificateRequest certReq = CreateCertificateRequestForKey(subjectDn, subjectDotNetPublicKey);

        // 1. BasicConstraints: always CA=false (critical) for leaf issuance
        certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));

        // 2. KeyUsage from profile (critical)
        certReq.CertificateExtensions.Add(new X509KeyUsageExtension(req.Profile.KeyUsages, critical: true));

        // 3. ExtendedKeyUsage from profile
        OidCollection ekuOids = new();
        foreach (string oid in req.Profile.ExtendedKeyUsageOids)
        {
            ekuOids.Add(new Oid(oid));
        }
        certReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekuOids, critical: false));

        // 4. SubjectAlternativeName (DNS names)
        SubjectAlternativeNameBuilder sanBuilder = new();
        foreach (string dnsName in req.CanonicalDnsIdentities)
        {
            sanBuilder.AddDnsName(dnsName);
        }
        certReq.CertificateExtensions.Add(sanBuilder.Build());

        // 5. SubjectKeyIdentifier & AuthorityKeyIdentifier
        X509SubjectKeyIdentifierExtension skiExt = new(certReq.PublicKey, critical: false);
        certReq.CertificateExtensions.Add(skiExt);

        X509SubjectKeyIdentifierExtension? issuerSki = issuerCert.Extensions
            .OfType<X509SubjectKeyIdentifierExtension>()
            .FirstOrDefault();

        if (issuerSki != null)
        {
            certReq.CertificateExtensions.Add(
                X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuerSki));
        }
        else
        {
            certReq.CertificateExtensions.Add(
                X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
                    issuerCert,
                    includeKeyIdentifier: true,
                    includeIssuerAndSerial: false));
        }

        // 6. CRL Distribution Point & Authority Information Access (when URLs are HTTP/HTTPS)
        if (!string.IsNullOrWhiteSpace(crlDistributionPointUrl)
            && (crlDistributionPointUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                || crlDistributionPointUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
        {
            certReq.CertificateExtensions.Add(
                CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([crlDistributionPointUrl]));
        }

        if (!string.IsNullOrWhiteSpace(authorityIssuerCertUrl)
            && (authorityIssuerCertUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                || authorityIssuerCertUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
        {
            certReq.CertificateExtensions.Add(
                new X509AuthorityInformationAccessExtension(
                    ocspUris: null,
                    caIssuersUris: [authorityIssuerCertUrl],
                    critical: false));
        }

        // Sign using the issuer's signature generator (keeps subject key algorithm and issuer signature distinct)
        X509SignatureGenerator sigGen = CreateSignatureGenerator(issuerKey);
        return certReq.Create(issuerCert.SubjectName, sigGen, notBefore, notAfter, serialBytes);
    }

    public static void ValidateIssuedLeafCertificate(
        X509Certificate2 leafCert,
        ValidatedCsrRequest req,
        X509Certificate2 issuerCert,
        string chainCertificatesPem,
        DateTimeOffset expectedNotBefore,
        DateTimeOffset expectedNotAfter)
    {
        // 1. Check BasicConstraints is NOT a CA
        X509BasicConstraintsExtension? bc = leafCert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault()
            ?? throw new CryptographicException("Issued leaf certificate is missing BasicConstraints.");
        if (bc.CertificateAuthority)
        {
            throw new CryptographicException("Issued leaf certificate has CA=true in BasicConstraints.");
        }

        // 2. Check KeyUsage matches profile
        X509KeyUsageExtension? ku = leafCert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault()
            ?? throw new CryptographicException("Issued leaf certificate is missing KeyUsage.");
        if ((ku.KeyUsages & req.Profile.KeyUsages) != req.Profile.KeyUsages)
        {
            throw new CryptographicException("Issued leaf certificate KeyUsage does not match profile.");
        }

        // 3. Check EKU matches profile
        X509EnhancedKeyUsageExtension? eku = leafCert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault()
            ?? throw new CryptographicException("Issued leaf certificate is missing ExtendedKeyUsage.");
        HashSet<string> actualEkus = eku.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value!).ToHashSet(StringComparer.Ordinal);
        foreach (string requiredOid in req.Profile.ExtendedKeyUsageOids)
        {
            if (!actualEkus.Contains(requiredOid))
            {
                throw new CryptographicException($"Issued leaf certificate is missing required EKU {requiredOid}.");
            }
        }

        // 4. Verify Subject Public Key matches CSR Public Key
        byte[] expectedSpki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(req.PublicKey).GetDerEncoded();
        byte[] actualSpki = leafCert.PublicKey.ExportSubjectPublicKeyInfo();
        if (!expectedSpki.SequenceEqual(actualSpki))
        {
            throw new CryptographicException("Issued leaf certificate public key does not match CSR public key.");
        }

        // 5. Verify validity bounds
        if (leafCert.NotAfter.ToUniversalTime() > issuerCert.NotAfter.ToUniversalTime())
        {
            throw new CryptographicException("Issued leaf certificate validity exceeds issuer validity.");
        }

        // 6. Verify signature using BouncyCastle against issuer public key AND build X509Chain up to root
        BcX509Certificate bcLeaf = new X509CertificateParser().ReadCertificate(leafCert.RawData);
        BcX509Certificate bcIssuer = new X509CertificateParser().ReadCertificate(issuerCert.RawData);
        bcLeaf.Verify(bcIssuer.GetPublicKey());

        using X509Chain chain = new();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

        List<X509Certificate2> disposableChainCerts = [];
        try
        {
            if (string.IsNullOrWhiteSpace(chainCertificatesPem))
            {
                chain.ChainPolicy.CustomTrustStore.Add(issuerCert);
            }
            else
            {
                chain.ChainPolicy.ExtraStore.Add(issuerCert);
                X509Certificate2Collection extra = [];
                extra.ImportFromPem(chainCertificatesPem);
                foreach (X509Certificate2 cert in extra)
                {
                    disposableChainCerts.Add(cert);
                    if (cert.SubjectName.RawData.SequenceEqual(cert.IssuerName.RawData))
                    {
                        chain.ChainPolicy.CustomTrustStore.Add(cert);
                    }
                    else
                    {
                        chain.ChainPolicy.ExtraStore.Add(cert);
                    }
                }
            }

            if (!chain.Build(leafCert))
            {
                string statuses = string.Join(", ", chain.ChainStatus.Select(s => $"{s.Status}: {s.StatusInformation}"));
                throw new CryptographicException($"Issued leaf certificate failed chain validation: {statuses}");
            }
        }
        finally
        {
            foreach (X509Certificate2 c in disposableChainCerts)
            {
                c.Dispose();
            }
        }
    }

    private static void ValidateCaCertificateAndKeyMatch(
        X509Certificate2 caCert,
        AsymmetricAlgorithm privateKey,
        string? chainCertsPem,
        out bool isIntermediate,
        out string normalizedChainPem)
    {
        // Verify CA BasicConstraints
        X509BasicConstraintsExtension? bc = caCert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault()
            ?? throw new ArgumentException("Imported CA certificate is missing BasicConstraints extension.");
        if (!bc.CertificateAuthority)
        {
            throw new ArgumentException("Imported certificate is not a CA certificate (BasicConstraints CA=false).");
        }

        // Verify KeyUsage if present includes KeyCertSign
        X509KeyUsageExtension? ku = caCert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (ku != null && (ku.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0)
        {
            throw new ArgumentException("Imported CA certificate KeyUsage does not allow KeyCertSign.");
        }

        // Verify public/private key match via SubjectPublicKeyInfo comparison
        byte[] certSpki = caCert.PublicKey.ExportSubjectPublicKeyInfo();
        byte[] keySpki = ExportPublicKeySpki(privateKey);
        if (!certSpki.SequenceEqual(keySpki))
        {
            throw new ArgumentException("Provided private key does not match the CA certificate's public key.");
        }

        bool selfIssued = caCert.SubjectName.RawData.SequenceEqual(caCert.IssuerName.RawData);
        isIntermediate = !selfIssued;
        normalizedChainPem = string.Empty;

        if (isIntermediate)
        {
            if (string.IsNullOrWhiteSpace(chainCertsPem))
            {
                throw new ArgumentException("Intermediate CA import requires the parent/root certificate chain PEM.");
            }

            X509Certificate2Collection chainCol = [];
            chainCol.ImportFromPem(chainCertsPem);
            if (chainCol.Count == 0)
            {
                throw new ArgumentException("No valid certificates were found in the supplied chain PEM.");
            }

            using X509Chain chain = new();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (X509Certificate2 c in chainCol)
            {
                if (c.SubjectName.RawData.SequenceEqual(c.IssuerName.RawData))
                {
                    chain.ChainPolicy.CustomTrustStore.Add(c);
                }
                else
                {
                    chain.ChainPolicy.ExtraStore.Add(c);
                }
            }

            if (!chain.Build(caCert))
            {
                string statuses = string.Join(", ", chain.ChainStatus.Select(s => $"{s.Status}: {s.StatusInformation}"));
                throw new ArgumentException($"Intermediate CA chain validation failed: {statuses}");
            }

            StringBuilder ordered = new();
            // Skip element 0 (which is caCert itself) and append parent(s) up to root in order
            for (int i = 1; i < chain.ChainElements.Count; i++)
            {
                ordered.AppendLine(chain.ChainElements[i].Certificate.ExportCertificatePem());
            }
            normalizedChainPem = ordered.ToString();
        }
        else
        {
            BcX509Certificate bcRoot = new X509CertificateParser().ReadCertificate(caCert.RawData);
            bcRoot.Verify(bcRoot.GetPublicKey());
        }
    }

    private static AsymmetricAlgorithm CreateDotNetAsymmetricKey(CertificateKeyFamily family, int bits)
    {
        return (family, bits) switch
        {
            (CertificateKeyFamily.Rsa, 2048 or 4096) => RSA.Create(bits),
            (CertificateKeyFamily.Ecdsa, 256) => ECDsa.Create(ECCurve.NamedCurves.nistP256),
            (CertificateKeyFamily.Ecdsa, 384) => ECDsa.Create(ECCurve.NamedCurves.nistP384),
            _ => throw new ArgumentException($"Unsupported key family/size: {family} {bits}")
        };
    }

    private static AsymmetricAlgorithm ImportSubjectPublicKey(CertificateKeyFamily family, byte[] spkiDer)
    {
        if (family == CertificateKeyFamily.Rsa)
        {
            RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spkiDer, out _);
            return rsa;
        }
        else
        {
            ECDsa ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(spkiDer, out _);
            return ecdsa;
        }
    }

    private static CertificateRequest CreateCertificateRequestForKey(X500DistinguishedName subjectDn, AsymmetricAlgorithm key)
    {
        return key switch
        {
            RSA rsa => new CertificateRequest(subjectDn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => new CertificateRequest(
                subjectDn,
                ecdsa,
                ecdsa.KeySize >= 384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException($"Unsupported key algorithm {key.GetType().Name}")
        };
    }

    private static X509SignatureGenerator CreateSignatureGenerator(AsymmetricAlgorithm issuerKey)
    {
        return issuerKey switch
        {
            RSA rsa => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => X509SignatureGenerator.CreateForECDsa(ecdsa),
            _ => throw new NotSupportedException($"Unsupported issuer key type {issuerKey.GetType().Name}")
        };
    }

    private static X509Certificate2 CopyWithPrivateKey(X509Certificate2 cert, AsymmetricAlgorithm key)
    {
        return key switch
        {
            RSA rsa => cert.CopyWithPrivateKey(rsa),
            ECDsa ecdsa => cert.CopyWithPrivateKey(ecdsa),
            _ => throw new NotSupportedException()
        };
    }

    private static AsymmetricAlgorithm LoadEncryptedKey(string encryptedKeyPath, string passphrase)
    {
        if (!File.Exists(encryptedKeyPath))
        {
            throw new FileNotFoundException("Encrypted CA signing key file was not found.", encryptedKeyPath);
        }

        byte[] encryptedBytes = File.ReadAllBytes(encryptedKeyPath);
        try
        {
            RSA rsa = RSA.Create();
            rsa.ImportEncryptedPkcs8PrivateKey(passphrase, encryptedBytes, out _);
            return rsa;
        }
        catch (CryptographicException)
        {
            ECDsa ecdsa = ECDsa.Create();
            ecdsa.ImportEncryptedPkcs8PrivateKey(passphrase, encryptedBytes, out _);
            return ecdsa;
        }
    }

    private static AsymmetricAlgorithm ImportPrivateKeyFromPem(
        X509Certificate2 cert,
        string privateKeyPem,
        string? passphrase)
    {
        string oid = cert.PublicKey.Oid.Value ?? string.Empty;
        if (oid == "1.2.840.113549.1.1.1") // RSA
        {
            RSA rsa = RSA.Create();
            if (!string.IsNullOrEmpty(passphrase) && privateKeyPem.Contains("ENCRYPTED", StringComparison.OrdinalIgnoreCase))
            {
                rsa.ImportFromEncryptedPem(privateKeyPem, passphrase);
            }
            else
            {
                rsa.ImportFromPem(privateKeyPem);
            }
            return rsa;
        }
        else
        {
            ECDsa ecdsa = ECDsa.Create();
            if (!string.IsNullOrEmpty(passphrase) && privateKeyPem.Contains("ENCRYPTED", StringComparison.OrdinalIgnoreCase))
            {
                ecdsa.ImportFromEncryptedPem(privateKeyPem, passphrase);
            }
            else
            {
                ecdsa.ImportFromPem(privateKeyPem);
            }
            return ecdsa;
        }
    }

    private static AsymmetricAlgorithm ExtractExportablePrivateKey(X509Certificate2 certWithKey)
    {
        RSA? rsa = certWithKey.GetRSAPrivateKey();
        if (rsa != null)
        {
            byte[] pkcs8 = rsa.ExportPkcs8PrivateKey();
            RSA copy = RSA.Create();
            copy.ImportPkcs8PrivateKey(pkcs8, out _);
            return copy;
        }

        ECDsa? ecdsa = certWithKey.GetECDsaPrivateKey();
        if (ecdsa != null)
        {
            byte[] pkcs8 = ecdsa.ExportPkcs8PrivateKey();
            ECDsa copy = ECDsa.Create();
            copy.ImportPkcs8PrivateKey(pkcs8, out _);
            return copy;
        }

        throw new ArgumentException("Unsupported private key algorithm in PKCS#12 archive.");
    }

    private static byte[] ExportPublicKeySpki(AsymmetricAlgorithm key)
    {
        return key switch
        {
            RSA rsa => rsa.ExportSubjectPublicKeyInfo(),
            ECDsa ecdsa => ecdsa.ExportSubjectPublicKeyInfo(),
            _ => throw new NotSupportedException()
        };
    }

    private static AsymmetricKeyParameter ConvertDotNetPrivateKeyToBouncyCastle(AsymmetricAlgorithm key)
    {
        byte[] pkcs8 = key switch
        {
            RSA rsa => rsa.ExportPkcs8PrivateKey(),
            ECDsa ecdsa => ecdsa.ExportPkcs8PrivateKey(),
            _ => throw new NotSupportedException()
        };
        try
        {
            return PrivateKeyFactory.CreateKey(pkcs8);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    public static byte[] AllocatePositiveSerialBytes(long positiveValue)
    {
        if (positiveValue <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(positiveValue), "Serial number must be positive.");
        }

        // 8 bytes from monotonic counter + 8 random bytes, high bit forced 0 so ASN.1 integer is strictly positive
        byte[] serial = new byte[12];
        byte[] counterBytes = BitConverter.GetBytes(positiveValue);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(counterBytes);
        }
        Buffer.BlockCopy(counterBytes, 0, serial, 0, 8);
        RandomNumberGenerator.Fill(serial.AsSpan(8, 4));
        serial[0] &= 0x7F;
        if (serial[0] == 0)
        {
            serial[0] = 0x01;
        }
        return serial;
    }

    private static X500DistinguishedName BuildX500DistinguishedName(
        string commonName,
        string country,
        string stateOrProvince,
        string locality,
        string organization,
        string organizationalUnit,
        string? emailAddress = null)
    {
        X500DistinguishedNameBuilder builder = new();
        if (!string.IsNullOrWhiteSpace(country))
        {
            builder.AddCountryOrRegion(country.Trim().ToUpperInvariant());
        }
        if (!string.IsNullOrWhiteSpace(stateOrProvince))
        {
            builder.AddStateOrProvinceName(stateOrProvince.Trim());
        }
        if (!string.IsNullOrWhiteSpace(locality))
        {
            builder.AddLocalityName(locality.Trim());
        }
        if (!string.IsNullOrWhiteSpace(organization))
        {
            builder.AddOrganizationName(organization.Trim());
        }
        if (!string.IsNullOrWhiteSpace(organizationalUnit))
        {
            builder.AddOrganizationalUnitName(organizationalUnit.Trim());
        }
        if (!string.IsNullOrWhiteSpace(commonName))
        {
            builder.AddCommonName(commonName.Trim());
        }
        if (!string.IsNullOrWhiteSpace(emailAddress))
        {
            builder.AddEmailAddress(emailAddress.Trim());
        }
        return builder.Build();
    }

    private static X500DistinguishedName ConvertBouncyCastleNameToX500(X509Name bcName, string fallbackCn)
    {
        string c = GetSingleAttribute(bcName, X509Name.C);
        string st = GetSingleAttribute(bcName, X509Name.ST);
        string l = GetSingleAttribute(bcName, X509Name.L);
        string o = GetSingleAttribute(bcName, X509Name.O);
        string ou = GetSingleAttribute(bcName, X509Name.OU);
        string cn = GetSingleAttribute(bcName, X509Name.CN);
        string e = GetSingleAttribute(bcName, X509Name.E);

        if (string.IsNullOrWhiteSpace(cn))
        {
            cn = fallbackCn;
        }

        return BuildX500DistinguishedName(cn, c, st, l, o, ou, e);
    }

    private static string GetSingleAttribute(X509Name name, DerObjectIdentifier oid)
    {
        var oids = name.GetOidList();
        var values = name.GetValueList();
        for (int i = 0; i < oids.Count; i++)
        {
            if (oid.Equals(oids[i]))
            {
                return ((string)values[i]!).Trim();
            }
        }
        return string.Empty;
    }

    private static string ChunkBase64(string base64, int lineLength)
    {
        StringBuilder sb = new();
        for (int i = 0; i < base64.Length; i += lineLength)
        {
            int len = Math.Min(lineLength, base64.Length - i);
            if (i > 0)
            {
                sb.Append('\n');
            }
            sb.Append(base64.AsSpan(i, len));
        }
        return sb.ToString();
    }

    private static void RestrictFilePermissionsIfUnix(string filePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                File.SetUnixFileMode(filePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch
            {
                // Ignore if filesystem does not support UnixFileMode
            }
        }
    }
}
