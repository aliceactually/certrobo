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
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace CertRobo.Services;

public sealed class CaKeyCustodyOptions
{
    public string StorageDirectory { get; set; } = Path.Combine("App_Data", "ca");
    public string? PassphraseEnvironmentVariable { get; set; } = "CERTROBO_CA_PASSPHRASE";
    public string? PassphraseFilePath { get; set; }
    public string? ConfiguredPassphrase { get; set; }
    public string? PublicBaseUrl { get; set; }
    public int CrlValidityHours { get; set; } = 168; // 7 days
    public int CrossProcessLockTimeoutMs { get; set; } = 30_000;
    public bool AutoCreateDevelopmentCaIfEmpty { get; set; }
}

public sealed record IssuanceOutcome(
    bool Succeeded,
    string? ErrorMessage,
    IssuedCertificateRecord? Record,
    string? CertificatePem,
    string? FullChainPem);

public sealed record CrlRefreshOutcome(
    int CaAuthorityId,
    string CaName,
    bool Succeeded,
    PublishedCrlRecord? PublishedCrl,
    string? ErrorMessage);

public enum RevocationPublicationStatus
{
    Rejected = 0,
    Published = 1,
    PendingSignerLocked = 2,
    PendingPublicationFailed = 3,
    PendingIssuerUnavailable = 4
}

public sealed record RevocationOutcome(
    bool Succeeded,
    bool RevocationAccepted,
    bool CrlPublished,
    RevocationPublicationStatus PublicationStatus,
    string? ErrorMessage,
    IssuedCertificateRecord? CertificateRecord = null,
    PublishedCrlRecord? PublishedCrl = null)
{
    public bool IsPendingPublication => RevocationAccepted && !CrlPublished;

    public void Deconstruct(out bool succeeded, out string? errorMessage)
    {
        succeeded = Succeeded;
        errorMessage = ErrorMessage;
    }
}

public sealed record CaAuthorityKeyCustodyStatus(
    int CaAuthorityId,
    string CaName,
    bool IsActive,
    bool IsIntermediate,
    bool IsExpired,
    int UnexpiredCertificateCount,
    bool RequiresCrlMaintenance,
    string EncryptedPrivateKeyPath,
    bool KeyFileExists,
    bool CanDecryptWithEffectivePassphrase,
    bool CanDecryptWithConfiguredPassphrase,
    string? FailureReason);

public sealed record PendingCaKeyCustodyStatus(
    int PendingEnrollmentId,
    string CaName,
    string EncryptedPrivateKeyPath,
    bool KeyFileExists,
    bool CanDecryptWithEffectivePassphrase,
    bool CanDecryptWithConfiguredPassphrase,
    string? FailureReason);

public sealed record CaKeyCustodyReport(
    bool HasConfiguredPersistentPassphrase,
    string ConfiguredPersistentSource,
    bool HasRuntimeUnlockedPassphrase,
    bool IsExplicitlyLocked,
    bool HasEffectivePassphrase,
    bool RuntimeMatchesConfiguredPassphrase,
    bool IsCustodyHealthy,
    bool ActiveAuthorityDecryptable,
    IReadOnlyList<CaAuthorityKeyCustodyStatus> Authorities,
    PendingCaKeyCustodyStatus? PendingEnrollment);

public sealed record CaKeyReprotectionResult(
    bool Succeeded,
    int ReprotectedAuthorityCount,
    bool ReprotectedPendingEnrollment,
    IReadOnlyList<int> ReprotectedAuthorityIds,
    string SummaryMessage);

/// <summary>
/// Manages CA lifecycle (creation, import, encrypted key custody, unlock state),
/// serial allocation, leaf certificate signing, post-issuance verification,
/// revocation, and X.509 v2 CRL signing/publication.
/// </summary>
public sealed class CertificateAuthorityService
{
    public const string CrossProcessLockFileName = ".ca-lifecycle.lock";

    private static readonly SemaphoreSlim SigningAndSerialLock = new(1, 1);

    private readonly IDbContextFactory<CertRoboDbContext> _dbFactory;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly CaKeyCustodyOptions _options;
    private readonly SemaphoreSlim _crlRefreshWakeSignal = new(0, 1);

    private string? _runtimeUnlockedPassphrase;
    private bool _isExplicitlyLocked;

    public Action<CaAuthorityRecord>? CrlPublicationFaultInjector { get; set; }
    public Action<string>? CaPersistenceFaultInjector { get; set; }

    public CertificateAuthorityService(
        IDbContextFactory<CertRoboDbContext> dbFactory,
        IServiceScopeFactory scopeFactory,
        CaKeyCustodyOptions options)
    {
        _dbFactory = dbFactory;
        _scopeFactory = scopeFactory;
        _options = options;
    }

    public void SignalCrlRefreshNeeded()
    {
        try
        {
            if (_crlRefreshWakeSignal.CurrentCount == 0)
            {
                _crlRefreshWakeSignal.Release();
            }
        }
        catch (SemaphoreFullException)
        {
        }
    }

    public Task<bool> WaitForCrlRefreshSignalAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken = default) =>
        _crlRefreshWakeSignal.WaitAsync(timeout, cancellationToken);

    public void UnlockRuntimePassphrase(string passphrase) =>
        UnlockRuntimePassphraseAsync(passphrase).GetAwaiter().GetResult();

    public async Task UnlockRuntimePassphraseAsync(
        string passphrase,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(passphrase))
        {
            throw new ArgumentException("Passphrase cannot be empty.", nameof(passphrase));
        }

        await using IAsyncDisposable _ = await AcquireInstanceLifecycleLockAsync(cancellationToken);
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await db.EnsureSchemaUpgradedAsync(cancellationToken);

        await ValidateCustodyCandidateCoreAsync(
            db,
            passphrase,
            secondaryParentPassphrase: null,
            requireExistingKeyForUnlock: true,
            cancellationToken);

        _runtimeUnlockedPassphrase = passphrase;
        _isExplicitlyLocked = false;
        SignalCrlRefreshNeeded();
    }

    public void LockRuntimePassphrase()
    {
        _runtimeUnlockedPassphrase = null;
        _isExplicitlyLocked = true;
    }

    internal Task<IAsyncDisposable> AcquireInstanceLifecycleLockAsync(CancellationToken cancellationToken = default) =>
        AcquireLifecycleLockAsync(
            _options.StorageDirectory,
            cancellationToken,
            TimeSpan.FromMilliseconds(Math.Max(100, _options.CrossProcessLockTimeoutMs)));

    public static async Task<IAsyncDisposable> AcquireLifecycleLockAsync(
        string? storageDirectory,
        CancellationToken cancellationToken = default,
        TimeSpan? timeout = null)
    {
        TimeSpan effectiveTimeout = timeout ?? TimeSpan.FromSeconds(30);
        Stopwatch sw = Stopwatch.StartNew();

        if (!await SigningAndSerialLock.WaitAsync(effectiveTimeout, cancellationToken))
        {
            throw new TimeoutException("Timed out waiting for in-process CA lifecycle lock.");
        }

        FileStream? lockStream = null;
        try
        {
            if (!string.IsNullOrWhiteSpace(storageDirectory))
            {
                Directory.CreateDirectory(storageDirectory);
                string lockFilePath = Path.Combine(storageDirectory, CrossProcessLockFileName);

                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    try
                    {
                        lockStream = new FileStream(
                            lockFilePath,
                            FileMode.OpenOrCreate,
                            FileAccess.ReadWrite,
                            FileShare.None);
                        RestrictFilePermissionsIfUnix(lockFilePath);
                        break;
                    }
                    catch (IOException ex)
                    {
                        TimeSpan remaining = effectiveTimeout - sw.Elapsed;
                        if (remaining <= TimeSpan.Zero)
                        {
                            throw new TimeoutException(
                                $"Timed out waiting for cross-process CA lifecycle lock '{lockFilePath}'. Another CertRobo process is currently accessing CA storage.",
                                ex);
                        }

                        int delayMs = (int)Math.Clamp(remaining.TotalMilliseconds, 10, 25);
                        await Task.Delay(delayMs, cancellationToken);
                    }
                }
            }

            return new LifecycleLockHandle(lockStream);
        }
        catch
        {
            lockStream?.Dispose();
            SigningAndSerialLock.Release();
            throw;
        }
    }

    private sealed class LifecycleLockHandle(FileStream? lockStream) : IAsyncDisposable, IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            try
            {
                lockStream?.Dispose();
            }
            finally
            {
                SigningAndSerialLock.Release();
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }

    public string? ResolveConfiguredPassphrase() =>
        ResolveConfiguredPassphraseWithSource().Passphrase;

    public (string? Passphrase, string Source) ResolveConfiguredPassphraseWithSource()
    {
        if (!string.IsNullOrEmpty(_options.PassphraseEnvironmentVariable))
        {
            string? envVal = Environment.GetEnvironmentVariable(_options.PassphraseEnvironmentVariable);
            if (!string.IsNullOrWhiteSpace(envVal))
            {
                return (envVal.Trim(), $"environment variable '{_options.PassphraseEnvironmentVariable}'");
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.PassphraseFilePath) && File.Exists(_options.PassphraseFilePath))
        {
            string fileVal = File.ReadAllText(_options.PassphraseFilePath).Trim();
            if (!string.IsNullOrEmpty(fileVal))
            {
                return (fileVal, $"passphrase file '{_options.PassphraseFilePath}'");
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ConfiguredPassphrase))
        {
            return (_options.ConfiguredPassphrase, "configuration 'CertRobo:CaPassphrase'");
        }

        return (null, "None");
    }

    public string? ResolveEffectivePassphrase()
    {
        if (_isExplicitlyLocked)
        {
            return null;
        }

        string? configured = ResolveConfiguredPassphrase();
        if (!string.IsNullOrEmpty(configured))
        {
            if (!string.IsNullOrEmpty(_runtimeUnlockedPassphrase)
                && !PassphrasesEqual(_runtimeUnlockedPassphrase, configured))
            {
                _runtimeUnlockedPassphrase = null;
            }

            return configured;
        }

        if (!string.IsNullOrEmpty(_runtimeUnlockedPassphrase))
        {
            return _runtimeUnlockedPassphrase;
        }

        return null;
    }

    public async Task<CaKeyCustodyReport> InspectKeyCustodyAsync(
        string? candidatePassphrase = null,
        CancellationToken cancellationToken = default)
    {
        await using IAsyncDisposable _ = await AcquireInstanceLifecycleLockAsync(cancellationToken);
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await db.EnsureSchemaUpgradedAsync(cancellationToken);

        DateTimeOffset now = DateTimeOffset.UtcNow;
        List<CaAuthorityRecord> authorities = await db.CaAuthorities
            .OrderBy(c => c.Id)
            .ToListAsync(cancellationToken);

        PendingCaEnrollmentRecord? pending = await db.PendingCaEnrollments
            .Where(p => p.Status != PendingCaEnrollmentStatus.Activated
                     && p.Status != PendingCaEnrollmentStatus.Cancelled)
            .OrderByDescending(p => p.Id)
            .FirstOrDefaultAsync(cancellationToken);

        string? configuredPassphrase = null;
        string configuredSource = "None";
        string? effectivePassphrase = null;
        string? passphraseReadError = null;
        try
        {
            EvictStaleRuntimeUnlockIfIncompatible(
                authorities,
                pending != null ? [pending] : []);

            (configuredPassphrase, configuredSource) = ResolveConfiguredPassphraseWithSource();
            effectivePassphrase = !string.IsNullOrEmpty(candidatePassphrase)
                ? candidatePassphrase
                : ResolveEffectivePassphrase();
        }
        catch (Exception ex)
        {
            passphraseReadError = $"Configured CA passphrase could not be read: {ex.Message}";
            if (!string.IsNullOrWhiteSpace(_options.PassphraseFilePath))
            {
                configuredSource = $"passphrase file '{_options.PassphraseFilePath}' (unreadable)";
            }
        }

        bool hasConfigured = !string.IsNullOrEmpty(configuredPassphrase) || passphraseReadError != null;
        bool hasRuntime = !_isExplicitlyLocked && !string.IsNullOrEmpty(_runtimeUnlockedPassphrase);
        bool hasEffective = !string.IsNullOrEmpty(effectivePassphrase);
        bool runtimeMatchesConfigured = passphraseReadError == null
            && (!hasConfigured
                || string.IsNullOrEmpty(effectivePassphrase)
                || PassphrasesEqual(effectivePassphrase, configuredPassphrase!));

        List<IssuedCertificateRecord> maintainedCerts = await db.IssuedCertificates
            .Where(c => c.CaAuthorityId.HasValue
                     && (c.Status == IssuanceStatus.Issued || c.Status == IssuanceStatus.Revoked))
            .ToListAsync(cancellationToken);

        HashSet<int> authoritiesWithUnexpiredCerts = maintainedCerts
            .Where(c => c.NotAfterUtc > now)
            .Select(c => c.CaAuthorityId!.Value)
            .ToHashSet();

        Dictionary<int, int> unexpiredCountsByAuthority = maintainedCerts
            .Where(c => c.NotAfterUtc > now)
            .GroupBy(c => c.CaAuthorityId!.Value)
            .ToDictionary(g => g.Key, g => g.Count());

        Dictionary<int, List<CaAuthorityRecord>> directSubordinatesByParent = MapDirectLocalSubordinatesByParentId(authorities);
        HashSet<int> authoritiesWithUnexpiredSubordinates = directSubordinatesByParent
            .Where(kv => kv.Value.Any(sub => sub.NotAfterUtc > now))
            .Select(kv => kv.Key)
            .ToHashSet();

        List<CaAuthorityKeyCustodyStatus> authorityStatuses = [];
        bool allAuthoritiesHealthy = true;
        bool activeDecryptable = false;

        foreach (CaAuthorityRecord authority in authorities)
        {
            bool isExpired = authority.NotAfterUtc <= now;
            int unexpiredSubCount = directSubordinatesByParent.TryGetValue(authority.Id, out List<CaAuthorityRecord>? subs)
                ? subs.Count(s => s.NotAfterUtc > now)
                : 0;
            int unexpiredCount = unexpiredCountsByAuthority.GetValueOrDefault(authority.Id, 0) + unexpiredSubCount;
            bool requiresMaintenance = authority.IsActive
                || (!isExpired && (authoritiesWithUnexpiredCerts.Contains(authority.Id)
                                || authoritiesWithUnexpiredSubordinates.Contains(authority.Id)));
            bool fileExists = File.Exists(authority.EncryptedPrivateKeyPath);

            string? effectiveErr = null;
            bool canDecryptEffective = hasEffective
                && TryVerifyAuthorityKey(authority, effectivePassphrase, out effectiveErr);
            string? failureReason = passphraseReadError
                ?? (hasEffective
                    ? (canDecryptEffective ? null : effectiveErr)
                    : (fileExists ? "CA signing key is locked (no effective passphrase is active)." : $"Encrypted private key file '{Path.GetFileName(authority.EncryptedPrivateKeyPath)}' was not found."));

            string? configuredErr = null;
            bool canDecryptConfigured = !string.IsNullOrEmpty(configuredPassphrase)
                && TryVerifyAuthorityKey(authority, configuredPassphrase, out configuredErr);
            if (hasConfigured && !canDecryptConfigured && failureReason == null)
            {
                failureReason = configuredErr;
            }

            if (authority.IsActive && canDecryptEffective && runtimeMatchesConfigured)
            {
                activeDecryptable = true;
            }

            bool authorityHealthy = fileExists
                && (!hasEffective || canDecryptEffective)
                && (!hasConfigured || canDecryptConfigured)
                && runtimeMatchesConfigured;
            if (!authorityHealthy)
            {
                allAuthoritiesHealthy = false;
            }

            authorityStatuses.Add(new(
                authority.Id,
                authority.Name,
                authority.IsActive,
                authority.IsIntermediate,
                isExpired,
                unexpiredCount,
                requiresMaintenance,
                authority.EncryptedPrivateKeyPath,
                fileExists,
                canDecryptEffective,
                canDecryptConfigured,
                failureReason));
        }

        PendingCaKeyCustodyStatus? pendingStatus = null;
        bool pendingHealthy = true;
        if (pending != null)
        {
            bool pendingFileExists = File.Exists(pending.EncryptedPrivateKeyPath);
            string? effPendingErr = null;
            bool canDecryptEffective = hasEffective
                && TryVerifyPendingKey(pending, effectivePassphrase, out effPendingErr);
            string? pendingFailure = passphraseReadError
                ?? (hasEffective
                    ? (canDecryptEffective ? null : effPendingErr)
                    : (pendingFileExists ? "Pending CA signing key is locked." : $"Encrypted pending private key file '{Path.GetFileName(pending.EncryptedPrivateKeyPath)}' was not found."));

            string? cfgPendingErr = null;
            bool canDecryptConfigured = !string.IsNullOrEmpty(configuredPassphrase)
                && TryVerifyPendingKey(pending, configuredPassphrase, out cfgPendingErr);
            if (hasConfigured && !canDecryptConfigured && pendingFailure == null)
            {
                pendingFailure = cfgPendingErr;
            }

            pendingHealthy = pendingFileExists
                && (!hasEffective || canDecryptEffective)
                && (!hasConfigured || canDecryptConfigured)
                && runtimeMatchesConfigured;

            pendingStatus = new(
                pending.Id,
                pending.CaName,
                pending.EncryptedPrivateKeyPath,
                pendingFileExists,
                canDecryptEffective,
                canDecryptConfigured,
                pendingFailure);
        }

        bool isHealthy = runtimeMatchesConfigured && allAuthoritiesHealthy && pendingHealthy;

        return new(
            hasConfigured,
            configuredSource,
            hasRuntime,
            _isExplicitlyLocked,
            hasEffective,
            runtimeMatchesConfigured,
            isHealthy,
            activeDecryptable,
            authorityStatuses,
            pendingStatus);
    }

    /// <summary>
    /// Explicit recovery/migration procedure to re-encrypt incompatible historical, active, or pending CA private keys
    /// onto the shared target storage passphrase without overwriting existing encrypted key files or discarding issuers.
    /// </summary>
    public Task<CaKeyReprotectionResult> ReprotectCaKeysAsync(
        string currentPassphrase,
        string targetStoragePassphrase,
        int? targetAuthorityId = null,
        CancellationToken cancellationToken = default,
        Action? onKeysStagedBeforeCommit = null) =>
        ReprotectCaKeysAsync([currentPassphrase], targetStoragePassphrase, targetAuthorityId, cancellationToken, onKeysStagedBeforeCommit);

    public async Task<CaKeyReprotectionResult> ReprotectCaKeysAsync(
        IReadOnlyCollection<string> currentPassphrases,
        string targetStoragePassphrase,
        int? targetAuthorityId = null,
        CancellationToken cancellationToken = default,
        Action? onKeysStagedBeforeCommit = null)
    {
        if (string.IsNullOrWhiteSpace(targetStoragePassphrase))
        {
            throw new ArgumentException("A non-empty target storage passphrase is required.", nameof(targetStoragePassphrase));
        }

        List<string> sourceCandidates = (currentPassphrases ?? [])
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .ToList();
        if (sourceCandidates.Count == 0)
        {
            throw new ArgumentException("At least one non-empty current key passphrase is required.", nameof(currentPassphrases));
        }

        IAsyncDisposable lifecycleLock = await AcquireInstanceLifecycleLockAsync(cancellationToken);
        try
        {
            await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await db.EnsureSchemaUpgradedAsync(cancellationToken);

            (string? configuredPassphrase, string configuredSource) = ResolveConfiguredPassphraseWithSource();
            if (!string.IsNullOrEmpty(configuredPassphrase)
                && !PassphrasesEqual(targetStoragePassphrase, configuredPassphrase))
            {
                throw new InvalidOperationException(
                    $"Target storage passphrase must match the configured persistent CA custody secret ({configuredSource}). Update the configured custody secret first or re-protect keys to match it.");
            }

            List<CaAuthorityRecord> authorities = await db.CaAuthorities
                .OrderBy(c => c.Id)
                .ToListAsync(cancellationToken);

            if (targetAuthorityId.HasValue && !authorities.Any(a => a.Id == targetAuthorityId.Value))
            {
                throw new InvalidOperationException($"CA authority #{targetAuthorityId.Value} was not found.");
            }

            List<PendingCaEnrollmentRecord> pendingEnrollments = targetAuthorityId.HasValue
                ? []
                : await db.PendingCaEnrollments
                    .Where(p => p.Status != PendingCaEnrollmentStatus.Activated
                             && p.Status != PendingCaEnrollmentStatus.Cancelled)
                    .OrderBy(p => p.Id)
                    .ToListAsync(cancellationToken);

            if (authorities.Count == 0 && pendingEnrollments.Count == 0)
            {
                throw new InvalidOperationException("No stored CA keys were found to re-protect.");
            }

            List<(CaAuthorityRecord Authority, string SourcePassphrase)> authoritiesToReprotect = [];
            foreach (CaAuthorityRecord authority in authorities)
            {
                if (targetAuthorityId.HasValue && authority.Id != targetAuthorityId.Value)
                {
                    continue;
                }

                if (!File.Exists(authority.EncryptedPrivateKeyPath))
                {
                    throw new FileNotFoundException(
                        $"Encrypted private key file for CA '{authority.Name}' (ID #{authority.Id}) was not found.",
                        authority.EncryptedPrivateKeyPath);
                }

                if (TryVerifyAuthorityKey(authority, targetStoragePassphrase, out _))
                {
                    continue;
                }

                string? matchedSource = sourceCandidates.FirstOrDefault(
                    candidate => TryVerifyAuthorityKey(authority, candidate, out _));
                if (string.IsNullOrEmpty(matchedSource))
                {
                    throw new InvalidOperationException(
                        $"Cannot re-protect CA '{authority.Name}' (ID #{authority.Id}): none of the supplied current passphrases unlocked its encrypted private key.");
                }

                authoritiesToReprotect.Add((authority, matchedSource));
            }

            List<(PendingCaEnrollmentRecord Pending, string SourcePassphrase)> pendingToReprotect = [];
            foreach (PendingCaEnrollmentRecord pending in pendingEnrollments)
            {
                if (!File.Exists(pending.EncryptedPrivateKeyPath))
                {
                    throw new FileNotFoundException(
                        $"Encrypted private key file for pending CA request '{pending.CaName}' (ID #{pending.Id}) was not found.",
                        pending.EncryptedPrivateKeyPath);
                }

                if (TryVerifyPendingKey(pending, targetStoragePassphrase, out _))
                {
                    continue;
                }

                string? matchedSource = sourceCandidates.FirstOrDefault(
                    candidate => TryVerifyPendingKey(pending, candidate, out _));
                if (string.IsNullOrEmpty(matchedSource))
                {
                    throw new InvalidOperationException(
                        $"Cannot re-protect pending CA request '{pending.CaName}' (ID #{pending.Id}): none of the supplied current passphrases unlocked its encrypted private key.");
                }

                pendingToReprotect.Add((pending, matchedSource));
            }

            Directory.CreateDirectory(_options.StorageDirectory);
            string backupDir = Path.Combine(_options.StorageDirectory, "recovery-backups");
            Directory.CreateDirectory(backupDir);
            if (!OperatingSystem.IsWindows())
            {
                try
                {
                    File.SetUnixFileMode(backupDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                }
                catch
                {
                }
            }

            List<string> createdKeyPaths = [];
            List<string> createdBackupPaths = [];
            List<(CaAuthorityRecord Authority, string NewKeyPath)> stagedAuthorityUpdates = [];
            List<(PendingCaEnrollmentRecord Pending, string NewKeyPath)> stagedPendingUpdates = [];

            try
            {
                foreach ((CaAuthorityRecord authority, string srcPass) in authoritiesToReprotect)
                {
                    // Preserve a non-overwritten backup copy in recovery-backups while also leaving the original .p8.enc file untouched
                    string backupFileName = $"{Path.GetFileName(authority.EncryptedPrivateKeyPath)}.bak-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}"[..Math.Min(96, Path.GetFileName(authority.EncryptedPrivateKeyPath).Length + 28)];
                    string backupFilePath = Path.Combine(backupDir, backupFileName);
                    File.Copy(authority.EncryptedPrivateKeyPath, backupFilePath, overwrite: false);
                    RestrictFilePermissionsIfUnix(backupFilePath);
                    createdBackupPaths.Add(backupFilePath);

                    using AsymmetricAlgorithm key = LoadEncryptedKey(authority.EncryptedPrivateKeyPath, srcPass);
                    byte[] reencryptedPkcs8 = key.ExportEncryptedPkcs8PrivateKey(
                        targetStoragePassphrase,
                        new PbeParameters(
                            PbeEncryptionAlgorithm.Aes256Cbc,
                            HashAlgorithmName.SHA256,
                            iterationCount: 100_000));

                    string newKeyFilePath = Path.Combine(_options.StorageDirectory, $"ca-key-{Guid.NewGuid():N}.p8.enc");
                    if (File.Exists(newKeyFilePath))
                    {
                        throw new IOException("Refusing to overwrite an existing encrypted CA key file.");
                    }

                    await File.WriteAllBytesAsync(newKeyFilePath, reencryptedPkcs8, cancellationToken);
                    RestrictFilePermissionsIfUnix(newKeyFilePath);
                    createdKeyPaths.Add(newKeyFilePath);

                    // Verify newly written key file on disk before updating database record
                    using AsymmetricAlgorithm verifiedKey = LoadEncryptedKey(newKeyFilePath, targetStoragePassphrase);
                    using X509Certificate2 cert = X509Certificate2.CreateFromPem(authority.IssuerCertificatePem);
                    if (!cert.PublicKey.ExportSubjectPublicKeyInfo().SequenceEqual(ExportPublicKeySpki(verifiedKey)))
                    {
                        throw new CryptographicException(
                            $"Re-protected key verification failed for CA '{authority.Name}' (ID #{authority.Id}).");
                    }

                    stagedAuthorityUpdates.Add((authority, newKeyFilePath));
                }

                foreach ((PendingCaEnrollmentRecord pending, string srcPass) in pendingToReprotect)
                {
                    string backupFileName = $"{Path.GetFileName(pending.EncryptedPrivateKeyPath)}.bak-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}"[..Math.Min(96, Path.GetFileName(pending.EncryptedPrivateKeyPath).Length + 28)];
                    string backupFilePath = Path.Combine(backupDir, backupFileName);
                    File.Copy(pending.EncryptedPrivateKeyPath, backupFilePath, overwrite: false);
                    RestrictFilePermissionsIfUnix(backupFilePath);
                    createdBackupPaths.Add(backupFilePath);

                    using AsymmetricAlgorithm key = LoadEncryptedKey(pending.EncryptedPrivateKeyPath, srcPass);
                    byte[] reencryptedPkcs8 = key.ExportEncryptedPkcs8PrivateKey(
                        targetStoragePassphrase,
                        new PbeParameters(
                            PbeEncryptionAlgorithm.Aes256Cbc,
                            HashAlgorithmName.SHA256,
                            iterationCount: 100_000));

                    string newKeyFilePath = Path.Combine(_options.StorageDirectory, $"ca-pending-key-{Guid.NewGuid():N}.p8.enc");
                    if (File.Exists(newKeyFilePath))
                    {
                        throw new IOException("Refusing to overwrite an existing encrypted pending CA key file.");
                    }

                    await File.WriteAllBytesAsync(newKeyFilePath, reencryptedPkcs8, cancellationToken);
                    RestrictFilePermissionsIfUnix(newKeyFilePath);
                    createdKeyPaths.Add(newKeyFilePath);

                    using AsymmetricAlgorithm verifiedKey = LoadEncryptedKey(newKeyFilePath, targetStoragePassphrase);
                    string spkiHex = Convert.ToHexString(SHA256.HashData(ExportPublicKeySpki(verifiedKey)));
                    if (!spkiHex.Equals(pending.PublicKeySpkiSha256Hex, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new CryptographicException(
                            $"Re-protected key verification failed for pending CA request '{pending.CaName}' (ID #{pending.Id}).");
                    }

                    stagedPendingUpdates.Add((pending, newKeyFilePath));
                }

                if (createdKeyPaths.Count > 0)
                {
                    onKeysStagedBeforeCommit?.Invoke();
                    if (string.Equals(
                            Environment.GetEnvironmentVariable("CERTROBO_TEST_FAIL_REPROTECT_AFTER_WRITE"),
                            "1",
                            StringComparison.Ordinal))
                    {
                        throw new IOException("Simulated mid-migration I/O failure after writing re-protected key file.");
                    }
                }

                await using var tx = await db.Database.BeginTransactionAsync(cancellationToken);
                foreach ((CaAuthorityRecord authority, string newKeyPath) in stagedAuthorityUpdates)
                {
                    authority.EncryptedPrivateKeyPath = newKeyPath;
                }
                foreach ((PendingCaEnrollmentRecord pending, string newKeyPath) in stagedPendingUpdates)
                {
                    pending.EncryptedPrivateKeyPath = newKeyPath;
                }
                await db.SaveChangesAsync(cancellationToken);
                await tx.CommitAsync(cancellationToken);
            }
            catch
            {
                foreach (string createdPath in createdKeyPaths.Concat(createdBackupPaths))
                {
                    try
                    {
                        if (File.Exists(createdPath))
                        {
                            File.Delete(createdPath);
                        }
                    }
                    catch
                    {
                        // Preserve original exception
                    }
                }
                throw;
            }

            bool allNowUnified = authorities.All(a => TryVerifyAuthorityKey(a, targetStoragePassphrase, out _))
                && pendingEnrollments.All(p => TryVerifyPendingKey(p, targetStoragePassphrase, out _));
            if (allNowUnified && !_isExplicitlyLocked)
            {
                _runtimeUnlockedPassphrase = targetStoragePassphrase;
                SignalCrlRefreshNeeded();
            }

            IReadOnlyList<int> reprotectedIds = stagedAuthorityUpdates.Select(u => u.Authority.Id).ToList();
            return new(
                true,
                reprotectedIds.Count,
                stagedPendingUpdates.Count > 0,
                reprotectedIds,
                $"Re-protected {reprotectedIds.Count} CA authority key(s){(stagedPendingUpdates.Count > 0 ? " and 1 pending CA key" : "")} to the shared storage passphrase. Original encrypted key files were preserved untouched.");
        }
        finally
        {
            await lifecycleLock.DisposeAsync();
        }
    }

    public async Task<CaAuthorityRecord?> GetActiveAuthorityAsync(CancellationToken cancellationToken = default)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        return await db.CaAuthorities
            .OrderByDescending(c => c.Id)
            .FirstOrDefaultAsync(c => c.IsActive, cancellationToken);
    }

    public async Task<CaAuthorityRecord?> GetAuthorityByIdAsync(int caId, CancellationToken cancellationToken = default)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        return await db.CaAuthorities
            .FirstOrDefaultAsync(c => c.Id == caId, cancellationToken);
    }

    public async Task<IReadOnlyList<CaAuthorityRecord>> ListAuthoritiesAsync(CancellationToken cancellationToken = default)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        return await db.CaAuthorities
            .OrderByDescending(c => c.Id)
            .ToListAsync(cancellationToken);
    }

    public async Task<PendingCaEnrollmentRecord?> GetActivePendingEnrollmentAsync(CancellationToken cancellationToken = default)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await db.EnsureSchemaUpgradedAsync(cancellationToken);
        return await db.PendingCaEnrollments
            .Where(p => p.Status != PendingCaEnrollmentStatus.Activated
                     && p.Status != PendingCaEnrollmentStatus.Cancelled)
            .OrderByDescending(p => p.Id)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<PendingCaEnrollmentRecord?> GetPendingEnrollmentByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await db.EnsureSchemaUpgradedAsync(cancellationToken);
        return await db.PendingCaEnrollments
            .FirstOrDefaultAsync(p => p.Id == id, cancellationToken);
    }

    public static CaActivationPreviewSummary? DeserializeActivationSummary(PendingCaEnrollmentRecord? pending)
    {
        if (pending == null || string.IsNullOrWhiteSpace(pending.ActivationSummaryJson))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<CaActivationPreviewSummary>(pending.ActivationSummaryJson);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Generates a CA private key on the CertRobo server, encrypts it at rest in CA storage,
    /// generates a signed PKCS #10 CSR requesting CA capabilities (BasicConstraints CA=true, KeyCertSign|CrlSign|DigitalSignature),
    /// and persists the pending request across restarts without affecting any active CA.
    /// </summary>
    public async Task<PendingCaEnrollmentRecord> CreatePendingCaEnrollmentAsync(
        string caName,
        string subjectCommonName,
        string country,
        string stateOrProvince,
        string locality,
        string organization,
        string organizationalUnit,
        CertificateKeyFamily keyFamily,
        int keyBits,
        string passphrase,
        int? requestedPathLengthConstraint = 0,
        string crlDistributionPointUrl = "/ca.crl",
        string authorityIssuerCertUrl = "/ca.crt",
        long initialSerialFloor = 1000,
        long initialCrlNumberFloor = 0,
        string? emailAddress = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(caName))
        {
            throw new ArgumentException("CA display name is required.", nameof(caName));
        }

        if (string.IsNullOrWhiteSpace(subjectCommonName))
        {
            throw new ArgumentException("Subject Common Name (CN) is required.", nameof(subjectCommonName));
        }

        if (string.IsNullOrWhiteSpace(passphrase))
        {
            throw new ArgumentException("A non-empty passphrase is required to protect the pending CA private key.", nameof(passphrase));
        }

        if (requestedPathLengthConstraint.HasValue && requestedPathLengthConstraint.Value < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(requestedPathLengthConstraint), "Path length constraint cannot be negative.");
        }

        IAsyncDisposable lifecycleLock = await AcquireInstanceLifecycleLockAsync(cancellationToken);
        try
        {
            await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await db.EnsureSchemaUpgradedAsync(cancellationToken);

            PendingCaEnrollmentRecord? existingPending = await db.PendingCaEnrollments
                .Where(p => p.Status != PendingCaEnrollmentStatus.Activated
                         && p.Status != PendingCaEnrollmentStatus.Cancelled)
                .OrderByDescending(p => p.Id)
                .FirstOrDefaultAsync(cancellationToken);

            if (existingPending != null)
            {
                throw new InvalidOperationException(
                    $"A pending external CA enrolment request ('{existingPending.CaName}') already exists. Review, complete, or cancel the existing request before generating a new CSR.");
            }

            await ValidateCustodyCandidateCoreAsync(
                db,
                passphrase,
                secondaryParentPassphrase: null,
                requireExistingKeyForUnlock: false,
                cancellationToken);

            using AsymmetricAlgorithm subjectKey = CreateDotNetAsymmetricKey(keyFamily, keyBits);
            X500DistinguishedName subjectDn = BuildX500DistinguishedName(
                subjectCommonName,
                country,
                stateOrProvince,
                locality,
                organization,
                organizationalUnit,
                emailAddress);

            CertificateRequest certReq = CreateCertificateRequestForKey(subjectDn, subjectKey);

            // Request CA BasicConstraints (critical)
            certReq.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(
                    certificateAuthority: true,
                    hasPathLengthConstraint: requestedPathLengthConstraint.HasValue,
                    pathLengthConstraint: requestedPathLengthConstraint ?? 0,
                    critical: true));

            // Request CA KeyUsage: KeyCertSign | CrlSign | DigitalSignature (critical)
            certReq.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
                    critical: true));

            // Request SubjectKeyIdentifier
            X509SubjectKeyIdentifierExtension skiExt = new(certReq.PublicKey, critical: false);
            certReq.CertificateExtensions.Add(skiExt);

            string csrPem = certReq.CreateSigningRequestPem().Trim() + "\n";

            // Verify PKCS #10 self-signature and public key correspondence immediately
            Pkcs10CertificationRequest decodedCsr = (new PemReader(new StringReader(csrPem)).ReadObject() as Pkcs10CertificationRequest)
                ?? throw new CryptographicException("Generated CA CSR could not be decoded.");
            if (!decodedCsr.Verify())
            {
                throw new CryptographicException("Generated CA CSR failed self-signature verification.");
            }

            byte[] spkiDer = ExportPublicKeySpki(subjectKey);
            string spkiSha256Hex = Convert.ToHexString(SHA256.HashData(spkiDer));
            string skiHex = skiExt.SubjectKeyIdentifier ?? spkiSha256Hex;

            byte[] encryptedPkcs8 = subjectKey.ExportEncryptedPkcs8PrivateKey(
                passphrase,
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    iterationCount: 100_000));

            Directory.CreateDirectory(_options.StorageDirectory);
            string keyFileName = $"ca-pending-key-{Guid.NewGuid():N}.p8.enc";
            string keyFilePath = Path.Combine(_options.StorageDirectory, keyFileName);
            await File.WriteAllBytesAsync(keyFilePath, encryptedPkcs8, cancellationToken);
            RestrictFilePermissionsIfUnix(keyFilePath);

            PendingCaEnrollmentRecord record = new()
            {
                CaName = caName.Trim(),
                SubjectCommonName = subjectCommonName.Trim(),
                SubjectDistinguishedName = subjectDn.Name,
                KeyAlgorithm = keyFamily == CertificateKeyFamily.Ecdsa ? "ECDSA" : "RSA",
                KeySizeBits = keyBits,
                RequestedPathLengthConstraint = requestedPathLengthConstraint,
                SubjectKeyIdentifierHex = skiHex,
                PublicKeySpkiSha256Hex = spkiSha256Hex,
                CsrPem = csrPem,
                EncryptedPrivateKeyPath = keyFilePath,
                CrlDistributionPointUrl = string.IsNullOrWhiteSpace(crlDistributionPointUrl) ? "/ca.crl" : crlDistributionPointUrl.Trim(),
                AuthorityIssuerCertUrl = string.IsNullOrWhiteSpace(authorityIssuerCertUrl) ? "/ca.crt" : authorityIssuerCertUrl.Trim(),
                InitialSerialFloor = Math.Max(1000L, initialSerialFloor),
                InitialCrlNumberFloor = Math.Max(0L, initialCrlNumberFloor),
                Status = PendingCaEnrollmentStatus.AwaitingSubmission,
                LastOutcomeCategory = "None",
                StatusDetailMessage = "PKCS #10 CSR generated locally. Download the CSR for external signing or submit to Microsoft AD CS CES.",
                CreatedAtUtc = DateTimeOffset.UtcNow
            };

            db.PendingCaEnrollments.Add(record);
            await db.SaveChangesAsync(cancellationToken);

            _runtimeUnlockedPassphrase = passphrase;
            _isExplicitlyLocked = false;

            return record;
        }
        finally
        {
            await lifecycleLock.DisposeAsync();
        }
    }

    /// <summary>
    /// Returns the persisted PKCS #10 CSR for the current (or specified) pending CA enrollment request
    /// without regenerating the key or exporting private key material.
    /// </summary>
    public async Task<(int PendingId, string FileName, string CsrPem)?> GetPendingCaCsrForDownloadAsync(
        int? pendingId = null,
        CancellationToken cancellationToken = default)
    {
        PendingCaEnrollmentRecord? pending = pendingId.HasValue
            ? await GetPendingEnrollmentByIdAsync(pendingId.Value, cancellationToken)
            : await GetActivePendingEnrollmentAsync(cancellationToken);

        if (pending == null || pending.Status == PendingCaEnrollmentStatus.Cancelled)
        {
            return null;
        }

        string safeSlug = string.Concat(pending.SubjectCommonName.Select(ch =>
            char.IsLetterOrDigit(ch) || ch is '-' or '.' or '_' ? ch : '-')).Trim('-');
        if (string.IsNullOrEmpty(safeSlug))
        {
            safeSlug = $"pending-ca-{pending.Id}";
        }

        return (pending.Id, $"{safeSlug}.csr", pending.CsrPem);
    }

    /// <summary>
    /// Validates an externally signed CA certificate and parent/root chain (from PEM, DER, or PKCS#7/P7B input)
    /// against the pending request's private key and CSR. On success, stages the validated certificate,
    /// ordered chain, and activation summary in ReadyForActivation state without replacing the active CA until explicit activation.
    /// On failure, preserves the pending request and any active CA intact.
    /// </summary>
    public async Task<CaBundleValidationResult> ValidateAndStageSignedCaBundleAsync(
        int pendingEnrollmentId,
        byte[]? signedCertBytes,
        string? signedCertText,
        byte[]? chainCertBytes = null,
        string? chainCertText = null,
        string? passphraseOverride = null,
        CancellationToken cancellationToken = default)
    {
        IAsyncDisposable lifecycleLock = await AcquireInstanceLifecycleLockAsync(cancellationToken);
        try
        {
            await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await db.EnsureSchemaUpgradedAsync(cancellationToken);

            PendingCaEnrollmentRecord? pending = await db.PendingCaEnrollments
                .FirstOrDefaultAsync(p => p.Id == pendingEnrollmentId, cancellationToken);

            if (pending == null)
            {
                return new(false, "Pending CA enrolment request was not found.", null, null, null);
            }

            if (pending.Status == PendingCaEnrollmentStatus.Activated || pending.Status == PendingCaEnrollmentStatus.Cancelled)
            {
                return new(false, $"Pending CA enrolment request is already in terminal state '{pending.Status}'.", null, null, null);
            }

            string? passphrase = !string.IsNullOrWhiteSpace(passphraseOverride)
                ? passphraseOverride
                : ResolveEffectivePassphrase();

            if (string.IsNullOrEmpty(passphrase))
            {
                return new(false, "CA storage passphrase is required to unlock and verify the pending private key.", null, null, null);
            }

            AsymmetricAlgorithm pendingKey;
            try
            {
                await ValidateCustodyCandidateCoreAsync(
                    db,
                    passphrase,
                    secondaryParentPassphrase: null,
                    requireExistingKeyForUnlock: true,
                    cancellationToken);
                pendingKey = LoadEncryptedKey(pending.EncryptedPrivateKeyPath, passphrase);
            }
            catch (InvalidOperationException ex)
            {
                return new(false, ex.Message, null, null, null);
            }
            catch (Exception)
            {
                return new(false, "Failed to unlock the pending CA private key with the supplied passphrase.", null, null, null);
            }

            using (pendingKey)
            {
                List<X509Certificate2> primaryCerts = [];
                List<X509Certificate2> chainCerts = [];
                try
                {
                    bool hasNewPrimaryInput = (signedCertBytes is { Length: > 0 }) || !string.IsNullOrWhiteSpace(signedCertText);
                    bool hasNewChainInput = (chainCertBytes is { Length: > 0 }) || !string.IsNullOrWhiteSpace(chainCertText);

                    if (hasNewPrimaryInput)
                    {
                        primaryCerts.AddRange(CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                            signedCertBytes,
                            signedCertText,
                            "signed CA certificate input"));
                    }
                    else if (!string.IsNullOrWhiteSpace(pending.ReceivedIssuerCertificatePem))
                    {
                        primaryCerts.AddRange(CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                            null,
                            pending.ReceivedIssuerCertificatePem,
                            "previously received CA certificate"));
                    }

                    if (hasNewChainInput)
                    {
                        chainCerts.AddRange(CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                            chainCertBytes,
                            chainCertText,
                            "parent/root chain input"));
                    }

                    if (!string.IsNullOrWhiteSpace(pending.ReceivedChainCertificatesPem))
                    {
                        chainCerts.AddRange(CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                            null,
                            pending.ReceivedChainCertificatesPem,
                            "previously received chain certificates"));
                    }

                    CaBundleValidationResult validation = CaChainAndConstraintValidator.ValidateSignedCaAndBuildActivationSummary(
                        pending.CsrPem,
                        pendingKey,
                        primaryCerts,
                        chainCerts);

                    if (!validation.IsValid || validation.Summary == null)
                    {
                        // If a matching signed CA certificate was found (e.g. from CES or upload) but only the root/parent chain is missing,
                        // keep ReceivedIssuerCertificatePem so the administrator can upload just the parent/root chain next.
                        if (!string.IsNullOrWhiteSpace(validation.ValidatedIssuerCertificatePem))
                        {
                            pending.ReceivedIssuerCertificatePem = validation.ValidatedIssuerCertificatePem;
                            using X509Certificate2 receivedIssuer = X509Certificate2.CreateFromPem(
                                validation.ValidatedIssuerCertificatePem);
                            string issuerFingerprint = receivedIssuer.GetCertHashString(HashAlgorithmName.SHA256);
                            StringBuilder retainedChain = new();
                            HashSet<string> retainedFingerprints = new(StringComparer.OrdinalIgnoreCase);
                            foreach (X509Certificate2 suppliedCert in primaryCerts.Concat(chainCerts))
                            {
                                string fingerprint = suppliedCert.GetCertHashString(HashAlgorithmName.SHA256);
                                if (!fingerprint.Equals(issuerFingerprint, StringComparison.OrdinalIgnoreCase)
                                    && retainedFingerprints.Add(fingerprint))
                                {
                                    retainedChain.AppendLine(suppliedCert.ExportCertificatePem().Trim());
                                }
                            }
                            if (retainedChain.Length > 0)
                            {
                                pending.ReceivedChainCertificatesPem = retainedChain.ToString();
                            }
                        }

                        pending.Status = PendingCaEnrollmentStatus.Failed;
                        pending.LastOutcomeCategory = "ValidationFailure";
                        pending.StatusDetailMessage = validation.ErrorMessage ?? "Certificate or chain validation failed.";
                        pending.ValidatedIssuerCertificatePem = null;
                        pending.ValidatedChainCertificatesPem = null;
                        pending.ActivationSummaryJson = null;
                        pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
                        await db.SaveChangesAsync(cancellationToken);
                        return validation;
                    }

                    pending.ReceivedIssuerCertificatePem = validation.ValidatedIssuerCertificatePem;
                    pending.ReceivedChainCertificatesPem = validation.ValidatedOrderedChainPem;
                    pending.ValidatedIssuerCertificatePem = validation.ValidatedIssuerCertificatePem;
                    pending.ValidatedChainCertificatesPem = validation.ValidatedOrderedChainPem;
                    pending.ActivationSummaryJson = JsonSerializer.Serialize(validation.Summary);
                    pending.Status = PendingCaEnrollmentStatus.ReadyForActivation;
                    pending.LastOutcomeCategory = "Validated";
                    pending.StatusDetailMessage = "Signed CA certificate and chain validated. Review the activation summary and activate when ready.";
                    pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
                    await db.SaveChangesAsync(cancellationToken);

                    _runtimeUnlockedPassphrase = passphrase;
                    _isExplicitlyLocked = false;

                    return validation;
                }
                catch (ArgumentException ex)
                {
                    pending.Status = PendingCaEnrollmentStatus.Failed;
                    pending.LastOutcomeCategory = "ValidationFailure";
                    pending.StatusDetailMessage = ex.Message;
                    pending.ValidatedIssuerCertificatePem = null;
                    pending.ValidatedChainCertificatesPem = null;
                    pending.ActivationSummaryJson = null;
                    pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
                    await db.SaveChangesAsync(cancellationToken);
                    return new(false, ex.Message, null, null, null);
                }
                finally
                {
                    foreach (X509Certificate2 c in primaryCerts) c.Dispose();
                    foreach (X509Certificate2 c in chainCerts) c.Dispose();
                }
            }
        }
        finally
        {
            await lifecycleLock.DisposeAsync();
        }
    }

    /// <summary>
    /// Atomically activates a validated pending external CA enrollment request, preserving any previous CA authority
    /// and its historical issued certificate records, and publishes initial CRL #1 for the new issuing CA.
    /// </summary>
    public async Task<CaAuthorityRecord> ActivatePendingCaEnrollmentAsync(
        int pendingEnrollmentId,
        string? passphraseOverride = null,
        CancellationToken cancellationToken = default)
    {
        IAsyncDisposable lifecycleLock = await AcquireInstanceLifecycleLockAsync(cancellationToken);
        try
        {
            await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await db.EnsureSchemaUpgradedAsync(cancellationToken);

            PendingCaEnrollmentRecord? pending = await db.PendingCaEnrollments
                .FirstOrDefaultAsync(p => p.Id == pendingEnrollmentId, cancellationToken)
                ?? throw new InvalidOperationException("Pending CA enrolment request was not found.");

            if (pending.Status != PendingCaEnrollmentStatus.ReadyForActivation
                || string.IsNullOrWhiteSpace(pending.ValidatedIssuerCertificatePem)
                || string.IsNullOrWhiteSpace(pending.ValidatedChainCertificatesPem))
            {
                throw new InvalidOperationException("Pending CA enrolment request is not in a validated ReadyForActivation state.");
            }

            string? passphrase = !string.IsNullOrWhiteSpace(passphraseOverride)
                ? passphraseOverride
                : ResolveEffectivePassphrase();

            if (string.IsNullOrEmpty(passphrase))
            {
                throw new InvalidOperationException("CA passphrase is required to unlock the pending private key and sign initial CRL #1.");
            }

            await ValidateCustodyCandidateCoreAsync(
                db,
                passphrase,
                secondaryParentPassphrase: null,
                requireExistingKeyForUnlock: true,
                cancellationToken);

            using AsymmetricAlgorithm pendingKey = LoadEncryptedKey(pending.EncryptedPrivateKeyPath, passphrase);

            // Re-validate right at activation time so expired certificates or tampered files cannot be activated
            List<X509Certificate2> primary = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                null, pending.ValidatedIssuerCertificatePem, "staged issuer certificate");
            List<X509Certificate2> chain = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                null, pending.ValidatedChainCertificatesPem, "staged chain certificates");

            try
            {
                CaBundleValidationResult recheck = CaChainAndConstraintValidator.ValidateSignedCaAndBuildActivationSummary(
                    pending.CsrPem,
                    pendingKey,
                    primary,
                    chain);

                if (!recheck.IsValid || recheck.Summary == null)
                {
                    pending.Status = PendingCaEnrollmentStatus.Failed;
                    pending.LastOutcomeCategory = "ValidationFailure";
                    pending.StatusDetailMessage = recheck.ErrorMessage ?? "Activation validation check failed.";
                    await db.SaveChangesAsync(cancellationToken);
                    throw new InvalidOperationException(recheck.ErrorMessage ?? "Activation validation check failed.");
                }

                using X509Certificate2 cert = X509Certificate2.CreateFromPem(recheck.ValidatedIssuerCertificatePem);
                string skiHex = cert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault()?.SubjectKeyIdentifier
                    ?? cert.GetCertHashString(HashAlgorithmName.SHA256);

                await using var tx = await db.Database.BeginTransactionAsync(cancellationToken);

                List<CaAuthorityRecord> previousActive = await db.CaAuthorities
                    .Where(c => c.IsActive)
                    .ToListAsync(cancellationToken);

                foreach (CaAuthorityRecord prev in previousActive)
                {
                    prev.IsActive = false;
                }

                CaAuthorityRecord newAuthority = new()
                {
                    Name = pending.CaName.Trim(),
                    IsActive = true,
                    IsIntermediate = true,
                    IssuerCertificatePem = recheck.ValidatedIssuerCertificatePem!,
                    ChainCertificatesPem = recheck.ValidatedOrderedChainPem!,
                    SubjectKeyIdentifierHex = skiHex,
                    ThumbprintOrSerialHex = cert.GetCertHashString(HashAlgorithmName.SHA256),
                    EncryptedPrivateKeyPath = pending.EncryptedPrivateKeyPath,
                    CrlDistributionPointUrl = pending.CrlDistributionPointUrl,
                    AuthorityIssuerCertUrl = pending.AuthorityIssuerCertUrl,
                    LastAllocatedSerial = Math.Max(1000L, pending.InitialSerialFloor),
                    LastCrlNumber = Math.Max(0L, pending.InitialCrlNumberFloor),
                    NotBeforeUtc = cert.NotBefore.ToUniversalTime(),
                    NotAfterUtc = cert.NotAfter.ToUniversalTime(),
                    CreatedAtUtc = DateTimeOffset.UtcNow
                };

                db.CaAuthorities.Add(newAuthority);
                await db.SaveChangesAsync(cancellationToken);
                ApplyStableIssuerPublicationUrls(newAuthority);
                await db.SaveChangesAsync(cancellationToken);

                pending.Status = PendingCaEnrollmentStatus.Activated;
                pending.LastOutcomeCategory = "Activated";
                pending.StatusDetailMessage = $"Activated as Issuing CA #{newAuthority.Id}.";
                pending.ActivatedAtUtc = DateTimeOffset.UtcNow;
                pending.ActivatedCaAuthorityId = newAuthority.Id;

                // Publish initial CRL #1 inside the same transaction
                await GenerateAndPersistCrlInternalAsync(db, newAuthority, passphrase, cancellationToken);

                await tx.CommitAsync(cancellationToken);

                _runtimeUnlockedPassphrase = passphrase;
                _isExplicitlyLocked = false;
                await WritePublicTrustFilesAsync(newAuthority, cancellationToken);

                return newAuthority;
            }
            finally
            {
                foreach (X509Certificate2 c in primary) c.Dispose();
                foreach (X509Certificate2 c in chain) c.Dispose();
            }
        }
        finally
        {
            await lifecycleLock.DisposeAsync();
        }
    }

    /// <summary>
    /// Cancels an unactivated pending external CA enrollment request without affecting any active CA.
    /// Removes the unactivated pending private key file if it is not referenced by any activated authority.
    /// </summary>
    public async Task<(bool Succeeded, string? ErrorMessage)> CancelPendingCaEnrollmentAsync(
        int pendingEnrollmentId,
        CancellationToken cancellationToken = default)
    {
        IAsyncDisposable lifecycleLock = await AcquireInstanceLifecycleLockAsync(cancellationToken);
        try
        {
            await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await db.EnsureSchemaUpgradedAsync(cancellationToken);

            PendingCaEnrollmentRecord? pending = await db.PendingCaEnrollments
                .FirstOrDefaultAsync(p => p.Id == pendingEnrollmentId, cancellationToken);

            if (pending == null)
            {
                return (false, "Pending CA enrolment request was not found.");
            }

            if (pending.Status == PendingCaEnrollmentStatus.Activated)
            {
                return (false, "Cannot cancel an enrolment request that has already been activated.");
            }

            pending.Status = PendingCaEnrollmentStatus.Cancelled;
            pending.LastOutcomeCategory = "Cancelled";
            pending.StatusDetailMessage = "Cancelled by administrator.";
            pending.ValidatedIssuerCertificatePem = null;
            pending.ValidatedChainCertificatesPem = null;
            pending.ActivationSummaryJson = null;
            await db.SaveChangesAsync(cancellationToken);

            bool usedByAnyCa = await db.CaAuthorities
                .AnyAsync(c => c.EncryptedPrivateKeyPath == pending.EncryptedPrivateKeyPath, cancellationToken);

            if (!usedByAnyCa && File.Exists(pending.EncryptedPrivateKeyPath))
            {
                try
                {
                    File.Delete(pending.EncryptedPrivateKeyPath);
                }
                catch
                {
                    // Ignore non-fatal file deletion errors
                }
            }

            return (true, null);
        }
        finally
        {
            await lifecycleLock.DisposeAsync();
        }
    }

    /// <summary>
    /// Resolves the ordered issuer certificate chain PEM for a leaf certificate, preserving historical issuer associations
    /// after CA rollover.
    /// </summary>
    public async Task<string?> ResolveCertificateChainPemAsync(
        string leafCertificatePem,
        string? fallbackChainPem = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(leafCertificatePem))
        {
            return fallbackChainPem;
        }

        try
        {
            List<X509Certificate2> parsed = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                null, leafCertificatePem, "leaf certificate");
            if (parsed.Count == 0)
            {
                return fallbackChainPem;
            }

            using X509Certificate2 leafCert = parsed[0];
            for (int i = 1; i < parsed.Count; i++) parsed[i].Dispose();

            string sha256 = leafCert.GetCertHashString(HashAlgorithmName.SHA256);

            await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);

            // 1. Check IssuedCertificateRecord by SHA-256 thumbprint
            IssuedCertificateRecord? issuedRecord = await db.IssuedCertificates
                .Where(c => c.ThumbprintSha256 == sha256)
                .OrderByDescending(c => c.Id)
                .FirstOrDefaultAsync(cancellationToken);

            if (issuedRecord != null)
            {
                if (!string.IsNullOrWhiteSpace(issuedRecord.ChainPem))
                {
                    return issuedRecord.ChainPem;
                }

                if (issuedRecord.CaAuthorityId.HasValue)
                {
                    CaAuthorityRecord? recordedIssuer = await db.CaAuthorities
                        .FirstOrDefaultAsync(c => c.Id == issuedRecord.CaAuthorityId.Value, cancellationToken);
                    if (recordedIssuer != null)
                    {
                        return BuildOrderedCertificateChainPem(recordedIssuer);
                    }
                }
            }

            // 2. Match against all CaAuthorityRecord rows (active and historical) by cryptographic signature verification
            List<CaAuthorityRecord> allCas = await db.CaAuthorities
                .OrderByDescending(c => c.Id)
                .ToListAsync(cancellationToken);

            foreach (CaAuthorityRecord candidateCa in allCas)
            {
                try
                {
                    using X509Certificate2 issuerCert = X509Certificate2.CreateFromPem(candidateCa.IssuerCertificatePem);
                    if (CaChainAndConstraintValidator.VerifySignatureCryptographically(leafCert, issuerCert, out _))
                    {
                        return BuildOrderedCertificateChainPem(candidateCa);
                    }
                }
                catch
                {
                    // Continue checking other authorities
                }
            }

            if (!string.IsNullOrWhiteSpace(fallbackChainPem))
            {
                return fallbackChainPem;
            }

            CaAuthorityRecord? active = allCas.FirstOrDefault(c => c.IsActive);
            return active != null ? BuildOrderedCertificateChainPem(active) : null;
        }
        catch
        {
            return fallbackChainPem;
        }
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
        CancellationToken cancellationToken = default,
        int? pathLengthConstraint = null)
    {
        if (string.IsNullOrWhiteSpace(passphrase))
        {
            throw new ArgumentException("A non-empty passphrase is required to protect the CA signing key.", nameof(passphrase));
        }

        if (pathLengthConstraint.HasValue && pathLengthConstraint.Value < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(pathLengthConstraint), "Path length constraint cannot be negative.");
        }

        IAsyncDisposable lifecycleLock = await AcquireInstanceLifecycleLockAsync(cancellationToken);
        try
        {
            await ThrowIfUnfinishedPendingEnrollmentExistsAsync(cancellationToken);
            CaAuthorityRecord? effectiveParent = null;
            long? allocatedParentSerial = null;
            byte[]? allocatedParentSerialBytes = null;

            await using (CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken))
            {
                await db.EnsureSchemaUpgradedAsync(cancellationToken);
                await ValidateCustodyCandidateCoreAsync(
                    db,
                    passphrase,
                    secondaryParentPassphrase: parentPassphrase,
                    requireExistingKeyForUnlock: false,
                    cancellationToken);

                if (parentAuthority != null)
                {
                    effectiveParent = await db.CaAuthorities
                        .FirstOrDefaultAsync(c => c.Id == parentAuthority.Id, cancellationToken)
                        ?? throw new InvalidOperationException(
                            $"Parent CA '{parentAuthority.Name}' (ID #{parentAuthority.Id}) was not found.");

                    if (!TryVerifyAuthorityKey(effectiveParent, passphrase, out string? parentErr))
                    {
                        throw new InvalidOperationException(
                            $"Parent CA '{effectiveParent.Name}' (ID #{effectiveParent.Id}) could not be unlocked with the supplied storage passphrase: {parentErr}");
                    }

                    var (nextParentSerial, nextSerialBytes, _) = await AllocateNextIssuerSerialAsync(db, effectiveParent, cancellationToken);
                    allocatedParentSerial = nextParentSerial;
                    allocatedParentSerialBytes = nextSerialBytes;
                }
            }

            using AsymmetricAlgorithm subjectKey = CreateDotNetAsymmetricKey(keyFamily, keyBits);
            X500DistinguishedName subjectDn = BuildX500DistinguishedName(
                subjectCommonName, country, stateOrProvince, locality, organization, organizationalUnit);

            CertificateRequest certReq = CreateCertificateRequestForKey(subjectDn, subjectKey);

            // CA BasicConstraints (critical)
            bool isSubordinate = effectiveParent != null;
            bool hasPathLen = pathLengthConstraint.HasValue || isSubordinate;
            int effectivePathLen = pathLengthConstraint ?? 0;
            certReq.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(
                    certificateAuthority: true,
                    hasPathLengthConstraint: hasPathLen,
                    pathLengthConstraint: hasPathLen ? effectivePathLen : 0,
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

            if (effectiveParent == null)
            {
                certReq.CertificateExtensions.Add(
                    X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(skiExt));
                issuedCaCert = certReq.CreateSelfSigned(notBefore, notAfter);
            }
            else
            {
                using X509Certificate2 parentCert = X509Certificate2.CreateFromPem(effectiveParent.IssuerCertificatePem);
                using AsymmetricAlgorithm parentKey = LoadEncryptedKey(
                    effectiveParent.EncryptedPrivateKeyPath,
                    parentPassphrase ?? passphrase);

                if (notBefore < parentCert.NotBefore.ToUniversalTime())
                {
                    notBefore = parentCert.NotBefore.ToUniversalTime();
                }

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
                else
                {
                    certReq.CertificateExtensions.Add(
                        X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
                            parentCert,
                            includeKeyIdentifier: true,
                            includeIssuerAndSerial: false));
                }

                var (parentCdpUrl, parentAiaUrl) = ResolveParentPublicationUrls(
                    effectiveParent,
                    crlDistributionPointUrl,
                    authorityIssuerCertUrl);

                if (!string.IsNullOrWhiteSpace(parentCdpUrl))
                {
                    certReq.CertificateExtensions.Add(
                        CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([parentCdpUrl]));
                }

                if (!string.IsNullOrWhiteSpace(parentAiaUrl))
                {
                    certReq.CertificateExtensions.Add(
                        new X509AuthorityInformationAccessExtension(
                            ocspUris: null,
                            caIssuersUris: [parentAiaUrl],
                            critical: false));
                }

                byte[] serialBytes = allocatedParentSerialBytes!;
                X509SignatureGenerator sigGen = CreateSignatureGenerator(parentKey);
                using X509Certificate2 signedCert = certReq.Create(
                    parentCert.SubjectName,
                    sigGen,
                    notBefore,
                    notAfter,
                    serialBytes);

                issuedCaCert = CopyWithPrivateKey(signedCert, subjectKey);
                chainPem = string.IsNullOrWhiteSpace(effectiveParent.ChainCertificatesPem)
                    ? effectiveParent.IssuerCertificatePem.Trim() + "\n"
                    : effectiveParent.IssuerCertificatePem.Trim() + "\n" + effectiveParent.ChainCertificatesPem.Trim() + "\n";
            }

            using (issuedCaCert)
            {
                bool validatedIsIntermediate;
                string normalizedChainPem;
                try
                {
                    ValidateCaCertificateAndKeyMatch(
                        issuedCaCert,
                        subjectKey,
                        string.IsNullOrWhiteSpace(chainPem) ? null : chainPem,
                        out validatedIsIntermediate,
                        out normalizedChainPem);
                }
                catch (ArgumentException ex)
                {
                    throw new InvalidOperationException(ex.Message, ex);
                }

                if (effectiveParent != null && allocatedParentSerial.HasValue)
                {
                    await using CertRoboDbContext parentSerialDb = await _dbFactory.CreateDbContextAsync(cancellationToken);
                    CaAuthorityRecord trackedParent = await parentSerialDb.CaAuthorities
                        .FirstAsync(c => c.Id == effectiveParent.Id, cancellationToken);
                    bool parentHasCrl = await parentSerialDb.PublishedCrls.AnyAsync(c => c.CaAuthorityId == trackedParent.Id, cancellationToken);
                    if (!parentHasCrl)
                    {
                        await GenerateAndPersistCrlInternalAsync(parentSerialDb, trackedParent, parentPassphrase ?? passphrase, cancellationToken);
                    }
                    if (allocatedParentSerial.Value > trackedParent.LastAllocatedSerial)
                    {
                        trackedParent.LastAllocatedSerial = allocatedParentSerial.Value;
                        await parentSerialDb.SaveChangesAsync(cancellationToken);
                    }
                    parentAuthority!.LastAllocatedSerial = Math.Max(parentAuthority.LastAllocatedSerial, allocatedParentSerial.Value);
                }

                string certPem = issuedCaCert.ExportCertificatePem() + "\n";
                byte[] encryptedPkcs8 = subjectKey.ExportEncryptedPkcs8PrivateKey(
                    passphrase,
                    new PbeParameters(
                        PbeEncryptionAlgorithm.Aes256Cbc,
                        HashAlgorithmName.SHA256,
                        iterationCount: 100_000));

                return await PersistAndActivateCaCoreAsync(
                    caName,
                    validatedIsIntermediate,
                    certPem,
                    normalizedChainPem,
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
            await lifecycleLock.DisposeAsync();
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

        if (string.IsNullOrWhiteSpace(issuerCertPem) || issuerCertPem.Length > CaChainAndConstraintValidator.MaxBundleTextLength)
        {
            throw new ArgumentException("Imported CA certificate PEM is missing or exceeds maximum permitted size.", nameof(issuerCertPem));
        }

        if (chainCertsPem is { Length: > CaChainAndConstraintValidator.MaxBundleTextLength })
        {
            throw new ArgumentException("Imported CA chain PEM exceeds maximum permitted size.", nameof(chainCertsPem));
        }

        if (string.IsNullOrWhiteSpace(privateKeyPem) || privateKeyPem.Length > PkcsBuilder.MaxKeyPemLength)
        {
            throw new ArgumentException("Imported CA private key PEM is missing or exceeds maximum permitted size.", nameof(privateKeyPem));
        }

        IAsyncDisposable lifecycleLock = await AcquireInstanceLifecycleLockAsync(cancellationToken);
        try
        {
            await ThrowIfUnfinishedPendingEnrollmentExistsAsync(cancellationToken);
            List<X509Certificate2> parsedIssuerCerts = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                null,
                issuerCertPem,
                "imported CA certificate");
            if (parsedIssuerCerts.Count != 1)
            {
                foreach (X509Certificate2 c in parsedIssuerCerts) c.Dispose();
                throw new ArgumentException("Imported CA certificate PEM must contain exactly one X.509 certificate.", nameof(issuerCertPem));
            }

            using X509Certificate2 cert = parsedIssuerCerts[0];
            using AsymmetricAlgorithm key = ImportPrivateKeyFromPem(cert, privateKeyPem, inputKeyPassphrase);

            ValidateCaCertificateAndKeyMatch(cert, key, chainCertsPem, out bool isIntermediate, out string normalizedChainPem);

            await using (CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken))
            {
                await db.EnsureSchemaUpgradedAsync(cancellationToken);
                await ValidateCustodyCandidateCoreAsync(
                    db,
                    storagePassphrase,
                    secondaryParentPassphrase: null,
                    requireExistingKeyForUnlock: false,
                    cancellationToken);
            }

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
            await lifecycleLock.DisposeAsync();
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
        CancellationToken cancellationToken = default,
        string? selectedCertificateThumbprintSha256 = null)
    {
        if (string.IsNullOrWhiteSpace(storagePassphrase))
        {
            throw new ArgumentException("A non-empty storage passphrase is required.", nameof(storagePassphrase));
        }

        if (pkcs12Bytes is not { Length: > 0 } || pkcs12Bytes.Length > CaChainAndConstraintValidator.MaxBundleRawBytes)
        {
            throw new ArgumentException($"PKCS#12 archive is empty or exceeds the maximum permitted size of {CaChainAndConstraintValidator.MaxBundleRawBytes} bytes.", nameof(pkcs12Bytes));
        }

        try
        {
            _ = Asn1Object.FromByteArray(pkcs12Bytes);
        }
        catch (Exception ex)
        {
            throw new ArgumentException("PKCS#12 archive could not be decoded.", nameof(pkcs12Bytes), ex);
        }

        IAsyncDisposable lifecycleLock = await AcquireInstanceLifecycleLockAsync(cancellationToken);
        try
        {
            await ThrowIfUnfinishedPendingEnrollmentExistsAsync(cancellationToken);
            X509Certificate2Collection collection;
            try
            {
                collection = X509CertificateLoader.LoadPkcs12Collection(
                    pkcs12Bytes,
                    pkcs12Password,
                    X509KeyStorageFlags.Exportable);
            }
            catch (CryptographicException ex)
            {
                throw new ArgumentException(
                    "Failed to decrypt or load the PKCS#12 archive using the supplied import bundle password.",
                    nameof(pkcs12Password),
                    ex);
            }

            try
            {
                List<X509Certificate2> distinctCertsWithKey = [];
                HashSet<string> seenKeyCertThumbprints = new(StringComparer.OrdinalIgnoreCase);
                foreach (X509Certificate2 cert in collection)
                {
                    if (cert.HasPrivateKey)
                    {
                        string sha256 = cert.GetCertHashString(HashAlgorithmName.SHA256);
                        if (seenKeyCertThumbprints.Add(sha256))
                        {
                            distinctCertsWithKey.Add(cert);
                        }
                    }
                }

                if (distinctCertsWithKey.Count == 0)
                {
                    throw new ArgumentException("PKCS#12 archive does not contain a certificate with a private key.");
                }

                X509Certificate2 caCertWithKey;
                if (!string.IsNullOrWhiteSpace(selectedCertificateThumbprintSha256))
                {
                    string normalizedSelectedThumbprint = selectedCertificateThumbprintSha256
                        .Trim()
                        .Replace(":", "")
                        .Replace(" ", "");
                    caCertWithKey = distinctCertsWithKey.FirstOrDefault(c =>
                            c.GetCertHashString(HashAlgorithmName.SHA256)
                                .Equals(normalizedSelectedThumbprint, StringComparison.OrdinalIgnoreCase))
                        ?? throw new ArgumentException(
                            $"PKCS#12 archive does not contain a private-key certificate matching SHA-256 thumbprint '{normalizedSelectedThumbprint}'.",
                            nameof(selectedCertificateThumbprintSha256));
                }
                else if (distinctCertsWithKey.Count > 1)
                {
                    string candidatesSummary = string.Join(
                        "; ",
                        distinctCertsWithKey
                            .OrderBy(c => c.GetCertHashString(HashAlgorithmName.SHA256), StringComparer.OrdinalIgnoreCase)
                            .Select(c => $"'{c.Subject}' (SHA-256: {c.GetCertHashString(HashAlgorithmName.SHA256)})"));
                    throw new ArgumentException(
                        $"PKCS#12 archive is ambiguous because it contains {distinctCertsWithKey.Count} distinct certificates with private keys ({candidatesSummary}). Provide a PKCS#12 archive containing only the single target CA private key (plus optional public chain certificates) or specify selectedCertificateThumbprintSha256 explicitly.",
                        nameof(pkcs12Bytes));
                }
                else
                {
                    caCertWithKey = distinctCertsWithKey[0];
                }

                using AsymmetricAlgorithm key = ExtractExportablePrivateKey(caCertWithKey);

                string selectedSha256 = caCertWithKey.GetCertHashString(HashAlgorithmName.SHA256);
                HashSet<string> addedChainThumbprints = new(StringComparer.OrdinalIgnoreCase) { selectedSha256 };
                StringBuilder extraChainBuilder = new();
                foreach (X509Certificate2 other in collection)
                {
                    string otherSha256 = other.GetCertHashString(HashAlgorithmName.SHA256);
                    if (addedChainThumbprints.Add(otherSha256))
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

                await using (CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken))
                {
                    await db.EnsureSchemaUpgradedAsync(cancellationToken);
                    await ValidateCustodyCandidateCoreAsync(
                        db,
                        storagePassphrase,
                        secondaryParentPassphrase: null,
                        requireExistingKeyForUnlock: false,
                        cancellationToken);
                }

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
                foreach (X509Certificate2 cert in collection)
                {
                    cert.Dispose();
                }
            }
        }
        finally
        {
            await lifecycleLock.DisposeAsync();
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

        IAsyncDisposable lifecycleLock = await AcquireInstanceLifecycleLockAsync(cancellationToken);
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

            string? passphrase;
            try
            {
                EvictStaleRuntimeUnlockIfIncompatible([ca], []);
                passphrase = ResolveEffectivePassphrase();
            }
            catch (Exception ex)
            {
                return new(false, $"Certificate signing failed: {ex.Message}", null, null, null);
            }

            if (string.IsNullOrEmpty(passphrase))
            {
                return new(false, "CA signing key is locked. An administrator must unlock the CA or configure the passphrase.", null, null, null);
            }

            if (!TryVerifyAuthorityKey(ca, passphrase, out string? keyUnlockError))
            {
                return new(false, $"Certificate signing failed: {keyUnlockError}", null, null, null);
            }

            // Ensure an initial CRL has been published before issuing certificates referencing it
            bool hasCrl = await db.PublishedCrls.AnyAsync(c => c.CaAuthorityId == ca.Id, cancellationToken);
            if (!hasCrl)
            {
                await GenerateAndPersistCrlInternalAsync(db, ca, passphrase, cancellationToken);
            }

            // Evaluate active CA chain validity, NameConstraints, and EKU restrictions before allocating a serial
            using X509Certificate2 issuerCert = X509Certificate2.CreateFromPem(ca.IssuerCertificatePem);
            List<X509Certificate2> activeChainCerts = [issuerCert];
            List<X509Certificate2> extraChainDisposables = [];
            try
            {
                if (!string.IsNullOrWhiteSpace(ca.ChainCertificatesPem))
                {
                    extraChainDisposables = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                        null,
                        ca.ChainCertificatesPem,
                        "active CA chain");
                    activeChainCerts.AddRange(extraChainDisposables);
                }

                DateTimeOffset now = DateTimeOffset.UtcNow;
                foreach (X509Certificate2 chainCert in activeChainCerts)
                {
                    if (now < chainCert.NotBefore.ToUniversalTime())
                    {
                        return new(false, $"Active CA chain certificate '{chainCert.Subject}' is not yet valid.", null, null, null);
                    }
                    if (now > chainCert.NotAfter.ToUniversalTime())
                    {
                        return new(false, $"Active CA chain certificate '{chainCert.Subject}' has expired.", null, null, null);
                    }
                }

                var (chainRestrictionsOk, chainRestrictionsErr, chainRestrictions, _, _) =
                    CaChainAndConstraintValidator.EvaluateChainExtensionsAndRestrictions(activeChainCerts);

                if (!chainRestrictionsOk || chainRestrictions == null)
                {
                    return new(false, chainRestrictionsErr ?? "Active CA chain restrictions prevent issuance.", null, null, null);
                }

                var (ncAllowed, ncDenialReason) = CaChainAndConstraintValidator.ValidateIdentitiesAgainstChainNameConstraints(
                    req.CanonicalDnsIdentities,
                    chainRestrictions);

                if (!ncAllowed)
                {
                    IssuedCertificateRecord deniedByChainEntry = new()
                    {
                        CaAuthorityId = ca.Id,
                        SerialNumberValue = 0,
                        SerialNumberHex = $"DENIED-{Guid.NewGuid():N}"[..24],
                        ProfileId = req.Profile.ProfileId,
                        CommonName = req.CommonName,
                        SubjectAlternativeNamesCsv = string.Join(",", req.CanonicalDnsIdentities),
                        SubjectDistinguishedName = req.SubjectName.ToString(),
                        IssuerDistinguishedName = issuerCert.Subject,
                        KeyAlgorithm = req.Profile.KeyFamily.ToString().ToUpperInvariant(),
                        KeySizeBits = req.Profile.KeyBits,
                        ThumbprintSha256 = string.Empty,
                        RequestedByUserId = user.Id,
                        RequestedByUserName = user.UserName ?? user.Id,
                        Status = IssuanceStatus.Denied,
                        FailureOrDenialReason = ncDenialReason,
                        CreatedAtUtc = now
                    };
                    db.IssuedCertificates.Add(deniedByChainEntry);
                    await db.SaveChangesAsync(cancellationToken);
                    return new(false, ncDenialReason, deniedByChainEntry, null, null);
                }

                IReadOnlyList<string> effectiveLeafEkus = req.Profile.ExtendedKeyUsageOids;
                if (chainRestrictions.EffectivePermittedEkuOids != null)
                {
                    effectiveLeafEkus = req.Profile.ExtendedKeyUsageOids
                        .Where(oid => chainRestrictions.EffectivePermittedEkuOids.Contains(oid, StringComparer.Ordinal))
                        .ToList();

                    if (!effectiveLeafEkus.Contains(CertificateProfiles.ServerAuthOid, StringComparer.Ordinal))
                    {
                        return new(
                            false,
                            $"Active CA chain EKU restrictions do not permit TLS Server Authentication ({CertificateProfiles.ServerAuthOid}).",
                            null,
                            null,
                            null);
                    }
                }

                // Allocate positive serial monotonically above CA's LastAllocatedSerial, ledger records, and any local subordinate CA serials
                var (nextSerial, serialBytes, serialHex) = await AllocateNextIssuerSerialAsync(db, ca, cancellationToken);
                ca.LastAllocatedSerial = nextSerial;

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
                    CreatedAtUtc = now
                };

                db.IssuedCertificates.Add(ledgerEntry);
                await db.SaveChangesAsync(cancellationToken);

                try
                {
                    using AsymmetricAlgorithm issuerKey = LoadEncryptedKey(ca.EncryptedPrivateKeyPath, passphrase);

                    int effectiveDays = requestedValidityDays ?? req.Profile.DefaultValidityDays;
                    effectiveDays = Math.Clamp(effectiveDays, 1, req.Profile.MaxValidityDays);

                    // Bound leaf validity to the usable issuing chain (including parent intermediates and root trust anchor)
                    DateTimeOffset notBefore = now.AddMinutes(-5);
                    if (notBefore < chainRestrictions.UsableNotBeforeUtc)
                    {
                        notBefore = chainRestrictions.UsableNotBeforeUtc;
                    }

                    DateTimeOffset notAfter = now.AddDays(effectiveDays);
                    if (notAfter > chainRestrictions.UsableNotAfterUtc)
                    {
                        notAfter = chainRestrictions.UsableNotAfterUtc;
                    }

                    if (notAfter <= notBefore)
                    {
                        throw new InvalidOperationException("Computed certificate validity window is invalid relative to usable issuing chain validity.");
                    }

                    using X509Certificate2 signedLeaf = SignLeafCertificate(
                        req,
                        issuerCert,
                        issuerKey,
                        serialBytes,
                        notBefore,
                        notAfter,
                        ca.CrlDistributionPointUrl,
                        ca.AuthorityIssuerCertUrl,
                        effectiveLeafEkus);

                    // Post-issuance verification: verify public key, identities, basic constraints, KU/EKU, validity, and chain
                    ValidateIssuedLeafCertificate(
                        signedLeaf,
                        req,
                        issuerCert,
                        ca.ChainCertificatesPem,
                        notBefore,
                        notAfter,
                        effectiveLeafEkus);

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
                foreach (X509Certificate2 c in extraChainDisposables)
                {
                    c.Dispose();
                }
            }
        }
        finally
        {
            await lifecycleLock.DisposeAsync();
        }
    }

    public async Task<RevocationOutcome> RevokeCertificateAsync(
        int certificateId,
        int revocationReasonCode,
        string revokedByUserName,
        CancellationToken cancellationToken = default)
    {
        IAsyncDisposable lifecycleLock = await AcquireInstanceLifecycleLockAsync(cancellationToken);
        try
        {
            await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await db.EnsureSchemaUpgradedAsync(cancellationToken);
            IssuedCertificateRecord? certRecord = await db.IssuedCertificates
                .FirstOrDefaultAsync(c => c.Id == certificateId, cancellationToken);

            if (certRecord == null)
            {
                return new(
                    Succeeded: false,
                    RevocationAccepted: false,
                    CrlPublished: false,
                    RevocationPublicationStatus.Rejected,
                    "Certificate record not found.");
            }

            if (certRecord.Status != IssuanceStatus.Issued && certRecord.Status != IssuanceStatus.Revoked)
            {
                return new(
                    Succeeded: false,
                    RevocationAccepted: false,
                    CrlPublished: false,
                    RevocationPublicationStatus.Rejected,
                    $"Certificate in status '{certRecord.Status}' cannot be revoked.");
            }

            await using (var tx = await db.Database.BeginTransactionAsync(cancellationToken))
            {
                bool targetWasAlreadyRevoked = certRecord.Status == IssuanceStatus.Revoked;
                DateTimeOffset effectiveRevokedAt = certRecord.RevokedAtUtc ?? DateTimeOffset.UtcNow;
                certRecord.Status = IssuanceStatus.Revoked;
                if (!targetWasAlreadyRevoked)
                {
                    certRecord.RevokedAtUtc = effectiveRevokedAt;
                    certRecord.RevocationReasonCode = revocationReasonCode;
                    certRecord.RevokedByUserName = revokedByUserName;
                }
                else
                {
                    certRecord.RevokedAtUtc ??= effectiveRevokedAt;
                    certRecord.RevocationReasonCode ??= revocationReasonCode;
                    certRecord.RevokedByUserName ??= revokedByUserName;
                }

                if (certRecord.CaAuthorityId.HasValue
                    && TryNormalizePositiveSerialHex(certRecord.SerialNumberHex, out BigInteger certSerialBi, out string canonicalCertHex, out _))
                {
                    List<IssuedCertificateRecord> sameIssuerRecords = await db.IssuedCertificates
                        .Where(c => c.CaAuthorityId == certRecord.CaAuthorityId.Value && c.Id != certRecord.Id)
                        .ToListAsync(cancellationToken);

                    List<IssuedCertificateRecord> siblingSerialRecords = sameIssuerRecords
                        .Where(c => TryNormalizePositiveSerialHex(c.SerialNumberHex, out BigInteger otherBi, out _, out _)
                                 && otherBi.Equals(certSerialBi))
                        .ToList();

                    // Revocation is per (issuer, serial): mark any Issued sibling records for the same serial as Revoked
                    // while preserving all issuance metadata and never overwriting prior revocation attribution on already-revoked siblings.
                    foreach (IssuedCertificateRecord sibling in siblingSerialRecords)
                    {
                        if (sibling.Status == IssuanceStatus.Issued || sibling.Status == IssuanceStatus.Revoked)
                        {
                            sibling.Status = IssuanceStatus.Revoked;
                            sibling.RevokedAtUtc ??= effectiveRevokedAt;
                            sibling.RevocationReasonCode ??= revocationReasonCode;
                            sibling.RevokedByUserName ??= revokedByUserName;
                        }
                    }

                    bool canonicalHexTakenBySibling = sameIssuerRecords.Any(c =>
                        string.Equals(c.SerialNumberHex, canonicalCertHex, StringComparison.OrdinalIgnoreCase));
                    if (!canonicalHexTakenBySibling)
                    {
                        certRecord.SerialNumberHex = canonicalCertHex;
                    }

                    int maxMatchingRecordId = siblingSerialRecords
                        .Select(s => s.Id)
                        .Append(certRecord.Id)
                        .Max();

                    db.SerialRevocationEvents.Add(new SerialRevocationEventRecord
                    {
                        CaAuthorityId = certRecord.CaAuthorityId.Value,
                        CanonicalSerialHex = canonicalCertHex,
                        TargetCertificateRecordId = certRecord.Id,
                        OperationType = "Revoke",
                        RevocationReasonCode = revocationReasonCode,
                        RevokedAtUtc = effectiveRevokedAt,
                        RevokedByUserName = revokedByUserName,
                        ReconciledMaxCertificateRecordId = maxMatchingRecordId,
                        CreatedAtUtc = DateTimeOffset.UtcNow
                    });
                }

                await db.SaveChangesAsync(cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                await tx.CommitAsync(CancellationToken.None);
            }

            return await TryPublishRevocationCrlCoreAsync(certRecord, cancellationToken);
        }
        finally
        {
            await lifecycleLock.DisposeAsync();
        }
    }

    /// <summary>
    /// Seeds an already-revoked serial number from an imported legacy CA so CRL continuity is preserved,
    /// and refreshes the active CA's CRL if unlocked.
    /// </summary>
    public async Task<RevocationOutcome> SeedRevokedSerialAsync(
        string serialNumberHex,
        string? commonName,
        int revocationReasonCode,
        string revokedByUserName,
        DateTimeOffset? revokedAtUtc = null,
        CancellationToken cancellationToken = default,
        int? targetCaAuthorityId = null)
    {
        if (!TryNormalizePositiveSerialHex(
                serialNumberHex,
                out BigInteger serialBigInt,
                out string canonicalHex,
                out string? serialError))
        {
            return new(
                Succeeded: false,
                RevocationAccepted: false,
                CrlPublished: false,
                RevocationPublicationStatus.Rejected,
                serialError ?? "Serial number must be valid hexadecimal.");
        }

        IAsyncDisposable lifecycleLock = await AcquireInstanceLifecycleLockAsync(cancellationToken);
        try
        {
            await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await db.EnsureSchemaUpgradedAsync(cancellationToken);
            CaAuthorityRecord? ca = targetCaAuthorityId.HasValue
                ? await db.CaAuthorities.FirstOrDefaultAsync(c => c.Id == targetCaAuthorityId.Value, cancellationToken)
                : await db.CaAuthorities
                    .OrderByDescending(c => c.Id)
                    .FirstOrDefaultAsync(c => c.IsActive, cancellationToken);

            if (ca == null)
            {
                return new(
                    Succeeded: false,
                    RevocationAccepted: false,
                    CrlPublished: false,
                    RevocationPublicationStatus.Rejected,
                    targetCaAuthorityId.HasValue
                        ? $"CA authority #{targetCaAuthorityId.Value} was not found."
                        : "No active CA is configured.");
            }

            List<IssuedCertificateRecord> caCertificates = await db.IssuedCertificates
                .Where(c => c.CaAuthorityId == ca.Id)
                .OrderBy(c => c.Id)
                .ToListAsync(cancellationToken);

            List<IssuedCertificateRecord> matchingRecords = caCertificates
                .Where(c => TryNormalizePositiveSerialHex(c.SerialNumberHex, out BigInteger existingBi, out _, out _)
                         && existingBi.Equals(serialBigInt))
                .ToList();

            List<IssuedCertificateRecord> revocableMatches = matchingRecords
                .Where(c => c.Status == IssuanceStatus.Issued || c.Status == IssuanceStatus.Revoked)
                .ToList();

            DateTimeOffset effectiveRevokedAt = revokedAtUtc ?? DateTimeOffset.UtcNow;
            IssuedCertificateRecord targetRecord;

            await using (var tx = await db.Database.BeginTransactionAsync(cancellationToken))
            {
                if (revocableMatches.Count > 0)
                {
                    IssuedCertificateRecord primary = revocableMatches
                        .FirstOrDefault(c => !string.IsNullOrWhiteSpace(c.CertificatePem))
                        ?? revocableMatches[0];

                    DateTimeOffset unifiedRevokedAt = revokedAtUtc
                        ?? primary.RevokedAtUtc
                        ?? revocableMatches.Select(r => r.RevokedAtUtc).FirstOrDefault(t => t.HasValue)
                        ?? effectiveRevokedAt;

                    // Preserve every existing ledger record and its prior revocation attribution (who revoked it and when)
                    // while transitioning any Issued sibling rows to Revoked and recording the authoritative Seed event.
                    foreach (IssuedCertificateRecord record in revocableMatches)
                    {
                        record.Status = IssuanceStatus.Revoked;
                        record.RevokedAtUtc ??= unifiedRevokedAt;
                        record.RevocationReasonCode ??= revocationReasonCode;
                        record.RevokedByUserName ??= revokedByUserName;
                    }

                    bool canonicalHexTakenByOther = caCertificates.Any(c =>
                        c.Id != primary.Id
                        && string.Equals(c.SerialNumberHex, canonicalHex, StringComparison.OrdinalIgnoreCase));
                    if (!canonicalHexTakenByOther)
                    {
                        primary.SerialNumberHex = canonicalHex;
                    }

                    int maxMatchingRecordId = matchingRecords.Max(r => r.Id);
                    db.SerialRevocationEvents.Add(new SerialRevocationEventRecord
                    {
                        CaAuthorityId = ca.Id,
                        CanonicalSerialHex = canonicalHex,
                        TargetCertificateRecordId = primary.Id,
                        OperationType = "Seed",
                        RevocationReasonCode = revocationReasonCode,
                        RevokedAtUtc = unifiedRevokedAt,
                        RevokedByUserName = revokedByUserName,
                        ReconciledMaxCertificateRecordId = maxMatchingRecordId,
                        CreatedAtUtc = DateTimeOffset.UtcNow
                    });

                    targetRecord = primary;
                    await db.SaveChangesAsync(cancellationToken);
                }
                else
                {
                    List<CaAuthorityRecord> allAuthorities = await db.CaAuthorities
                        .AsNoTracking()
                        .OrderBy(c => c.Id)
                        .ToListAsync(cancellationToken);
                    Dictionary<int, List<CaAuthorityRecord>> directSubsByParent = MapDirectLocalSubordinatesByParentId(allAuthorities);
                    CaAuthorityRecord? matchedLocalSubordinate = null;
                    if (directSubsByParent.TryGetValue(ca.Id, out List<CaAuthorityRecord>? directSubs))
                    {
                        foreach (CaAuthorityRecord sub in directSubs)
                        {
                            try
                            {
                                using X509Certificate2 subCert = X509Certificate2.CreateFromPem(sub.IssuerCertificatePem);
                                string subSerialHex = Convert.ToHexString(subCert.GetSerialNumber().Reverse().ToArray());
                                if (TryNormalizePositiveSerialHex(subSerialHex, out BigInteger subBi, out _, out _)
                                    && subBi.Equals(serialBigInt))
                                {
                                    matchedLocalSubordinate = sub;
                                    break;
                                }
                            }
                            catch
                            {
                            }
                        }
                    }

                    string effectiveCommonName = !string.IsNullOrWhiteSpace(commonName)
                        ? commonName.Trim()
                        : (matchedLocalSubordinate?.Name ?? "legacy-revoked");

                    string nonCollidingSerialHex = AllocateNonCollidingEquivalentSerialHex(canonicalHex, caCertificates);
                    IssuedCertificateRecord seeded = new()
                    {
                        CaAuthorityId = ca.Id,
                        SerialNumberHex = nonCollidingSerialHex,
                        SerialNumberValue = 0,
                        ProfileId = matchedLocalSubordinate != null ? "local-subordinate-ca" : "legacy-imported",
                        CommonName = effectiveCommonName,
                        SubjectAlternativeNamesCsv = !string.IsNullOrWhiteSpace(commonName) ? commonName.Trim() : string.Empty,
                        SubjectDistinguishedName = $"CN={effectiveCommonName}",
                        IssuerDistinguishedName = string.Empty,
                        KeyAlgorithm = "LEGACY",
                        KeySizeBits = 0,
                        ThumbprintSha256 = matchedLocalSubordinate?.ThumbprintOrSerialHex ?? ("LEGACY-" + canonicalHex),
                        NotBeforeUtc = matchedLocalSubordinate?.NotBeforeUtc ?? ca.NotBeforeUtc,
                        NotAfterUtc = matchedLocalSubordinate?.NotAfterUtc ?? ca.NotAfterUtc,
                        RequestedByUserId = "legacy-migration",
                        RequestedByUserName = revokedByUserName,
                        Status = IssuanceStatus.Revoked,
                        CreatedAtUtc = effectiveRevokedAt,
                        RevokedAtUtc = effectiveRevokedAt,
                        RevocationReasonCode = revocationReasonCode,
                        RevokedByUserName = revokedByUserName
                    };
                    db.IssuedCertificates.Add(seeded);
                    await db.SaveChangesAsync(cancellationToken);

                    int maxMatchingRecordId = matchingRecords
                        .Select(r => r.Id)
                        .Append(seeded.Id)
                        .Max();

                    db.SerialRevocationEvents.Add(new SerialRevocationEventRecord
                    {
                        CaAuthorityId = ca.Id,
                        CanonicalSerialHex = canonicalHex,
                        TargetCertificateRecordId = seeded.Id,
                        OperationType = "Seed",
                        RevocationReasonCode = revocationReasonCode,
                        RevokedAtUtc = effectiveRevokedAt,
                        RevokedByUserName = revokedByUserName,
                        ReconciledMaxCertificateRecordId = maxMatchingRecordId,
                        CreatedAtUtc = DateTimeOffset.UtcNow
                    });
                    await db.SaveChangesAsync(cancellationToken);
                    targetRecord = seeded;
                }

                cancellationToken.ThrowIfCancellationRequested();
                await tx.CommitAsync(CancellationToken.None);
            }

            return await TryPublishRevocationCrlCoreAsync(targetRecord, cancellationToken);
        }
        finally
        {
            await lifecycleLock.DisposeAsync();
        }
    }

    private async Task<RevocationOutcome> TryPublishRevocationCrlCoreAsync(
        IssuedCertificateRecord certRecord,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!certRecord.CaAuthorityId.HasValue)
            {
                SignalCrlRefreshNeeded();
                return new(
                    Succeeded: false,
                    RevocationAccepted: true,
                    CrlPublished: false,
                    RevocationPublicationStatus.PendingIssuerUnavailable,
                    $"Revocation recorded for serial {certRecord.SerialNumberHex}, but CRL publication could not be completed because the certificate has no associated issuing CA authority.",
                    certRecord,
                    null);
            }

            await using CertRoboDbContext crlDb = await _dbFactory.CreateDbContextAsync(cancellationToken);
            CaAuthorityRecord? ca = await crlDb.CaAuthorities
                .FirstOrDefaultAsync(c => c.Id == certRecord.CaAuthorityId.Value, cancellationToken);

            if (ca == null)
            {
                SignalCrlRefreshNeeded();
                return new(
                    Succeeded: false,
                    RevocationAccepted: true,
                    CrlPublished: false,
                    RevocationPublicationStatus.PendingIssuerUnavailable,
                    $"Revocation recorded for serial {certRecord.SerialNumberHex}, but CRL publication could not be completed because issuing CA #{certRecord.CaAuthorityId.Value} was not found.",
                    certRecord,
                    null);
            }

            EvictStaleRuntimeUnlockIfIncompatible([ca], []);
            string? passphrase = ResolveEffectivePassphrase();
            if (string.IsNullOrEmpty(passphrase))
            {
                SignalCrlRefreshNeeded();
                return new(
                    Succeeded: false,
                    RevocationAccepted: true,
                    CrlPublished: false,
                    RevocationPublicationStatus.PendingSignerLocked,
                    $"Revocation recorded for serial {certRecord.SerialNumberHex}, but CRL publication is pending because the CA signing key is locked. Unlock the CA and refresh the CRL to publish this revocation.",
                    certRecord,
                    null);
            }

            if (!TryVerifyAuthorityKey(ca, passphrase, out string? custodyErr))
            {
                SignalCrlRefreshNeeded();
                return new(
                    Succeeded: false,
                    RevocationAccepted: true,
                    CrlPublished: false,
                    RevocationPublicationStatus.PendingPublicationFailed,
                    $"Revocation recorded for serial {certRecord.SerialNumberHex}, but CRL publication failed and remains pending: {custodyErr}",
                    certRecord,
                    null);
            }

            await using var tx = await crlDb.Database.BeginTransactionAsync(cancellationToken);
            PublishedCrlRecord publishedCrl = await GenerateAndPersistCrlInternalAsync(crlDb, ca, passphrase, cancellationToken);

            if (!TryNormalizePositiveSerialHex(certRecord.SerialNumberHex, out BigInteger expectedSerialBi, out _, out _))
            {
                throw new InvalidOperationException(
                    $"Revoked serial '{certRecord.SerialNumberHex}' is not a valid positive integer.");
            }

            X509Crl verifiedCrl = new X509CrlParser().ReadCrl(publishedCrl.CrlDer);
            if (verifiedCrl.GetRevokedCertificate(expectedSerialBi) == null)
            {
                throw new InvalidOperationException(
                    $"Generated CRL #{publishedCrl.CrlNumber} did not contain expected revoked serial {certRecord.SerialNumberHex}.");
            }

            await tx.CommitAsync(cancellationToken);
            return new(
                Succeeded: true,
                RevocationAccepted: true,
                CrlPublished: true,
                RevocationPublicationStatus.Published,
                null,
                certRecord,
                publishedCrl);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            SignalCrlRefreshNeeded();
            throw;
        }
        catch (Exception ex)
        {
            SignalCrlRefreshNeeded();
            return new(
                Succeeded: false,
                RevocationAccepted: true,
                CrlPublished: false,
                RevocationPublicationStatus.PendingPublicationFailed,
                $"Revocation recorded for serial {certRecord.SerialNumberHex}, but CRL publication failed and remains pending: {ex.Message}",
                certRecord,
                null);
        }
    }

    public async Task<PublishedCrlRecord?> RefreshActiveCrlAsync(CancellationToken cancellationToken = default)
    {
        IAsyncDisposable lifecycleLock = await AcquireInstanceLifecycleLockAsync(cancellationToken);
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

            EvictStaleRuntimeUnlockIfIncompatible([ca], []);
            string? passphrase = ResolveEffectivePassphrase();
            if (string.IsNullOrEmpty(passphrase))
            {
                throw new InvalidOperationException("Cannot refresh CRL while CA signing key is locked.");
            }

            if (!TryVerifyAuthorityKey(ca, passphrase, out string? keyUnlockError))
            {
                throw new InvalidOperationException($"Cannot refresh CRL for CA '{ca.Name}': {keyUnlockError}");
            }

            return await GenerateAndPersistCrlInternalAsync(db, ca, passphrase, cancellationToken);
        }
        finally
        {
            await lifecycleLock.DisposeAsync();
        }
    }

    public async Task<IReadOnlyList<CrlRefreshOutcome>> RefreshDueCrlsAsync(
        TimeSpan dueWithin,
        CancellationToken cancellationToken = default)
    {
        IAsyncDisposable lifecycleLock = await AcquireInstanceLifecycleLockAsync(cancellationToken);
        try
        {
            List<CaAuthorityRecord> authorities;
            List<IssuedCertificateRecord> maintainedCertificates;
            List<SerialRevocationEventRecord> revocationEvents;
            await using (CertRoboDbContext readDb = await _dbFactory.CreateDbContextAsync(cancellationToken))
            {
                await readDb.EnsureSchemaUpgradedAsync(cancellationToken);
                authorities = await readDb.CaAuthorities
                    .AsNoTracking()
                    .OrderBy(c => c.Id)
                    .ToListAsync(cancellationToken);
                maintainedCertificates = await readDb.IssuedCertificates
                    .AsNoTracking()
                    .Where(c => c.Status == IssuanceStatus.Issued || c.Status == IssuanceStatus.Revoked)
                    .ToListAsync(cancellationToken);
                revocationEvents = await readDb.SerialRevocationEvents
                    .AsNoTracking()
                    .OrderBy(e => e.Id)
                    .ToListAsync(cancellationToken);
            }

            DateTimeOffset now = DateTimeOffset.UtcNow;
            DateTimeOffset dueBefore = now.Add(dueWithin);

            string? passphrase = null;
            string? passphraseResolutionError = null;
            try
            {
                EvictStaleRuntimeUnlockIfIncompatible(authorities, []);
                passphrase = ResolveEffectivePassphrase();
            }
            catch (Exception ex)
            {
                passphraseResolutionError = ex.Message;
            }

            HashSet<int> authoritiesWithUnexpiredCertificates = maintainedCertificates
                .Where(c => c.CaAuthorityId.HasValue && c.NotAfterUtc > now)
                .Select(c => c.CaAuthorityId!.Value)
                .ToHashSet();
            Dictionary<int, List<CaAuthorityRecord>> directSubordinatesByParent = MapDirectLocalSubordinatesByParentId(authorities);
            HashSet<int> authoritiesWithUnexpiredSubordinates = directSubordinatesByParent
                .Where(kv => kv.Value.Any(sub => sub.NotAfterUtc > now))
                .Select(kv => kv.Key)
                .ToHashSet();
            Dictionary<int, List<IssuedCertificateRecord>> revokedByAuthority = maintainedCertificates
                .Where(c => c.CaAuthorityId.HasValue && c.Status == IssuanceStatus.Revoked)
                .GroupBy(c => c.CaAuthorityId!.Value)
                .ToDictionary(g => g.Key, g => g.ToList());
            Dictionary<int, List<SerialRevocationEventRecord>> eventsByAuthority = revocationEvents
                .GroupBy(e => e.CaAuthorityId)
                .ToDictionary(g => g.Key, g => g.ToList());
            HashSet<int> knownAuthorityIds = authorities.Select(a => a.Id).ToHashSet();
            List<CrlRefreshOutcome> outcomes = [];

            if (maintainedCertificates.Any(c => !c.CaAuthorityId.HasValue && c.Status == IssuanceStatus.Revoked))
            {
                outcomes.Add(new(
                    0,
                    "Unassigned Issuer",
                    false,
                    null,
                    "One or more revoked certificates have no assigned issuing CA authority; CRL publication cannot be completed."));
            }

            foreach (int missingCaId in revokedByAuthority.Keys.Where(id => !knownAuthorityIds.Contains(id)).OrderBy(id => id))
            {
                outcomes.Add(new(
                    missingCaId,
                    $"Missing CA #{missingCaId}",
                    false,
                    null,
                    $"Issuing CA #{missingCaId} was not found in storage; cannot publish pending revocation(s)."));
            }

            foreach (CaAuthorityRecord authority in authorities)
            {
                try
                {
                    PublishedCrlRecord? latest;
                    await using (CertRoboDbContext latestDb = await _dbFactory.CreateDbContextAsync(cancellationToken))
                    {
                        latest = await latestDb.PublishedCrls
                            .AsNoTracking()
                            .Where(c => c.CaAuthorityId == authority.Id)
                            .OrderByDescending(c => c.CrlNumber)
                            .FirstOrDefaultAsync(cancellationToken);
                    }

                    bool hasUnpublishedRevocations = HasUnpublishedRevocations(
                        latest,
                        revokedByAuthority.GetValueOrDefault(authority.Id),
                        eventsByAuthority.GetValueOrDefault(authority.Id));

                    if (authority.NotAfterUtc <= now)
                    {
                        if (hasUnpublishedRevocations || authority.IsActive)
                        {
                            outcomes.Add(new(
                                authority.Id,
                                authority.Name,
                                false,
                                null,
                                $"Could not refresh CRL for stored issuer '{authority.Name}': CA certificate expired at {authority.NotAfterUtc:O}."));
                        }
                        continue;
                    }

                    bool shouldMaintain = authority.IsActive
                        || authoritiesWithUnexpiredCertificates.Contains(authority.Id)
                        || authoritiesWithUnexpiredSubordinates.Contains(authority.Id)
                        || hasUnpublishedRevocations;
                    if (!shouldMaintain)
                    {
                        continue;
                    }

                    if (passphraseResolutionError != null)
                    {
                        outcomes.Add(new(
                            authority.Id,
                            authority.Name,
                            false,
                            null,
                            $"Could not refresh CRL for stored issuer '{authority.Name}': {passphraseResolutionError}"));
                        continue;
                    }

                    if (!string.IsNullOrEmpty(passphrase)
                        && !TryVerifyAuthorityKey(authority, passphrase, out string? custodyErr))
                    {
                        outcomes.Add(new(
                            authority.Id,
                            authority.Name,
                            false,
                            null,
                            $"Could not refresh CRL for stored issuer '{authority.Name}': {custodyErr}"));
                        continue;
                    }

                    bool isDueBySchedule = latest == null || latest.NextUpdateUtc <= dueBefore;
                    if (!hasUnpublishedRevocations && !isDueBySchedule)
                    {
                        continue;
                    }

                    if (string.IsNullOrEmpty(passphrase))
                    {
                        outcomes.Add(new(
                            authority.Id,
                            authority.Name,
                            false,
                            null,
                            "CA signing key is locked."));
                        continue;
                    }

                    await using CertRoboDbContext authorityDb = await _dbFactory.CreateDbContextAsync(cancellationToken);
                    await using var tx = await authorityDb.Database.BeginTransactionAsync(cancellationToken);
                    CaAuthorityRecord? trackedAuthority = await authorityDb.CaAuthorities
                        .FirstOrDefaultAsync(c => c.Id == authority.Id, cancellationToken);
                    if (trackedAuthority == null)
                    {
                        outcomes.Add(new(
                            authority.Id,
                            authority.Name,
                            false,
                            null,
                            $"Could not refresh CRL for stored issuer '{authority.Name}': authority record was not found."));
                        continue;
                    }

                    PublishedCrlRecord refreshed = await GenerateAndPersistCrlInternalAsync(
                        authorityDb,
                        trackedAuthority,
                        passphrase,
                        cancellationToken);
                    await tx.CommitAsync(cancellationToken);
                    outcomes.Add(new(authority.Id, authority.Name, true, refreshed, null));
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    outcomes.Add(new(
                        authority.Id,
                        authority.Name,
                        false,
                        null,
                        $"Could not refresh CRL for stored issuer '{authority.Name}': {ex.Message}"));
                }
            }

            return outcomes;
        }
        finally
        {
            await lifecycleLock.DisposeAsync();
        }
    }

    public async Task<IReadOnlySet<int>> GetCertificateIdsWithUnpublishedRevocationsAsync(
        CancellationToken cancellationToken = default)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await db.EnsureSchemaUpgradedAsync(cancellationToken);
        List<IssuedCertificateRecord> revokedCerts = await db.IssuedCertificates
            .AsNoTracking()
            .Where(c => c.Status == IssuanceStatus.Revoked)
            .ToListAsync(cancellationToken);

        if (revokedCerts.Count == 0)
        {
            return new HashSet<int>();
        }

        List<SerialRevocationEventRecord> allEvents = await db.SerialRevocationEvents
            .AsNoTracking()
            .OrderBy(e => e.Id)
            .ToListAsync(cancellationToken);
        Dictionary<int, List<SerialRevocationEventRecord>> eventsByAuthority = allEvents
            .GroupBy(e => e.CaAuthorityId)
            .ToDictionary(g => g.Key, g => g.ToList());

        HashSet<int> knownAuthorityIds = (await db.CaAuthorities
            .AsNoTracking()
            .Select(a => a.Id)
            .ToListAsync(cancellationToken))
            .ToHashSet();

        HashSet<int> unpublishedIds = [];
        foreach (IssuedCertificateRecord unattached in revokedCerts.Where(c => !c.CaAuthorityId.HasValue || !knownAuthorityIds.Contains(c.CaAuthorityId.Value)))
        {
            unpublishedIds.Add(unattached.Id);
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        foreach (IGrouping<int, IssuedCertificateRecord> group in revokedCerts
            .Where(c => c.CaAuthorityId.HasValue && knownAuthorityIds.Contains(c.CaAuthorityId.Value))
            .GroupBy(c => c.CaAuthorityId!.Value))
        {
            List<IssuedCertificateRecord> groupRecords = group.ToList();
            List<SerialRevocationEventRecord>? authorityEvents = eventsByAuthority.GetValueOrDefault(group.Key);
            var (canonicalEntries, conflictingIds, _) = AnalyzeRevokedSerialGroups(groupRecords, now, authorityEvents);
            foreach (int conflictId in conflictingIds)
            {
                unpublishedIds.Add(conflictId);
            }

            PublishedCrlRecord? latestCrl = await db.PublishedCrls
                .AsNoTracking()
                .Where(c => c.CaAuthorityId == group.Key)
                .OrderByDescending(c => c.CrlNumber)
                .FirstOrDefaultAsync(cancellationToken);

            if (latestCrl == null || latestCrl.CrlDer is not { Length: > 0 })
            {
                foreach (IssuedCertificateRecord r in groupRecords)
                {
                    unpublishedIds.Add(r.Id);
                }
                continue;
            }

            X509Crl? parsedCrl = null;
            try
            {
                parsedCrl = new X509CrlParser().ReadCrl(latestCrl.CrlDer);
            }
            catch
            {
            }

            if (parsedCrl == null)
            {
                foreach (IssuedCertificateRecord r in groupRecords)
                {
                    unpublishedIds.Add(r.Id);
                }
                continue;
            }

            foreach (CanonicalCrlRevocationEntry entry in canonicalEntries)
            {
                if (IsCanonicalRevocationEntryUnpublished(parsedCrl, entry))
                {
                    foreach (int recordId in entry.RecordIds)
                    {
                        unpublishedIds.Add(recordId);
                    }
                }
            }
        }

        return unpublishedIds;
    }

    public static bool HasUnpublishedRevocations(
        PublishedCrlRecord? latestCrl,
        IReadOnlyList<IssuedCertificateRecord>? revokedCertificates,
        IReadOnlyList<SerialRevocationEventRecord>? serialEvents = null)
    {
        if (latestCrl == null)
        {
            return true;
        }

        if (revokedCertificates == null || revokedCertificates.Count == 0)
        {
            return false;
        }

        var (canonicalEntries, conflictingIds, _) = AnalyzeRevokedSerialGroups(
            revokedCertificates,
            DateTimeOffset.UtcNow,
            serialEvents);
        if (conflictingIds.Count > 0)
        {
            return true;
        }

        if (latestCrl.CrlDer is not { Length: > 0 })
        {
            return true;
        }

        X509Crl parsedCrl;
        try
        {
            parsedCrl = new X509CrlParser().ReadCrl(latestCrl.CrlDer);
        }
        catch
        {
            return true;
        }

        foreach (CanonicalCrlRevocationEntry entry in canonicalEntries)
        {
            if (IsCanonicalRevocationEntryUnpublished(parsedCrl, entry))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsCanonicalRevocationEntryUnpublished(
        X509Crl parsedCrl,
        CanonicalCrlRevocationEntry expectedEntry)
    {
        X509CrlEntry? entry = parsedCrl.GetRevokedCertificate(expectedEntry.SerialBigInt);
        if (entry == null)
        {
            return true;
        }

        int actualReason = ExtractCrlEntryReasonCode(entry);
        if (actualReason != expectedEntry.ReasonCode)
        {
            return true;
        }

        DateTime actualRevDateUtc = TruncateToSeconds(entry.RevocationDate.ToUniversalTime());
        if (actualRevDateUtc != expectedEntry.RevocationDateUtc)
        {
            return true;
        }

        return false;
    }

    public static bool TryNormalizePositiveSerialHex(
        string? rawHex,
        out BigInteger serialBigInt,
        out string canonicalHex,
        out string? errorMessage)
    {
        serialBigInt = BigInteger.Zero;
        canonicalHex = string.Empty;
        errorMessage = null;

        if (string.IsNullOrWhiteSpace(rawHex))
        {
            errorMessage = "Serial number (hex) is required.";
            return false;
        }

        StringBuilder cleaned = new(rawHex.Length);
        foreach (char ch in rawHex)
        {
            if (char.IsWhiteSpace(ch) || ch is ':' or '-')
            {
                continue;
            }
            cleaned.Append(char.ToUpperInvariant(ch));
        }

        if (cleaned.Length == 0)
        {
            errorMessage = "Serial number (hex) is required.";
            return false;
        }

        string paddedHex = cleaned.Length % 2 == 0
            ? cleaned.ToString()
            : "0" + cleaned;

        byte[] rawBytes;
        try
        {
            rawBytes = Convert.FromHexString(paddedHex);
        }
        catch (FormatException)
        {
            errorMessage = "Serial number must be valid hexadecimal.";
            return false;
        }

        serialBigInt = new BigInteger(1, rawBytes);
        if (serialBigInt.CompareTo(BigInteger.Zero) <= 0)
        {
            errorMessage = "Serial number must represent a positive integer.";
            return false;
        }

        byte[] unsignedBytes = serialBigInt.ToByteArrayUnsigned();
        canonicalHex = Convert.ToHexString(unsignedBytes);
        return true;
    }

    private static string AllocateNonCollidingEquivalentSerialHex(
        string canonicalHex,
        IReadOnlyCollection<IssuedCertificateRecord> existingForIssuer)
    {
        HashSet<string> usedHex = existingForIssuer
            .Select(c => c.SerialNumberHex)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (!usedHex.Contains(canonicalHex))
        {
            return canonicalHex;
        }

        string candidate = canonicalHex;
        while (candidate.Length + 2 <= 64)
        {
            candidate = "00" + candidate;
            if (!usedHex.Contains(candidate))
            {
                return candidate;
            }
        }

        for (int split = 2; split < canonicalHex.Length && canonicalHex.Length + 1 <= 64; split += 2)
        {
            string colonCandidate = canonicalHex[..split] + ":" + canonicalHex[split..];
            if (!usedHex.Contains(colonCandidate))
            {
                return colonCandidate;
            }
        }

        throw new InvalidOperationException(
            $"Could not allocate a non-colliding serial representation for '{canonicalHex}'.");
    }

    private sealed record CanonicalCrlRevocationEntry(
        BigInteger SerialBigInt,
        string CanonicalHex,
        DateTime RevocationDateUtc,
        int ReasonCode,
        IReadOnlyList<int> RecordIds);

    private static (
        IReadOnlyList<CanonicalCrlRevocationEntry> Entries,
        HashSet<int> ConflictingRecordIds,
        IReadOnlyList<string> ConflictMessages)
        AnalyzeRevokedSerialGroups(
            IReadOnlyList<IssuedCertificateRecord> revokedCerts,
            DateTimeOffset fallbackNow,
            IReadOnlyList<SerialRevocationEventRecord>? serialEvents = null)
    {
        List<CanonicalCrlRevocationEntry> canonicalEntries = [];
        HashSet<int> conflictingIds = [];
        List<string> conflictMessages = [];

        Dictionary<string, SerialRevocationEventRecord> latestEventBySerial = new(StringComparer.Ordinal);
        if (serialEvents != null)
        {
            foreach (SerialRevocationEventRecord evt in serialEvents.OrderBy(e => e.Id))
            {
                if (TryNormalizePositiveSerialHex(evt.CanonicalSerialHex, out _, out string normEvtHex, out _))
                {
                    latestEventBySerial[normEvtHex] = evt;
                }
            }
        }

        Dictionary<string, (BigInteger SerialBigInt, List<IssuedCertificateRecord> Records)> byCanonicalHex =
            new(StringComparer.Ordinal);

        foreach (IssuedCertificateRecord revoked in revokedCerts)
        {
            if (!TryNormalizePositiveSerialHex(
                    revoked.SerialNumberHex,
                    out BigInteger serialBigInt,
                    out string canonicalHex,
                    out string? parseErr))
            {
                conflictingIds.Add(revoked.Id);
                conflictMessages.Add(
                    $"Revoked certificate record #{revoked.Id} has an invalid serial number '{revoked.SerialNumberHex}': {parseErr}");
                continue;
            }

            if (!byCanonicalHex.TryGetValue(canonicalHex, out var bucket))
            {
                bucket = (serialBigInt, []);
                byCanonicalHex[canonicalHex] = bucket;
            }
            bucket.Records.Add(revoked);
        }

        foreach ((string canonicalHex, (BigInteger serialBigInt, List<IssuedCertificateRecord> groupRecords)) in byCanonicalHex)
        {
            List<int> groupRecordIds = groupRecords.Select(r => r.Id).ToList();

            if (latestEventBySerial.TryGetValue(canonicalHex, out SerialRevocationEventRecord? latestEvent))
            {
                DateTime eventRevDateUtc = TruncateToSeconds(latestEvent.RevokedAtUtc.UtcDateTime);
                int eventReason = latestEvent.RevocationReasonCode;

                bool allPostEventRecordsAgree = groupRecords
                    .Where(r => r.Id > latestEvent.ReconciledMaxCertificateRecordId)
                    .All(r =>
                        (r.RevocationReasonCode ?? CrlReason.Unspecified) == eventReason
                        && (!r.RevokedAtUtc.HasValue || TruncateToSeconds(r.RevokedAtUtc.Value.UtcDateTime) == eventRevDateUtc));

                if (allPostEventRecordsAgree)
                {
                    canonicalEntries.Add(new CanonicalCrlRevocationEntry(
                        serialBigInt,
                        canonicalHex,
                        eventRevDateUtc,
                        eventReason,
                        groupRecordIds));
                    continue;
                }
            }

            HashSet<int> distinctReasons = groupRecords
                .Select(r => r.RevocationReasonCode ?? CrlReason.Unspecified)
                .ToHashSet();

            HashSet<DateTime> distinctTimestamps = groupRecords
                .Where(r => r.RevokedAtUtc.HasValue)
                .Select(r => TruncateToSeconds(r.RevokedAtUtc!.Value.UtcDateTime))
                .ToHashSet();

            if (distinctReasons.Count > 1 || distinctTimestamps.Count > 1)
            {
                foreach (IssuedCertificateRecord r in groupRecords)
                {
                    conflictingIds.Add(r.Id);
                }

                string recordDetails = string.Join(
                    ", ",
                    groupRecords.Select(r =>
                        $"#{r.Id} (raw='{r.SerialNumberHex}', reason={r.RevocationReasonCode ?? CrlReason.Unspecified}, revokedAt={r.RevokedAtUtc?.UtcDateTime:O})"));
                conflictMessages.Add(
                    $"Conflicting revocation records exist for canonical serial {canonicalHex}: [{recordDetails}]. Reconcile the serial via RevokeCertificateAsync or SeedRevokedSerialAsync.");
                continue;
            }

            int agreedReason = distinctReasons.First();
            DateTime agreedRevDateUtc = distinctTimestamps.Count > 0
                ? distinctTimestamps.First()
                : TruncateToSeconds(fallbackNow.UtcDateTime);

            canonicalEntries.Add(new CanonicalCrlRevocationEntry(
                serialBigInt,
                canonicalHex,
                agreedRevDateUtc,
                agreedReason,
                groupRecordIds));
        }

        canonicalEntries.Sort((a, b) => a.SerialBigInt.CompareTo(b.SerialBigInt));
        return (canonicalEntries, conflictingIds, conflictMessages);
    }

    private static int ExtractCrlEntryReasonCode(X509CrlEntry entry)
    {
        Asn1OctetString? extOctets = entry.GetExtensionValue(X509Extensions.ReasonCode);
        if (extOctets == null)
        {
            return CrlReason.Unspecified;
        }

        try
        {
            DerEnumerated enumerated = DerEnumerated.GetInstance(Asn1Object.FromByteArray(extOctets.GetOctets()));
            return enumerated.Value.IntValueExact;
        }
        catch
        {
            return CrlReason.Unspecified;
        }
    }

    private static DateTime TruncateToSeconds(DateTime utcDateTime) =>
        new(
            utcDateTime.Year,
            utcDateTime.Month,
            utcDateTime.Day,
            utcDateTime.Hour,
            utcDateTime.Minute,
            utcDateTime.Second,
            DateTimeKind.Utc);

    public async Task<PublishedCrlRecord?> GetLatestCrlAsync(
        CancellationToken cancellationToken = default,
        int? caAuthorityId = null)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);

        int targetCaId;
        if (caAuthorityId.HasValue)
        {
            targetCaId = caAuthorityId.Value;
        }
        else
        {
            CaAuthorityRecord? ca = await db.CaAuthorities
                .OrderByDescending(c => c.Id)
                .FirstOrDefaultAsync(c => c.IsActive, cancellationToken);

            if (ca == null)
            {
                return null;
            }
            targetCaId = ca.Id;
        }

        return await db.PublishedCrls
            .Where(c => c.CaAuthorityId == targetCaId)
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

        try
        {
            CaPersistenceFaultInjector?.Invoke(caName);
            await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            await using var tx = await db.Database.BeginTransactionAsync(cancellationToken);

            List<CaAuthorityRecord> previousActive = await db.CaAuthorities
                .Where(c => c.IsActive)
                .ToListAsync(cancellationToken);
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
            ApplyStableIssuerPublicationUrls(record);
            await db.SaveChangesAsync(cancellationToken);

            // Publish initial CRL #1 in the same transaction as activation.
            await GenerateAndPersistCrlInternalAsync(db, record, passphrase, cancellationToken);
            await tx.CommitAsync(cancellationToken);

            _runtimeUnlockedPassphrase = passphrase;
            _isExplicitlyLocked = false;

            // Also update static/rootca.crt if writable so static/legacy links see the current trust chain.
            await WritePublicTrustFilesAsync(record, cancellationToken);
            return record;
        }
        catch
        {
            try
            {
                File.Delete(keyFilePath);
            }
            catch
            {
                // Preserve the original activation exception if orphan cleanup fails.
            }
            throw;
        }
    }

    private async Task ThrowIfUnfinishedPendingEnrollmentExistsAsync(CancellationToken cancellationToken)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await db.EnsureSchemaUpgradedAsync(cancellationToken);
        PendingCaEnrollmentRecord? pending = await db.PendingCaEnrollments
            .Where(p => p.Status != PendingCaEnrollmentStatus.Activated
                     && p.Status != PendingCaEnrollmentStatus.Cancelled)
            .OrderByDescending(p => p.Id)
            .FirstOrDefaultAsync(cancellationToken);
        if (pending != null)
        {
            throw new InvalidOperationException(
                $"Pending external CA enrolment request '{pending.CaName}' must be completed or cancelled before activating another CA.");
        }
    }

    private async Task<PublishedCrlRecord> GenerateAndPersistCrlInternalAsync(
        CertRoboDbContext db,
        CaAuthorityRecord ca,
        string passphrase,
        CancellationToken cancellationToken)
    {
        CrlPublicationFaultInjector?.Invoke(ca);

        using X509Certificate2 issuerDotNetCert = X509Certificate2.CreateFromPem(ca.IssuerCertificatePem);
        X509BasicConstraintsExtension? issuerBc = issuerDotNetCert.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault();
        if (issuerBc == null || !issuerBc.CertificateAuthority || !issuerBc.Critical)
        {
            throw new InvalidOperationException(
                $"Cannot publish a CRL for CA '{ca.Name}' because its certificate is missing a critical BasicConstraints CA=true extension.");
        }

        X509KeyUsageExtension? issuerKu = issuerDotNetCert.Extensions
            .OfType<X509KeyUsageExtension>()
            .FirstOrDefault();
        if (issuerKu == null || (issuerKu.KeyUsages & X509KeyUsageFlags.CrlSign) == 0)
        {
            throw new InvalidOperationException(
                $"Cannot publish a CRL for CA '{ca.Name}' because its certificate KeyUsage does not include CrlSign.");
        }

        using AsymmetricAlgorithm issuerDotNetKey = LoadEncryptedKey(ca.EncryptedPrivateKeyPath, passphrase);

        BcX509Certificate bcIssuerCert = new X509CertificateParser().ReadCertificate(issuerDotNetCert.RawData);
        AsymmetricKeyParameter bcSigningKey = ConvertDotNetPrivateKeyToBouncyCastle(issuerDotNetKey);

        long maxExistingCrl = await db.PublishedCrls
            .Where(c => c.CaAuthorityId == ca.Id)
            .Select(c => (long?)c.CrlNumber)
            .MaxAsync(cancellationToken) ?? 0L;

        long nextCrlNumber = Math.Max(ca.LastCrlNumber, maxExistingCrl) + 1;

        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset thisUpdate = now.AddMinutes(-1);
        DateTimeOffset nextUpdate = now.AddHours(Math.Max(1, _options.CrlValidityHours));
        if (nextUpdate > ca.NotAfterUtc)
        {
            nextUpdate = ca.NotAfterUtc;
        }
        if (nextUpdate <= thisUpdate)
        {
            throw new InvalidOperationException(
                $"Cannot publish a usable CRL for CA '{ca.Name}' because its certificate validity ends at {ca.NotAfterUtc:O}.");
        }

        X509V2CrlGenerator crlGen = new();
        crlGen.SetIssuerDN(bcIssuerCert.SubjectDN);
        crlGen.SetThisUpdate(thisUpdate.UtcDateTime);
        crlGen.SetNextUpdate(nextUpdate.UtcDateTime);

        await db.EnsureSchemaUpgradedAsync(cancellationToken);

        List<IssuedCertificateRecord> revokedCerts = await db.IssuedCertificates
            .Where(c => c.CaAuthorityId == ca.Id && c.Status == IssuanceStatus.Revoked)
            .OrderBy(c => c.SerialNumberValue)
            .ThenBy(c => c.Id)
            .ToListAsync(cancellationToken);

        List<SerialRevocationEventRecord> serialEvents = await db.SerialRevocationEvents
            .Where(e => e.CaAuthorityId == ca.Id)
            .OrderBy(e => e.Id)
            .ToListAsync(cancellationToken);

        var (canonicalRevocationEntries, _, conflictMessages) = AnalyzeRevokedSerialGroups(revokedCerts, now, serialEvents);
        if (conflictMessages.Count > 0)
        {
            throw new InvalidOperationException(string.Join(" ", conflictMessages));
        }

        if (canonicalRevocationEntries.Count > 0)
        {
            Dictionary<string, CanonicalCrlRevocationEntry> entryByCanonicalHex = canonicalRevocationEntries
                .ToDictionary(e => e.CanonicalHex, StringComparer.Ordinal);
            List<IssuedCertificateRecord> issuedForAuthority = await db.IssuedCertificates
                .Where(c => c.CaAuthorityId == ca.Id && c.Status == IssuanceStatus.Issued)
                .ToListAsync(cancellationToken);

            foreach (IssuedCertificateRecord issuedRow in issuedForAuthority)
            {
                if (TryNormalizePositiveSerialHex(issuedRow.SerialNumberHex, out _, out string issuedCanonicalHex, out _)
                    && entryByCanonicalHex.TryGetValue(issuedCanonicalHex, out CanonicalCrlRevocationEntry? revEntry))
                {
                    issuedRow.Status = IssuanceStatus.Revoked;
                    issuedRow.RevokedAtUtc ??= new DateTimeOffset(revEntry.RevocationDateUtc, TimeSpan.Zero);
                    issuedRow.RevocationReasonCode ??= revEntry.ReasonCode;
                    issuedRow.RevokedByUserName ??= "crl-reconcile";
                }
            }
        }

        foreach (IssuedCertificateRecord revoked in revokedCerts)
        {
            revoked.RevokedAtUtc ??= now;
        }

        foreach (CanonicalCrlRevocationEntry revokedEntry in canonicalRevocationEntries)
        {
            crlGen.AddCrlEntry(
                revokedEntry.SerialBigInt,
                revokedEntry.RevocationDateUtc,
                revokedEntry.ReasonCode);
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

        ca.LastCrlNumber = nextCrlNumber;

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

    private void ApplyStableIssuerPublicationUrls(CaAuthorityRecord authority)
    {
        // Preserve the legacy active aliases for compatibility, but new certificates should use
        // issuer-stable resources so rollover does not make their AIA/CDP resolve to a different CA.
        authority.CrlDistributionPointUrl = RewriteActiveAliasToStableIssuerUrl(
            authority.CrlDistributionPointUrl,
            ["/ca.crl"],
            $"/authorities/{authority.Id}/ca.crl");

        authority.AuthorityIssuerCertUrl = RewriteActiveAliasToStableIssuerUrl(
            authority.AuthorityIssuerCertUrl,
            ["/ca.crt", "/rootca.crt"],
            $"/authorities/{authority.Id}/issuer.crt");
    }

    private string RewriteActiveAliasToStableIssuerUrl(
        string configuredUrl,
        IReadOnlyList<string> legacyAliasPaths,
        string stablePath)
    {
        if (legacyAliasPaths.Any(alias => configuredUrl.Equals(alias, StringComparison.OrdinalIgnoreCase)))
        {
            if (Uri.TryCreate(_options.PublicBaseUrl, UriKind.Absolute, out Uri? publicBase)
                && (publicBase.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                    || publicBase.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
            {
                return new Uri(publicBase, stablePath).AbsoluteUri;
            }
            return stablePath;
        }

        if (Uri.TryCreate(configuredUrl, UriKind.Absolute, out Uri? absolute)
            && (absolute.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                || absolute.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            && legacyAliasPaths.Any(alias => absolute.AbsolutePath.Equals(alias, StringComparison.OrdinalIgnoreCase)))
        {
            UriBuilder builder = new(absolute)
            {
                Path = stablePath,
                Query = string.Empty,
                Fragment = string.Empty
            };
            return builder.Uri.AbsoluteUri;
        }

        return configuredUrl;
    }

    private (string? CdpUrl, string? AiaUrl) ResolveParentPublicationUrls(
        CaAuthorityRecord parentAuthority,
        string? childConfiguredCdpUrl,
        string? childConfiguredAiaUrl)
    {
        string cdpCandidate = RewriteActiveAliasToStableIssuerUrl(
            parentAuthority.CrlDistributionPointUrl ?? string.Empty,
            ["/ca.crl"],
            $"/authorities/{parentAuthority.Id}/ca.crl");

        string aiaCandidate = RewriteActiveAliasToStableIssuerUrl(
            parentAuthority.AuthorityIssuerCertUrl ?? string.Empty,
            ["/ca.crt", "/rootca.crt"],
            $"/authorities/{parentAuthority.Id}/issuer.crt");

        string? resolvedCdp = ResolveToHttpUriOrNull(
            cdpCandidate,
            $"/authorities/{parentAuthority.Id}/ca.crl",
            childConfiguredCdpUrl,
            ["/ca.crl"]);

        string? resolvedAia = ResolveToHttpUriOrNull(
            aiaCandidate,
            $"/authorities/{parentAuthority.Id}/issuer.crt",
            childConfiguredAiaUrl,
            ["/ca.crt", "/rootca.crt"]);

        return (resolvedCdp, resolvedAia);
    }

    private string? ResolveToHttpUriOrNull(
        string candidateUrl,
        string stableAuthorityPath,
        string? fallbackChildAliasUrl,
        IReadOnlyList<string> defaultAliasPaths)
    {
        if (string.IsNullOrWhiteSpace(candidateUrl))
        {
            return null;
        }

        if (Uri.TryCreate(candidateUrl, UriKind.Absolute, out Uri? absUri)
            && (absUri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                || absUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
        {
            return absUri.AbsoluteUri;
        }

        if (candidateUrl.StartsWith("/", StringComparison.Ordinal))
        {
            if (Uri.TryCreate(_options.PublicBaseUrl, UriKind.Absolute, out Uri? publicBase)
                && (publicBase.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                    || publicBase.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
            {
                return new Uri(publicBase, candidateUrl).AbsoluteUri;
            }

            if (!string.IsNullOrWhiteSpace(fallbackChildAliasUrl)
                && Uri.TryCreate(fallbackChildAliasUrl, UriKind.Absolute, out Uri? childUri)
                && (childUri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                    || childUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                && defaultAliasPaths.Any(alias => childUri.AbsolutePath.Equals(alias, StringComparison.OrdinalIgnoreCase)))
            {
                UriBuilder builder = new(childUri)
                {
                    Path = stableAuthorityPath,
                    Query = string.Empty,
                    Fragment = string.Empty
                };
                return builder.Uri.AbsoluteUri;
            }
        }

        return null;
    }

    private async Task<(long SerialValue, byte[] SerialBytes, string SerialHex)> AllocateNextIssuerSerialAsync(
        CertRoboDbContext db,
        CaAuthorityRecord trackedIssuer,
        CancellationToken cancellationToken)
    {
        List<IssuedCertificateRecord> existingLedger = await db.IssuedCertificates
            .AsNoTracking()
            .Where(c => c.CaAuthorityId == trackedIssuer.Id)
            .ToListAsync(cancellationToken);

        List<SerialRevocationEventRecord> existingEvents = await db.SerialRevocationEvents
            .AsNoTracking()
            .Where(e => e.CaAuthorityId == trackedIssuer.Id)
            .ToListAsync(cancellationToken);

        List<CaAuthorityRecord> allAuthorities = await db.CaAuthorities
            .AsNoTracking()
            .OrderBy(c => c.Id)
            .ToListAsync(cancellationToken);

        Dictionary<int, List<CaAuthorityRecord>> directSubordinatesByParent = MapDirectLocalSubordinatesByParentId(allAuthorities);
        IReadOnlyList<CaAuthorityRecord> directSubordinates = directSubordinatesByParent.TryGetValue(
            trackedIssuer.Id,
            out List<CaAuthorityRecord>? subs)
            ? subs
            : [];

        long maxCounterFloor = Math.Max(1000L, trackedIssuer.LastAllocatedSerial);
        HashSet<BigInteger> usedSerialValues = [];
        HashSet<string> usedCanonicalHexes = new(StringComparer.OrdinalIgnoreCase);

        foreach (IssuedCertificateRecord rec in existingLedger)
        {
            if (rec.SerialNumberValue > maxCounterFloor)
            {
                maxCounterFloor = rec.SerialNumberValue;
            }

            if (TryNormalizePositiveSerialHex(rec.SerialNumberHex, out BigInteger bi, out string canonHex, out _))
            {
                usedSerialValues.Add(bi);
                usedCanonicalHexes.Add(canonHex);
                if (TryExtractAllocatedCounterFloor(canonHex, bi, out long counterFloor) && counterFloor > maxCounterFloor)
                {
                    maxCounterFloor = counterFloor;
                }
            }
        }

        foreach (SerialRevocationEventRecord evt in existingEvents)
        {
            if (TryNormalizePositiveSerialHex(evt.CanonicalSerialHex, out BigInteger bi, out string canonHex, out _))
            {
                usedSerialValues.Add(bi);
                usedCanonicalHexes.Add(canonHex);
                if (TryExtractAllocatedCounterFloor(canonHex, bi, out long counterFloor) && counterFloor > maxCounterFloor)
                {
                    maxCounterFloor = counterFloor;
                }
            }
        }

        foreach (CaAuthorityRecord sub in directSubordinates)
        {
            try
            {
                using X509Certificate2 subCert = X509Certificate2.CreateFromPem(sub.IssuerCertificatePem);
                string subSerialHex = Convert.ToHexString(subCert.GetSerialNumber().Reverse().ToArray());
                if (TryNormalizePositiveSerialHex(subSerialHex, out BigInteger bi, out string canonHex, out _))
                {
                    usedSerialValues.Add(bi);
                    usedCanonicalHexes.Add(canonHex);
                    if (TryExtractAllocatedCounterFloor(canonHex, bi, out long counterFloor) && counterFloor > maxCounterFloor)
                    {
                        maxCounterFloor = counterFloor;
                    }
                }
            }
            catch
            {
            }
        }

        long nextSerial = checked(maxCounterFloor + 1);
        while (true)
        {
            byte[] serialBytes = AllocatePositiveSerialBytes(nextSerial);
            string serialHex = Convert.ToHexString(serialBytes);
            if (TryNormalizePositiveSerialHex(serialHex, out BigInteger candidateBi, out string canonicalHex, out _)
                && !usedSerialValues.Contains(candidateBi)
                && !usedCanonicalHexes.Contains(canonicalHex))
            {
                return (nextSerial, serialBytes, serialHex);
            }

            nextSerial = checked(nextSerial + 1);
        }
    }

    private static bool TryExtractAllocatedCounterFloor(string canonicalHex, BigInteger serialBigInt, out long counterFloor)
    {
        counterFloor = 0;

        if (serialBigInt.CompareTo(BigInteger.One) >= 0
            && serialBigInt.CompareTo(BigInteger.ValueOf(1_000_000_000L)) <= 0)
        {
            counterFloor = serialBigInt.LongValue;
            return true;
        }

        try
        {
            byte[] bytes = Convert.FromHexString(canonicalHex);
            if (bytes.Length == 12)
            {
                byte[] counterBytes = new byte[8];
                Buffer.BlockCopy(bytes, 0, counterBytes, 0, 8);
                if (counterBytes[0] == 0x01 && counterBytes[1] == 0x00)
                {
                    counterBytes[0] = 0x00;
                }
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(counterBytes);
                }
                long extracted = BitConverter.ToInt64(counterBytes, 0);
                if (extracted > 0 && extracted <= 1_000_000_000_000L)
                {
                    counterFloor = extracted;
                    return true;
                }
            }
        }
        catch
        {
        }

        return false;
    }

    private static Dictionary<int, List<CaAuthorityRecord>> MapDirectLocalSubordinatesByParentId(
        IReadOnlyList<CaAuthorityRecord> authorities)
    {
        Dictionary<int, List<CaAuthorityRecord>> result = [];
        if (authorities.Count <= 1)
        {
            return result;
        }

        Dictionary<int, X509Certificate2> parsedByAuthorityId = [];
        try
        {
            foreach (CaAuthorityRecord auth in authorities)
            {
                try
                {
                    parsedByAuthorityId[auth.Id] = X509Certificate2.CreateFromPem(auth.IssuerCertificatePem);
                }
                catch
                {
                }
            }

            foreach (CaAuthorityRecord child in authorities.Where(a => a.IsIntermediate))
            {
                if (!parsedByAuthorityId.TryGetValue(child.Id, out X509Certificate2? childCert))
                {
                    continue;
                }

                CaAuthorityRecord? matchedParent = null;
                foreach (CaAuthorityRecord candidateParent in authorities.OrderByDescending(a => a.Id))
                {
                    if (candidateParent.Id == child.Id
                        || !parsedByAuthorityId.TryGetValue(candidateParent.Id, out X509Certificate2? parentCert))
                    {
                        continue;
                    }

                    if (childCert.RawDataMemory.Span.SequenceEqual(parentCert.RawDataMemory.Span))
                    {
                        continue;
                    }

                    if (!childCert.IssuerName.RawData.SequenceEqual(parentCert.SubjectName.RawData))
                    {
                        continue;
                    }

                    X509AuthorityKeyIdentifierExtension? childAki = childCert.Extensions
                        .OfType<X509AuthorityKeyIdentifierExtension>()
                        .FirstOrDefault();
                    X509SubjectKeyIdentifierExtension? parentSki = parentCert.Extensions
                        .OfType<X509SubjectKeyIdentifierExtension>()
                        .FirstOrDefault();

                    if (childAki?.KeyIdentifier is { Length: > 0 } akiBytes
                        && parentSki?.SubjectKeyIdentifierBytes is { Length: > 0 } skiBytes
                        && !akiBytes.Span.SequenceEqual(skiBytes.Span))
                    {
                        continue;
                    }

                    if (CaChainAndConstraintValidator.VerifySignatureCryptographically(childCert, parentCert, out _))
                    {
                        matchedParent = candidateParent;
                        break;
                    }
                }

                if (matchedParent != null)
                {
                    if (!result.TryGetValue(matchedParent.Id, out List<CaAuthorityRecord>? list))
                    {
                        list = [];
                        result[matchedParent.Id] = list;
                    }
                    list.Add(child);
                }
            }

            return result;
        }
        finally
        {
            foreach (X509Certificate2 cert in parsedByAuthorityId.Values)
            {
                cert.Dispose();
            }
        }
    }

    private static async Task WritePublicTrustFilesAsync(CaAuthorityRecord ca, CancellationToken cancellationToken)
    {
        try
        {
            if (Directory.Exists("static"))
            {
                string orderedChain = BuildOrderedCertificateChainPem(ca);
                List<X509Certificate2> parsed = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                    null,
                    orderedChain,
                    "stored CA chain");
                try
                {
                    string rootPem = parsed[^1].ExportCertificatePem() + "\n";
                    await File.WriteAllTextAsync(Path.Combine("static", "rootca.crt"), rootPem, cancellationToken);
                    await File.WriteAllTextAsync(Path.Combine("static", "ca-chain.crt"), orderedChain, cancellationToken);
                    await File.WriteAllTextAsync(
                        Path.Combine("static", "ca.crt"),
                        ca.IssuerCertificatePem.Trim() + "\n",
                        cancellationToken);
                }
                finally
                {
                    foreach (X509Certificate2 cert in parsed) cert.Dispose();
                }
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
        string authorityIssuerCertUrl,
        IReadOnlyList<string>? effectiveEkuOids = null)
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

        // 3. ExtendedKeyUsage from profile (intersected with active CA chain EKU constraints if present)
        OidCollection ekuOids = new();
        IReadOnlyList<string> oidsToEmit = effectiveEkuOids ?? req.Profile.ExtendedKeyUsageOids;
        foreach (string oid in oidsToEmit)
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
        DateTimeOffset expectedNotAfter,
        IReadOnlyList<string>? expectedEkuOids = null)
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

        // 3. Check EKU matches profile / chain-constrained EKUs
        X509EnhancedKeyUsageExtension? eku = leafCert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault()
            ?? throw new CryptographicException("Issued leaf certificate is missing ExtendedKeyUsage.");
        HashSet<string> actualEkus = eku.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value!).ToHashSet(StringComparer.Ordinal);
        IReadOnlyList<string> requiredEkus = expectedEkuOids ?? req.Profile.ExtendedKeyUsageOids;
        foreach (string requiredOid in requiredEkus)
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
                    if (CaChainAndConstraintValidator.IsSelfSignedCryptographically(cert))
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
            ?? throw new ArgumentException("CA certificate is missing the required BasicConstraints extension.");
        if (!bc.CertificateAuthority)
        {
            throw new ArgumentException("Certificate is not a CA certificate (BasicConstraints CA=false).");
        }
        if (!bc.Critical)
        {
            throw new ArgumentException("CA certificate BasicConstraints extension must be critical.");
        }
        if (bc.HasPathLengthConstraint && bc.PathLengthConstraint < 0)
        {
            throw new ArgumentException("CA certificate BasicConstraints pathLenConstraint cannot be negative.");
        }

        // Verify KeyUsage is present and includes both KeyCertSign and CrlSign
        X509KeyUsageExtension? ku = caCert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault()
            ?? throw new ArgumentException("CA certificate is missing the required KeyUsage extension (KeyCertSign and CrlSign are required).");
        if ((ku.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0)
        {
            throw new ArgumentException("CA certificate KeyUsage does not allow KeyCertSign.");
        }
        if ((ku.KeyUsages & X509KeyUsageFlags.CrlSign) == 0)
        {
            throw new ArgumentException("CA certificate KeyUsage does not allow CrlSign, which CertRobo requires to publish CRLs.");
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (now < caCert.NotBefore.ToUniversalTime())
        {
            throw new ArgumentException($"CA certificate is not yet valid (NotBefore: {caCert.NotBefore.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC).");
        }
        if (now > caCert.NotAfter.ToUniversalTime())
        {
            throw new ArgumentException($"CA certificate has expired (NotAfter: {caCert.NotAfter.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC).");
        }

        // Verify public/private key match via SubjectPublicKeyInfo comparison
        byte[] certSpki = caCert.PublicKey.ExportSubjectPublicKeyInfo();
        byte[] keySpki = ExportPublicKeySpki(privateKey);
        if (!certSpki.SequenceEqual(keySpki))
        {
            throw new ArgumentException("Provided private key does not match the CA certificate's public key.");
        }

        bool isSelfSignedRoot = CaChainAndConstraintValidator.IsSelfSignedCryptographically(caCert);
        isIntermediate = !isSelfSignedRoot;
        normalizedChainPem = string.Empty;

        if (isIntermediate)
        {
            if (string.IsNullOrWhiteSpace(chainCertsPem))
            {
                if (CaChainAndConstraintValidator.IsSelfIssued(caCert))
                {
                    throw new ArgumentException("CA certificate is self-issued but failed self-signature verification, and no parent/root certificate chain PEM was provided.");
                }
                throw new ArgumentException("Intermediate CA requires the parent/root certificate chain PEM.");
            }

            List<X509Certificate2> parsedChain = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                null, chainCertsPem, "imported chain certificates");
            try
            {
                string caThumbprint = caCert.GetCertHashString(HashAlgorithmName.SHA256);
                List<X509Certificate2> ancestorCandidates = parsedChain
                    .Where(c => !c.GetCertHashString(HashAlgorithmName.SHA256).Equals(caThumbprint, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (ancestorCandidates.Count == 0)
                {
                    throw new ArgumentException("No valid parent/root certificates were found in the supplied chain PEM.");
                }

                var (chainResolved, chainErr, orderedChain) = CaChainAndConstraintValidator.ResolveUnambiguousCryptographicChain(
                    caCert,
                    ancestorCandidates);
                if (!chainResolved || orderedChain == null)
                {
                    throw new ArgumentException($"Intermediate CA chain validation failed: {chainErr}");
                }

                var (ancOk, ancErr) = CaChainAndConstraintValidator.ValidateAncestorChainCapabilities(orderedChain, now);
                if (!ancOk)
                {
                    throw new ArgumentException($"Intermediate CA chain validation failed: {ancErr}");
                }

                var (extOk, extErr, _, _, _) = CaChainAndConstraintValidator.EvaluateChainExtensionsAndRestrictions(orderedChain);
                if (!extOk)
                {
                    throw new ArgumentException(extErr ?? "CA chain contains unsupported restrictions.");
                }

                var (dotNetChainOk, dotNetChainErr) = CaChainAndConstraintValidator.VerifyWithDotNetCustomRootChain(orderedChain, now);
                if (!dotNetChainOk)
                {
                    throw new ArgumentException($"Intermediate CA chain validation failed: {dotNetChainErr}");
                }

                StringBuilder ordered = new();
                for (int i = 1; i < orderedChain.Count; i++)
                {
                    ordered.AppendLine(orderedChain[i].ExportCertificatePem().Trim());
                }

                normalizedChainPem = ordered.ToString();
            }
            finally
            {
                foreach (X509Certificate2 c in parsedChain) c.Dispose();
            }
        }
        else
        {
            BcX509Certificate bcRoot = new X509CertificateParser().ReadCertificate(caCert.RawData);
            bcRoot.Verify(bcRoot.GetPublicKey());
            var (extOk, extErr, _, _, _) = CaChainAndConstraintValidator.EvaluateChainExtensionsAndRestrictions([caCert]);
            if (!extOk)
            {
                throw new ArgumentException(extErr ?? "CA certificate contains unsupported restrictions.");
            }
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

    private async Task ValidateCustodyCandidateCoreAsync(
        CertRoboDbContext db,
        string candidatePassphrase,
        string? secondaryParentPassphrase,
        bool requireExistingKeyForUnlock,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(candidatePassphrase))
        {
            throw new ArgumentException("A non-empty CA storage passphrase is required.", nameof(candidatePassphrase));
        }

        if (!string.IsNullOrWhiteSpace(secondaryParentPassphrase)
            && !PassphrasesEqual(candidatePassphrase, secondaryParentPassphrase))
        {
            throw new InvalidOperationException(
                "The subordinate CA storage passphrase must match the parent CA storage passphrase under the shared custody policy.");
        }

        (string? configuredPassphrase, string configuredSource) = ResolveConfiguredPassphraseWithSource();
        if (!string.IsNullOrEmpty(configuredPassphrase)
            && !PassphrasesEqual(candidatePassphrase, configuredPassphrase))
        {
            throw new InvalidOperationException(
                $"The supplied CA storage passphrase does not match the configured persistent CA custody secret ({configuredSource}). All CA keys must use the same custody passphrase so the active issuer and historical CRLs remain operational across restarts.");
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        List<CaAuthorityRecord> authorities = await db.CaAuthorities
            .OrderBy(c => c.Id)
            .ToListAsync(cancellationToken);

        List<PendingCaEnrollmentRecord> pendingEnrollments = await db.PendingCaEnrollments
            .Where(p => p.Status != PendingCaEnrollmentStatus.Activated
                     && p.Status != PendingCaEnrollmentStatus.Cancelled)
            .OrderBy(p => p.Id)
            .ToListAsync(cancellationToken);

        EvictStaleRuntimeUnlockIfIncompatible(authorities, pendingEnrollments);

        if (!requireExistingKeyForUnlock
            && !_isExplicitlyLocked
            && !string.IsNullOrEmpty(_runtimeUnlockedPassphrase)
            && !PassphrasesEqual(candidatePassphrase, _runtimeUnlockedPassphrase))
        {
            throw new InvalidOperationException(
                "The supplied CA storage passphrase does not match the currently unlocked runtime CA passphrase. All active and historical CA keys must share one storage passphrase.");
        }

        if (requireExistingKeyForUnlock && authorities.Count == 0 && pendingEnrollments.Count == 0)
        {
            throw new InvalidOperationException(
                "No CA signing key is configured to unlock. Provision, import, or request a CA first.");
        }

        HashSet<int> authoritiesWithUnexpiredCerts = (await db.IssuedCertificates
            .Where(c => c.CaAuthorityId.HasValue
                     && (c.Status == IssuanceStatus.Issued || c.Status == IssuanceStatus.Revoked))
            .ToListAsync(cancellationToken))
            .Where(c => c.NotAfterUtc > now)
            .Select(c => c.CaAuthorityId!.Value)
            .ToHashSet();

        Dictionary<int, List<CaAuthorityRecord>> directSubordinatesByParent = MapDirectLocalSubordinatesByParentId(authorities);
        HashSet<int> authoritiesWithUnexpiredSubordinates = directSubordinatesByParent
            .Where(kv => kv.Value.Any(sub => sub.NotAfterUtc > now))
            .Select(kv => kv.Key)
            .ToHashSet();

        foreach (CaAuthorityRecord authority in authorities)
        {
            bool requiresMaintenance = authority.IsActive
                || (authority.NotAfterUtc > now && (authoritiesWithUnexpiredCerts.Contains(authority.Id)
                                                 || authoritiesWithUnexpiredSubordinates.Contains(authority.Id)));
            bool shouldVerify = requiresMaintenance
                || authority.NotAfterUtc > now
                || File.Exists(authority.EncryptedPrivateKeyPath);

            if (!shouldVerify)
            {
                continue;
            }

            if (!TryVerifyAuthorityKey(authority, candidatePassphrase, out string? keyErr))
            {
                string roleDesc = authority.IsActive ? "active" : (requiresMaintenance ? "maintained historical" : "stored historical");
                throw new InvalidOperationException(
                    $"CA key custody validation failed for {roleDesc} CA '{authority.Name}' (ID #{authority.Id}): {keyErr} All active and maintained historical CA keys must share one storage passphrase. If existing keys use mixed passphrases, run the CA key custody recovery/re-protection procedure.");
            }
        }

        foreach (PendingCaEnrollmentRecord pending in pendingEnrollments)
        {
            if (!TryVerifyPendingKey(pending, candidatePassphrase, out string? pendingErr))
            {
                throw new InvalidOperationException(
                    $"CA key custody validation failed for pending CA request '{pending.CaName}' (ID #{pending.Id}): {pendingErr}");
            }
        }
    }

    private void EvictStaleRuntimeUnlockIfIncompatible(
        IReadOnlyCollection<CaAuthorityRecord> authorities,
        IReadOnlyCollection<PendingCaEnrollmentRecord> pendingEnrollments)
    {
        if (string.IsNullOrEmpty(_runtimeUnlockedPassphrase))
        {
            return;
        }

        string? configured;
        try
        {
            configured = ResolveConfiguredPassphrase();
        }
        catch
        {
            _runtimeUnlockedPassphrase = null;
            throw;
        }

        if (!string.IsNullOrEmpty(configured) && !PassphrasesEqual(_runtimeUnlockedPassphrase, configured))
        {
            _runtimeUnlockedPassphrase = null;
            return;
        }

        bool anyAuthorityIncompatible = authorities.Any(a =>
            File.Exists(a.EncryptedPrivateKeyPath)
            && !TryVerifyAuthorityKey(a, _runtimeUnlockedPassphrase, out _));
        bool anyPendingIncompatible = pendingEnrollments.Any(p =>
            File.Exists(p.EncryptedPrivateKeyPath)
            && !TryVerifyPendingKey(p, _runtimeUnlockedPassphrase, out _));

        if (anyAuthorityIncompatible || anyPendingIncompatible)
        {
            _runtimeUnlockedPassphrase = null;
        }
    }

    private static bool TryVerifyAuthorityKey(
        CaAuthorityRecord authority,
        string? passphrase,
        out string? error)
    {
        error = null;
        if (!File.Exists(authority.EncryptedPrivateKeyPath))
        {
            error = $"Encrypted private key file '{Path.GetFileName(authority.EncryptedPrivateKeyPath)}' for CA '{authority.Name}' (ID #{authority.Id}) was not found.";
            return false;
        }

        if (string.IsNullOrEmpty(passphrase))
        {
            error = $"No CA storage passphrase is available to unlock CA '{authority.Name}' (ID #{authority.Id}).";
            return false;
        }

        try
        {
            using AsymmetricAlgorithm key = LoadEncryptedKey(authority.EncryptedPrivateKeyPath, passphrase);
            using X509Certificate2 cert = X509Certificate2.CreateFromPem(authority.IssuerCertificatePem);
            byte[] certSpki = cert.PublicKey.ExportSubjectPublicKeyInfo();
            byte[] keySpki = ExportPublicKeySpki(key);
            if (!certSpki.SequenceEqual(keySpki))
            {
                error = $"Decrypted private key for CA '{authority.Name}' (ID #{authority.Id}) does not match its certificate public key.";
                return false;
            }

            return true;
        }
        catch (Exception)
        {
            error = $"CA '{authority.Name}' (ID #{authority.Id}) private key could not be unlocked with the supplied passphrase.";
            return false;
        }
    }

    private static bool TryVerifyPendingKey(
        PendingCaEnrollmentRecord pending,
        string? passphrase,
        out string? error)
    {
        error = null;
        if (!File.Exists(pending.EncryptedPrivateKeyPath))
        {
            error = $"Encrypted private key file '{Path.GetFileName(pending.EncryptedPrivateKeyPath)}' for pending CA request '{pending.CaName}' (ID #{pending.Id}) was not found.";
            return false;
        }

        if (string.IsNullOrEmpty(passphrase))
        {
            error = $"No CA storage passphrase is available to unlock pending CA request '{pending.CaName}' (ID #{pending.Id}).";
            return false;
        }

        try
        {
            using AsymmetricAlgorithm key = LoadEncryptedKey(pending.EncryptedPrivateKeyPath, passphrase);
            byte[] spkiDer = ExportPublicKeySpki(key);
            string spkiSha256Hex = Convert.ToHexString(SHA256.HashData(spkiDer));
            if (!spkiSha256Hex.Equals(pending.PublicKeySpkiSha256Hex, StringComparison.OrdinalIgnoreCase))
            {
                error = $"Decrypted private key for pending CA request '{pending.CaName}' (ID #{pending.Id}) does not match its CSR public key.";
                return false;
            }

            return true;
        }
        catch (Exception)
        {
            error = $"Pending CA request '{pending.CaName}' (ID #{pending.Id}) private key could not be unlocked with the supplied passphrase.";
            return false;
        }
    }

    private static bool PassphrasesEqual(string a, string b)
    {
        byte[] aBytes = Encoding.UTF8.GetBytes(a);
        byte[] bBytes = Encoding.UTF8.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
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
        byte[] keyDer = PkcsBuilder.ExtractPemOrBase64BytesBounded(
            privateKeyPem,
            PkcsBuilder.MaxKeyPemLength,
            PkcsBuilder.MaxKeyDerBytes,
            "Imported CA private key");
        try
        {
            _ = Asn1Object.FromByteArray(keyDer);
        }
        catch (Exception ex)
        {
            throw new ArgumentException("Imported CA private key could not be decoded.", nameof(privateKeyPem), ex);
        }

        bool isEncryptedPem = privateKeyPem.Contains("ENCRYPTED", StringComparison.OrdinalIgnoreCase);
        if (isEncryptedPem && string.IsNullOrEmpty(passphrase))
        {
            throw new ArgumentException(
                "Imported CA private key PEM is encrypted; an input key decryption passphrase is required.",
                nameof(passphrase));
        }

        string oid = cert.PublicKey.Oid.Value ?? string.Empty;
        try
        {
            if (oid == "1.2.840.113549.1.1.1") // RSA
            {
                RSA rsa = RSA.Create();
                if (isEncryptedPem)
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
                if (isEncryptedPem)
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
        catch (CryptographicException ex) when (isEncryptedPem)
        {
            throw new ArgumentException(
                "Failed to decrypt the imported CA private key PEM using the supplied input key passphrase.",
                nameof(passphrase),
                ex);
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
