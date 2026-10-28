using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace CertRobo.Data;

public static class AppRoles
{
    public const string Administrator = "Administrator";
    public const string Issuer = "Issuer";
}

public class ApplicationUser : IdentityUser
{
    public bool IsDisabled { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string? DisplayName { get; set; }
}

public class DomainPermissionRule
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(128)]
    public string SubjectType { get; set; } = "User"; // "User" or "Role"

    [Required]
    [MaxLength(256)]
    public string SubjectValue { get; set; } = string.Empty; // UserId or RoleName

    [Required]
    [MaxLength(256)]
    public string DomainPattern { get; set; } = string.Empty; // e.g., "*.contoso.com", "contoso.com", "*"

    [Required]
    [MaxLength(128)]
    public string AllowedProfileId { get; set; } = "*"; // "*" or specific profile ID

    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public class SubjectDefaultsConfig
{
    [Key]
    public int Id { get; set; } = 1;

    [MaxLength(2)]
    public string Country { get; set; } = "US";

    [MaxLength(128)]
    public string StateOrProvince { get; set; } = "Washington";

    [MaxLength(128)]
    public string Locality { get; set; } = "Redmond";

    [MaxLength(256)]
    public string Organisation { get; set; } = "Contoso Corporation";

    [MaxLength(256)]
    public string OrganisationalUnit { get; set; } = "IT";

    [MaxLength(256)]
    public string EmailAddress { get; set; } = "it@contoso.com";
}

public class CaAuthorityRecord
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(256)]
    public string Name { get; set; } = string.Empty;

    public bool IsActive { get; set; }
    public bool IsIntermediate { get; set; }

    [Required]
    public string IssuerCertificatePem { get; set; } = string.Empty;

    /// <summary>
    /// Additional chain certificates (e.g., parent intermediate / root certificates) in PEM order from immediate parent up to root.
    /// </summary>
    public string ChainCertificatesPem { get; set; } = string.Empty;

    [Required]
    [MaxLength(128)]
    public string SubjectKeyIdentifierHex { get; set; } = string.Empty;

    [Required]
    [MaxLength(128)]
    public string ThumbprintOrSerialHex { get; set; } = string.Empty;

    /// <summary>
    /// File path to the encrypted private key on disk (never stored unencrypted in DB).
    /// </summary>
    [Required]
    [MaxLength(512)]
    public string EncryptedPrivateKeyPath { get; set; } = string.Empty;

    [MaxLength(512)]
    public string CrlDistributionPointUrl { get; set; } = string.Empty;

    [MaxLength(512)]
    public string AuthorityIssuerCertUrl { get; set; } = string.Empty;

    public long LastAllocatedSerial { get; set; } = 1000;
    public long LastCrlNumber { get; set; } = 0;

    public DateTimeOffset NotBeforeUtc { get; set; }
    public DateTimeOffset NotAfterUtc { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public enum PendingCaEnrollmentStatus
{
    AwaitingSubmission = 0,
    SubmissionUncertain = 1,
    AwaitingApproval = 2,
    ReadyForActivation = 3,
    Failed = 4,
    Activated = 5,
    Cancelled = 6
}

public class PendingCaEnrollmentRecord
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(256)]
    public string CaName { get; set; } = string.Empty;

    [Required]
    [MaxLength(256)]
    public string SubjectCommonName { get; set; } = string.Empty;

    [Required]
    [MaxLength(512)]
    public string SubjectDistinguishedName { get; set; } = string.Empty;

    [Required]
    [MaxLength(64)]
    public string KeyAlgorithm { get; set; } = string.Empty;

    public int KeySizeBits { get; set; }

    public int? RequestedPathLengthConstraint { get; set; } = 0;

    [Required]
    [MaxLength(128)]
    public string SubjectKeyIdentifierHex { get; set; } = string.Empty;

    [Required]
    [MaxLength(128)]
    public string PublicKeySpkiSha256Hex { get; set; } = string.Empty;

    [Required]
    public string CsrPem { get; set; } = string.Empty;

    /// <summary>
    /// File path to the encrypted private key on disk (never stored unencrypted in DB).
    /// </summary>
    [Required]
    [MaxLength(512)]
    public string EncryptedPrivateKeyPath { get; set; } = string.Empty;

    [MaxLength(512)]
    public string CrlDistributionPointUrl { get; set; } = "/ca.crl";

    [MaxLength(512)]
    public string AuthorityIssuerCertUrl { get; set; } = "/ca.crt";

    public long InitialSerialFloor { get; set; } = 1000;
    public long InitialCrlNumberFloor { get; set; } = 0;

    public PendingCaEnrollmentStatus Status { get; set; } = PendingCaEnrollmentStatus.AwaitingSubmission;

    [MaxLength(128)]
    public string? LastOutcomeCategory { get; set; }

    public string? StatusDetailMessage { get; set; }

    [MaxLength(512)]
    public string? UpstreamEndpointUrl { get; set; }

    [MaxLength(256)]
    public string? UpstreamTemplateName { get; set; }

    [MaxLength(128)]
    public string? UpstreamRequestId { get; set; }

    [MaxLength(128)]
    public string? UpstreamErrorCode { get; set; }

    [MaxLength(128)]
    public string? LastMessageId { get; set; }

    public DateTimeOffset? LastSubmittedAtUtc { get; set; }
    public DateTimeOffset? LastCheckedAtUtc { get; set; }

    /// <summary>
    /// Holds a signed CA certificate received from CES or manual upload even before full chain validation completes,
    /// or the validated certificate once Status == ReadyForActivation.
    /// </summary>
    public string? ReceivedIssuerCertificatePem { get; set; }

    /// <summary>
    /// Holds any intermediate/root certificates received alongside the signed CA certificate.
    /// </summary>
    public string? ReceivedChainCertificatesPem { get; set; }

    public string? ValidatedIssuerCertificatePem { get; set; }
    public string? ValidatedChainCertificatesPem { get; set; }
    public string? ActivationSummaryJson { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ActivatedAtUtc { get; set; }
    public int? ActivatedCaAuthorityId { get; set; }
}

public class AdCsCesConnectorConfig
{
    [Key]
    public int Id { get; set; } = 1;

    public bool IsEnabled { get; set; }

    [MaxLength(512)]
    public string EndpointUrl { get; set; } = string.Empty;

    [MaxLength(256)]
    public string CertificateTemplate { get; set; } = string.Empty;

    /// <summary>
    /// "UsernamePassword" or "ClientCertificate"
    /// </summary>
    [Required]
    [MaxLength(64)]
    public string AuthenticationMode { get; set; } = "UsernamePassword";

    [MaxLength(256)]
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Encrypted using ASP.NET Core DataProtection; never stored in plaintext.
    /// </summary>
    public string ProtectedPassword { get; set; } = string.Empty;

    public string ClientCertificatePem { get; set; } = string.Empty;

    /// <summary>
    /// Encrypted using ASP.NET Core DataProtection; never stored in plaintext.
    /// </summary>
    public string ProtectedClientPrivateKeyPem { get; set; } = string.Empty;

    /// <summary>
    /// Optional PEM bundle of internal Root/Intermediate CA certificates trusted for validating the CES HTTPS endpoint's TLS certificate.
    /// </summary>
    public string CustomServerTlsTrustPem { get; set; } = string.Empty;

    /// <summary>
    /// Optional PEM bundle of parent/root CA certificates used to complete chain validation when CES returns only the subordinate CA certificate.
    /// </summary>
    public string DefaultParentChainTrustPem { get; set; } = string.Empty;

    public int RequestTimeoutSeconds { get; set; } = 30;

    public DateTimeOffset UpdatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public enum IssuanceStatus
{
    Pending = 0,
    Issued = 1,
    Revoked = 2,
    Failed = 3,
    Denied = 4
}

public class IssuedCertificateRecord
{
    [Key]
    public int Id { get; set; }

    public int? CaAuthorityId { get; set; }

    [Required]
    [MaxLength(64)]
    public string SerialNumberHex { get; set; } = string.Empty;

    public long SerialNumberValue { get; set; }

    [Required]
    [MaxLength(128)]
    public string ProfileId { get; set; } = string.Empty;

    [Required]
    [MaxLength(256)]
    public string CommonName { get; set; } = string.Empty;

    /// <summary>
    /// Comma-separated canonical DNS SANs.
    /// </summary>
    [Required]
    public string SubjectAlternativeNamesCsv { get; set; } = string.Empty;

    [Required]
    [MaxLength(512)]
    public string SubjectDistinguishedName { get; set; } = string.Empty;

    [Required]
    [MaxLength(512)]
    public string IssuerDistinguishedName { get; set; } = string.Empty;

    [Required]
    [MaxLength(64)]
    public string KeyAlgorithm { get; set; } = string.Empty;

    public int KeySizeBits { get; set; }

    [Required]
    [MaxLength(128)]
    public string ThumbprintSha256 { get; set; } = string.Empty;

    public string CertificatePem { get; set; } = string.Empty;
    public string ChainPem { get; set; } = string.Empty;

    public DateTimeOffset NotBeforeUtc { get; set; }
    public DateTimeOffset NotAfterUtc { get; set; }

    [Required]
    [MaxLength(256)]
    public string RequestedByUserId { get; set; } = string.Empty;

    [Required]
    [MaxLength(256)]
    public string RequestedByUserName { get; set; } = string.Empty;

    public IssuanceStatus Status { get; set; } = IssuanceStatus.Pending;

    public string? FailureOrDenialReason { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? RevokedAtUtc { get; set; }
    public int? RevocationReasonCode { get; set; }
    public string? RevokedByUserName { get; set; }
}

public class PublishedCrlRecord
{
    [Key]
    public int Id { get; set; }

    public int CaAuthorityId { get; set; }
    public long CrlNumber { get; set; }
    public byte[] CrlDer { get; set; } = [];
    public string CrlPem { get; set; } = string.Empty;
    public DateTimeOffset ThisUpdateUtc { get; set; }
    public DateTimeOffset NextUpdateUtc { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
}

public class CertRoboDbContext(DbContextOptions<CertRoboDbContext> options)
    : IdentityDbContext<ApplicationUser, IdentityRole, string>(options)
{
    public DbSet<DomainPermissionRule> DomainPermissionRules => Set<DomainPermissionRule>();
    public DbSet<SubjectDefaultsConfig> SubjectDefaults => Set<SubjectDefaultsConfig>();
    public DbSet<CaAuthorityRecord> CaAuthorities => Set<CaAuthorityRecord>();
    public DbSet<PendingCaEnrollmentRecord> PendingCaEnrollments => Set<PendingCaEnrollmentRecord>();
    public DbSet<AdCsCesConnectorConfig> AdCsCesConfigs => Set<AdCsCesConnectorConfig>();
    public DbSet<IssuedCertificateRecord> IssuedCertificates => Set<IssuedCertificateRecord>();
    public DbSet<PublishedCrlRecord> PublishedCrls => Set<PublishedCrlRecord>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<DomainPermissionRule>()
            .HasIndex(r => new { r.SubjectType, r.SubjectValue, r.DomainPattern, r.AllowedProfileId })
            .IsUnique();

        builder.Entity<IssuedCertificateRecord>()
            .HasIndex(c => new { c.CaAuthorityId, c.SerialNumberHex })
            .IsUnique();

        builder.Entity<IssuedCertificateRecord>()
            .HasIndex(c => c.Status);

        builder.Entity<PublishedCrlRecord>()
            .HasIndex(c => new { c.CaAuthorityId, c.CrlNumber })
            .IsUnique();

        builder.Entity<PendingCaEnrollmentRecord>()
            .HasIndex(p => p.Status);
    }

    public async Task EnsureSchemaUpgradedAsync(CancellationToken cancellationToken = default)
    {
        await Database.EnsureCreatedAsync(cancellationToken);

        const string createPendingTableSql = """
            CREATE TABLE IF NOT EXISTS "PendingCaEnrollments" (
                "Id" INTEGER NOT NULL CONSTRAINT "PK_PendingCaEnrollments" PRIMARY KEY AUTOINCREMENT,
                "CaName" TEXT NOT NULL,
                "SubjectCommonName" TEXT NOT NULL,
                "SubjectDistinguishedName" TEXT NOT NULL,
                "KeyAlgorithm" TEXT NOT NULL,
                "KeySizeBits" INTEGER NOT NULL,
                "RequestedPathLengthConstraint" INTEGER NULL,
                "SubjectKeyIdentifierHex" TEXT NOT NULL,
                "PublicKeySpkiSha256Hex" TEXT NOT NULL,
                "CsrPem" TEXT NOT NULL,
                "EncryptedPrivateKeyPath" TEXT NOT NULL,
                "CrlDistributionPointUrl" TEXT NOT NULL,
                "AuthorityIssuerCertUrl" TEXT NOT NULL,
                "InitialSerialFloor" INTEGER NOT NULL,
                "InitialCrlNumberFloor" INTEGER NOT NULL,
                "Status" INTEGER NOT NULL,
                "LastOutcomeCategory" TEXT NULL,
                "StatusDetailMessage" TEXT NULL,
                "UpstreamEndpointUrl" TEXT NULL,
                "UpstreamTemplateName" TEXT NULL,
                "UpstreamRequestId" TEXT NULL,
                "UpstreamErrorCode" TEXT NULL,
                "LastMessageId" TEXT NULL,
                "LastSubmittedAtUtc" TEXT NULL,
                "LastCheckedAtUtc" TEXT NULL,
                "ReceivedIssuerCertificatePem" TEXT NULL,
                "ReceivedChainCertificatesPem" TEXT NULL,
                "ValidatedIssuerCertificatePem" TEXT NULL,
                "ValidatedChainCertificatesPem" TEXT NULL,
                "ActivationSummaryJson" TEXT NULL,
                "CreatedAtUtc" TEXT NOT NULL,
                "ActivatedAtUtc" TEXT NULL,
                "ActivatedCaAuthorityId" INTEGER NULL
            );
            CREATE INDEX IF NOT EXISTS "IX_PendingCaEnrollments_Status" ON "PendingCaEnrollments" ("Status");
            """;

        const string createCesConfigTableSql = """
            CREATE TABLE IF NOT EXISTS "AdCsCesConfigs" (
                "Id" INTEGER NOT NULL CONSTRAINT "PK_AdCsCesConfigs" PRIMARY KEY AUTOINCREMENT,
                "IsEnabled" INTEGER NOT NULL,
                "EndpointUrl" TEXT NOT NULL,
                "CertificateTemplate" TEXT NOT NULL,
                "AuthenticationMode" TEXT NOT NULL,
                "Username" TEXT NOT NULL,
                "ProtectedPassword" TEXT NOT NULL,
                "ClientCertificatePem" TEXT NOT NULL,
                "ProtectedClientPrivateKeyPem" TEXT NOT NULL,
                "CustomServerTlsTrustPem" TEXT NOT NULL,
                "DefaultParentChainTrustPem" TEXT NOT NULL,
                "RequestTimeoutSeconds" INTEGER NOT NULL,
                "UpdatedAtUtc" TEXT NOT NULL
            );
            """;

        await Database.ExecuteSqlRawAsync(createPendingTableSql, cancellationToken);
        await Database.ExecuteSqlRawAsync(createCesConfigTableSql, cancellationToken);
        await Database.ExecuteSqlRawAsync(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS "IX_CaAuthorities_SingleActive"
                ON "CaAuthorities" ("IsActive") WHERE "IsActive" = 1;
            CREATE UNIQUE INDEX IF NOT EXISTS "IX_PendingCaEnrollments_SingleUnfinished"
                ON "PendingCaEnrollments" ((1))
                WHERE "Status" NOT IN (5, 6);
            """,
            cancellationToken);
    }
}
