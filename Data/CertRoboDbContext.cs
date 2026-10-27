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
    }
}
