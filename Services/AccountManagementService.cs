using CertRobo.Data;
using CertRobo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace CertRobo.Services;

public sealed record UserSummaryDto(
    string Id,
    string UserName,
    string? Email,
    string? DisplayName,
    bool IsDisabled,
    DateTimeOffset CreatedAtUtc,
    IReadOnlyList<string> Roles,
    IReadOnlyList<DomainPermissionRule> DirectPermissions);

public sealed class AccountManagementService(
    UserManager<ApplicationUser> userManager,
    RoleManager<IdentityRole> roleManager,
    CertRoboDbContext dbContext)
{
    private static readonly SemaphoreSlim BootstrapLock = new(1, 1);

    public async Task EnsureRolesAndDefaultsAsync(CancellationToken cancellationToken = default)
    {
        foreach (string role in new[] { AppRoles.Administrator, AppRoles.Issuer })
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
            }
        }

        if (!await dbContext.SubjectDefaults.AnyAsync(cancellationToken))
        {
            dbContext.SubjectDefaults.Add(new SubjectDefaultsConfig
            {
                Id = 1,
                Country = "US",
                StateOrProvince = "Washington",
                Locality = "Redmond",
                Organisation = "Contoso Corporation",
                OrganisationalUnit = "IT",
                EmailAddress = "it@contoso.com"
            });
            await dbContext.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task<bool> IsBootstrapRequiredAsync(CancellationToken cancellationToken = default)
    {
        await EnsureRolesAndDefaultsAsync(cancellationToken);
        IList<ApplicationUser> admins = await userManager.GetUsersInRoleAsync(AppRoles.Administrator);
        return admins.Count == 0;
    }

    /// <summary>
    /// Atomically creates the initial administrator account if and only if no administrator exists yet.
    /// Protects against concurrent or repeated bootstrap attempts.
    /// </summary>
    public async Task<(bool Succeeded, string? ErrorMessage, ApplicationUser? User)> BootstrapFirstAdminAsync(
        string userName,
        string password,
        string? email = null,
        string? initialAllowedDomainPattern = "*",
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
        {
            return (false, "Username and password are required.", null);
        }

        await BootstrapLock.WaitAsync(cancellationToken);
        try
        {
            await EnsureRolesAndDefaultsAsync(cancellationToken);

            IList<ApplicationUser> existingAdmins = await userManager.GetUsersInRoleAsync(AppRoles.Administrator);
            if (existingAdmins.Count > 0)
            {
                return (false, "Initial administrator setup has already been completed.", null);
            }

            ApplicationUser user = new()
            {
                UserName = userName.Trim(),
                Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
                EmailConfirmed = true,
                IsDisabled = false,
                DisplayName = "Initial Administrator"
            };

            IdentityResult createResult = await userManager.CreateAsync(user, password);
            if (!createResult.Succeeded)
            {
                return (false, string.Join("; ", createResult.Errors.Select(e => e.Description)), null);
            }

            await userManager.AddToRolesAsync(user, [AppRoles.Administrator, AppRoles.Issuer]);

            if (!string.IsNullOrWhiteSpace(initialAllowedDomainPattern))
            {
                string canonical = DomainPolicyEvaluator.CanonicalizeDomainPatternOrIdentity(initialAllowedDomainPattern);
                if (!string.IsNullOrEmpty(canonical))
                {
                    dbContext.DomainPermissionRules.Add(new DomainPermissionRule
                    {
                        SubjectType = "User",
                        SubjectValue = user.Id,
                        DomainPattern = canonical,
                        AllowedProfileId = "*"
                    });
                    await dbContext.SaveChangesAsync(cancellationToken);
                }
            }

            return (true, null, user);
        }
        finally
        {
            BootstrapLock.Release();
        }
    }

    public async Task<(bool Succeeded, string? ErrorMessage, ApplicationUser? User)> CreateUserAsync(
        string userName,
        string password,
        string? email,
        IEnumerable<string> roles,
        IEnumerable<string>? allowedDomainPatterns = null,
        CancellationToken cancellationToken = default)
    {
        await EnsureRolesAndDefaultsAsync(cancellationToken);

        ApplicationUser user = new()
        {
            UserName = userName.Trim(),
            Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
            EmailConfirmed = true,
            IsDisabled = false
        };

        IdentityResult createResult = await userManager.CreateAsync(user, password);
        if (!createResult.Succeeded)
        {
            return (false, string.Join("; ", createResult.Errors.Select(e => e.Description)), null);
        }

        string[] validRoles = roles
            .Where(r => r.Equals(AppRoles.Administrator, StringComparison.OrdinalIgnoreCase)
                     || r.Equals(AppRoles.Issuer, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (validRoles.Length > 0)
        {
            await userManager.AddToRolesAsync(user, validRoles);
        }

        if (allowedDomainPatterns != null)
        {
            foreach (string rawPattern in allowedDomainPatterns)
            {
                string canonical = DomainPolicyEvaluator.CanonicalizeDomainPatternOrIdentity(rawPattern);
                if (!string.IsNullOrEmpty(canonical))
                {
                    dbContext.DomainPermissionRules.Add(new DomainPermissionRule
                    {
                        SubjectType = "User",
                        SubjectValue = user.Id,
                        DomainPattern = canonical,
                        AllowedProfileId = "*"
                    });
                }
            }
            await dbContext.SaveChangesAsync(cancellationToken);
        }

        return (true, null, user);
    }

    /// <summary>
    /// Enables or disables a user account and rotates their SecurityStamp + LockoutEnd so active cookies/circuits are invalidated.
    /// </summary>
    public async Task<(bool Succeeded, string? ErrorMessage)> SetUserDisabledAsync(
        string userId,
        bool isDisabled,
        CancellationToken cancellationToken = default)
    {
        ApplicationUser? user = await userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return (false, "User not found.");
        }

        user.IsDisabled = isDisabled;
        user.LockoutEnabled = true;
        user.LockoutEnd = isDisabled ? DateTimeOffset.MaxValue : null;

        IdentityResult updateResult = await userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
        {
            return (false, string.Join("; ", updateResult.Errors.Select(e => e.Description)));
        }

        await userManager.UpdateSecurityStampAsync(user);
        return (true, null);
    }

    /// <summary>
    /// Resets a user's password (used by Administrator UI or CLI break-glass recovery) and rotates SecurityStamp.
    /// </summary>
    public async Task<(bool Succeeded, string? ErrorMessage)> ResetPasswordAsync(
        string userNameOrId,
        string newPassword,
        CancellationToken cancellationToken = default)
    {
        ApplicationUser? user = await userManager.FindByIdAsync(userNameOrId)
            ?? await userManager.FindByNameAsync(userNameOrId);

        if (user == null)
        {
            return (false, $"User '{userNameOrId}' was not found.");
        }

        string resetToken = await userManager.GeneratePasswordResetTokenAsync(user);
        IdentityResult resetResult = await userManager.ResetPasswordAsync(user, resetToken, newPassword);
        if (!resetResult.Succeeded)
        {
            return (false, string.Join("; ", resetResult.Errors.Select(e => e.Description)));
        }

        if (user.IsDisabled)
        {
            user.IsDisabled = false;
        }
        user.LockoutEnd = null;
        await userManager.UpdateAsync(user);
        await userManager.UpdateSecurityStampAsync(user);
        return (true, null);
    }

    public async Task<(bool Succeeded, string? ErrorMessage)> AddDomainPermissionAsync(
        string subjectType,
        string subjectValue,
        string domainPattern,
        string allowedProfileId = "*",
        CancellationToken cancellationToken = default)
    {
        if (subjectType != "User" && subjectType != "Role")
        {
            return (false, "SubjectType must be 'User' or 'Role'.");
        }

        string canonicalPattern = DomainPolicyEvaluator.CanonicalizeDomainPatternOrIdentity(domainPattern);
        if (string.IsNullOrEmpty(canonicalPattern))
        {
            return (false, "Domain pattern is invalid.");
        }

        if (allowedProfileId != "*" && !CertificateProfiles.All.ContainsKey(allowedProfileId))
        {
            return (false, $"Unknown certificate profile '{allowedProfileId}'.");
        }

        bool exists = await dbContext.DomainPermissionRules.AnyAsync(
            r => r.SubjectType == subjectType
              && r.SubjectValue == subjectValue
              && r.DomainPattern == canonicalPattern
              && r.AllowedProfileId == allowedProfileId,
            cancellationToken);

        if (!exists)
        {
            dbContext.DomainPermissionRules.Add(new DomainPermissionRule
            {
                SubjectType = subjectType,
                SubjectValue = subjectValue,
                DomainPattern = canonicalPattern,
                AllowedProfileId = allowedProfileId
            });
            await dbContext.SaveChangesAsync(cancellationToken);
        }

        return (true, null);
    }

    public async Task RemoveDomainPermissionAsync(int ruleId, CancellationToken cancellationToken = default)
    {
        DomainPermissionRule? rule = await dbContext.DomainPermissionRules.FindAsync([ruleId], cancellationToken);
        if (rule != null)
        {
            dbContext.DomainPermissionRules.Remove(rule);
            await dbContext.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task<IReadOnlyList<UserSummaryDto>> ListUsersAsync(CancellationToken cancellationToken = default)
    {
        List<ApplicationUser> users = await userManager.Users
            .OrderBy(u => u.UserName)
            .ToListAsync(cancellationToken);

        List<DomainPermissionRule> allUserRules = await dbContext.DomainPermissionRules
            .Where(r => r.SubjectType == "User")
            .ToListAsync(cancellationToken);

        List<UserSummaryDto> summaries = new(users.Count);
        foreach (ApplicationUser u in users)
        {
            IList<string> roles = await userManager.GetRolesAsync(u);
            List<DomainPermissionRule> rules = allUserRules.Where(r => r.SubjectValue == u.Id).ToList();
            summaries.Add(new UserSummaryDto(
                u.Id,
                u.UserName ?? string.Empty,
                u.Email,
                u.DisplayName,
                u.IsDisabled,
                u.CreatedAtUtc,
                roles.ToList(),
                rules));
        }

        return summaries;
    }

    public async Task<SubjectDefaultsConfig> GetSubjectDefaultsAsync(CancellationToken cancellationToken = default)
    {
        await EnsureRolesAndDefaultsAsync(cancellationToken);
        return await dbContext.SubjectDefaults.OrderBy(s => s.Id).FirstAsync(cancellationToken);
    }

    public async Task UpdateSubjectDefaultsAsync(SubjectDefaultsConfig updated, CancellationToken cancellationToken = default)
    {
        SubjectDefaultsConfig existing = await GetSubjectDefaultsAsync(cancellationToken);
        existing.Country = updated.Country.Trim().ToUpperInvariant();
        existing.StateOrProvince = updated.StateOrProvince.Trim();
        existing.Locality = updated.Locality.Trim();
        existing.Organisation = updated.Organisation.Trim();
        existing.OrganisationalUnit = updated.OrganisationalUnit.Trim();
        existing.EmailAddress = updated.EmailAddress.Trim();
        await dbContext.SaveChangesAsync(cancellationToken);
    }
}
