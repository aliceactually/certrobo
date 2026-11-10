using CertRobo.Data;
using CertRobo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Collections.Concurrent;

namespace CertRobo.Services;

public sealed record UserSummaryDto(
    string Id,
    string UserName,
    string? Email,
    string? DisplayName,
    bool IsDisabled,
    DateTimeOffset CreatedAtUtc,
    IReadOnlyList<string> Roles,
    IReadOnlyList<DomainPermissionRule> DirectPermissions,
    bool IsExternalAccount = false,
    string? ExternalIssuer = null,
    string? ExternalSubject = null,
    DateTimeOffset? LastExternalLoginAtUtc = null,
    IReadOnlyList<string>? SyncedExternalGroups = null,
    IReadOnlyList<DomainPermissionRule>? EffectiveGroupPermissions = null);

public sealed record ExternalGroupMappingSummaryDto(
    int Id,
    string GroupName,
    string RoleName,
    DateTimeOffset CreatedAtUtc,
    IReadOnlyList<DomainPermissionRule> DomainPermissions);

public sealed class AccountManagementService(
    UserManager<ApplicationUser> userManager,
    RoleManager<IdentityRole> roleManager,
    CertRoboDbContext dbContext,
    OidcFederationOptions? oidcOptions = null)
{
    private static readonly SemaphoreSlim BootstrapLock = new(1, 1);
    private static readonly ConcurrentDictionary<string, byte> SeededOidcConfigDatabases = new(StringComparer.Ordinal);

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

        if (oidcOptions is { GroupMappings.Count: > 0 })
        {
            string dbKey = dbContext.Database.GetDbConnection().DataSource ?? string.Empty;
            if (!string.IsNullOrEmpty(dbKey) && SeededOidcConfigDatabases.TryAdd(dbKey, 1))
            {
                foreach (ConfiguredOidcGroupMapping cfg in oidcOptions.GroupMappings)
                {
                    if (string.IsNullOrWhiteSpace(cfg.GroupName))
                    {
                        continue;
                    }

                    await SetExternalGroupRoleMappingAsync(
                        cfg.GroupName,
                        cfg.Role,
                        cfg.DomainPatterns,
                        string.IsNullOrWhiteSpace(cfg.AllowedProfileId) ? "*" : cfg.AllowedProfileId,
                        cancellationToken);
                }
            }
        }
    }

    public async Task<bool> IsBootstrapRequiredAsync(CancellationToken cancellationToken = default)
    {
        await EnsureRolesAndDefaultsAsync(cancellationToken);
        IList<ApplicationUser> admins = await userManager.GetUsersInRoleAsync(AppRoles.Administrator);
        return !admins.Any(a => !a.IsExternalAccount);
    }

    /// <summary>
    /// Atomically creates the initial local administrator account if and only if no local administrator exists yet.
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
            if (existingAdmins.Any(a => !a.IsExternalAccount))
            {
                return (false, "Initial administrator setup has already been completed.", null);
            }

            await DisambiguateCollidingExternalUserNameIfAnyAsync(userName.Trim(), cancellationToken);

            ApplicationUser user = new()
            {
                UserName = userName.Trim(),
                Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
                EmailConfirmed = true,
                IsDisabled = false,
                IsExternalAccount = false,
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
                        SubjectType = PermissionSubjectTypes.User,
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

        string trimmedUserName = userName.Trim();
        await DisambiguateCollidingExternalUserNameIfAnyAsync(trimmedUserName, cancellationToken);

        ApplicationUser user = new()
        {
            UserName = trimmedUserName,
            Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
            EmailConfirmed = true,
            IsDisabled = false,
            IsExternalAccount = false
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
                        SubjectType = PermissionSubjectTypes.User,
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

    private async Task DisambiguateCollidingExternalUserNameIfAnyAsync(string targetLocalUserName, CancellationToken cancellationToken)
    {
        string normalized = userManager.NormalizeName(targetLocalUserName);
        ApplicationUser? collidingExt = await dbContext.Users
            .FirstOrDefaultAsync(u => u.NormalizedUserName == normalized && u.IsExternalAccount, cancellationToken);
        if (collidingExt != null)
        {
            string suffix = OidcFederationService.ComputeExternalIdentityShortHash(
                collidingExt.ExternalIssuer ?? "oidc",
                collidingExt.ExternalSubject ?? collidingExt.Id);
            collidingExt.UserName = $"{OidcFederationService.SanitizeUserNameCandidate(targetLocalUserName)}+oidc.{suffix}";
            await userManager.UpdateAsync(collidingExt);
        }
    }

    /// <summary>
    /// Enables or disables a user account (local or external OIDC) and rotates their SecurityStamp + LockoutEnd
    /// so active cookies and Blazor Server circuits are invalidated.
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
    /// Administrator-initiated local kill switch for a single user account (local or external):
    /// rotates the account's SecurityStamp so active HTTP cookies and Blazor Server circuits are invalidated.
    /// </summary>
    public async Task<(bool Succeeded, string? ErrorMessage)> InvalidateUserSessionsAsync(
        string userNameOrId,
        CancellationToken cancellationToken = default)
    {
        ApplicationUser? user = await userManager.FindByIdAsync(userNameOrId)
            ?? await userManager.FindByNameAsync(userNameOrId);
        if (user == null)
        {
            return (false, $"User '{userNameOrId}' was not found.");
        }

        IdentityResult stampResult = await userManager.UpdateSecurityStampAsync(user);
        if (!stampResult.Succeeded)
        {
            return (false, string.Join("; ", stampResult.Errors.Select(e => e.Description)));
        }

        return (true, null);
    }

    /// <summary>
    /// Administrator-initiated global kill switch for all external OpenID Connect accounts:
    /// rotates SecurityStamp on every external account so all active federated sessions and Blazor circuits must re-authenticate.
    /// </summary>
    public async Task<int> InvalidateAllExternalSessionsAsync(CancellationToken cancellationToken = default)
    {
        List<ApplicationUser> externalUsers = await userManager.Users
            .Where(u => u.IsExternalAccount)
            .ToListAsync(cancellationToken);

        int count = 0;
        foreach (ApplicationUser extUser in externalUsers)
        {
            IdentityResult res = await userManager.UpdateSecurityStampAsync(extUser);
            if (res.Succeeded)
            {
                count++;
            }
        }

        return count;
    }

    /// <summary>
    /// Resets a local user's password (used by Administrator UI or CLI break-glass recovery) and rotates SecurityStamp.
    /// Refuses to set a local password on an external OIDC account.
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

        if (user.IsExternalAccount)
        {
            return (false, $"Account '{user.UserName}' is an external OpenID Connect account and cannot be assigned a local password.");
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

    public async Task<(bool Succeeded, string? ErrorMessage, ExternalGroupRoleMapping? Mapping)> SetExternalGroupRoleMappingAsync(
        string groupName,
        string roleName,
        IEnumerable<string>? initialDomainPatterns = null,
        string allowedProfileId = "*",
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(groupName))
        {
            return (false, "External group name is required.", null);
        }

        string trimmedGroup = groupName.Trim();
        if (trimmedGroup.Length > 256)
        {
            return (false, "External group name cannot exceed 256 characters.", null);
        }

        string canonicalRole;
        if (string.Equals(roleName?.Trim(), AppRoles.Administrator, StringComparison.OrdinalIgnoreCase))
        {
            canonicalRole = AppRoles.Administrator;
        }
        else if (string.Equals(roleName?.Trim(), AppRoles.Issuer, StringComparison.OrdinalIgnoreCase))
        {
            canonicalRole = AppRoles.Issuer;
        }
        else
        {
            return (false, $"Role must be '{AppRoles.Administrator}' or '{AppRoles.Issuer}'.", null);
        }

        string profile = string.IsNullOrWhiteSpace(allowedProfileId) ? "*" : allowedProfileId.Trim();
        if (profile != "*" && !CertificateProfiles.All.ContainsKey(profile))
        {
            return (false, $"Unknown certificate profile '{profile}'.", null);
        }

        List<string> canonicalDomains = [];
        if (initialDomainPatterns != null)
        {
            foreach (string rawPattern in initialDomainPatterns)
            {
                if (string.IsNullOrWhiteSpace(rawPattern))
                {
                    continue;
                }

                string canonical = DomainPolicyEvaluator.CanonicalizeDomainPatternOrIdentity(rawPattern);
                if (string.IsNullOrEmpty(canonical))
                {
                    return (false, $"Domain pattern '{rawPattern}' is invalid.", null);
                }

                if (!canonicalDomains.Contains(canonical, StringComparer.OrdinalIgnoreCase))
                {
                    canonicalDomains.Add(canonical);
                }
            }
        }

        ExternalGroupRoleMapping? existing = await dbContext.ExternalGroupRoleMappings
            .FirstOrDefaultAsync(m => m.GroupName == trimmedGroup, cancellationToken);

        if (existing == null)
        {
            existing = new ExternalGroupRoleMapping
            {
                GroupName = trimmedGroup,
                RoleName = canonicalRole,
                CreatedAtUtc = DateTimeOffset.UtcNow
            };
            dbContext.ExternalGroupRoleMappings.Add(existing);
        }
        else
        {
            existing.RoleName = canonicalRole;
        }

        foreach (string canonicalDomain in canonicalDomains)
        {
            bool ruleExists = await dbContext.DomainPermissionRules.AnyAsync(
                r => r.SubjectType == PermissionSubjectTypes.ExternalGroup
                  && r.SubjectValue == trimmedGroup
                  && r.DomainPattern == canonicalDomain
                  && r.AllowedProfileId == profile,
                cancellationToken);

            if (!ruleExists)
            {
                dbContext.DomainPermissionRules.Add(new DomainPermissionRule
                {
                    SubjectType = PermissionSubjectTypes.ExternalGroup,
                    SubjectValue = trimmedGroup,
                    DomainPattern = canonicalDomain,
                    AllowedProfileId = profile
                });
            }
        }

        await dbContext.SaveChangesAsync(cancellationToken);
        await SynchronizeExternalUsersForGroupAsync(trimmedGroup, cancellationToken);

        return (true, null, existing);
    }

    public async Task<(bool Succeeded, string? ErrorMessage)> RemoveExternalGroupRoleMappingAsync(
        int mappingId,
        CancellationToken cancellationToken = default)
    {
        ExternalGroupRoleMapping? mapping = await dbContext.ExternalGroupRoleMappings
            .FindAsync([mappingId], cancellationToken);
        if (mapping == null)
        {
            return (false, "External group mapping was not found.");
        }

        return await RemoveExternalGroupRoleMappingCoreAsync(mapping, cancellationToken);
    }

    public async Task<(bool Succeeded, string? ErrorMessage)> RemoveExternalGroupRoleMappingByNameAsync(
        string groupName,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(groupName))
        {
            return (false, "External group name is required.");
        }

        string trimmed = groupName.Trim();
        ExternalGroupRoleMapping? mapping = await dbContext.ExternalGroupRoleMappings
            .FirstOrDefaultAsync(m => m.GroupName == trimmed, cancellationToken);
        if (mapping == null)
        {
            return (false, $"External group mapping '{trimmed}' was not found.");
        }

        return await RemoveExternalGroupRoleMappingCoreAsync(mapping, cancellationToken);
    }

    private async Task<(bool Succeeded, string? ErrorMessage)> RemoveExternalGroupRoleMappingCoreAsync(
        ExternalGroupRoleMapping mapping,
        CancellationToken cancellationToken)
    {
        string groupName = mapping.GroupName;
        List<DomainPermissionRule> groupRules = await dbContext.DomainPermissionRules
            .Where(r => r.SubjectType == PermissionSubjectTypes.ExternalGroup && r.SubjectValue == groupName)
            .ToListAsync(cancellationToken);

        if (groupRules.Count > 0)
        {
            dbContext.DomainPermissionRules.RemoveRange(groupRules);
        }

        dbContext.ExternalGroupRoleMappings.Remove(mapping);
        await dbContext.SaveChangesAsync(cancellationToken);

        await SynchronizeExternalUsersForGroupAsync(groupName, cancellationToken);
        return (true, null);
    }

    public async Task<IReadOnlyList<ExternalGroupMappingSummaryDto>> ListExternalGroupMappingsAsync(
        CancellationToken cancellationToken = default)
    {
        List<ExternalGroupRoleMapping> mappings = await dbContext.ExternalGroupRoleMappings
            .AsNoTracking()
            .OrderBy(m => m.GroupName)
            .ToListAsync(cancellationToken);

        List<DomainPermissionRule> groupRules = await dbContext.DomainPermissionRules
            .AsNoTracking()
            .Where(r => r.SubjectType == PermissionSubjectTypes.ExternalGroup)
            .OrderBy(r => r.DomainPattern)
            .ToListAsync(cancellationToken);

        List<ExternalGroupMappingSummaryDto> summaries = new(mappings.Count);
        foreach (ExternalGroupRoleMapping m in mappings)
        {
            List<DomainPermissionRule> rules = groupRules
                .Where(r => string.Equals(r.SubjectValue, m.GroupName, StringComparison.Ordinal))
                .ToList();

            summaries.Add(new ExternalGroupMappingSummaryDto(
                m.Id,
                m.GroupName,
                m.RoleName,
                m.CreatedAtUtc,
                rules));
        }

        return summaries;
    }

    private async Task SynchronizeExternalUsersForGroupAsync(
        string affectedGroupName,
        CancellationToken cancellationToken)
    {
        List<ApplicationUser> externalUsers = await userManager.Users
            .Where(u => u.IsExternalAccount)
            .ToListAsync(cancellationToken);

        if (externalUsers.Count == 0)
        {
            return;
        }

        List<ExternalGroupRoleMapping> allMappings = await dbContext.ExternalGroupRoleMappings
            .AsNoTracking()
            .ToListAsync(cancellationToken);

        foreach (ApplicationUser extUser in externalUsers)
        {
            IReadOnlyList<string> userGroups = OidcFederationService.ParseSyncedGroupsJson(extUser.LastSyncedGroupsJson);
            if (!userGroups.Contains(affectedGroupName, StringComparer.Ordinal))
            {
                continue;
            }

            List<ExternalGroupRoleMapping> matched = allMappings
                .Where(m => userGroups.Contains(m.GroupName, StringComparer.Ordinal))
                .ToList();

            bool isAdmin = matched.Any(m => string.Equals(m.RoleName, AppRoles.Administrator, StringComparison.OrdinalIgnoreCase));
            bool isIssuer = isAdmin || matched.Any(m => string.Equals(m.RoleName, AppRoles.Issuer, StringComparison.OrdinalIgnoreCase));

            string[] effectiveRoles = isAdmin
                ? [AppRoles.Administrator, AppRoles.Issuer]
                : (isIssuer ? [AppRoles.Issuer] : []);

            IList<string> currentRoles = await userManager.GetRolesAsync(extUser);
            string[] toRemove = currentRoles
                .Where(r => !effectiveRoles.Contains(r, StringComparer.OrdinalIgnoreCase))
                .ToArray();
            string[] toAdd = effectiveRoles
                .Where(r => !currentRoles.Contains(r, StringComparer.OrdinalIgnoreCase))
                .ToArray();

            if (toRemove.Length > 0)
            {
                await userManager.RemoveFromRolesAsync(extUser, toRemove);
            }
            if (toAdd.Length > 0)
            {
                await userManager.AddToRolesAsync(extUser, toAdd);
            }

            // Always rotate SecurityStamp when a mapped group for this user changes so active sessions revalidate/terminate
            await userManager.UpdateSecurityStampAsync(extUser);
        }
    }

    public async Task<(bool Succeeded, string? ErrorMessage)> AddDomainPermissionAsync(
        string subjectType,
        string subjectValue,
        string domainPattern,
        string allowedProfileId = "*",
        CancellationToken cancellationToken = default)
    {
        if (subjectType != PermissionSubjectTypes.User
            && subjectType != PermissionSubjectTypes.Role
            && subjectType != PermissionSubjectTypes.ExternalGroup)
        {
            return (false, "SubjectType must be 'User', 'Role', or 'ExternalGroup'.");
        }

        if (string.IsNullOrWhiteSpace(subjectValue))
        {
            return (false, "SubjectValue is required.");
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
            string subjectType = rule.SubjectType;
            string subjectValue = rule.SubjectValue;
            dbContext.DomainPermissionRules.Remove(rule);
            await dbContext.SaveChangesAsync(cancellationToken);

            if (subjectType == PermissionSubjectTypes.ExternalGroup)
            {
                await SynchronizeExternalUsersForGroupAsync(subjectValue, cancellationToken);
            }
            else if (subjectType == PermissionSubjectTypes.User)
            {
                ApplicationUser? affectedUser = await userManager.FindByIdAsync(subjectValue);
                if (affectedUser != null)
                {
                    await userManager.UpdateSecurityStampAsync(affectedUser);
                }
            }
        }
    }

    public async Task<IReadOnlyList<UserSummaryDto>> ListUsersAsync(CancellationToken cancellationToken = default)
    {
        List<ApplicationUser> users = await userManager.Users
            .OrderBy(u => u.UserName)
            .ToListAsync(cancellationToken);

        List<DomainPermissionRule> allRules = await dbContext.DomainPermissionRules
            .AsNoTracking()
            .ToListAsync(cancellationToken);

        List<ExternalGroupRoleMapping> activeGroupMappings = await dbContext.ExternalGroupRoleMappings
            .AsNoTracking()
            .ToListAsync(cancellationToken);
        HashSet<string> activeMappedGroupNames = activeGroupMappings
            .Select(m => m.GroupName)
            .ToHashSet(StringComparer.Ordinal);

        List<UserSummaryDto> summaries = new(users.Count);
        foreach (ApplicationUser u in users)
        {
            IList<string> roles = await userManager.GetRolesAsync(u);
            List<DomainPermissionRule> directRules = allRules
                .Where(r => r.SubjectType == PermissionSubjectTypes.User && r.SubjectValue == u.Id)
                .ToList();

            IReadOnlyList<string> syncedGroups = u.IsExternalAccount
                ? OidcFederationService.ParseSyncedGroupsJson(u.LastSyncedGroupsJson)
                : [];

            List<string> activeGroupsForUser = syncedGroups
                .Where(g => activeMappedGroupNames.Contains(g))
                .ToList();

            List<DomainPermissionRule> groupRules = u.IsExternalAccount && activeGroupsForUser.Count > 0
                ? allRules
                    .Where(r => r.SubjectType == PermissionSubjectTypes.ExternalGroup
                             && activeGroupsForUser.Contains(r.SubjectValue, StringComparer.Ordinal))
                    .ToList()
                : [];

            summaries.Add(new UserSummaryDto(
                u.Id,
                u.UserName ?? string.Empty,
                u.Email,
                u.DisplayName,
                u.IsDisabled,
                u.CreatedAtUtc,
                roles.ToList(),
                directRules,
                u.IsExternalAccount,
                u.ExternalIssuer,
                u.ExternalSubject,
                u.LastExternalLoginAtUtc,
                syncedGroups,
                groupRules));
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
