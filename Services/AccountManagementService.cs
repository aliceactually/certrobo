using CertRobo.Data;
using CertRobo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

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
    IReadOnlyList<DomainPermissionRule>? EffectiveGroupPermissions = null,
    IReadOnlyList<DomainPermissionRule>? EffectiveRolePermissions = null);

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
    OidcFederationOptions? oidcOptions = null,
    OidcFederationService? oidcFederationService = null)
{
    private static readonly SemaphoreSlim AccountMutationLock = new(1, 1);

    public async Task EnsureRolesAndDefaultsAsync(CancellationToken cancellationToken = default)
    {
        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            await EnsureRolesAndDefaultsCoreAsync(cancellationToken);
        }
        finally
        {
            AccountMutationLock.Release();
        }
    }

    private async Task EnsureRolesAndDefaultsCoreAsync(CancellationToken cancellationToken)
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

        OidcPortalSettingsConfig portalSettings = await EnsureOidcPortalSettingsRowCoreAsync(cancellationToken);

        // Durable one-time seed of configured OIDC group mappings:
        // Only import from configuration when HasSeededConfiguredGroupMappings is false.
        // Once seeded (or once any group mapping / group domain rule is modified or removed via UI/CLI),
        // HasSeededConfiguredGroupMappings is persisted as true in SQLite so process restarts never resurrect
        // removed mappings, revert role changes, or restore deleted domain rules.
        if (!portalSettings.HasSeededConfiguredGroupMappings && oidcOptions is { GroupMappings.Count: > 0 })
        {
            foreach (ConfiguredOidcGroupMapping cfg in oidcOptions.GroupMappings)
            {
                if (string.IsNullOrWhiteSpace(cfg.GroupName))
                {
                    continue;
                }

                await SetExternalGroupRoleMappingCoreAsync(
                    cfg.GroupName,
                    cfg.Role,
                    cfg.DomainPatterns,
                    string.IsNullOrWhiteSpace(cfg.AllowedProfileId) ? "*" : cfg.AllowedProfileId,
                    cancellationToken);
            }

            portalSettings.HasSeededConfiguredGroupMappings = true;
            portalSettings.UpdatedAtUtc = DateTimeOffset.UtcNow;
            await dbContext.SaveChangesAsync(cancellationToken);
        }
    }

    private async Task<OidcPortalSettingsConfig> EnsureOidcPortalSettingsRowCoreAsync(CancellationToken cancellationToken)
    {
        OidcPortalSettingsConfig? existing = await dbContext.OidcPortalSettings
            .OrderBy(s => s.Id)
            .FirstOrDefaultAsync(cancellationToken);

        string configDisplayName = !string.IsNullOrWhiteSpace(oidcOptions?.DisplayName)
            ? oidcOptions!.DisplayName.Trim()
            : "OpenID Connect";
        string configDefaultMode = LoginEmphasisModes.Normalize(oidcOptions?.DefaultLoginMode);

        if (existing == null)
        {
            existing = new OidcPortalSettingsConfig
            {
                Id = 1,
                HasSeededConfiguredGroupMappings = false,
                IsCustomizedByAdmin = false,
                ProviderDisplayName = configDisplayName,
                DefaultLoginMode = configDefaultMode,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            dbContext.OidcPortalSettings.Add(existing);
            await dbContext.SaveChangesAsync(cancellationToken);
            return existing;
        }

        // If the administrator has not customized the portal display settings in SQLite,
        // keep the row synchronized with configuration defaults.
        if (!existing.IsCustomizedByAdmin && oidcOptions != null)
        {
            bool changed = false;
            if (!string.Equals(existing.ProviderDisplayName, configDisplayName, StringComparison.Ordinal))
            {
                existing.ProviderDisplayName = configDisplayName;
                changed = true;
            }
            if (!string.Equals(existing.DefaultLoginMode, configDefaultMode, StringComparison.Ordinal))
            {
                existing.DefaultLoginMode = configDefaultMode;
                changed = true;
            }
            if (changed)
            {
                await dbContext.SaveChangesAsync(cancellationToken);
            }
        }

        return existing;
    }

    private async Task MarkConfiguredGroupMappingsSeededCoreAsync(CancellationToken cancellationToken)
    {
        OidcPortalSettingsConfig portalSettings = await EnsureOidcPortalSettingsRowCoreAsync(cancellationToken);
        if (!portalSettings.HasSeededConfiguredGroupMappings)
        {
            portalSettings.HasSeededConfiguredGroupMappings = true;
            portalSettings.UpdatedAtUtc = DateTimeOffset.UtcNow;
            await dbContext.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task<OidcPortalSettingsConfig> GetOidcPortalSettingsAsync(CancellationToken cancellationToken = default)
    {
        await EnsureRolesAndDefaultsAsync(cancellationToken);
        return await dbContext.OidcPortalSettings
            .AsNoTracking()
            .OrderBy(s => s.Id)
            .FirstAsync(cancellationToken);
    }

    public async Task<(bool Succeeded, string? ErrorMessage, OidcPortalSettingsConfig? Settings)> UpdateOidcPortalSettingsAsync(
        string providerDisplayName,
        string defaultLoginMode,
        ClaimsPrincipal? actingPrincipal = null,
        CancellationToken cancellationToken = default)
    {
        string trimmedLabel = providerDisplayName?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(trimmedLabel))
        {
            return (false, "Provider display label cannot be empty.", null);
        }
        if (trimmedLabel.Length > 128)
        {
            return (false, "Provider display label cannot exceed 128 characters.", null);
        }

        string normalizedMode = LoginEmphasisModes.Normalize(defaultLoginMode);

        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            await EnsureRolesAndDefaultsCoreAsync(cancellationToken);
            var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
            if (!actorOk)
            {
                return (false, actorErr, null);
            }

            OidcPortalSettingsConfig existing = await EnsureOidcPortalSettingsRowCoreAsync(cancellationToken);
            existing.ProviderDisplayName = trimmedLabel;
            existing.DefaultLoginMode = normalizedMode;
            existing.IsCustomizedByAdmin = true;
            existing.UpdatedAtUtc = DateTimeOffset.UtcNow;
            await dbContext.SaveChangesAsync(cancellationToken);

            if (oidcOptions != null)
            {
                oidcOptions.DisplayName = trimmedLabel;
                oidcOptions.DefaultLoginMode = normalizedMode;
            }

            return (true, null, existing);
        }
        finally
        {
            AccountMutationLock.Release();
        }
    }

    /// <summary>
    /// Revalidates an acting administrator's live database state (enabled, unlocked, matching SecurityStamp,
    /// active Administrator role, and for external OIDC sessions, active group mapping to Administrator and bounded lifetime).
    /// </summary>
    public async Task<(bool IsAuthorized, string? ErrorMessage, ApplicationUser? Actor)> VerifyActiveAdministratorPrincipalAsync(
        ClaimsPrincipal? principal,
        CancellationToken cancellationToken = default)
    {
        if (principal?.Identity?.IsAuthenticated != true)
        {
            return (false, "Authorisation Error: only an active authenticated Administrator may perform this action.", null);
        }

        string? userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        ApplicationUser? actor = !string.IsNullOrWhiteSpace(userId)
            ? await dbContext.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId, cancellationToken)
            : null;

        if (actor == null && !string.IsNullOrWhiteSpace(principal.Identity?.Name))
        {
            string normalizedName = userManager.NormalizeName(principal.Identity.Name);
            actor = await dbContext.Users.AsNoTracking().FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedName, cancellationToken);
        }

        if (actor == null || actor.IsDisabled)
        {
            return (false, "Authorisation Error: the acting administrator account is disabled or does not exist.", null);
        }

        if (actor.LockoutEnd.HasValue && actor.LockoutEnd.Value > DateTimeOffset.UtcNow)
        {
            return (false, "Authorisation Error: the acting administrator account is locked out.", null);
        }

        string? principalStamp = principal.FindFirstValue("AspNet.Identity.SecurityStamp")
            ?? principal.FindFirstValue(userManager.Options.ClaimsIdentity.SecurityStampClaimType);
        if (!string.IsNullOrEmpty(principalStamp)
            && !string.Equals(principalStamp, actor.SecurityStamp, StringComparison.Ordinal))
        {
            return (false, "Authorisation Error: your administrator session has been invalidated. Please sign in again.", null);
        }

        IReadOnlyList<string> actorRoles = await GetFreshUserRoleNamesCoreAsync(actor.Id, cancellationToken);
        if (!actorRoles.Contains(AppRoles.Administrator, StringComparer.OrdinalIgnoreCase))
        {
            return (false, "Authorisation Error: the acting account no longer holds the Administrator role.", null);
        }

        bool principalIsOidc = principal.HasClaim(OidcClaimTypes.AuthMethod, OidcClaimTypes.AuthMethodOidc);
        if (actor.IsExternalAccount != principalIsOidc)
        {
            return (false, "Authorisation Error: session authentication method does not match account type.", null);
        }

        if (actor.IsExternalAccount)
        {
            if (oidcFederationService != null)
            {
                if (!await oidcFederationService.ValidateSessionPrincipalAsync(principal, cancellationToken))
                {
                    return (false, "Authorisation Error: your federated OIDC administrator session is no longer valid.", null);
                }
            }
            else
            {
                IReadOnlyList<string> syncedGroups = OidcFederationService.ParseSyncedGroupsJson(actor.LastSyncedGroupsJson);
                bool hasAdminGroup = await dbContext.ExternalGroupRoleMappings
                    .AsNoTracking()
                    .AnyAsync(
                        m => syncedGroups.Contains(m.GroupName)
                          && m.RoleName == AppRoles.Administrator,
                        cancellationToken);
                if (!hasAdminGroup)
                {
                    return (false, "Authorisation Error: your external group is no longer mapped to the Administrator role.", null);
                }
            }
        }

        return (true, null, actor);
    }

    private async Task<(bool IsAuthorized, string? ErrorMessage, ApplicationUser? Actor)> VerifyActingAdministratorIfProvidedAsync(
        ClaimsPrincipal? actingPrincipal,
        CancellationToken cancellationToken)
    {
        if (actingPrincipal == null)
        {
            return (true, null, null);
        }

        return await VerifyActiveAdministratorPrincipalAsync(actingPrincipal, cancellationToken);
    }

    /// <summary>
    /// Counts how many local accounts currently have the Administrator role, a local password hash,
    /// and are enabled and not locked out, optionally excluding a target user ID.
    /// Queries SQLite directly with AsNoTracking() so concurrent operations in other scopes are always observed.
    /// </summary>
    private async Task<int> CountActiveLocalAdministratorsWithPasswordCoreAsync(
        string? excludeUserId,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string normalizedAdminRole = roleManager.NormalizeKey(AppRoles.Administrator);
        List<string> adminRoleIds = await dbContext.Roles
            .AsNoTracking()
            .Where(r => r.NormalizedName == normalizedAdminRole || r.Name == AppRoles.Administrator)
            .Select(r => r.Id)
            .ToListAsync(cancellationToken);

        if (adminRoleIds.Count == 0)
        {
            return 0;
        }

        List<string> adminUserIds = await dbContext.UserRoles
            .AsNoTracking()
            .Where(ur => adminRoleIds.Contains(ur.RoleId))
            .Select(ur => ur.UserId)
            .Distinct()
            .ToListAsync(cancellationToken);

        if (adminUserIds.Count == 0)
        {
            return 0;
        }

        List<ApplicationUser> adminUsers = await dbContext.Users
            .AsNoTracking()
            .Where(u => adminUserIds.Contains(u.Id))
            .ToListAsync(cancellationToken);

        return adminUsers.Count(u =>
            !string.Equals(u.Id, excludeUserId, StringComparison.Ordinal)
            && !u.IsExternalAccount
            && !u.IsDisabled
            && !(u.LockoutEnabled && u.LockoutEnd.HasValue && u.LockoutEnd.Value > now)
            && !string.IsNullOrEmpty(u.PasswordHash));
    }

    public async Task<bool> IsBootstrapRequiredAsync(CancellationToken cancellationToken = default)
    {
        await EnsureRolesAndDefaultsAsync(cancellationToken);
        IList<ApplicationUser> admins = await userManager.GetUsersInRoleAsync(AppRoles.Administrator);
        return !admins.Any(a => !a.IsExternalAccount && !string.IsNullOrEmpty(a.PasswordHash));
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

        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            await EnsureRolesAndDefaultsCoreAsync(cancellationToken);

            IList<ApplicationUser> existingAdmins = await userManager.GetUsersInRoleAsync(AppRoles.Administrator);
            if (existingAdmins.Any(a => !a.IsExternalAccount && !string.IsNullOrEmpty(a.PasswordHash)))
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
            AccountMutationLock.Release();
        }
    }

    public async Task<(bool Succeeded, string? ErrorMessage, ApplicationUser? User)> CreateUserAsync(
        string userName,
        string password,
        string? email,
        IEnumerable<string> roles,
        IEnumerable<string>? allowedDomainPatterns = null,
        CancellationToken cancellationToken = default,
        ClaimsPrincipal? actingPrincipal = null)
    {
        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            await EnsureRolesAndDefaultsCoreAsync(cancellationToken);
            var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
            if (!actorOk)
            {
                return (false, actorErr, null);
            }

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
        finally
        {
            AccountMutationLock.Release();
        }
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

    private async Task<IReadOnlyList<string>> GetFreshUserRoleNamesCoreAsync(
        string userId,
        CancellationToken cancellationToken)
    {
        List<string> roleIds = await dbContext.UserRoles
            .AsNoTracking()
            .Where(ur => ur.UserId == userId)
            .Select(ur => ur.RoleId)
            .ToListAsync(cancellationToken);

        if (roleIds.Count == 0)
        {
            return [];
        }

        List<string> roleNames = await dbContext.Roles
            .AsNoTracking()
            .Where(r => roleIds.Contains(r.Id) && r.Name != null)
            .Select(r => r.Name!)
            .ToListAsync(cancellationToken);

        return roleNames;
    }

    private async Task SyncTrackedUserRolesCacheAsync(
        string userId,
        CancellationToken cancellationToken)
    {
        List<IdentityUserRole<string>> trackedUserRoles = dbContext.ChangeTracker
            .Entries<IdentityUserRole<string>>()
            .Where(e => e.Entity.UserId == userId)
            .Select(e => e.Entity)
            .ToList();

        foreach (IdentityUserRole<string> entry in trackedUserRoles)
        {
            dbContext.Entry(entry).State = EntityState.Detached;
        }

        await Task.CompletedTask;
    }

    private async Task<ApplicationUser?> FindFreshTrackedUserByIdOrNameAsync(
        string userNameOrId,
        CancellationToken cancellationToken)
    {
        ApplicationUser? tracked = await userManager.FindByIdAsync(userNameOrId)
            ?? await userManager.FindByNameAsync(userNameOrId);
        if (tracked != null)
        {
            await dbContext.Entry(tracked).ReloadAsync(cancellationToken);
            await SyncTrackedUserRolesCacheAsync(tracked.Id, cancellationToken);
        }
        return tracked;
    }

    /// <summary>
    /// Enables or disables a user account (local or external OIDC) and rotates their SecurityStamp + LockoutEnd
    /// so active cookies and Blazor Server circuits are invalidated.
    /// Enforces that at least one enabled local Administrator with a local password remains active.
    /// </summary>
    public async Task<(bool Succeeded, string? ErrorMessage)> SetUserDisabledAsync(
        string userId,
        bool isDisabled,
        CancellationToken cancellationToken = default,
        ClaimsPrincipal? actingPrincipal = null)
    {
        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
            if (!actorOk)
            {
                return (false, actorErr);
            }

            ApplicationUser? user = await FindFreshTrackedUserByIdOrNameAsync(userId, cancellationToken);
            if (user == null)
            {
                return (false, "User not found.");
            }

            if (isDisabled && !user.IsExternalAccount && await userManager.IsInRoleAsync(user, AppRoles.Administrator))
            {
                int remainingLocalAdmins = await CountActiveLocalAdministratorsWithPasswordCoreAsync(user.Id, cancellationToken);
                if (remainingLocalAdmins == 0)
                {
                    return (
                        false,
                        "Cannot disable the last active local Administrator account. CertRobo requires at least one enabled local Administrator with a local password for break-glass recovery.");
                }
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
        finally
        {
            AccountMutationLock.Release();
        }
    }

    /// <summary>
    /// Updates a local account's roles (Administrator and/or Issuer) while enforcing that at least one
    /// enabled local Administrator with a local password remains active.
    /// </summary>
    public async Task<(bool Succeeded, string? ErrorMessage)> SetLocalUserRolesAsync(
        string userId,
        IEnumerable<string> roles,
        CancellationToken cancellationToken = default,
        ClaimsPrincipal? actingPrincipal = null)
    {
        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            await EnsureRolesAndDefaultsCoreAsync(cancellationToken);
            var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
            if (!actorOk)
            {
                return (false, actorErr);
            }

            ApplicationUser? user = await FindFreshTrackedUserByIdOrNameAsync(userId, cancellationToken);
            if (user == null)
            {
                return (false, "User not found.");
            }

            if (user.IsExternalAccount)
            {
                return (false, "External OpenID Connect account roles are controlled by external group mappings.");
            }

            string[] targetRoles = (roles ?? [])
                .Where(r => r.Equals(AppRoles.Administrator, StringComparison.OrdinalIgnoreCase)
                         || r.Equals(AppRoles.Issuer, StringComparison.OrdinalIgnoreCase))
                .Select(r => r.Equals(AppRoles.Administrator, StringComparison.OrdinalIgnoreCase) ? AppRoles.Administrator : AppRoles.Issuer)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (targetRoles.Length == 0)
            {
                return (false, $"At least one valid role ('{AppRoles.Issuer}' or '{AppRoles.Administrator}') must be assigned.");
            }

            IReadOnlyList<string> currentRoles = await GetFreshUserRoleNamesCoreAsync(user.Id, cancellationToken);
            bool wasAdmin = currentRoles.Contains(AppRoles.Administrator, StringComparer.OrdinalIgnoreCase);
            bool willBeAdmin = targetRoles.Contains(AppRoles.Administrator, StringComparer.OrdinalIgnoreCase);

            if (wasAdmin && !willBeAdmin)
            {
                int remainingLocalAdmins = await CountActiveLocalAdministratorsWithPasswordCoreAsync(user.Id, cancellationToken);
                if (remainingLocalAdmins == 0)
                {
                    return (
                        false,
                        "Cannot demote the last active local Administrator account. CertRobo requires at least one enabled local Administrator with a local password for break-glass recovery.");
                }
            }

            string[] toRemove = currentRoles
                .Where(r => !targetRoles.Contains(r, StringComparer.OrdinalIgnoreCase))
                .ToArray();
            string[] toAdd = targetRoles
                .Where(r => !currentRoles.Contains(r, StringComparer.OrdinalIgnoreCase))
                .ToArray();

            if (toRemove.Length > 0)
            {
                await userManager.RemoveFromRolesAsync(user, toRemove);
            }
            if (toAdd.Length > 0)
            {
                await userManager.AddToRolesAsync(user, toAdd);
            }

            if (toRemove.Length > 0 || toAdd.Length > 0)
            {
                await userManager.UpdateSecurityStampAsync(user);
            }

            return (true, null);
        }
        finally
        {
            AccountMutationLock.Release();
        }
    }

    /// <summary>
    /// Deletes a user account while enforcing that at least one enabled local Administrator with a local password remains active.
    /// </summary>
    public async Task<(bool Succeeded, string? ErrorMessage)> DeleteUserAsync(
        string userId,
        CancellationToken cancellationToken = default,
        ClaimsPrincipal? actingPrincipal = null)
    {
        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
            if (!actorOk)
            {
                return (false, actorErr);
            }

            ApplicationUser? user = await FindFreshTrackedUserByIdOrNameAsync(userId, cancellationToken);
            if (user == null)
            {
                return (false, "User not found.");
            }

            if (!user.IsExternalAccount && await userManager.IsInRoleAsync(user, AppRoles.Administrator))
            {
                int remainingLocalAdmins = await CountActiveLocalAdministratorsWithPasswordCoreAsync(user.Id, cancellationToken);
                if (remainingLocalAdmins == 0)
                {
                    return (
                        false,
                        "Cannot delete the last active local Administrator account. CertRobo requires at least one enabled local Administrator with a local password for break-glass recovery.");
                }
            }

            List<DomainPermissionRule> directRules = await dbContext.DomainPermissionRules
                .Where(r => r.SubjectType == PermissionSubjectTypes.User && r.SubjectValue == user.Id)
                .ToListAsync(cancellationToken);
            if (directRules.Count > 0)
            {
                dbContext.DomainPermissionRules.RemoveRange(directRules);
                await dbContext.SaveChangesAsync(cancellationToken);
            }

            IdentityResult delResult = await userManager.DeleteAsync(user);
            if (!delResult.Succeeded)
            {
                return (false, string.Join("; ", delResult.Errors.Select(e => e.Description)));
            }

            return (true, null);
        }
        finally
        {
            AccountMutationLock.Release();
        }
    }

    /// <summary>
    /// Administrator-initiated local kill switch for a single user account (local or external):
    /// rotates the account's SecurityStamp so active HTTP cookies and Blazor Server circuits are invalidated.
    /// </summary>
    public async Task<(bool Succeeded, string? ErrorMessage)> InvalidateUserSessionsAsync(
        string userNameOrId,
        CancellationToken cancellationToken = default,
        ClaimsPrincipal? actingPrincipal = null)
    {
        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
            if (!actorOk)
            {
                return (false, actorErr);
            }

            ApplicationUser? user = await FindFreshTrackedUserByIdOrNameAsync(userNameOrId, cancellationToken);
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
        finally
        {
            AccountMutationLock.Release();
        }
    }

    /// <summary>
    /// Administrator-initiated global kill switch for all external OpenID Connect accounts:
    /// rotates SecurityStamp on every external account so all active federated sessions and Blazor circuits must re-authenticate.
    /// </summary>
    public async Task<int> InvalidateAllExternalSessionsAsync(
        CancellationToken cancellationToken = default,
        ClaimsPrincipal? actingPrincipal = null)
    {
        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
            if (!actorOk)
            {
                throw new UnauthorizedAccessException(actorErr);
            }

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
        finally
        {
            AccountMutationLock.Release();
        }
    }

    /// <summary>
    /// Resets a local user's password (used by Administrator UI or CLI break-glass recovery) and rotates SecurityStamp.
    /// Refuses to set a local password on an external OIDC account.
    /// When invoked without an actingPrincipal (CLI break-glass mode), bypasses interactive session checks so
    /// an OS-authorized operator can always recover a locked-out or disabled local administrator.
    /// </summary>
    public async Task<(bool Succeeded, string? ErrorMessage)> ResetPasswordAsync(
        string userNameOrId,
        string newPassword,
        CancellationToken cancellationToken = default,
        ClaimsPrincipal? actingPrincipal = null)
    {
        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
            if (!actorOk)
            {
                return (false, actorErr);
            }

            ApplicationUser? user = await FindFreshTrackedUserByIdOrNameAsync(userNameOrId, cancellationToken);

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
        finally
        {
            AccountMutationLock.Release();
        }
    }

    public async Task<(bool Succeeded, string? ErrorMessage, ExternalGroupRoleMapping? Mapping)> SetExternalGroupRoleMappingAsync(
        string groupName,
        string roleName,
        IEnumerable<string>? initialDomainPatterns = null,
        string allowedProfileId = "*",
        CancellationToken cancellationToken = default,
        ClaimsPrincipal? actingPrincipal = null)
    {
        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            await EnsureRolesAndDefaultsCoreAsync(cancellationToken);
            var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
            if (!actorOk)
            {
                return (false, actorErr, null);
            }

            var result = await SetExternalGroupRoleMappingCoreAsync(
                groupName,
                roleName,
                initialDomainPatterns,
                allowedProfileId,
                cancellationToken);
            if (result.Succeeded)
            {
                await MarkConfiguredGroupMappingsSeededCoreAsync(cancellationToken);
            }
            return result;
        }
        finally
        {
            AccountMutationLock.Release();
        }
    }

    private async Task<(bool Succeeded, string? ErrorMessage, ExternalGroupRoleMapping? Mapping)> SetExternalGroupRoleMappingCoreAsync(
        string groupName,
        string roleName,
        IEnumerable<string>? initialDomainPatterns,
        string allowedProfileId,
        CancellationToken cancellationToken)
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
        CancellationToken cancellationToken = default,
        ClaimsPrincipal? actingPrincipal = null)
    {
        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            await EnsureRolesAndDefaultsCoreAsync(cancellationToken);
            var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
            if (!actorOk)
            {
                return (false, actorErr);
            }

            ExternalGroupRoleMapping? mapping = await dbContext.ExternalGroupRoleMappings
                .FindAsync([mappingId], cancellationToken);
            if (mapping == null)
            {
                return (false, "External group mapping was not found.");
            }

            return await RemoveExternalGroupRoleMappingCoreAsync(mapping, cancellationToken);
        }
        finally
        {
            AccountMutationLock.Release();
        }
    }

    public async Task<(bool Succeeded, string? ErrorMessage)> RemoveExternalGroupRoleMappingByNameAsync(
        string groupName,
        CancellationToken cancellationToken = default,
        ClaimsPrincipal? actingPrincipal = null)
    {
        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            await EnsureRolesAndDefaultsCoreAsync(cancellationToken);
            var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
            if (!actorOk)
            {
                return (false, actorErr);
            }

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
        finally
        {
            AccountMutationLock.Release();
        }
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
        await MarkConfiguredGroupMappingsSeededCoreAsync(cancellationToken);

        await SynchronizeExternalUsersForGroupAsync(groupName, cancellationToken);
        return (true, null);
    }

    public async Task<IReadOnlyList<ExternalGroupMappingSummaryDto>> ListExternalGroupMappingsAsync(
        CancellationToken cancellationToken = default)
    {
        await EnsureRolesAndDefaultsAsync(cancellationToken);

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
        CancellationToken cancellationToken = default,
        ClaimsPrincipal? actingPrincipal = null)
    {
        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            await EnsureRolesAndDefaultsCoreAsync(cancellationToken);
            var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
            if (!actorOk)
            {
                return (false, actorErr);
            }

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

            if (subjectType == PermissionSubjectTypes.ExternalGroup)
            {
                await MarkConfiguredGroupMappingsSeededCoreAsync(cancellationToken);
            }

            return (true, null);
        }
        finally
        {
            AccountMutationLock.Release();
        }
    }

    public async Task<(bool Succeeded, string? ErrorMessage)> RemoveDomainPermissionAsync(
        int ruleId,
        CancellationToken cancellationToken = default,
        ClaimsPrincipal? actingPrincipal = null)
    {
        await AccountMutationLock.WaitAsync(cancellationToken);
        try
        {
            await EnsureRolesAndDefaultsCoreAsync(cancellationToken);
            var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
            if (!actorOk)
            {
                return (false, actorErr);
            }

            DomainPermissionRule? rule = await dbContext.DomainPermissionRules.FindAsync([ruleId], cancellationToken);
            if (rule != null)
            {
                string subjectType = rule.SubjectType;
                string subjectValue = rule.SubjectValue;
                dbContext.DomainPermissionRules.Remove(rule);
                await dbContext.SaveChangesAsync(cancellationToken);

                if (subjectType == PermissionSubjectTypes.ExternalGroup)
                {
                    await MarkConfiguredGroupMappingsSeededCoreAsync(cancellationToken);
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

            return (true, null);
        }
        finally
        {
            AccountMutationLock.Release();
        }
    }

    public async Task<IReadOnlyList<UserSummaryDto>> ListUsersAsync(CancellationToken cancellationToken = default)
    {
        await EnsureRolesAndDefaultsAsync(cancellationToken);

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

            // Ordinary Role rules apply ONLY to local accounts, never to external OIDC accounts
            List<DomainPermissionRule> roleRules = !u.IsExternalAccount && roles.Count > 0
                ? allRules
                    .Where(r => r.SubjectType == PermissionSubjectTypes.Role
                             && roles.Contains(r.SubjectValue, StringComparer.OrdinalIgnoreCase))
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
                groupRules,
                roleRules));
        }

        return summaries;
    }

    public async Task<SubjectDefaultsConfig> GetSubjectDefaultsAsync(CancellationToken cancellationToken = default)
    {
        await EnsureRolesAndDefaultsAsync(cancellationToken);
        return await dbContext.SubjectDefaults.OrderBy(s => s.Id).FirstAsync(cancellationToken);
    }

    public async Task<(bool Succeeded, string? ErrorMessage)> UpdateSubjectDefaultsAsync(
        SubjectDefaultsConfig updated,
        CancellationToken cancellationToken = default,
        ClaimsPrincipal? actingPrincipal = null)
    {
        var (actorOk, actorErr, _) = await VerifyActingAdministratorIfProvidedAsync(actingPrincipal, cancellationToken);
        if (!actorOk)
        {
            return (false, actorErr);
        }

        SubjectDefaultsConfig existing = await GetSubjectDefaultsAsync(cancellationToken);
        existing.Country = updated.Country.Trim().ToUpperInvariant();
        existing.StateOrProvince = updated.StateOrProvince.Trim();
        existing.Locality = updated.Locality.Trim();
        existing.Organisation = updated.Organisation.Trim();
        existing.OrganisationalUnit = updated.OrganisationalUnit.Trim();
        existing.EmailAddress = updated.EmailAddress.Trim();
        await dbContext.SaveChangesAsync(cancellationToken);
        return (true, null);
    }
}
