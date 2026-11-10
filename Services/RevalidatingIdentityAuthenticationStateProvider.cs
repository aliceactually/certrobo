using CertRobo.Data;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace CertRobo.Services;

/// <summary>
/// Periodically revalidates the user's SecurityStamp, disabled status, bounded OIDC session lifetime,
/// and active external group mappings inside active Blazor Server circuits so disabled accounts,
/// removed group mappings, or reset passwords lose access promptly.
/// </summary>
public sealed class RevalidatingIdentityAuthenticationStateProvider(
    ILoggerFactory loggerFactory,
    IServiceScopeFactory scopeFactory,
    IOptions<IdentityOptions> optionsAccessor,
    OidcFederationOptions? oidcOptions = null)
    : RevalidatingServerAuthenticationStateProvider(loggerFactory)
{
    private readonly IdentityOptions _options = optionsAccessor.Value;

    protected override TimeSpan RevalidationInterval =>
        TimeSpan.FromSeconds(Math.Max(1, oidcOptions?.SessionRevalidationSeconds ?? 10));

    protected override async Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authenticationState,
        CancellationToken cancellationToken)
    {
        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
        OidcFederationService? oidcService = scope.ServiceProvider.GetService<OidcFederationService>();
        if (oidcService != null)
        {
            return await oidcService.ValidateSessionPrincipalAsync(authenticationState.User, cancellationToken);
        }

        UserManager<ApplicationUser> userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        return await ValidateSecurityStampFallbackAsync(userManager, authenticationState.User);
    }

    private async Task<bool> ValidateSecurityStampFallbackAsync(
        UserManager<ApplicationUser> userManager,
        ClaimsPrincipal principal)
    {
        ApplicationUser? user = await userManager.GetUserAsync(principal);
        if (user == null || user.IsDisabled)
        {
            return false;
        }

        if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTimeOffset.UtcNow)
        {
            return false;
        }

        if (!userManager.SupportsUserSecurityStamp)
        {
            return true;
        }

        string? principalStamp = principal.FindFirstValue(_options.ClaimsIdentity.SecurityStampClaimType);
        string? userStamp = await userManager.GetSecurityStampAsync(user);
        return principalStamp == userStamp;
    }
}
