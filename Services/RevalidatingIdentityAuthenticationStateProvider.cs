using CertRobo.Data;
using CertRobo.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace CertRobo.Services;

/// <summary>
/// Periodically revalidates the user's SecurityStamp and disabled status inside active Blazor Server circuits
/// so disabled accounts or reset passwords lose access promptly.
/// </summary>
public sealed class RevalidatingIdentityAuthenticationStateProvider(
    ILoggerFactory loggerFactory,
    IServiceScopeFactory scopeFactory,
    IOptions<IdentityOptions> optionsAccessor)
    : RevalidatingServerAuthenticationStateProvider(loggerFactory)
{
    private readonly IdentityOptions _options = optionsAccessor.Value;

    protected override TimeSpan RevalidationInterval => TimeSpan.FromSeconds(10);

    protected override async Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authenticationState,
        CancellationToken cancellationToken)
    {
        await using AsyncServiceScope scope = scopeFactory.CreateAsyncScope();
        UserManager<ApplicationUser> userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        return await ValidateSecurityStampAsync(userManager, authenticationState.User);
    }

    private async Task<bool> ValidateSecurityStampAsync(
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
