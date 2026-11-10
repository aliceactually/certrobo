using CertRobo.Data;
using CertRobo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CertRobo.Services;

public static class OidcConstants
{
    public const string AuthenticationScheme = "OpenIdConnect";
}

public sealed class MultiValueJsonClaimAction(string claimType)
    : Microsoft.AspNetCore.Authentication.OAuth.Claims.ClaimAction(claimType, ClaimValueTypes.String)
{
    public override void Run(JsonElement userData, ClaimsIdentity identity, string issuer)
    {
        if (userData.ValueKind != JsonValueKind.Object
            || !userData.TryGetProperty(ClaimType, out JsonElement prop))
        {
            return;
        }

        if (prop.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in prop.EnumerateArray())
            {
                string? val = item.ValueKind == JsonValueKind.String ? item.GetString() : item.ToString();
                if (!string.IsNullOrWhiteSpace(val) && !identity.HasClaim(ClaimType, val))
                {
                    identity.AddClaim(new Claim(ClaimType, val, ValueType, issuer));
                }
            }
        }
        else if (prop.ValueKind == JsonValueKind.String)
        {
            string? val = prop.GetString();
            if (!string.IsNullOrWhiteSpace(val) && !identity.HasClaim(ClaimType, val))
            {
                identity.AddClaim(new Claim(ClaimType, val, ValueType, issuer));
            }
        }
    }
}

public static class OidcClaimTypes
{
    public const string AuthMethod = "certrobo:auth_method";
    public const string AuthMethodOidc = "oidc";
    public const string AuthMethodLocal = "local";
    public const string OidcIssuer = "certrobo:oidc_issuer";
    public const string OidcSubject = "certrobo:oidc_subject";
    public const string OidcAuthTimeUtc = "certrobo:oidc_auth_time_utc";
    public const string OidcGroup = "certrobo:oidc_group";
}

public sealed class ConfiguredOidcGroupMapping
{
    public string GroupName { get; set; } = string.Empty;
    public string Role { get; set; } = AppRoles.Issuer;
    public List<string> DomainPatterns { get; set; } = [];
    public string AllowedProfileId { get; set; } = "*";
}

public sealed class ReverseProxyOptions
{
    public List<string> KnownProxies { get; set; } = ["127.0.0.1", "::1"];
    public List<string> KnownNetworks { get; set; } = [];
    public int ForwardLimit { get; set; } = 1;

    public static ReverseProxyOptions FromConfiguration(IConfiguration configuration)
    {
        ReverseProxyOptions opts = new();
        IConfigurationSection section = configuration.GetSection("CertRobo:ReverseProxy");
        if (!section.Exists())
        {
            return opts;
        }

        if (int.TryParse(section["ForwardLimit"], out int limit) && limit >= 1)
        {
            opts.ForwardLimit = limit;
        }

        List<string> proxies = ParseStringList(section.GetSection("KnownProxies"), section["KnownProxies"]);
        if (proxies.Count > 0)
        {
            opts.KnownProxies = proxies;
        }

        List<string> networks = ParseStringList(section.GetSection("KnownNetworks"), section["KnownNetworks"]);
        if (networks.Count > 0)
        {
            opts.KnownNetworks = networks;
        }

        return opts;
    }

    internal static List<string> ParseStringList(IConfigurationSection section, string? scalarValue)
    {
        List<string> items = [];
        foreach (IConfigurationSection child in section.GetChildren())
        {
            if (!string.IsNullOrWhiteSpace(child.Value))
            {
                foreach (string part in child.Value.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (!items.Contains(part, StringComparer.OrdinalIgnoreCase))
                    {
                        items.Add(part);
                    }
                }
            }
        }

        if (items.Count == 0 && !string.IsNullOrWhiteSpace(scalarValue))
        {
            foreach (string part in scalarValue.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!items.Contains(part, StringComparer.OrdinalIgnoreCase))
                {
                    items.Add(part);
                }
            }
        }

        return items;
    }
}

public sealed class OidcFederationOptions
{
    public bool Enabled { get; set; }
    public string DisplayName { get; set; } = "OpenID Connect";
    public string Issuer { get; set; } = string.Empty;
    public string Authority { get; set; } = string.Empty;
    public string? MetadataAddress { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string? ClientSecret { get; set; }
    public string? ClientSecretFile { get; set; }
    public string ClientSecretEnvironmentVariable { get; set; } = "CERTROBO_OIDC_CLIENT_SECRET";
    public string PublicCallbackUrl { get; set; } = string.Empty;
    public string SignedOutCallbackPath { get; set; } = "/signout-callback-oidc";
    public bool EnableIdpSignOut { get; set; }
    public bool GetClaimsFromUserInfoEndpoint { get; set; }
    public string GroupClaimType { get; set; } = "groups";
    public string SubjectClaimType { get; set; } = "sub";
    public string PreferredUsernameClaimType { get; set; } = "preferred_username";
    public string EmailClaimType { get; set; } = "email";
    public string DisplayNameClaimType { get; set; } = "name";
    public List<string> Scopes { get; set; } = ["openid", "profile", "email"];
    public int MaxSessionLifetimeMinutes { get; set; } = 60;
    public int SessionRevalidationSeconds { get; set; } = 10;
    public List<ConfiguredOidcGroupMapping> GroupMappings { get; set; } = [];

    /// <summary>
    /// Optional backchannel handler used by local OIDC test fixtures to serve signed discovery/JWKS/token responses in-memory over HTTPS.
    /// </summary>
    public HttpMessageHandler? BackchannelHttpHandler { get; set; }

    public string EffectiveIssuer =>
        !string.IsNullOrWhiteSpace(Issuer) ? Issuer.Trim() : Authority.Trim();

    public string EffectiveAuthority =>
        !string.IsNullOrWhiteSpace(Authority) ? Authority.Trim() : Issuer.Trim();

    public string EffectiveCallbackPath
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(PublicCallbackUrl)
                && Uri.TryCreate(PublicCallbackUrl.Trim(), UriKind.Absolute, out Uri? parsed)
                && !string.IsNullOrWhiteSpace(parsed.AbsolutePath)
                && parsed.AbsolutePath != "/")
            {
                return parsed.AbsolutePath;
            }

            return "/signin-oidc";
        }
    }

    public string? ResolveEffectiveClientSecret()
    {
        if (!string.IsNullOrWhiteSpace(ClientSecretEnvironmentVariable))
        {
            string? envVal = Environment.GetEnvironmentVariable(ClientSecretEnvironmentVariable);
            if (!string.IsNullOrWhiteSpace(envVal))
            {
                return envVal.Trim();
            }
        }

        if (!string.IsNullOrWhiteSpace(ClientSecretFile) && File.Exists(ClientSecretFile))
        {
            try
            {
                string fileVal = File.ReadAllText(ClientSecretFile).Trim();
                if (!string.IsNullOrEmpty(fileVal))
                {
                    return fileVal;
                }
            }
            catch
            {
            }
        }

        return string.IsNullOrWhiteSpace(ClientSecret) ? null : ClientSecret.Trim();
    }

    public string DescribeSecretSource()
    {
        if (!string.IsNullOrWhiteSpace(ClientSecretEnvironmentVariable)
            && !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(ClientSecretEnvironmentVariable)))
        {
            return $"Environment ({ClientSecretEnvironmentVariable})";
        }

        if (!string.IsNullOrWhiteSpace(ClientSecretFile) && File.Exists(ClientSecretFile))
        {
            return $"File ({ClientSecretFile})";
        }

        if (!string.IsNullOrWhiteSpace(ClientSecret))
        {
            return "Configuration (CertRobo:Oidc:ClientSecret)";
        }

        return "Not configured";
    }

    public (bool IsValid, string? ErrorMessage) Validate()
    {
        if (!Enabled)
        {
            return (true, null);
        }

        string issuer = EffectiveIssuer;
        if (string.IsNullOrWhiteSpace(issuer)
            || !Uri.TryCreate(issuer, UriKind.Absolute, out Uri? issuerUri)
            || !string.Equals(issuerUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(issuerUri.Query)
            || !string.IsNullOrEmpty(issuerUri.Fragment))
        {
            return (false, "OIDC Issuer must be a valid https:// URL without query or fragment parameters.");
        }

        string authority = EffectiveAuthority;
        if (string.IsNullOrWhiteSpace(authority)
            || !Uri.TryCreate(authority, UriKind.Absolute, out Uri? authorityUri)
            || !string.Equals(authorityUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(authorityUri.Query)
            || !string.IsNullOrEmpty(authorityUri.Fragment))
        {
            return (false, "OIDC Authority must be a valid https:// URL without query or fragment parameters.");
        }

        if (!string.IsNullOrWhiteSpace(MetadataAddress))
        {
            if (!Uri.TryCreate(MetadataAddress.Trim(), UriKind.Absolute, out Uri? metaUri)
                || !string.Equals(metaUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                return (false, "OIDC MetadataAddress must be a valid https:// URL.");
            }
        }

        if (string.IsNullOrWhiteSpace(ClientId))
        {
            return (false, "OIDC ClientId is required when OIDC is enabled.");
        }

        if (string.IsNullOrWhiteSpace(ResolveEffectiveClientSecret()))
        {
            return (false, "OIDC ClientSecret is required (via CERTROBO_OIDC_CLIENT_SECRET, ClientSecretFile, or ClientSecret) when OIDC is enabled.");
        }

        if (string.IsNullOrWhiteSpace(PublicCallbackUrl)
            || !Uri.TryCreate(PublicCallbackUrl.Trim(), UriKind.Absolute, out Uri? callbackUri)
            || !string.Equals(callbackUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(callbackUri.AbsolutePath)
            || callbackUri.AbsolutePath == "/"
            || !string.IsNullOrEmpty(callbackUri.Query)
            || !string.IsNullOrEmpty(callbackUri.Fragment))
        {
            return (false, "OIDC PublicCallbackUrl must be an explicit https:// callback URL with a dedicated path (for example, https://pki.contoso.com/signin-oidc).");
        }

        if (string.IsNullOrWhiteSpace(GroupClaimType))
        {
            return (false, "OIDC GroupClaimType cannot be empty.");
        }

        if (string.IsNullOrWhiteSpace(SubjectClaimType))
        {
            return (false, "OIDC SubjectClaimType cannot be empty.");
        }

        if (MaxSessionLifetimeMinutes < 1 || MaxSessionLifetimeMinutes > 1440)
        {
            return (false, "OIDC MaxSessionLifetimeMinutes must be between 1 and 1440 minutes.");
        }

        foreach (ConfiguredOidcGroupMapping mapping in GroupMappings)
        {
            if (string.IsNullOrWhiteSpace(mapping.GroupName))
            {
                return (false, "Configured OIDC GroupMappings cannot contain an empty GroupName.");
            }

            if (!string.Equals(mapping.Role, AppRoles.Administrator, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(mapping.Role, AppRoles.Issuer, StringComparison.OrdinalIgnoreCase))
            {
                return (false, $"Configured OIDC group '{mapping.GroupName}' specifies unsupported role '{mapping.Role}'. Allowed roles are '{AppRoles.Administrator}' and '{AppRoles.Issuer}'.");
            }

            string profileId = string.IsNullOrWhiteSpace(mapping.AllowedProfileId) ? "*" : mapping.AllowedProfileId.Trim();
            if (profileId != "*" && !CertificateProfiles.All.ContainsKey(profileId))
            {
                return (false, $"Configured OIDC group '{mapping.GroupName}' specifies unknown certificate profile '{profileId}'.");
            }

            foreach (string rawPattern in mapping.DomainPatterns)
            {
                if (string.IsNullOrWhiteSpace(DomainPolicyEvaluator.CanonicalizeDomainPatternOrIdentity(rawPattern)))
                {
                    return (false, $"Configured OIDC group '{mapping.GroupName}' specifies invalid domain pattern '{rawPattern}'.");
                }
            }
        }

        return (true, null);
    }

    public static OidcFederationOptions FromConfiguration(IConfiguration configuration)
    {
        OidcFederationOptions opts = new();
        IConfigurationSection section = configuration.GetSection("CertRobo:Oidc");
        if (!section.Exists())
        {
            return opts;
        }

        if (bool.TryParse(section["Enabled"], out bool enabled))
        {
            opts.Enabled = enabled;
        }

        if (!string.IsNullOrWhiteSpace(section["DisplayName"]))
        {
            opts.DisplayName = section["DisplayName"]!.Trim();
        }

        if (!string.IsNullOrWhiteSpace(section["Issuer"]))
        {
            opts.Issuer = section["Issuer"]!.Trim();
        }

        if (!string.IsNullOrWhiteSpace(section["Authority"]))
        {
            opts.Authority = section["Authority"]!.Trim();
        }

        if (!string.IsNullOrWhiteSpace(section["MetadataAddress"]))
        {
            opts.MetadataAddress = section["MetadataAddress"]!.Trim();
        }

        if (!string.IsNullOrWhiteSpace(section["ClientId"]))
        {
            opts.ClientId = section["ClientId"]!.Trim();
        }

        if (!string.IsNullOrWhiteSpace(section["ClientSecret"]))
        {
            opts.ClientSecret = section["ClientSecret"]!.Trim();
        }

        if (!string.IsNullOrWhiteSpace(section["ClientSecretFile"]))
        {
            opts.ClientSecretFile = section["ClientSecretFile"]!.Trim();
        }

        if (!string.IsNullOrWhiteSpace(section["ClientSecretEnv"]))
        {
            opts.ClientSecretEnvironmentVariable = section["ClientSecretEnv"]!.Trim();
        }
        else if (!string.IsNullOrWhiteSpace(section["ClientSecretEnvironmentVariable"]))
        {
            opts.ClientSecretEnvironmentVariable = section["ClientSecretEnvironmentVariable"]!.Trim();
        }

        if (!string.IsNullOrWhiteSpace(section["PublicCallbackUrl"]))
        {
            opts.PublicCallbackUrl = section["PublicCallbackUrl"]!.Trim();
        }

        if (!string.IsNullOrWhiteSpace(section["SignedOutCallbackPath"]))
        {
            string signedOutPath = section["SignedOutCallbackPath"]!.Trim();
            opts.SignedOutCallbackPath = signedOutPath.StartsWith('/') ? signedOutPath : "/" + signedOutPath;
        }

        if (bool.TryParse(section["EnableIdpSignOut"], out bool idpSignOut))
        {
            opts.EnableIdpSignOut = idpSignOut;
        }

        if (bool.TryParse(section["GetClaimsFromUserInfoEndpoint"], out bool getUserInfo))
        {
            opts.GetClaimsFromUserInfoEndpoint = getUserInfo;
        }

        if (!string.IsNullOrWhiteSpace(section["GroupClaimType"]))
        {
            opts.GroupClaimType = section["GroupClaimType"]!.Trim();
        }

        if (!string.IsNullOrWhiteSpace(section["SubjectClaimType"]))
        {
            opts.SubjectClaimType = section["SubjectClaimType"]!.Trim();
        }

        if (!string.IsNullOrWhiteSpace(section["PreferredUsernameClaimType"]))
        {
            opts.PreferredUsernameClaimType = section["PreferredUsernameClaimType"]!.Trim();
        }

        if (!string.IsNullOrWhiteSpace(section["EmailClaimType"]))
        {
            opts.EmailClaimType = section["EmailClaimType"]!.Trim();
        }

        if (!string.IsNullOrWhiteSpace(section["DisplayNameClaimType"]))
        {
            opts.DisplayNameClaimType = section["DisplayNameClaimType"]!.Trim();
        }

        if (int.TryParse(section["MaxSessionLifetimeMinutes"], out int maxMins))
        {
            opts.MaxSessionLifetimeMinutes = maxMins;
        }

        if (int.TryParse(section["SessionRevalidationSeconds"], out int revalSecs) && revalSecs >= 0)
        {
            opts.SessionRevalidationSeconds = revalSecs;
        }

        List<string> configuredScopes = ParseScopes(section.GetSection("Scopes"), section["Scopes"]);
        if (configuredScopes.Count > 0)
        {
            if (!configuredScopes.Contains("openid", StringComparer.Ordinal))
            {
                configuredScopes.Insert(0, "openid");
            }
            opts.Scopes = configuredScopes;
        }

        opts.GroupMappings = ParseGroupMappings(section.GetSection("GroupMappings"), section["GroupMappingsSpec"] ?? section["GroupMappings"]);
        return opts;
    }

    private static List<string> ParseScopes(IConfigurationSection scopesSection, string? scalarScopes)
    {
        List<string> scopes = [];
        foreach (IConfigurationSection child in scopesSection.GetChildren())
        {
            if (!string.IsNullOrWhiteSpace(child.Value))
            {
                foreach (string s in child.Value.Split([' ', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (!scopes.Contains(s, StringComparer.Ordinal))
                    {
                        scopes.Add(s);
                    }
                }
            }
        }

        if (scopes.Count == 0 && !string.IsNullOrWhiteSpace(scalarScopes))
        {
            foreach (string s in scalarScopes.Split([' ', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!scopes.Contains(s, StringComparer.Ordinal))
                {
                    scopes.Add(s);
                }
            }
        }

        return scopes;
    }

    private static List<ConfiguredOidcGroupMapping> ParseGroupMappings(IConfigurationSection mappingsSection, string? specText)
    {
        List<ConfiguredOidcGroupMapping> list = [];
        foreach (IConfigurationSection child in mappingsSection.GetChildren())
        {
            string? groupName = child["GroupName"]?.Trim();
            if (string.IsNullOrWhiteSpace(groupName))
            {
                continue;
            }

            string role = child["Role"]?.Trim() ?? AppRoles.Issuer;
            string allowedProfileId = child["AllowedProfileId"]?.Trim() ?? "*";
            List<string> domains = ReverseProxyOptions.ParseStringList(
                child.GetSection("DomainPatterns"),
                child["DomainPatterns"]);

            list.Add(new ConfiguredOidcGroupMapping
            {
                GroupName = groupName,
                Role = role,
                AllowedProfileId = string.IsNullOrWhiteSpace(allowedProfileId) ? "*" : allowedProfileId,
                DomainPatterns = domains
            });
        }

        if (list.Count == 0 && !string.IsNullOrWhiteSpace(specText))
        {
            // Support concise semicolon-separated spec:
            // "GroupA=Administrator:*;GroupB=Issuer:*.contoso.com,contoso.com@tls-server-ecdsa-256"
            foreach (string entry in specText.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                int eqIdx = entry.IndexOf('=');
                if (eqIdx <= 0)
                {
                    continue;
                }

                string groupName = entry[..eqIdx].Trim();
                string rhs = entry[(eqIdx + 1)..].Trim();
                string role = AppRoles.Issuer;
                string domainsPart = string.Empty;
                string profileId = "*";

                int colonIdx = rhs.IndexOf(':');
                if (colonIdx >= 0)
                {
                    role = rhs[..colonIdx].Trim();
                    domainsPart = rhs[(colonIdx + 1)..].Trim();
                }
                else
                {
                    role = rhs;
                }

                int atIdx = domainsPart.IndexOf('@');
                if (atIdx >= 0)
                {
                    profileId = domainsPart[(atIdx + 1)..].Trim();
                    domainsPart = domainsPart[..atIdx].Trim();
                }

                List<string> domains = domainsPart
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .ToList();

                list.Add(new ConfiguredOidcGroupMapping
                {
                    GroupName = groupName,
                    Role = string.IsNullOrWhiteSpace(role) ? AppRoles.Issuer : role,
                    AllowedProfileId = string.IsNullOrWhiteSpace(profileId) ? "*" : profileId,
                    DomainPatterns = domains
                });
            }
        }

        return list;
    }
}

public sealed record OidcLoginOutcome(
    bool Succeeded,
    string? ErrorMessage,
    ApplicationUser? User = null,
    ClaimsPrincipal? ApplicationPrincipal = null);

/// <summary>
/// Provider-agnostic OpenID Connect federation service.
/// Validates external identity strictly by (issuer, subject), enforces explicit administrator-controlled
/// group-to-role and group-to-domain/profile mappings, prevents automatic account linking by email or username,
/// and revalidates active HTTP and Blazor Server sessions against bounded lifetimes and current group mappings.
/// </summary>
public sealed class OidcFederationService(
    OidcFederationOptions oidcOptions,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    CertRoboDbContext dbContext,
    IOptions<IdentityOptions> identityOptionsAccessor)
{
    private static readonly SemaphoreSlim ProvisionLock = new(1, 1);
    private readonly IdentityOptions _identityOptions = identityOptionsAccessor.Value;

    public OidcFederationOptions Options => oidcOptions;

    public bool IsEnabledAndValid => oidcOptions.Enabled && oidcOptions.Validate().IsValid;

    public static bool IsSafeLocalReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return false;
        }

        foreach (char c in returnUrl)
        {
            if (char.IsControl(c))
            {
                return false;
            }
        }

        if (returnUrl[0] != '/')
        {
            return false;
        }

        if (returnUrl.Length > 1 && (returnUrl[1] == '/' || returnUrl[1] == '\\'))
        {
            return false;
        }

        if (!Uri.IsWellFormedUriString(returnUrl, UriKind.Relative))
        {
            return false;
        }

        if (returnUrl.StartsWith("/login", StringComparison.OrdinalIgnoreCase)
            || returnUrl.StartsWith("/account/", StringComparison.OrdinalIgnoreCase)
            || returnUrl.StartsWith("/signin-oidc", StringComparison.OrdinalIgnoreCase)
            || returnUrl.StartsWith("/signout-callback-oidc", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    public static string NormalizeReturnUrl(string? returnUrl) =>
        IsSafeLocalReturnUrl(returnUrl) ? returnUrl! : "/";

    public static IReadOnlyList<string> ExtractGroupsFromPrincipal(ClaimsPrincipal principal, string groupClaimType)
    {
        if (string.IsNullOrWhiteSpace(groupClaimType))
        {
            return [];
        }

        List<string> groups = [];
        foreach (Claim claim in principal.Claims)
        {
            if (!string.Equals(claim.Type, groupClaimType, StringComparison.Ordinal))
            {
                continue;
            }

            string rawValue = claim.Value?.Trim() ?? string.Empty;
            if (string.IsNullOrEmpty(rawValue))
            {
                continue;
            }

            if (rawValue.StartsWith('[') && rawValue.EndsWith(']'))
            {
                try
                {
                    string[]? parsedArray = JsonSerializer.Deserialize<string[]>(rawValue);
                    if (parsedArray != null)
                    {
                        foreach (string item in parsedArray)
                        {
                            string trimmed = item?.Trim() ?? string.Empty;
                            if (!string.IsNullOrEmpty(trimmed) && !groups.Contains(trimmed, StringComparer.Ordinal))
                            {
                                groups.Add(trimmed);
                            }
                        }
                        continue;
                    }
                }
                catch
                {
                    // Fall through and treat as literal string if not valid JSON string array
                }
            }

            if (!groups.Contains(rawValue, StringComparer.Ordinal))
            {
                groups.Add(rawValue);
            }
        }

        return groups;
    }

    public static IReadOnlyList<string> ParseSyncedGroupsJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            string[]? arr = JsonSerializer.Deserialize<string[]>(json);
            return arr?
                .Where(g => !string.IsNullOrWhiteSpace(g))
                .Select(g => g.Trim())
                .Distinct(StringComparer.Ordinal)
                .ToList() ?? [];
        }
        catch
        {
            return [];
        }
    }

    /// <summary>
    /// Validates the authenticated OIDC principal against CertRobo's issuer, subject, account status,
    /// and administrator-controlled group mappings, then provisions or updates the external user record
    /// keyed strictly by (ExternalIssuer, ExternalSubject) without linking by email or username.
    /// </summary>
    public async Task<OidcLoginOutcome> ProcessValidatedOidcLoginAsync(
        ClaimsPrincipal externalPrincipal,
        string? validatedTokenIssuer = null,
        CancellationToken cancellationToken = default)
    {
        var (configValid, configErr) = oidcOptions.Validate();
        if (!oidcOptions.Enabled || !configValid)
        {
            return new(false, configErr ?? "OpenID Connect federated login is not enabled.");
        }

        string expectedIssuer = oidcOptions.EffectiveIssuer;
        string? claimIssuer = externalPrincipal.FindFirstValue("iss")?.Trim();
        string? effectiveTokenIssuer = !string.IsNullOrWhiteSpace(validatedTokenIssuer)
            ? validatedTokenIssuer.Trim()
            : claimIssuer;

        if (string.IsNullOrWhiteSpace(effectiveTokenIssuer)
            || !string.Equals(effectiveTokenIssuer, expectedIssuer, StringComparison.Ordinal)
            || (!string.IsNullOrWhiteSpace(claimIssuer) && !string.Equals(claimIssuer, expectedIssuer, StringComparison.Ordinal)))
        {
            return new(false, "Access denied: OIDC token issuer does not match the configured trusted issuer.");
        }

        string? subject = externalPrincipal.FindFirstValue(oidcOptions.SubjectClaimType)?.Trim();
        if (string.IsNullOrWhiteSpace(subject) || subject.Length > 256)
        {
            return new(false, $"Access denied: OIDC token is missing a valid '{oidcOptions.SubjectClaimType}' subject claim.");
        }

        IReadOnlyList<string> tokenGroups = ExtractGroupsFromPrincipal(externalPrincipal, oidcOptions.GroupClaimType);

        await ProvisionLock.WaitAsync(cancellationToken);
        try
        {
            ApplicationUser? existingUser = await dbContext.Users
                .FirstOrDefaultAsync(
                    u => u.ExternalIssuer == expectedIssuer && u.ExternalSubject == subject,
                    cancellationToken);

            if (existingUser != null && !existingUser.IsExternalAccount)
            {
                return new(false, "Access denied: external identity conflicts with a non-external account record.");
            }

            if (existingUser != null
                && (existingUser.IsDisabled || (existingUser.LockoutEnd.HasValue && existingUser.LockoutEnd.Value > DateTimeOffset.UtcNow)))
            {
                return new(false, "Invalid credentials or disabled account.");
            }

            List<ExternalGroupRoleMapping> allMappings = await dbContext.ExternalGroupRoleMappings
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            List<ExternalGroupRoleMapping> matchedMappings = allMappings
                .Where(m => tokenGroups.Contains(m.GroupName, StringComparer.Ordinal))
                .ToList();

            if (tokenGroups.Count == 0 || matchedMappings.Count == 0)
            {
                if (existingUser != null)
                {
                    IList<string> oldRoles = await userManager.GetRolesAsync(existingUser);
                    if (oldRoles.Count > 0)
                    {
                        await userManager.RemoveFromRolesAsync(existingUser, oldRoles);
                    }
                    existingUser.LastSyncedGroupsJson = "[]";
                    await userManager.UpdateAsync(existingUser);
                    await userManager.UpdateSecurityStampAsync(existingUser);
                }

                return new(
                    false,
                    tokenGroups.Count == 0
                        ? $"Access denied: the identity provider token did not contain any '{oidcOptions.GroupClaimType}' group claims."
                        : "Access denied: none of your identity provider groups are mapped to an authorised CertRobo role.");
            }

            bool isAdmin = matchedMappings.Any(m =>
                string.Equals(m.RoleName, AppRoles.Administrator, StringComparison.OrdinalIgnoreCase));
            bool isIssuer = isAdmin || matchedMappings.Any(m =>
                string.Equals(m.RoleName, AppRoles.Issuer, StringComparison.OrdinalIgnoreCase));

            if (!isIssuer)
            {
                return new(false, "Access denied: matched group mapping does not grant a valid CertRobo role.");
            }

            string[] effectiveRoles = isAdmin
                ? [AppRoles.Administrator, AppRoles.Issuer]
                : [AppRoles.Issuer];

            // Extract informational metadata (never used for account lookup or linking)
            string? emailClaim = SanitizeOptionalMetadata(externalPrincipal.FindFirstValue(oidcOptions.EmailClaimType), 256);
            string? displayNameClaim = SanitizeOptionalMetadata(externalPrincipal.FindFirstValue(oidcOptions.DisplayNameClaimType), 256);
            string? preferredUsernameClaim = SanitizeOptionalMetadata(externalPrincipal.FindFirstValue(oidcOptions.PreferredUsernameClaimType), 256);

            // Store only the groups from the token; authorization checks always intersect against active ExternalGroupRoleMappings
            string syncedGroupsJson = JsonSerializer.Serialize(tokenGroups);
            DateTimeOffset nowUtc = DateTimeOffset.UtcNow;

            ApplicationUser user;
            if (existingUser == null)
            {
                string allocatedUserName = await AllocateNonCollidingExternalUserNameAsync(
                    expectedIssuer,
                    subject,
                    preferredUsernameClaim ?? emailClaim,
                    existingUserId: null,
                    cancellationToken);

                user = new ApplicationUser
                {
                    UserName = allocatedUserName,
                    Email = emailClaim,
                    EmailConfirmed = true,
                    DisplayName = displayNameClaim ?? preferredUsernameClaim ?? emailClaim ?? subject,
                    IsDisabled = false,
                    IsExternalAccount = true,
                    ExternalIssuer = expectedIssuer,
                    ExternalSubject = subject,
                    CreatedAtUtc = nowUtc,
                    LastExternalLoginAtUtc = nowUtc,
                    LastSyncedGroupsJson = syncedGroupsJson
                };

                IdentityResult createResult = await userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    return new(false, "Failed to provision external account: " + string.Join("; ", createResult.Errors.Select(e => e.Description)));
                }

                await userManager.AddToRolesAsync(user, effectiveRoles);
                await userManager.AddLoginAsync(user, new UserLoginInfo(expectedIssuer, subject, oidcOptions.DisplayName));
            }
            else
            {
                user = existingUser;
                user.Email = emailClaim ?? user.Email;
                user.DisplayName = displayNameClaim ?? preferredUsernameClaim ?? user.DisplayName ?? subject;
                user.LastExternalLoginAtUtc = nowUtc;
                user.LastSyncedGroupsJson = syncedGroupsJson;

                IdentityResult updateResult = await userManager.UpdateAsync(user);
                if (!updateResult.Succeeded)
                {
                    return new(false, "Failed to update external account metadata.");
                }

                IList<string> currentRoles = await userManager.GetRolesAsync(user);
                string[] rolesToRemove = currentRoles
                    .Where(r => !effectiveRoles.Contains(r, StringComparer.OrdinalIgnoreCase))
                    .ToArray();
                string[] rolesToAdd = effectiveRoles
                    .Where(r => !currentRoles.Contains(r, StringComparer.OrdinalIgnoreCase))
                    .ToArray();

                if (rolesToRemove.Length > 0)
                {
                    await userManager.RemoveFromRolesAsync(user, rolesToRemove);
                }
                if (rolesToAdd.Length > 0)
                {
                    await userManager.AddToRolesAsync(user, rolesToAdd);
                }
                if (rolesToRemove.Length > 0 || rolesToAdd.Length > 0)
                {
                    await userManager.UpdateSecurityStampAsync(user);
                }

                IList<UserLoginInfo> logins = await userManager.GetLoginsAsync(user);
                if (!logins.Any(l => l.LoginProvider == expectedIssuer && l.ProviderKey == subject))
                {
                    await userManager.AddLoginAsync(user, new UserLoginInfo(expectedIssuer, subject, oidcOptions.DisplayName));
                }
            }

            ClaimsPrincipal appPrincipal = await signInManager.CreateUserPrincipalAsync(user);
            if (appPrincipal.Identity is ClaimsIdentity identity)
            {
                identity.AddClaim(new Claim(OidcClaimTypes.AuthMethod, OidcClaimTypes.AuthMethodOidc));
                identity.AddClaim(new Claim(OidcClaimTypes.OidcIssuer, expectedIssuer));
                identity.AddClaim(new Claim(OidcClaimTypes.OidcSubject, subject));
                identity.AddClaim(new Claim(OidcClaimTypes.OidcAuthTimeUtc, nowUtc.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
                foreach (string grp in tokenGroups)
                {
                    identity.AddClaim(new Claim(OidcClaimTypes.OidcGroup, grp));
                }
            }

            return new(true, null, user, appPrincipal);
        }
        finally
        {
            ProvisionLock.Release();
        }
    }

    /// <summary>
    /// Validates an active HTTP cookie or Blazor Server circuit principal against account status,
    /// SecurityStamp, OIDC session lifetime bounds, and current administrator-configured group mappings.
    /// </summary>
    public async Task<bool> ValidateSessionPrincipalAsync(
        ClaimsPrincipal? principal,
        CancellationToken cancellationToken = default)
    {
        if (principal?.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        ApplicationUser? user = await userManager.GetUserAsync(principal);
        if (user == null || user.IsDisabled)
        {
            return false;
        }

        if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTimeOffset.UtcNow)
        {
            return false;
        }

        if (userManager.SupportsUserSecurityStamp)
        {
            string? principalStamp = principal.FindFirstValue(_identityOptions.ClaimsIdentity.SecurityStampClaimType);
            string? userStamp = await userManager.GetSecurityStampAsync(user);
            if (string.IsNullOrEmpty(principalStamp) || !string.Equals(principalStamp, userStamp, StringComparison.Ordinal))
            {
                return false;
            }
        }

        bool principalIsOidc = principal.HasClaim(OidcClaimTypes.AuthMethod, OidcClaimTypes.AuthMethodOidc);
        if (user.IsExternalAccount != principalIsOidc)
        {
            return false;
        }

        if (!user.IsExternalAccount)
        {
            return true;
        }

        // External OIDC account checks:
        if (!oidcOptions.Enabled)
        {
            return false;
        }

        string? principalIssuer = principal.FindFirstValue(OidcClaimTypes.OidcIssuer);
        string? principalSubject = principal.FindFirstValue(OidcClaimTypes.OidcSubject);
        if (string.IsNullOrWhiteSpace(principalIssuer)
            || string.IsNullOrWhiteSpace(principalSubject)
            || !string.Equals(principalIssuer, user.ExternalIssuer, StringComparison.Ordinal)
            || !string.Equals(principalSubject, user.ExternalSubject, StringComparison.Ordinal)
            || !string.Equals(principalIssuer, oidcOptions.EffectiveIssuer, StringComparison.Ordinal))
        {
            return false;
        }

        // Enforce explicit, bounded external session lifetime
        string? authTimeStr = principal.FindFirstValue(OidcClaimTypes.OidcAuthTimeUtc);
        if (string.IsNullOrWhiteSpace(authTimeStr)
            || !long.TryParse(authTimeStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out long authUnixSeconds))
        {
            return false;
        }

        DateTimeOffset authTimeUtc = DateTimeOffset.FromUnixTimeSeconds(authUnixSeconds);
        TimeSpan maxLifetime = TimeSpan.FromMinutes(Math.Clamp(oidcOptions.MaxSessionLifetimeMinutes, 1, 1440));
        if (DateTimeOffset.UtcNow - authTimeUtc > maxLifetime)
        {
            return false;
        }

        // Verify the external user's groups still map to their active roles in CertRobo
        List<string> principalGroups = principal.FindAll(OidcClaimTypes.OidcGroup)
            .Select(c => c.Value.Trim())
            .Where(g => !string.IsNullOrEmpty(g))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        IReadOnlyList<string> syncedGroups = ParseSyncedGroupsJson(user.LastSyncedGroupsJson);
        List<string> effectiveGroups = principalGroups
            .Where(g => syncedGroups.Contains(g, StringComparer.Ordinal))
            .ToList();

        if (effectiveGroups.Count == 0)
        {
            return false;
        }

        List<ExternalGroupRoleMapping> currentMappings = await dbContext.ExternalGroupRoleMappings
            .AsNoTracking()
            .Where(m => effectiveGroups.Contains(m.GroupName))
            .ToListAsync(cancellationToken);

        if (currentMappings.Count == 0)
        {
            return false;
        }

        bool stillAdmin = currentMappings.Any(m =>
            string.Equals(m.RoleName, AppRoles.Administrator, StringComparison.OrdinalIgnoreCase));
        bool stillIssuer = stillAdmin || currentMappings.Any(m =>
            string.Equals(m.RoleName, AppRoles.Issuer, StringComparison.OrdinalIgnoreCase));

        if (!stillIssuer)
        {
            return false;
        }

        // If the session cookie asserts Administrator, the user must still hold a group mapped to Administrator
        if (principal.IsInRole(AppRoles.Administrator) && !stillAdmin)
        {
            return false;
        }

        return true;
    }

    internal async Task<string> AllocateNonCollidingExternalUserNameAsync(
        string issuer,
        string subject,
        string? preferredHint,
        string? existingUserId,
        CancellationToken cancellationToken)
    {
        string deterministicSuffix = ComputeExternalIdentityShortHash(issuer, subject);
        string sanitizedHint = SanitizeUserNameCandidate(preferredHint);
        if (string.IsNullOrEmpty(sanitizedHint))
        {
            sanitizedHint = SanitizeUserNameCandidate(subject);
        }
        if (string.IsNullOrEmpty(sanitizedHint))
        {
            sanitizedHint = "oidc-user";
        }

        string candidate = sanitizedHint;
        string normalizedCandidate = userManager.NormalizeName(candidate);
        bool collision = await dbContext.Users.AnyAsync(
            u => u.NormalizedUserName == normalizedCandidate && u.Id != existingUserId,
            cancellationToken);

        if (!collision)
        {
            return candidate;
        }

        string disambiguated = $"{sanitizedHint}+oidc.{deterministicSuffix}";
        string normalizedDisambiguated = userManager.NormalizeName(disambiguated);
        bool secondCollision = await dbContext.Users.AnyAsync(
            u => u.NormalizedUserName == normalizedDisambiguated && u.Id != existingUserId,
            cancellationToken);

        if (!secondCollision)
        {
            return disambiguated;
        }

        return $"oidc.{deterministicSuffix}.{Guid.NewGuid():N}"[..32];
    }

    public static string ComputeExternalIdentityShortHash(string issuer, string subject)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{issuer}\0{subject}"));
        return Convert.ToHexString(hash)[..12].ToLowerInvariant();
    }

    public static string SanitizeUserNameCandidate(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        const string allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
        StringBuilder sb = new(raw.Length);
        foreach (char c in raw.Trim())
        {
            if (allowedChars.Contains(c))
            {
                sb.Append(c);
            }
            else if (char.IsWhiteSpace(c) || c is ':' or '/' or '\\')
            {
                sb.Append('_');
            }
        }

        string result = sb.ToString().Trim('_', '.', '-');
        if (result.Length > 64)
        {
            result = result[..64];
        }
        return result;
    }

    private static string? SanitizeOptionalMetadata(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string trimmed = value.Trim();
        return trimmed.Length <= maxLength ? trimmed : trimmed[..maxLength];
    }
}
