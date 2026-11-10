using CertRobo.Data;
using CertRobo.Models;
using CertRobo.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CertRobo.Tests;

/// <summary>
/// Local in-memory OpenID Connect identity provider fixture that serves discovery metadata,
/// JWKS public keys, and OAuth 2.0 / OIDC token responses with real RSA-signed (or tampered) JWT ID tokens,
/// validating PKCE (S256), client authentication, and redirect_uri matching.
/// </summary>
public sealed class LocalSignedOidcIdpFixture : HttpMessageHandler, IDisposable
{
    public const string DefaultIssuer = "https://idp.example.test";
    public const string DefaultClientId = "certrobo-web-client";
    public const string DefaultClientSecret = "OidcFixtureSecret!2026# SuperSecretValueNotLogged";
    public const string DefaultPublicCallbackUrl = "https://pki.contoso.com/signin-oidc";

    private readonly RSA _signingRsa = RSA.Create(2048);
    private readonly RSA _untrustedRsa = RSA.Create(2048);
    private readonly RsaSecurityKey _signingKey;
    private readonly RsaSecurityKey _untrustedKey;
    private readonly Dictionary<string, PendingAuthCodeRecord> _issuedCodes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Action<HttpRequestMessage, Dictionary<string, object>>> _userInfoHandlers = new(StringComparer.Ordinal);

    public string Issuer { get; }
    public string ClientId { get; }
    public string ClientSecret { get; }
    public bool EnforcePkceValidation { get; set; } = true;
    public string? LastIssuedIdToken { get; private set; }
    public string? LastIssuedAccessToken { get; private set; }

    public sealed record PendingAuthCodeRecord(
        string Code,
        string ClientId,
        string RedirectUri,
        string Nonce,
        string CodeChallenge,
        string CodeChallengeMethod,
        Func<PendingAuthCodeRecord, string> IdTokenBuilder,
        string AccessToken);

    public LocalSignedOidcIdpFixture(
        string issuer = DefaultIssuer,
        string clientId = DefaultClientId,
        string clientSecret = DefaultClientSecret)
    {
        Issuer = issuer.TrimEnd('/');
        ClientId = clientId;
        ClientSecret = clientSecret;
        _signingKey = new RsaSecurityKey(_signingRsa) { KeyId = "fixture-key-1" };
        _untrustedKey = new RsaSecurityKey(_untrustedRsa) { KeyId = "fixture-key-1" };
    }

    public string IssueAuthorizationCode(
        Uri authorizationRedirectUri,
        string? subject = "00u1234567890abcdef",
        string? email = "alice@contoso.com",
        string? preferredUsername = "alice@contoso.com",
        string? displayName = "Alice Operator",
        IEnumerable<string>? groups = null,
        string groupClaimType = "groups",
        string subjectClaimType = "sub",
        string? overrideTokenIssuer = null,
        string? overrideAudience = null,
        string? overrideNonce = null,
        DateTimeOffset? notBeforeUtc = null,
        DateTimeOffset? expiresUtc = null,
        bool signWithUntrustedKey = false,
        bool produceUnsignedAlgNoneToken = false,
        bool tamperSignatureBytes = false,
        Dictionary<string, object>? userInfoClaims = null)
    {
        Dictionary<string, Microsoft.Extensions.Primitives.StringValues> query = QueryHelpers.ParseQuery(authorizationRedirectUri.Query);
        string clientId = query.TryGetValue("client_id", out var cid) ? cid.ToString() : string.Empty;
        string redirectUri = query.TryGetValue("redirect_uri", out var ruri) ? ruri.ToString() : string.Empty;
        string nonce = query.TryGetValue("nonce", out var n) ? n.ToString() : string.Empty;
        string codeChallenge = query.TryGetValue("code_challenge", out var cc) ? cc.ToString() : string.Empty;
        string codeChallengeMethod = query.TryGetValue("code_challenge_method", out var ccm) ? ccm.ToString() : string.Empty;

        string code = $"code_{Guid.NewGuid():N}";
        string accessToken = $"at_{Guid.NewGuid():N}";

        if (userInfoClaims != null)
        {
            _userInfoHandlers[accessToken] = (_, target) =>
            {
                foreach (var kv in userInfoClaims)
                {
                    target[kv.Key] = kv.Value;
                }
            };
        }

        _issuedCodes[code] = new PendingAuthCodeRecord(
            code,
            clientId,
            redirectUri,
            nonce,
            codeChallenge,
            codeChallengeMethod,
            rec => BuildIdToken(
                subject: subject,
                email: email,
                preferredUsername: preferredUsername,
                displayName: displayName,
                groups: groups,
                groupClaimType: groupClaimType,
                subjectClaimType: subjectClaimType,
                issuer: overrideTokenIssuer ?? Issuer,
                audience: overrideAudience ?? ClientId,
                nonce: overrideNonce ?? rec.Nonce,
                notBeforeUtc: notBeforeUtc,
                expiresUtc: expiresUtc,
                signWithUntrustedKey: signWithUntrustedKey,
                produceUnsignedAlgNoneToken: produceUnsignedAlgNoneToken,
                tamperSignatureBytes: tamperSignatureBytes),
            accessToken);

        return code;
    }

    public string BuildIdToken(
        string? subject,
        string? email,
        string? preferredUsername,
        string? displayName,
        IEnumerable<string>? groups,
        string groupClaimType,
        string subjectClaimType,
        string issuer,
        string audience,
        string? nonce,
        DateTimeOffset? notBeforeUtc = null,
        DateTimeOffset? expiresUtc = null,
        bool signWithUntrustedKey = false,
        bool produceUnsignedAlgNoneToken = false,
        bool tamperSignatureBytes = false)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset nbf = notBeforeUtc ?? now.AddMinutes(-1);
        DateTimeOffset exp = expiresUtc ?? now.AddMinutes(15);

        List<Claim> claims =
        [
            new Claim("iat", now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        ];

        if (!string.IsNullOrEmpty(subject))
        {
            claims.Add(new Claim(subjectClaimType, subject));
        }

        if (!string.IsNullOrEmpty(nonce))
        {
            claims.Add(new Claim("nonce", nonce));
        }

        if (!string.IsNullOrEmpty(email))
        {
            claims.Add(new Claim("email", email));
        }

        if (!string.IsNullOrEmpty(preferredUsername))
        {
            claims.Add(new Claim("preferred_username", preferredUsername));
        }

        if (!string.IsNullOrEmpty(displayName))
        {
            claims.Add(new Claim("name", displayName));
        }

        if (groups != null)
        {
            foreach (string g in groups)
            {
                claims.Add(new Claim(groupClaimType, g));
            }
        }

        if (produceUnsignedAlgNoneToken)
        {
            string headerJson = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
            Dictionary<string, object?> payload = new()
            {
                ["iss"] = issuer,
                ["aud"] = audience,
                ["nbf"] = nbf.ToUnixTimeSeconds(),
                ["exp"] = exp.ToUnixTimeSeconds(),
                ["iat"] = now.ToUnixTimeSeconds()
            };
            if (!string.IsNullOrEmpty(subject)) payload[subjectClaimType] = subject;
            if (!string.IsNullOrEmpty(nonce)) payload["nonce"] = nonce;
            if (groups != null) payload[groupClaimType] = groups.ToArray();

            string payloadJson = JsonSerializer.Serialize(payload);
            return $"{Base64UrlEncoder.Encode(headerJson)}.{Base64UrlEncoder.Encode(payloadJson)}.";
        }

        SigningCredentials creds = new(
            signWithUntrustedKey ? _untrustedKey : _signingKey,
            SecurityAlgorithms.RsaSha256);

        JwtSecurityToken jwt = new(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: nbf.UtcDateTime,
            expires: exp.UtcDateTime,
            signingCredentials: creds);

        string encoded = new JwtSecurityTokenHandler().WriteToken(jwt);
        if (tamperSignatureBytes)
        {
            string[] parts = encoded.Split('.');
            byte[] sigBytes = Base64UrlEncoder.DecodeBytes(parts[2]);
            sigBytes[0] ^= 0xFF;
            sigBytes[^1] ^= 0xAA;
            encoded = $"{parts[0]}.{parts[1]}.{Base64UrlEncoder.Encode(sigBytes)}";
        }

        return encoded;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        string path = request.RequestUri?.AbsolutePath ?? string.Empty;

        if (path.EndsWith("/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase))
        {
            var doc = new
            {
                issuer = Issuer,
                authorization_endpoint = $"{Issuer}/oauth2/v1/authorize",
                token_endpoint = $"{Issuer}/oauth2/v1/token",
                userinfo_endpoint = $"{Issuer}/oauth2/v1/userinfo",
                end_session_endpoint = $"{Issuer}/oauth2/v1/logout",
                jwks_uri = $"{Issuer}/oauth2/v1/keys",
                response_types_supported = new[] { "code" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { "RS256" },
                code_challenge_methods_supported = new[] { "S256" },
                token_endpoint_auth_methods_supported = new[] { "client_secret_post", "client_secret_basic" }
            };
            return JsonResponse(HttpStatusCode.OK, doc);
        }

        if (path.EndsWith("/oauth2/v1/keys", StringComparison.OrdinalIgnoreCase))
        {
            RSAParameters rsaParams = _signingRsa.ExportParameters(false);
            var jwks = new
            {
                keys = new[]
                {
                    new
                    {
                        kty = "RSA",
                        use = "sig",
                        kid = _signingKey.KeyId,
                        alg = "RS256",
                        n = Base64UrlEncoder.Encode(rsaParams.Modulus!),
                        e = Base64UrlEncoder.Encode(rsaParams.Exponent!)
                    }
                }
            };
            return JsonResponse(HttpStatusCode.OK, jwks);
        }

        if (path.EndsWith("/oauth2/v1/token", StringComparison.OrdinalIgnoreCase))
        {
            string body = request.Content != null
                ? await request.Content.ReadAsStringAsync(cancellationToken)
                : string.Empty;
            var form = QueryHelpers.ParseQuery(body);

            string grantType = form.TryGetValue("grant_type", out var gt) ? gt.ToString() : string.Empty;
            string code = form.TryGetValue("code", out var c) ? c.ToString() : string.Empty;
            string redirectUri = form.TryGetValue("redirect_uri", out var ruri) ? ruri.ToString() : string.Empty;
            string codeVerifier = form.TryGetValue("code_verifier", out var cv) ? cv.ToString() : string.Empty;
            string clientId = form.TryGetValue("client_id", out var cid) ? cid.ToString() : string.Empty;
            string clientSecret = form.TryGetValue("client_secret", out var cs) ? cs.ToString() : string.Empty;

            if (request.Headers.Authorization is { Scheme: "Basic", Parameter: not null } basicAuth)
            {
                string decodedBasic = Encoding.UTF8.GetString(Convert.FromBase64String(basicAuth.Parameter));
                int colon = decodedBasic.IndexOf(':');
                if (colon > 0)
                {
                    clientId = Uri.UnescapeDataString(decodedBasic[..colon]);
                    clientSecret = Uri.UnescapeDataString(decodedBasic[(colon + 1)..]);
                }
            }

            if (grantType != "authorization_code" || !_issuedCodes.TryGetValue(code, out PendingAuthCodeRecord? record))
            {
                return JsonResponse(HttpStatusCode.BadRequest, new { error = "invalid_grant", error_description = "Invalid authorization code." });
            }

            _issuedCodes.Remove(code);

            if (!string.Equals(clientId, ClientId, StringComparison.Ordinal)
                || !string.Equals(clientSecret, ClientSecret, StringComparison.Ordinal))
            {
                return JsonResponse(HttpStatusCode.Unauthorized, new { error = "invalid_client", error_description = "Client authentication failed." });
            }

            if (!string.Equals(redirectUri, record.RedirectUri, StringComparison.Ordinal))
            {
                return JsonResponse(HttpStatusCode.BadRequest, new { error = "invalid_grant", error_description = "redirect_uri mismatch." });
            }

            if (EnforcePkceValidation)
            {
                if (string.IsNullOrWhiteSpace(codeVerifier) || record.CodeChallengeMethod != "S256")
                {
                    return JsonResponse(HttpStatusCode.BadRequest, new { error = "invalid_grant", error_description = "PKCE code_verifier is required." });
                }

                byte[] verifierHash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
                string computedChallenge = Base64UrlEncoder.Encode(verifierHash);
                if (!string.Equals(computedChallenge, record.CodeChallenge, StringComparison.Ordinal))
                {
                    return JsonResponse(HttpStatusCode.BadRequest, new { error = "invalid_grant", error_description = "PKCE S256 verification failed." });
                }
            }

            string idToken = record.IdTokenBuilder(record);
            LastIssuedIdToken = idToken;
            LastIssuedAccessToken = record.AccessToken;
            var tokenResponse = new
            {
                access_token = record.AccessToken,
                token_type = "Bearer",
                expires_in = 3600,
                id_token = idToken
            };
            return JsonResponse(HttpStatusCode.OK, tokenResponse);
        }

        if (path.EndsWith("/oauth2/v1/userinfo", StringComparison.OrdinalIgnoreCase))
        {
            string? bearer = request.Headers.Authorization?.Parameter;
            Dictionary<string, object> claims = new();
            if (!string.IsNullOrEmpty(bearer) && _userInfoHandlers.TryGetValue(bearer, out var populate))
            {
                populate(request, claims);
            }
            return JsonResponse(HttpStatusCode.OK, claims);
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode status, object payload)
    {
        string json = JsonSerializer.Serialize(payload);
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _signingRsa.Dispose();
            _untrustedRsa.Dispose();
        }
        base.Dispose(disposing);
    }
}

public sealed class InMemoryLogCollector : ILoggerProvider
{
    private readonly System.Collections.Concurrent.ConcurrentQueue<string> _entries = new();

    public IReadOnlyCollection<string> Entries => _entries.ToArray();

    public ILogger CreateLogger(string categoryName) => new InMemoryLogger(categoryName, _entries);

    public void Dispose() { }

    private sealed class InMemoryLogger(
        string category,
        System.Collections.Concurrent.ConcurrentQueue<string> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            entries.Enqueue($"[{category}:{logLevel}] {formatter(state, exception)} {exception}");
        }
    }
}

public class OidcFederatedLoginTests : IDisposable
{
    private readonly string _tempDir;
    private readonly List<IDisposable> _disposables = [];
    private readonly CryptoFactory _crypto = new();

    public OidcFederatedLoginTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"certrobo-oidc-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    private (WebApplicationFactory<Program> Factory, LocalSignedOidcIdpFixture Idp, InMemoryLogCollector Logs) CreateOidcTestHost(
        Action<OidcFederationOptions>? configureOidc = null,
        Dictionary<string, string?>? extraSettings = null,
        IPAddress? simulatedRemoteIp = null)
    {
        string subDir = Path.Combine(_tempDir, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(subDir);

        LocalSignedOidcIdpFixture idp = new();
        InMemoryLogCollector logCollector = new();
        _disposables.Add(idp);
        _disposables.Add(logCollector);

        WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("CertRobo:DataDirectory", subDir);
            builder.UseSetting("CertRobo:SqliteFilePath", Path.Combine(subDir, "certrobo.db"));
            builder.UseSetting("CertRobo:CaStorageDirectory", Path.Combine(subDir, "ca"));
            builder.UseSetting("CertRobo:CaPassphrase", "TestCaPassphrase!2026");

            builder.UseSetting("CertRobo:Oidc:Enabled", "true");
            builder.UseSetting("CertRobo:Oidc:DisplayName", "Corporate SSO");
            builder.UseSetting("CertRobo:Oidc:Issuer", idp.Issuer);
            builder.UseSetting("CertRobo:Oidc:Authority", idp.Issuer);
            builder.UseSetting("CertRobo:Oidc:ClientId", idp.ClientId);
            builder.UseSetting("CertRobo:Oidc:ClientSecret", idp.ClientSecret);
            builder.UseSetting("CertRobo:Oidc:PublicCallbackUrl", LocalSignedOidcIdpFixture.DefaultPublicCallbackUrl);
            builder.UseSetting("CertRobo:Oidc:SessionRevalidationSeconds", "0");

            if (extraSettings != null)
            {
                foreach (var kv in extraSettings)
                {
                    builder.UseSetting(kv.Key, kv.Value);
                }
            }

            builder.ConfigureLogging(logging =>
            {
                logging.AddProvider(logCollector);
            });

            builder.ConfigureServices(services =>
            {
                if (simulatedRemoteIp != null)
                {
                    services.Insert(0, ServiceDescriptor.Transient<IStartupFilter>(_ => new SimulatedRemoteIpStartupFilter(simulatedRemoteIp)));
                }

                services.PostConfigure<OidcFederationOptions>(opts =>
                {
                    opts.BackchannelHttpHandler = idp;
                    configureOidc?.Invoke(opts);
                });

                // Re-register singleton OidcFederationOptions with the fixture BackchannelHttpHandler
                ServiceDescriptor? existingDesc = services.FirstOrDefault(d => d.ServiceType == typeof(OidcFederationOptions));
                if (existingDesc?.ImplementationInstance is OidcFederationOptions singletonOpts)
                {
                    singletonOpts.BackchannelHttpHandler = idp;
                    configureOidc?.Invoke(singletonOpts);
                }
            });
        });

        _disposables.Add(factory);
        return (factory, idp, logCollector);
    }

    private sealed class SimulatedRemoteIpStartupFilter(IPAddress remoteIp) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                app.Use((ctx, nxt) =>
                {
                    ctx.Connection.RemoteIpAddress = remoteIp;
                    return nxt(ctx);
                });
                next(app);
            };
        }
    }

    [Fact]
    public async Task OidcAuthorizationCodePkce_ValidatesSignatureIssuerAudienceLifetimeStateNonce_AndDoesNotLeakSecretsOrTokens()
    {
        var (factory, idp, logs) = CreateOidcTestHost();

        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            await acct.BootstrapFirstAdminAsync("breakglass-admin", "BreakGlass!2026", "admin@contoso.com", "*");
            await acct.SetExternalGroupRoleMappingAsync("CertRobo-Issuers", AppRoles.Issuer, ["*.contoso.com"], "*");
        }

        using HttpClient client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://pki.contoso.com"),
            AllowAutoRedirect = false
        });

        // 1. Verify /login renders the configured OIDC provider button alongside local login
        HttpResponseMessage loginGet = await client.GetAsync("/login");
        Assert.Equal(HttpStatusCode.OK, loginGet.StatusCode);
        string loginHtml = await loginGet.Content.ReadAsStringAsync();
        Assert.Contains("Sign in with Corporate SSO", loginHtml);
        Assert.DoesNotContain(idp.ClientSecret, loginHtml);

        // 2. Start OIDC challenge and verify Authorization Code + PKCE (S256) + state + nonce parameters
        Uri authRedirect = await StartOidcChallengeAsync(client, "/");
        var authQuery = QueryHelpers.ParseQuery(authRedirect.Query);
        Assert.Equal("code", authQuery["response_type"].ToString());
        Assert.Equal(idp.ClientId, authQuery["client_id"].ToString());
        Assert.Equal(LocalSignedOidcIdpFixture.DefaultPublicCallbackUrl, authQuery["redirect_uri"].ToString());
        Assert.Equal("S256", authQuery["code_challenge_method"].ToString());
        Assert.False(string.IsNullOrWhiteSpace(authQuery["code_challenge"].ToString()));
        Assert.False(string.IsNullOrWhiteSpace(authQuery["state"].ToString()));
        Assert.False(string.IsNullOrWhiteSpace(authQuery["nonce"].ToString()));

        // 3. Valid signed token with mapped group succeeds and redirects to /
        string validCode = idp.IssueAuthorizationCode(
            authRedirect,
            subject: "sub-valid-001",
            email: "alice@contoso.com",
            preferredUsername: "alice.operator",
            displayName: "Alice Operator",
            groups: ["CertRobo-Issuers"]);

        HttpResponseMessage callbackOk = await client.GetAsync($"/signin-oidc?code={Uri.EscapeDataString(validCode)}&state={Uri.EscapeDataString(authQuery["state"].ToString())}");
        Assert.True(
            callbackOk.Headers.Location?.OriginalString == "/",
            $"Expected '/' but got '{callbackOk.Headers.Location?.OriginalString}'. Logs:\n" + string.Join("\n", logs.Entries));
        Assert.Equal(HttpStatusCode.Redirect, callbackOk.StatusCode);
        CopyCookies(callbackOk, client);

        HttpResponseMessage homeGet = await client.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, homeGet.StatusCode);
        string homeHtml = await homeGet.Content.ReadAsStringAsync();
        Assert.Contains("alice.operator", homeHtml);
        Assert.Contains("OIDC", homeHtml);

        // 4. Reject wrong issuer
        await AssertOidcCallbackRejectedAsync(factory, idp, authUri =>
            idp.IssueAuthorizationCode(authUri, overrideTokenIssuer: "https://wrong-issuer.example.test", groups: ["CertRobo-Issuers"]),
            "issuer");

        // 5. Reject wrong audience
        await AssertOidcCallbackRejectedAsync(factory, idp, authUri =>
            idp.IssueAuthorizationCode(authUri, overrideAudience: "wrong-audience-client", groups: ["CertRobo-Issuers"]),
            "audience");

        // 6. Reject expired token
        await AssertOidcCallbackRejectedAsync(factory, idp, authUri =>
            idp.IssueAuthorizationCode(
                authUri,
                notBeforeUtc: DateTimeOffset.UtcNow.AddMinutes(-30),
                expiresUtc: DateTimeOffset.UtcNow.AddMinutes(-10),
                groups: ["CertRobo-Issuers"]),
            "expired");

        // 7. Reject untrusted signing key
        await AssertOidcCallbackRejectedAsync(factory, idp, authUri =>
            idp.IssueAuthorizationCode(authUri, signWithUntrustedKey: true, groups: ["CertRobo-Issuers"]),
            "signature");

        // 8. Reject tampered signature bytes
        await AssertOidcCallbackRejectedAsync(factory, idp, authUri =>
            idp.IssueAuthorizationCode(authUri, tamperSignatureBytes: true, groups: ["CertRobo-Issuers"]),
            "signature");

        // 9. Reject unsigned alg:none token
        await AssertOidcCallbackRejectedAsync(factory, idp, authUri =>
            idp.IssueAuthorizationCode(authUri, produceUnsignedAlgNoneToken: true, groups: ["CertRobo-Issuers"]),
            "authentication failed");

        // 10. Reject mismatched nonce
        await AssertOidcCallbackRejectedAsync(factory, idp, authUri =>
            idp.IssueAuthorizationCode(authUri, overrideNonce: "wrong-nonce-value", groups: ["CertRobo-Issuers"]),
            "nonce");

        // 11. Reject corrupted/mismatched state parameter
        using (HttpClient stateClient = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://pki.contoso.com"),
            AllowAutoRedirect = false
        }))
        {
            Uri stateRedirect = await StartOidcChallengeAsync(stateClient, "/");
            string codeForBadState = idp.IssueAuthorizationCode(stateRedirect, groups: ["CertRobo-Issuers"]);
            HttpResponseMessage badStateResp = await stateClient.GetAsync($"/signin-oidc?code={Uri.EscapeDataString(codeForBadState)}&state=corrupted-state-value");
            Assert.Equal(HttpStatusCode.Redirect, badStateResp.StatusCode);
            string badStateLoc = Uri.UnescapeDataString(badStateResp.Headers.Location?.OriginalString ?? string.Empty);
            Assert.StartsWith("/login?error=", badStateLoc);
            Assert.Contains("state", badStateLoc, StringComparison.OrdinalIgnoreCase);
        }

        // 12. Verify client secret and raw tokens are never logged
        Assert.NotNull(idp.LastIssuedIdToken);
        Assert.NotNull(idp.LastIssuedAccessToken);
        foreach (string logLine in logs.Entries)
        {
            Assert.DoesNotContain(idp.ClientSecret, logLine, StringComparison.Ordinal);
            Assert.DoesNotContain(idp.LastIssuedIdToken!, logLine, StringComparison.Ordinal);
            Assert.DoesNotContain(idp.LastIssuedAccessToken!, logLine, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task ExternalIdentity_ResolvesStrictlyByIssuerAndSubject_NeverAutoLinksByEmailOrUserName_AndPreservesLocalBreakGlassAdmin()
    {
        var (factory, idp, _) = CreateOidcTestHost();

        ApplicationUser localAdmin;
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            var (ok, err, user) = await acct.BootstrapFirstAdminAsync(
                "admin",
                "LocalAdminPass!2026",
                "admin@contoso.com",
                "*");
            Assert.True(ok, err);
            localAdmin = user!;

            // Map external group only to Issuer for *.dev.contoso.com
            await acct.SetExternalGroupRoleMappingAsync(
                "Dev-Certificate-Issuers",
                AppRoles.Issuer,
                ["*.dev.contoso.com"],
                "*");
        }

        // Sign in via OIDC with a subject that claims the exact same email ("admin@contoso.com")
        // and preferred_username ("admin") as the local Administrator account!
        using HttpClient extClient = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://pki.contoso.com"),
            AllowAutoRedirect = false
        });

        Uri authRedirect = await StartOidcChallengeAsync(extClient, "/");
        var authQuery = QueryHelpers.ParseQuery(authRedirect.Query);
        string code = idp.IssueAuthorizationCode(
            authRedirect,
            subject: "00u-external-impostor-999",
            email: "admin@contoso.com",
            preferredUsername: "admin",
            displayName: "External User With Admin Email",
            groups: ["Dev-Certificate-Issuers"]);

        HttpResponseMessage callback = await extClient.GetAsync(
            $"/signin-oidc?code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(authQuery["state"].ToString())}");
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        CopyCookies(callback, extClient);

        // 1. Verify the external user was NOT linked to the local admin account and did NOT gain Administrator role
        ApplicationUser externalUser;
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            UserManager<ApplicationUser> userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

            externalUser = (await db.Users.FirstOrDefaultAsync(
                u => u.ExternalIssuer == idp.Issuer && u.ExternalSubject == "00u-external-impostor-999"))!;
            Assert.NotNull(externalUser);
            Assert.NotEqual(localAdmin.Id, externalUser.Id);
            Assert.True(externalUser.IsExternalAccount);
            Assert.NotEqual("admin", externalUser.UserName, StringComparer.OrdinalIgnoreCase);
            Assert.StartsWith("admin+oidc.", externalUser.UserName, StringComparison.OrdinalIgnoreCase);

            IList<string> extRoles = await userMgr.GetRolesAsync(externalUser);
            Assert.Contains(AppRoles.Issuer, extRoles);
            Assert.DoesNotContain(AppRoles.Administrator, extRoles);

            // Verify external user cannot issue for *.prod.contoso.com (which localAdmin is allowed to do via '*')
            IssuancePolicyService policy = scope.ServiceProvider.GetRequiredService<IssuancePolicyService>();
            KeyPair kp = _crypto.KeyGen(256);
            string prodCsr = _crypto.CSRGen(kp, "api.prod.contoso.com", ["api.prod.contoso.com"], "US", "Washington", "Redmond", "Contoso", "IT", "");
            PolicyEvaluationResult prodEval = await policy.EvaluateCsrRequestAsync(externalUser.Id, prodCsr);
            Assert.False(prodEval.IsAllowed);

            string devCsr = _crypto.CSRGen(kp, "api.dev.contoso.com", ["api.dev.contoso.com"], "US", "Washington", "Redmond", "Contoso", "IT", "");
            PolicyEvaluationResult devEval = await policy.EvaluateCsrRequestAsync(externalUser.Id, devCsr);
            Assert.True(devEval.IsAllowed, devEval.DenialReason);
        }

        // 2. Verify external user cannot access /admin/pending-ca/csr (Administrator-only endpoint)
        HttpResponseMessage adminEndpointResp = await extClient.GetAsync("/admin/pending-ca/csr");
        Assert.Equal(HttpStatusCode.Redirect, adminEndpointResp.StatusCode);
        Assert.Contains("/login", adminEndpointResp.Headers.Location?.OriginalString);

        // 3. Re-login with same (issuer, subject) but updated email & display name -> resolves to same user ID
        using HttpClient extClient2 = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://pki.contoso.com"),
            AllowAutoRedirect = false
        });
        Uri authRedirect2 = await StartOidcChallengeAsync(extClient2, "/");
        var authQuery2 = QueryHelpers.ParseQuery(authRedirect2.Query);
        string code2 = idp.IssueAuthorizationCode(
            authRedirect2,
            subject: "00u-external-impostor-999",
            email: "renamed.user@contoso.com",
            preferredUsername: "renamed.user",
            displayName: "Renamed External User",
            groups: ["Dev-Certificate-Issuers"]);

        HttpResponseMessage callback2 = await extClient2.GetAsync(
            $"/signin-oidc?code={Uri.EscapeDataString(code2)}&state={Uri.EscapeDataString(authQuery2["state"].ToString())}");
        Assert.Equal(HttpStatusCode.Redirect, callback2.StatusCode);

        using (IServiceScope scope = factory.Services.CreateScope())
        {
            CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            List<ApplicationUser> matches = await db.Users
                .Where(u => u.ExternalIssuer == idp.Issuer && u.ExternalSubject == "00u-external-impostor-999")
                .ToListAsync();
            Assert.Single(matches);
            Assert.Equal(externalUser.Id, matches[0].Id);
            Assert.Equal("renamed.user@contoso.com", matches[0].Email);
            Assert.Equal("Renamed External User", matches[0].DisplayName);

            // Verify ResetPasswordAsync refuses external OIDC accounts
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            var (resetExtOk, resetExtErr) = await acct.ResetPasswordAsync(externalUser.Id, "CannotSetLocalPass!2026");
            Assert.False(resetExtOk);
            Assert.Contains("external OpenID Connect account", resetExtErr);
        }

        // 4. Verify local break-glass Administrator can still sign in with local credentials and reset password
        using HttpClient localClient = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://pki.contoso.com"),
            AllowAutoRedirect = false
        });
        HttpResponseMessage localLoginGet = await localClient.GetAsync("/login");
        string localLoginHtml = await localLoginGet.Content.ReadAsStringAsync();
        string localToken = ExtractAntiforgeryToken(localLoginHtml);
        CopyCookies(localLoginGet, localClient);

        HttpResponseMessage localLoginPost = await localClient.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = localToken,
            ["userName"] = "admin",
            ["password"] = "LocalAdminPass!2026",
            ["returnUrl"] = "/admin"
        }));
        Assert.Equal(HttpStatusCode.Redirect, localLoginPost.StatusCode);
        Assert.Equal("/admin", localLoginPost.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task GroupMappings_EnforceRolesAndDomainProfilePolicy_SupportCustomClaimNames_AndRejectUnmappedOrMissingClaims()
    {
        // Configure non-default claim types and UserInfo endpoint retrieval to prove provider-agnostic OIDC behavior
        var (factory, idp, _) = CreateOidcTestHost(configureOidc: opts =>
        {
            opts.GroupClaimType = " directory_groups ";
            opts.GroupClaimType = opts.GroupClaimType.Trim();
            opts.SubjectClaimType = "oid";
            opts.GetClaimsFromUserInfoEndpoint = true;
        });

        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            CertificateAuthorityService ca = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
            await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");
            await ca.CreateSelfSignedOrIntermediateCaAsync(
                "Test Root CA",
                "root.contoso.com",
                "US", "Washington", "Redmond", "Contoso", "PKI",
                CertificateKeyFamily.Ecdsa, 256, 365, "TestCaPassphrase!2026");

            // Map "ecdsa256-app-issuers" -> Issuer role, "*.app.contoso.com", profile "tls-server-ecdsa-256" only
            var (mapOk, mapErr, _) = await acct.SetExternalGroupRoleMappingAsync(
                "ecdsa256-app-issuers",
                AppRoles.Issuer,
                ["*.app.contoso.com"],
                CertificateProfiles.EcdsaP256ServerId);
            Assert.True(mapOk, mapErr);
        }

        // 1. Reject login when required OIDC 'sub' or custom subject claim ("oid") is missing
        await AssertOidcCallbackRejectedAsync(factory, idp, authUri =>
            idp.IssueAuthorizationCode(authUri, subject: null, subjectClaimType: "oid", groupClaimType: "directory_groups", groups: ["ecdsa256-app-issuers"]),
            "subject");

        // 2. Reject login when group claims are missing
        await AssertOidcCallbackRejectedAsync(factory, idp, authUri =>
            idp.IssueAuthorizationCode(
                authUri,
                subject: "user-no-groups",
                subjectClaimType: "sub",
                groupClaimType: "directory_groups",
                groups: [],
                userInfoClaims: new Dictionary<string, object>
                {
                    ["sub"] = "user-no-groups",
                    ["oid"] = "user-no-groups"
                }),
            "did not contain any 'directory_groups' group claims");

        // 3. Reject login when groups are present but unmapped
        await AssertOidcCallbackRejectedAsync(factory, idp, authUri =>
            idp.IssueAuthorizationCode(
                authUri,
                subject: "user-unmapped",
                subjectClaimType: "sub",
                groupClaimType: "directory_groups",
                groups: ["Everyone", "HR-Users"],
                userInfoClaims: new Dictionary<string, object>
                {
                    ["sub"] = "user-unmapped",
                    ["oid"] = "user-unmapped"
                }),
            "none of your identity provider groups are mapped");

        // 4. Succeed when group claim is delivered via UserInfo endpoint (or ID token) and matches mapping
        using HttpClient client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://pki.contoso.com"),
            AllowAutoRedirect = false
        });
        Uri authRedirect = await StartOidcChallengeAsync(client, "/");
        var authQuery = QueryHelpers.ParseQuery(authRedirect.Query);
        string code = idp.IssueAuthorizationCode(
            authRedirect,
            subject: "oid-issuer-42",
            subjectClaimType: "sub",
            email: "federated.issuer@contoso.com",
            preferredUsername: "federated.issuer",
            displayName: "Federated Issuer",
            groups: null, // omitted from ID token, supplied via UserInfo endpoint!
            groupClaimType: "directory_groups",
            userInfoClaims: new Dictionary<string, object>
            {
                ["sub"] = "oid-issuer-42",
                ["oid"] = "oid-issuer-42",
                ["directory_groups"] = new[] { "ecdsa256-app-issuers" }
            });

        HttpResponseMessage callback = await client.GetAsync(
            $"/signin-oidc?code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(authQuery["state"].ToString())}");
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("/", callback.Headers.Location?.OriginalString);

        // 5. Verify CSR issuance policy & audit attribution for this external user
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            CertificateAuthorityService ca = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
            ApplicationUser extUser = await db.Users.SingleAsync(u => u.ExternalSubject == "oid-issuer-42");

            // Allowed: ECDSA P-256 CSR for service.app.contoso.com
            KeyPair ec256 = _crypto.KeyGen(256);
            string allowedCsr = _crypto.CSRGen(
                ec256, "service.app.contoso.com", ["service.app.contoso.com"], "US", "Washington", "Redmond", "Contoso", "IT", "");
            IssuanceOutcome issued = await ca.IssueCertificateFromCsrAsync(extUser.Id, allowedCsr);
            Assert.True(issued.Succeeded, issued.ErrorMessage);
            Assert.NotNull(issued.Record);
            Assert.Equal(extUser.Id, issued.Record!.RequestedByUserId);
            Assert.Equal("federated.issuer", issued.Record.RequestedByUserName);

            // Denied: RSA 2048 CSR for service.app.contoso.com (group mapping only allows tls-server-ecdsa-256)
            KeyPair rsa2048 = _crypto.KeyGen(2048);
            string wrongProfileCsr = _crypto.CSRGen(
                rsa2048, "service.app.contoso.com", ["service.app.contoso.com"], "US", "Washington", "Redmond", "Contoso", "IT", "");
            IssuanceOutcome deniedProfile = await ca.IssueCertificateFromCsrAsync(extUser.Id, wrongProfileCsr);
            Assert.False(deniedProfile.Succeeded);
            Assert.Contains("profile", deniedProfile.ErrorMessage, StringComparison.OrdinalIgnoreCase);

            // Denied: ECDSA P-256 CSR for forbidden.other.contoso.com
            string wrongDomainCsr = _crypto.CSRGen(
                ec256, "forbidden.other.contoso.com", ["forbidden.other.contoso.com"], "US", "Washington", "Redmond", "Contoso", "IT", "");
            IssuanceOutcome deniedDomain = await ca.IssueCertificateFromCsrAsync(extUser.Id, wrongDomainCsr);
            Assert.False(deniedDomain.Succeeded);
            Assert.Contains("forbidden.other.contoso.com", deniedDomain.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task GroupRemoval_AccountDisablement_BoundedLifetime_AndKillSwitch_InvalidateHttpSessionsAndBlazorCircuits()
    {
        var (factory, idp, _) = CreateOidcTestHost();

        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");
            await acct.SetExternalGroupRoleMappingAsync("Ops-Admins", AppRoles.Administrator, ["*.contoso.com"], "*");
        }

        // Sign in external user in "Ops-Admins"
        using HttpClient client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://pki.contoso.com"),
            AllowAutoRedirect = false
        });

        Uri authRedirect = await StartOidcChallengeAsync(client, "/admin");
        var authQuery = QueryHelpers.ParseQuery(authRedirect.Query);
        string code = idp.IssueAuthorizationCode(
            authRedirect,
            subject: "sub-ops-admin-1",
            email: "ops1@contoso.com",
            preferredUsername: "ops1",
            groups: ["Ops-Admins"]);

        HttpResponseMessage callback = await client.GetAsync(
            $"/signin-oidc?code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(authQuery["state"].ToString())}");
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("/admin", callback.Headers.Location?.OriginalString);
        CopyCookies(callback, client);

        // Verify HTTP access to /admin succeeds initially
        HttpResponseMessage adminBefore = await client.GetAsync("/admin");
        Assert.Equal(HttpStatusCode.OK, adminBefore.StatusCode);

        // Capture the ClaimsPrincipal and test Blazor Server circuit revalidation via RevalidatingIdentityAuthenticationStateProvider
        ClaimsPrincipal activeCircuitPrincipal;
        string extUserId;
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
            OidcFederationService oidcSvc = scope.ServiceProvider.GetRequiredService<OidcFederationService>();
            ApplicationUser extUser = await db.Users.SingleAsync(u => u.ExternalSubject == "sub-ops-admin-1");
            extUserId = extUser.Id;

            ClaimsIdentity extIdentity = new(
            [
                new Claim("sub", extUser.ExternalSubject!),
                new Claim("iss", idp.Issuer),
                new Claim("groups", "Ops-Admins"),
                new Claim("preferred_username", "ops1")
            ], "TestOidc");
            OidcLoginOutcome outcome = await oidcSvc.ProcessValidatedOidcLoginAsync(new ClaimsPrincipal(extIdentity), idp.Issuer);
            Assert.True(outcome.Succeeded);
            activeCircuitPrincipal = outcome.ApplicationPrincipal!;

            Assert.True(await RevalidateBlazorCircuitAsync(factory.Services, activeCircuitPrincipal));
        }

        // 1. Remove the "Ops-Admins" group mapping -> immediately invalidates both Blazor circuit, HTTP cookie session, and CSR policy
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            IssuancePolicyService policy = scope.ServiceProvider.GetRequiredService<IssuancePolicyService>();

            var (rmOk, rmErr) = await acct.RemoveExternalGroupRoleMappingByNameAsync("Ops-Admins");
            Assert.True(rmOk, rmErr);

            // Blazor circuit revalidation must now return false
            Assert.False(await RevalidateBlazorCircuitAsync(factory.Services, activeCircuitPrincipal));

            // Server-side policy must deny issuance
            KeyPair kp = _crypto.KeyGen(256);
            string csr = _crypto.CSRGen(kp, "web.contoso.com", ["web.contoso.com"], "US", "Washington", "Redmond", "Contoso", "IT", "");
            PolicyEvaluationResult evalAfterGroupRemoval = await policy.EvaluateCsrRequestAsync(extUserId, csr);
            Assert.False(evalAfterGroupRemoval.IsAllowed);
        }

        // Next HTTP request with the previously valid cookie must be rejected by CookieAuthenticationEvents.OnValidatePrincipal:
        // - Authorized HTTP endpoint redirects to /login
        // - Blazor /admin page renders NotAuthorized ("Authentication Required") instead of "CertRobo Administration"
        HttpResponseMessage adminEndpointAfterGroupRemoval = await client.GetAsync("/admin/pending-ca/csr");
        Assert.Equal(HttpStatusCode.Redirect, adminEndpointAfterGroupRemoval.StatusCode);
        Assert.Contains("/login", adminEndpointAfterGroupRemoval.Headers.Location?.OriginalString);

        HttpResponseMessage adminPageAfterGroupRemoval = await client.GetAsync("/admin");
        string adminAfterHtml = await adminPageAfterGroupRemoval.Content.ReadAsStringAsync();
        Assert.Contains("Authentication Required", adminAfterHtml);
        Assert.DoesNotContain("CertRobo Administration", adminAfterHtml);

        // 2. Re-add group mapping, sign in again, then test Administrator kill switch and Account Disablement
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            await acct.SetExternalGroupRoleMappingAsync("Ops-Admins", AppRoles.Administrator, ["*.contoso.com"], "*");
        }

        using HttpClient client2 = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://pki.contoso.com"),
            AllowAutoRedirect = false
        });
        Uri authRedirect2 = await StartOidcChallengeAsync(client2, "/admin");
        var authQuery2 = QueryHelpers.ParseQuery(authRedirect2.Query);
        string code2 = idp.IssueAuthorizationCode(
            authRedirect2,
            subject: "sub-ops-admin-1",
            email: "ops1@contoso.com",
            preferredUsername: "ops1",
            groups: ["Ops-Admins"]);
        HttpResponseMessage callback2 = await client2.GetAsync(
            $"/signin-oidc?code={Uri.EscapeDataString(code2)}&state={Uri.EscapeDataString(authQuery2["state"].ToString())}");
        CopyCookies(callback2, client2);
        Assert.Equal(HttpStatusCode.OK, (await client2.GetAsync("/admin")).StatusCode);

        // Trigger global external session kill switch
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            int invalidatedCount = await acct.InvalidateAllExternalSessionsAsync();
            Assert.True(invalidatedCount >= 1);
        }

        HttpResponseMessage afterKillSwitchEndpoint = await client2.GetAsync("/admin/pending-ca/csr");
        Assert.Equal(HttpStatusCode.Redirect, afterKillSwitchEndpoint.StatusCode);
        Assert.Contains("/login", afterKillSwitchEndpoint.Headers.Location?.OriginalString);

        HttpResponseMessage afterKillSwitchPage = await client2.GetAsync("/admin");
        string afterKillSwitchHtml = await afterKillSwitchPage.Content.ReadAsStringAsync();
        Assert.Contains("Authentication Required", afterKillSwitchHtml);
        Assert.DoesNotContain("CertRobo Administration", afterKillSwitchHtml);

        // 3. Disable the external account -> blocks new OIDC logins
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            await acct.SetUserDisabledAsync(extUserId, isDisabled: true);
        }

        await AssertOidcCallbackRejectedAsync(factory, idp, authUri =>
            idp.IssueAuthorizationCode(authUri, subject: "sub-ops-admin-1", groups: ["Ops-Admins"]),
            "disabled");

        // 4. Re-enable and verify bounded OIDC session lifetime (MaxSessionLifetimeMinutes) expiry
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            OidcFederationService oidcSvc = scope.ServiceProvider.GetRequiredService<OidcFederationService>();
            await acct.SetUserDisabledAsync(extUserId, isDisabled: false);

            ClaimsIdentity extIdentity = new(
            [
                new Claim("sub", "sub-ops-admin-1"),
                new Claim("iss", idp.Issuer),
                new Claim("groups", "Ops-Admins"),
                new Claim("preferred_username", "ops1")
            ], "TestOidc");
            OidcLoginOutcome freshOutcome = await oidcSvc.ProcessValidatedOidcLoginAsync(new ClaimsPrincipal(extIdentity), idp.Issuer);
            Assert.True(freshOutcome.Succeeded);

            // Replace OidcAuthTimeUtc with a timestamp 120 minutes in the past (exceeding default 60-minute MaxSessionLifetimeMinutes)
            ClaimsIdentity mutatedIdentity = new(
                freshOutcome.ApplicationPrincipal!.Claims
                    .Where(c => c.Type != OidcClaimTypes.OidcAuthTimeUtc)
                    .Append(new Claim(OidcClaimTypes.OidcAuthTimeUtc, DateTimeOffset.UtcNow.AddMinutes(-120).ToUnixTimeSeconds().ToString())),
                IdentityConstants.ApplicationScheme);
            ClaimsPrincipal expiredPrincipal = new(mutatedIdentity);

            Assert.False(await oidcSvc.ValidateSessionPrincipalAsync(expiredPrincipal));
            Assert.False(await RevalidateBlazorCircuitAsync(factory.Services, expiredPrincipal));
        }
    }

    [Fact]
    public async Task SafeRedirects_TrustedReverseProxyBoundaries_AndSignOutBehavior()
    {
        // 1. Verify safe return URL validation blocks external, scheme-relative, backslash, and login-loop URLs
        Assert.True(OidcFederationService.IsSafeLocalReturnUrl("/"));
        Assert.True(OidcFederationService.IsSafeLocalReturnUrl("/admin"));
        Assert.False(OidcFederationService.IsSafeLocalReturnUrl("https://evil.example/phish"));
        Assert.False(OidcFederationService.IsSafeLocalReturnUrl("//evil.example/phish"));
        Assert.False(OidcFederationService.IsSafeLocalReturnUrl("/\\evil.example"));
        Assert.False(OidcFederationService.IsSafeLocalReturnUrl("/login"));
        Assert.False(OidcFederationService.IsSafeLocalReturnUrl("/signin-oidc"));
        Assert.Equal("/", OidcFederationService.NormalizeReturnUrl("https://evil.example/phish"));

        // 2. Test reverse proxy boundary:
        //    - When request arrives from trusted proxy IP 10.20.30.40 (configured in KnownProxies) with X-Forwarded-Proto: https,
        //      the plain-HTTP internal request is upgraded to https and external OIDC callback succeeds.
        var (trustedProxyFactory, trustedIdp, _) = CreateOidcTestHost(
            configureOidc: opts => opts.EnableIdpSignOut = true,
            extraSettings: new Dictionary<string, string?>
            {
                ["CertRobo:ReverseProxy:KnownProxies:0"] = "10.20.30.40"
            },
            simulatedRemoteIp: IPAddress.Parse("10.20.30.40"));

        using (IServiceScope scope = trustedProxyFactory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");
            await acct.SetExternalGroupRoleMappingAsync("Proxy-Issuers", AppRoles.Issuer, ["*.contoso.com"], "*");
        }

        using HttpClient proxyClient = trustedProxyFactory.CreateClient(new WebApplicationFactoryClientOptions
        {
            // Internal connection between Nginx and Kestrel is http://, with X-Forwarded-Proto: https
            BaseAddress = new Uri("http://pki.contoso.com"),
            AllowAutoRedirect = false
        });
        proxyClient.DefaultRequestHeaders.Add("X-Forwarded-Proto", "https");
        proxyClient.DefaultRequestHeaders.Add("X-Forwarded-For", "203.0.113.50");

        Uri authRedirect = await StartOidcChallengeAsync(proxyClient, "https://evil.example/steal");
        var authQuery = QueryHelpers.ParseQuery(authRedirect.Query);
        string code = trustedIdp.IssueAuthorizationCode(
            authRedirect,
            subject: "sub-proxy-user",
            preferredUsername: "proxy.user",
            groups: ["Proxy-Issuers"]);

        HttpResponseMessage proxyCallback = await proxyClient.GetAsync(
            $"/signin-oidc?code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(authQuery["state"].ToString())}");
        Assert.Equal(HttpStatusCode.Redirect, proxyCallback.StatusCode);
        // Unsafe ReturnUrl ("https://evil.example/steal") must be normalized to "/"
        Assert.Equal("/", proxyCallback.Headers.Location?.OriginalString);
        CopyCookies(proxyCallback, proxyClient);

        // 3. Verify sign-out when EnableIdpSignOut == true clears local cookie and redirects to IdP end_session_endpoint
        HttpResponseMessage homePage = await proxyClient.GetAsync("/");
        string homeHtml = await homePage.Content.ReadAsStringAsync();
        string logoutToken = ExtractAntiforgeryToken(homeHtml);
        CopyCookies(homePage, proxyClient);

        HttpResponseMessage logoutResp = await proxyClient.PostAsync("/account/logout", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = logoutToken
        }));
        Assert.Equal(HttpStatusCode.Redirect, logoutResp.StatusCode);
        string logoutLocation = logoutResp.Headers.Location?.OriginalString ?? string.Empty;
        Assert.StartsWith($"{trustedIdp.Issuer}/oauth2/v1/logout", logoutLocation, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("post_logout_redirect_uri=", logoutLocation, StringComparison.OrdinalIgnoreCase);

        // 4. Test untrusted proxy IP (192.0.2.99 not in KnownProxies): spoofed X-Forwarded-Proto: https is ignored,
        //    so plain-HTTP callback to /signin-oidc is rejected because Request.IsHttps is false!
        var (untrustedProxyFactory, _, _) = CreateOidcTestHost(
            extraSettings: new Dictionary<string, string?>
            {
                ["CertRobo:ReverseProxy:KnownProxies:0"] = "10.20.30.40"
            },
            simulatedRemoteIp: IPAddress.Parse("192.0.2.99"));

        using (IServiceScope scope = untrustedProxyFactory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");
        }

        using HttpClient untrustedClient = untrustedProxyFactory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://pki.contoso.com"),
            AllowAutoRedirect = false
        });
        untrustedClient.DefaultRequestHeaders.Add("X-Forwarded-Proto", "https");

        HttpResponseMessage spoofedCallback = await untrustedClient.GetAsync("/signin-oidc?code=fake&state=fake");
        Assert.Equal(HttpStatusCode.Redirect, spoofedCallback.StatusCode);
        string spoofedLoc = Uri.UnescapeDataString(spoofedCallback.Headers.Location?.OriginalString ?? string.Empty);
        Assert.StartsWith("/login?error=", spoofedLoc);
        Assert.Contains("HTTPS", spoofedLoc, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AdminUi_And_BackupRestore_ManageAndPreserveExternalGroupMappings()
    {
        var (factory, _, _) = CreateOidcTestHost();

        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");
            await acct.SetExternalGroupRoleMappingAsync(
                "Okta-PKI-Issuers",
                AppRoles.Issuer,
                ["*.svc.contoso.com", "svc.contoso.com"],
                CertificateProfiles.EcdsaP384ServerId);
        }

        // 1. Sign in as local admin and verify /admin Users & Permissions tab renders OIDC group mappings and valid <label for="...">
        using HttpClient adminClient = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://pki.contoso.com"),
            AllowAutoRedirect = false
        });
        HttpResponseMessage loginGet = await adminClient.GetAsync("/login");
        string loginToken = ExtractAntiforgeryToken(await loginGet.Content.ReadAsStringAsync());
        CopyCookies(loginGet, adminClient);

        HttpResponseMessage loginPost = await adminClient.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = loginToken,
            ["userName"] = "admin",
            ["password"] = "AdminPass!2026",
            ["returnUrl"] = "/admin"
        }));
        CopyCookies(loginPost, adminClient);

        // Exercise Admin component directly on UsersAndPermissions tab
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            IReadOnlyList<ExternalGroupMappingSummaryDto> mappings = await acct.ListExternalGroupMappingsAsync();
            Assert.Single(mappings);
            Assert.Equal("Okta-PKI-Issuers", mappings[0].GroupName);
            Assert.Equal(AppRoles.Issuer, mappings[0].RoleName);
            Assert.Equal(2, mappings[0].DomainPermissions.Count);

            // Backup & Restore to a clean directory and verify external group mappings and domain rules survive restore
            BackupRestoreService backupSvc = scope.ServiceProvider.GetRequiredService<BackupRestoreService>();
            string srcDb = Path.Combine(_tempDir, "backup-src.db");
            string srcDp = Path.Combine(_tempDir, "backup-dp");
            Directory.CreateDirectory(srcDp);
            byte[] archive = await backupSvc.CreateConsistentBackupArchiveAsync(srcDb, srcDp);

            string restoredDir = Path.Combine(_tempDir, "restored-oidc");
            string restoredDb = Path.Combine(restoredDir, "certrobo.db");
            BackupRestoreService.RestoreBackupArchive(
                archive,
                restoredDb,
                Path.Combine(restoredDir, "ca"),
                Path.Combine(restoredDir, "dp"));

            DbContextOptions<CertRoboDbContext> restoredOpts = new DbContextOptionsBuilder<CertRoboDbContext>()
                .UseSqlite($"Data Source={restoredDb}")
                .Options;
            await using CertRoboDbContext restoredContext = new(restoredOpts);
            await restoredContext.EnsureSchemaUpgradedAsync();
            List<ExternalGroupRoleMapping> restoredMappings = await restoredContext.ExternalGroupRoleMappings.ToListAsync();
            Assert.Single(restoredMappings);
            Assert.Equal("Okta-PKI-Issuers", restoredMappings[0].GroupName);

            List<DomainPermissionRule> restoredGroupRules = await restoredContext.DomainPermissionRules
                .Where(r => r.SubjectType == PermissionSubjectTypes.ExternalGroup && r.SubjectValue == "Okta-PKI-Issuers")
                .ToListAsync();
            Assert.Equal(2, restoredGroupRules.Count);
        }
    }

    [Fact]
    public async Task CliCommands_AdminUiComponent_ConfigValidation_AndPrivilegeEscalationPrevention_WorkEndToEnd()
    {
        // 1. Validate OidcFederationOptions validation rules (HTTPS issuer, HTTPS callback URL, secret file support, GroupMappingsSpec parsing)
        string secretFile = Path.Combine(_tempDir, "oidc.secret");
        await File.WriteAllTextAsync(secretFile, "FileStoredClientSecret!2026\n");

        Microsoft.Extensions.Configuration.IConfigurationRoot config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CertRobo:Oidc:Enabled"] = "true",
                ["CertRobo:Oidc:DisplayName"] = "Generic OIDC",
                ["CertRobo:Oidc:Issuer"] = "https://idp.contoso.com/oauth2/default",
                ["CertRobo:Oidc:ClientId"] = "client-123",
                ["CertRobo:Oidc:ClientSecretFile"] = secretFile,
                ["CertRobo:Oidc:PublicCallbackUrl"] = "https://pki.contoso.com/signin-oidc",
                ["CertRobo:Oidc:GroupMappingsSpec"] = "PKI-Admins=Administrator:*;Web-Issuers=Issuer:*.web.contoso.com,web.contoso.com@tls-server-ecdsa-256"
            })
            .Build();

        OidcFederationOptions parsedOpts = OidcFederationOptions.FromConfiguration(config);
        Assert.True(parsedOpts.Validate().IsValid, parsedOpts.Validate().ErrorMessage);
        Assert.Equal("FileStoredClientSecret!2026", parsedOpts.ResolveEffectiveClientSecret());
        Assert.Equal(2, parsedOpts.GroupMappings.Count);
        Assert.Equal("PKI-Admins", parsedOpts.GroupMappings[0].GroupName);
        Assert.Equal(AppRoles.Administrator, parsedOpts.GroupMappings[0].Role);
        Assert.Equal("Web-Issuers", parsedOpts.GroupMappings[1].GroupName);
        Assert.Equal(AppRoles.Issuer, parsedOpts.GroupMappings[1].Role);
        Assert.Equal(CertificateProfiles.EcdsaP256ServerId, parsedOpts.GroupMappings[1].AllowedProfileId);

        // Plain HTTP issuer or callback URL must be rejected
        OidcFederationOptions badHttpIssuer = new()
        {
            Enabled = true,
            Issuer = "http://insecure.idp.contoso.com",
            ClientId = "cid",
            ClientSecret = "sec",
            PublicCallbackUrl = "https://pki.contoso.com/signin-oidc"
        };
        Assert.False(badHttpIssuer.Validate().IsValid);

        OidcFederationOptions badCallback = new()
        {
            Enabled = true,
            Issuer = "https://idp.contoso.com",
            ClientId = "cid",
            ClientSecret = "sec",
            PublicCallbackUrl = "https://pki.contoso.com/"
        };
        Assert.False(badCallback.Validate().IsValid);

        // 2. Verify privilege escalation prevention: an external principal carrying unmapped or forged Role claims
        //    ("Administrator") in the IdP token while only mapped to an Issuer group NEVER receives Administrator privileges.
        var (factory, idp, _) = CreateOidcTestHost();
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            OidcFederationService oidcSvc = scope.ServiceProvider.GetRequiredService<OidcFederationService>();
            UserManager<ApplicationUser> userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

            await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");
            await acct.SetExternalGroupRoleMappingAsync("Only-Issuers", AppRoles.Issuer, ["*.contoso.com"], "*");

            ClaimsIdentity forgedIdpClaims = new(
            [
                new Claim("sub", "sub-forged-role-attempt"),
                new Claim("iss", idp.Issuer),
                new Claim("groups", "Only-Issuers"),
                new Claim(ClaimTypes.Role, AppRoles.Administrator),
                new Claim("role", AppRoles.Administrator),
                new Claim("roles", AppRoles.Administrator)
            ], "ForgedOidc");

            OidcLoginOutcome outcome = await oidcSvc.ProcessValidatedOidcLoginAsync(new ClaimsPrincipal(forgedIdpClaims), idp.Issuer);
            Assert.True(outcome.Succeeded);
            Assert.NotNull(outcome.User);
            Assert.False(await userMgr.IsInRoleAsync(outcome.User!, AppRoles.Administrator));
            Assert.True(await userMgr.IsInRoleAsync(outcome.User!, AppRoles.Issuer));
            Assert.False(outcome.ApplicationPrincipal!.IsInRole(AppRoles.Administrator));

            // 3. Exercise Pages.Admin UI methods for adding/removing external group mappings and invalidating sessions
            CertRobo.Pages.Admin adminPage = new();
            SetProperty(adminPage, "AccountService", acct);
            SetProperty(adminPage, "CaService", scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>());
            SetProperty(adminPage, "CesService", scope.ServiceProvider.GetRequiredService<AdCsCesEnrollmentService>());
            SetProperty(adminPage, "BackupService", scope.ServiceProvider.GetRequiredService<BackupRestoreService>());
            SetProperty(adminPage, "MigrationService", scope.ServiceProvider.GetRequiredService<LegacySettingsMigrationService>());
            SetProperty(adminPage, "Configuration", scope.ServiceProvider.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>());
            SetProperty(adminPage, "HostEnvironment", scope.ServiceProvider.GetRequiredService<IWebHostEnvironment>());
            SetProperty(adminPage, "AuthenticationStateProvider", scope.ServiceProvider.GetRequiredService<AuthenticationStateProvider>());
            SetProperty(adminPage, "NotificationService", scope.ServiceProvider.GetRequiredService<Radzen.NotificationService>());

            await InvokeMethodAsync(adminPage, "OnInitializedAsync");

            SetField(adminPage, "newGroupMappingName", "UI-Created-Group");
            SetField(adminPage, "newGroupMappingRole", AppRoles.Issuer);
            SetField(adminPage, "newGroupMappingProfile", CertificateProfiles.Rsa2048ServerId);
            SetField(adminPage, "newGroupMappingDomains", "*.ui.contoso.com");
            await InvokeMethodAsync(adminPage, "SaveExternalGroupMappingClick");

            IReadOnlyList<ExternalGroupMappingSummaryDto> uiMappings = GetField<IReadOnlyList<ExternalGroupMappingSummaryDto>>(adminPage, "externalGroupMappings");
            ExternalGroupMappingSummaryDto? createdUiMap = uiMappings.FirstOrDefault(m => m.GroupName == "UI-Created-Group");
            Assert.NotNull(createdUiMap);
            Assert.Single(createdUiMap!.DomainPermissions);
            Assert.Equal("*.ui.contoso.com", createdUiMap.DomainPermissions[0].DomainPattern);

            await InvokeMethodAsync(adminPage, "InvalidateAllExternalSessionsClick");
            Assert.Contains("External Sessions Invalidated", GetField<string?>(adminPage, "statusBannerMessage"));

            await InvokeMethodAsync(adminPage, "RemoveExternalGroupMappingClick", createdUiMap);
            uiMappings = GetField<IReadOnlyList<ExternalGroupMappingSummaryDto>>(adminPage, "externalGroupMappings");
            Assert.DoesNotContain(uiMappings, m => m.GroupName == "UI-Created-Group");
        }

        // 4. Exercise CLI commands: --add-oidc-group-mapping, --remove-oidc-group-mapping, --invalidate-external-sessions
        string cliDb = Path.Combine(_tempDir, "cli-oidc.db");
        string cliCa = Path.Combine(_tempDir, "cli-oidc-ca");
        var (addExit, addOut, addErr) = await RunCliAsync(
            cliDb, cliCa,
            ["--add-oidc-group-mapping", "CLI-Issuers", "Issuer", "*.cli.contoso.com,cli.contoso.com", "tls-server-ecdsa-256"]);
        Assert.True(addExit == 0, $"CLI add failed: {addOut}\n{addErr}");
        Assert.Contains("Configured external group mapping 'CLI-Issuers'", addOut);

        var (invExit, invOut, invErr) = await RunCliAsync(
            cliDb, cliCa,
            ["--invalidate-external-sessions"]);
        Assert.True(invExit == 0, $"CLI invalidate failed: {invOut}\n{invErr}");
        Assert.Contains("Invalidated active sessions", invOut);

        var (rmExit, rmOut, rmErr) = await RunCliAsync(
            cliDb, cliCa,
            ["--remove-oidc-group-mapping", "CLI-Issuers"]);
        Assert.True(rmExit == 0, $"CLI remove failed: {rmOut}\n{rmErr}");
        Assert.Contains("Removed external group mapping 'CLI-Issuers'", rmOut);
    }

    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunCliAsync(
        string dbPath,
        string caDir,
        IReadOnlyList<string> cliArgs)
    {
        string certRoboDll = typeof(Program).Assembly.Location;
        System.Diagnostics.ProcessStartInfo psi = new("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        psi.ArgumentList.Add("exec");
        psi.ArgumentList.Add(certRoboDll);
        foreach (string arg in cliArgs)
        {
            psi.ArgumentList.Add(arg);
        }

        psi.Environment["CertRobo__DataDirectory"] = Path.GetDirectoryName(dbPath)!;
        psi.Environment["CertRobo__SqliteFilePath"] = dbPath;
        psi.Environment["CertRobo__CaStorageDirectory"] = caDir;

        using System.Diagnostics.Process proc = System.Diagnostics.Process.Start(psi)!;
        string stdout = await proc.StandardOutput.ReadToEndAsync();
        string stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        return (proc.ExitCode, stdout, stderr);
    }

    private static void SetProperty(object instance, string name, object value)
    {
        var prop = instance.GetType().GetProperty(name, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic)!;
        prop.SetValue(instance, value);
    }

    private static T GetField<T>(object instance, string name)
    {
        var field = instance.GetType().GetField(name, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        return (T)field.GetValue(instance)!;
    }

    private static void SetField(object instance, string name, object? value)
    {
        var field = instance.GetType().GetField(name, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        field.SetValue(instance, value);
    }

    private static async Task InvokeMethodAsync(object instance, string name, params object[] args)
    {
        var method = instance.GetType().GetMethod(name, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        if (method.Invoke(instance, args) is Task task)
        {
            await task;
        }
    }

    private static async Task<bool> RevalidateBlazorCircuitAsync(IServiceProvider rootServices, ClaimsPrincipal principal)
    {
        RevalidatingIdentityAuthenticationStateProvider provider = new(
            rootServices.GetRequiredService<ILoggerFactory>(),
            rootServices.GetRequiredService<IServiceScopeFactory>(),
            rootServices.GetRequiredService<IOptions<IdentityOptions>>(),
            rootServices.GetService<OidcFederationOptions>());

        var method = typeof(RevalidatingIdentityAuthenticationStateProvider).GetMethod(
            "ValidateAuthenticationStateAsync",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;

        Task<bool> task = (Task<bool>)method.Invoke(
            provider,
            [new AuthenticationState(principal), CancellationToken.None])!;
        return await task;
    }

    private static async Task AssertOidcCallbackRejectedAsync(
        WebApplicationFactory<Program> factory,
        LocalSignedOidcIdpFixture idp,
        Func<Uri, string> issueCodeFunc,
        string expectedErrorSubstring)
    {
        using HttpClient client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://pki.contoso.com"),
            AllowAutoRedirect = false
        });

        Uri authRedirect = await StartOidcChallengeAsync(client, "/");
        var authQuery = QueryHelpers.ParseQuery(authRedirect.Query);
        string code = issueCodeFunc(authRedirect);

        HttpResponseMessage callback = await client.GetAsync(
            $"/signin-oidc?code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(authQuery["state"].ToString())}");
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);

        string location = Uri.UnescapeDataString(callback.Headers.Location?.OriginalString ?? string.Empty);
        Assert.StartsWith("/login?error=", location);
        Assert.Contains(expectedErrorSubstring, location, StringComparison.OrdinalIgnoreCase);

        // Ensure no CertRobo.Auth session cookie was granted
        if (callback.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            Assert.DoesNotContain(setCookies, c => c.StartsWith("CertRobo.Auth=", StringComparison.OrdinalIgnoreCase) && !c.Contains("CertRobo.Auth=;"));
        }
    }

    private static async Task<Uri> StartOidcChallengeAsync(HttpClient client, string returnUrl)
    {
        HttpResponseMessage loginGet = await client.GetAsync("/login");
        string loginHtml = await loginGet.Content.ReadAsStringAsync();
        string token = ExtractAntiforgeryToken(loginHtml);
        CopyCookies(loginGet, client);

        HttpResponseMessage challengePost = await client.PostAsync("/account/external-login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
            ["returnUrl"] = returnUrl
        }));
        Assert.Equal(HttpStatusCode.Redirect, challengePost.StatusCode);
        CopyCookies(challengePost, client);

        Uri? redirectUri = challengePost.Headers.Location;
        Assert.NotNull(redirectUri);
        return redirectUri!;
    }

    private static string ExtractAntiforgeryToken(string html)
    {
        Match m = Regex.Match(html, "name=\"__RequestVerificationToken\"\\s+value=\"([^\"]+)\"");
        Assert.True(m.Success, "Could not find __RequestVerificationToken in HTML.");
        return WebUtility.HtmlDecode(m.Groups[1].Value);
    }

    private static void CopyCookies(HttpResponseMessage response, HttpClient client)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? setCookies))
        {
            return;
        }

        Dictionary<string, string> jar = new(StringComparer.OrdinalIgnoreCase);
        if (client.DefaultRequestHeaders.TryGetValues("Cookie", out IEnumerable<string>? existing))
        {
            foreach (string raw in existing.SelectMany(h => h.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)))
            {
                int eq = raw.IndexOf('=');
                if (eq > 0)
                {
                    jar[raw[..eq]] = raw[(eq + 1)..];
                }
            }
            client.DefaultRequestHeaders.Remove("Cookie");
        }

        foreach (string cookieHeader in setCookies)
        {
            string nameValue = cookieHeader.Split(';', 2)[0].Trim();
            int eq = nameValue.IndexOf('=');
            if (eq > 0)
            {
                string key = nameValue[..eq];
                string val = nameValue[(eq + 1)..];
                if (string.IsNullOrEmpty(val))
                {
                    jar.Remove(key);
                }
                else
                {
                    jar[key] = val;
                }
            }
        }

        if (jar.Count > 0)
        {
            client.DefaultRequestHeaders.Add("Cookie", string.Join("; ", jar.Select(kv => $"{kv.Key}={kv.Value}")));
        }
    }

    public void Dispose()
    {
        foreach (IDisposable d in _disposables)
        {
            try { d.Dispose(); }
            catch { }
        }
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (Directory.Exists(_tempDir))
        {
            try { Directory.Delete(_tempDir, recursive: true); }
            catch { }
        }
    }
}

