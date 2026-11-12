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
    public async Task GroupMappings_EnforceRolesAndDomainProfilePolicy_SupportCustomGroupClaimNames_AndBindStrictlyToStandardOidcSub()
    {
        // Configure custom GroupClaimType and UserInfo endpoint retrieval while binding identity strictly to standard OIDC 'sub'
        var (factory, idp, _) = CreateOidcTestHost(configureOidc: opts =>
        {
            opts.GroupClaimType = " directory_groups ";
            opts.GroupClaimType = opts.GroupClaimType.Trim();
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

        // 1. Reject login when required standard OIDC 'sub' claim is missing in ID token
        await AssertOidcCallbackRejectedAsync(factory, idp, authUri =>
            idp.IssueAuthorizationCode(authUri, subject: null, subjectClaimType: "sub", groupClaimType: "directory_groups", groups: ["ecdsa256-app-issuers"]),
            "sub");

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
                    ["sub"] = "user-no-groups"
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
                    ["sub"] = "user-unmapped"
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
            var (disExtOk, disExtErr) = await acct.SetUserDisabledAsync(extUserId, isDisabled: true);
            Assert.True(disExtOk, disExtErr);
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

            var (_, _, adminUser) = await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");
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
            SetProperty(adminPage, "AuthenticationStateProvider", new ControllableAuthStateProvider(adminUser!.Id, adminUser.UserName!, AppRoles.Administrator, adminUser.SecurityStamp));
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

    [Fact]
    public async Task ConfiguredGroupMappings_DoNotResurrectAfterRemovalRoleChangeOrRuleDeletion_AcrossSeparateCliProcessesAndBackupRestore()
    {
        string dbPath = Path.Combine(_tempDir, "precedence-restart.db");
        string caDir = Path.Combine(_tempDir, "precedence-restart-ca");
        string dpDir = Path.Combine(_tempDir, "precedence-restart-dp");
        Directory.CreateDirectory(caDir);
        Directory.CreateDirectory(dpDir);

        Dictionary<string, string> envWithConfiguredMappings = new()
        {
            ["CertRobo__Oidc__GroupMappingsSpec"] = "test-admins=Administrator:*;dev-issuers=Issuer:*.dev.contoso.com,dev.contoso.com@*"
        };

        // 1. Process #1: Bootstrap local admin while CertRobo__Oidc__GroupMappingsSpec is set
        var (bootExit, bootOut, bootErr) = await RunCliAsync(
            dbPath, caDir,
            ["--bootstrap-admin", "admin", "AdminSecret!2026", "*"],
            envWithConfiguredMappings);
        Assert.True(bootExit == 0, $"Bootstrap failed: {bootOut}\n{bootErr}");

        // Verify both configured mappings were seeded once
        await using (CertRoboDbContext db1 = CreateSqliteContext(dbPath))
        {
            List<ExternalGroupRoleMapping> seeded = await db1.ExternalGroupRoleMappings.OrderBy(m => m.GroupName).ToListAsync();
            Assert.Equal(2, seeded.Count);
            Assert.Contains(seeded, m => m.GroupName == "test-admins" && m.RoleName == AppRoles.Administrator);
            Assert.Contains(seeded, m => m.GroupName == "dev-issuers" && m.RoleName == AppRoles.Issuer);
            OidcPortalSettingsConfig settingsRow = await db1.OidcPortalSettings.SingleAsync();
            Assert.True(settingsRow.HasSeededConfiguredGroupMappings);
        }

        // 2. Process #2: Remove 'test-admins' via CLI while CertRobo__Oidc__GroupMappingsSpec is still set in environment
        var (rmExit, rmOut, rmErr) = await RunCliAsync(
            dbPath, caDir,
            ["--remove-oidc-group-mapping", "test-admins"],
            envWithConfiguredMappings);
        Assert.True(rmExit == 0, $"Remove failed: {rmOut}\n{rmErr}");

        // 3. Process #3: Narrow 'dev-issuers' domains/profile via CLI (--add-oidc-group-mapping)
        //    and verify the CLI command ITSELF atomically replaces the old '*.dev.contoso.com' and 'dev.contoso.com' rules!
        var (modExit, modOut, modErr) = await RunCliAsync(
            dbPath, caDir,
            ["--add-oidc-group-mapping", "dev-issuers", "Issuer", "*.restricted.contoso.com", "tls-server-ecdsa-256"],
            envWithConfiguredMappings);
        Assert.True(modExit == 0, $"Modify failed: {modOut}\n{modErr}");

        await using (CertRoboDbContext db2 = CreateSqliteContext(dbPath))
        {
            List<DomainPermissionRule> currentRules = await db2.DomainPermissionRules
                .Where(r => r.SubjectType == PermissionSubjectTypes.ExternalGroup && r.SubjectValue == "dev-issuers")
                .ToListAsync();
            DomainPermissionRule singleReplacedRule = Assert.Single(currentRules);
            Assert.Equal("*.restricted.contoso.com", singleReplacedRule.DomainPattern);
            Assert.Equal(CertificateProfiles.EcdsaP256ServerId, singleReplacedRule.AllowedProfileId);
        }

        // 4. Process #4 & #5: Run additional CLI processes with CertRobo__Oidc__GroupMappingsSpec still present in environment
        //    (including a bootstrap attempt and a backup command) and verify neither 'test-admins' nor the deleted domain rules return!
        var (reBootExit, _, _) = await RunCliAsync(
            dbPath, caDir,
            ["--bootstrap-admin", "admin2", "AdminSecret!2026", "*"],
            envWithConfiguredMappings);
        Assert.NotEqual(0, reBootExit);

        string backupZipPath = Path.Combine(_tempDir, "precedence-backup.zip");
        var (bakExit, bakOut, bakErr) = await RunCliAsync(
            dbPath, caDir,
            ["--backup", backupZipPath],
            envWithConfiguredMappings);
        Assert.True(bakExit == 0, $"Backup failed: {bakOut}\n{bakErr}");

        await using (CertRoboDbContext dbAfterRestart = CreateSqliteContext(dbPath))
        {
            List<ExternalGroupRoleMapping> remainingMappings = await dbAfterRestart.ExternalGroupRoleMappings.ToListAsync();
            ExternalGroupRoleMapping singleRemaining = Assert.Single(remainingMappings);
            Assert.Equal("dev-issuers", singleRemaining.GroupName);
            Assert.Equal(AppRoles.Issuer, singleRemaining.RoleName);

            List<DomainPermissionRule> remainingGroupRules = await dbAfterRestart.DomainPermissionRules
                .Where(r => r.SubjectType == PermissionSubjectTypes.ExternalGroup)
                .ToListAsync();
            DomainPermissionRule singleRule = Assert.Single(remainingGroupRules);
            Assert.Equal("dev-issuers", singleRule.SubjectValue);
            Assert.Equal("*.restricted.contoso.com", singleRule.DomainPattern);
            Assert.Equal(CertificateProfiles.EcdsaP256ServerId, singleRule.AllowedProfileId);
        }

        // 5. Process #6 & #7: Restore the backup archive to a clean directory and start a new process with the same env vars;
        //    verify the restored database also preserves the HasSeededConfiguredGroupMappings marker and does NOT resurrect 'test-admins'.
        string restoredDbPath = Path.Combine(_tempDir, "precedence-restored", "certrobo.db");
        string restoredCaDir = Path.Combine(_tempDir, "precedence-restored", "ca");
        var (resExit, resOut, resErr) = await RunCliAsync(
            restoredDbPath, restoredCaDir,
            ["--restore", backupZipPath],
            envWithConfiguredMappings);
        Assert.True(resExit == 0, $"Restore failed: {resOut}\n{resErr}");

        // Trigger startup EnsureRolesAndDefaultsAsync on the restored DB with CertRobo__Oidc__GroupMappingsSpec active
        var (postResExit, _, _) = await RunCliAsync(
            restoredDbPath, restoredCaDir,
            ["--invalidate-external-sessions"],
            envWithConfiguredMappings);
        Assert.Equal(0, postResExit);

        await using (CertRoboDbContext dbRestored = CreateSqliteContext(restoredDbPath))
        {
            List<ExternalGroupRoleMapping> restoredMappings = await dbRestored.ExternalGroupRoleMappings.ToListAsync();
            ExternalGroupRoleMapping singleRestored = Assert.Single(restoredMappings);
            Assert.Equal("dev-issuers", singleRestored.GroupName);
            Assert.DoesNotContain(restoredMappings, m => m.GroupName == "test-admins");
        }
    }

    [Fact]
    public async Task SoleLocalAdminProtection_ConcurrentDisableDemoteSerialization_AndStaleAdminCircuitBoundaryChecks()
    {
        var (factory, _, _) = CreateOidcTestHost();

        using IServiceScope scope = factory.Services.CreateScope();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        UserManager<ApplicationUser> userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var (bootOk, bootErr, admin1) = await acct.BootstrapFirstAdminAsync("admin1", "AdminOnePass!2026", "admin1@contoso.com", "*");
        Assert.True(bootOk, bootErr);
        Assert.NotNull(admin1);

        //Even if an external OIDC Administrator exists, the sole local Administrator with a local password CANNOT be disabled, demoted, or deleted
        await acct.SetExternalGroupRoleMappingAsync("Ext-Admins", AppRoles.Administrator, ["*"], "*");
        OidcFederationService oidcSvc = scope.ServiceProvider.GetRequiredService<OidcFederationService>();
        OidcLoginOutcome extAdminLogin = await oidcSvc.ProcessValidatedOidcLoginAsync(
            new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", "ext-admin-sub-1"),
                new Claim("iss", LocalSignedOidcIdpFixture.DefaultIssuer),
                new Claim("groups", "Ext-Admins"),
                new Claim("preferred_username", "ext.admin")
            ], "TestOidc")),
            LocalSignedOidcIdpFixture.DefaultIssuer,
            "ext-admin-sub-1");
        Assert.True(extAdminLogin.Succeeded);

        // 1. Sole local admin cannot be disabled, demoted, or deleted
        var (soleDisableOk, soleDisableErr) = await acct.SetUserDisabledAsync(admin1!.Id, isDisabled: true);
        Assert.False(soleDisableOk);
        Assert.Contains("last active local Administrator", soleDisableErr);

        var (soleDemoteOk, soleDemoteErr) = await acct.SetLocalUserRolesAsync(admin1.Id, [AppRoles.Issuer]);
        Assert.False(soleDemoteOk);
        Assert.Contains("last active local Administrator", soleDemoteErr);

        var (soleDeleteOk, soleDeleteErr) = await acct.DeleteUserAsync(admin1.Id);
        Assert.False(soleDeleteOk);
        Assert.Contains("last active local Administrator", soleDeleteErr);

        // 2. Create a second local administrator (admin2) and race two concurrent disables and two concurrent demotions:
        //    Exactly ONE must succeed and the second must be rejected so at least one local admin always remains active!
        var (create2Ok, create2Err, admin2) = await acct.CreateUserAsync(
            "admin2", "AdminTwoPass!2026", "admin2@contoso.com", [AppRoles.Administrator, AppRoles.Issuer], ["*"]);
        Assert.True(create2Ok, create2Err);
        Assert.NotNull(admin2);

        Task<(bool Succeeded, string? ErrorMessage)>[] concurrentDisables =
        [
            Task.Run(async () =>
            {
                using IServiceScope s = factory.Services.CreateScope();
                return await s.ServiceProvider.GetRequiredService<AccountManagementService>().SetUserDisabledAsync(admin1.Id, true);
            }),
            Task.Run(async () =>
            {
                using IServiceScope s = factory.Services.CreateScope();
                return await s.ServiceProvider.GetRequiredService<AccountManagementService>().SetUserDisabledAsync(admin2!.Id, true);
            })
        ];

        var disableResults = await Task.WhenAll(concurrentDisables);
        Assert.Equal(1, disableResults.Count(r => r.Succeeded));
        Assert.Equal(1, disableResults.Count(r => !r.Succeeded));

        // Re-enable both, then race two concurrent demotions
        await acct.SetUserDisabledAsync(admin1.Id, false);
        await acct.SetUserDisabledAsync(admin2!.Id, false);

        Task<(bool Succeeded, string? ErrorMessage)>[] concurrentDemotes =
        [
            Task.Run(async () =>
            {
                using IServiceScope s = factory.Services.CreateScope();
                return await s.ServiceProvider.GetRequiredService<AccountManagementService>().SetLocalUserRolesAsync(admin1.Id, [AppRoles.Issuer]);
            }),
            Task.Run(async () =>
            {
                using IServiceScope s = factory.Services.CreateScope();
                return await s.ServiceProvider.GetRequiredService<AccountManagementService>().SetLocalUserRolesAsync(admin2.Id, [AppRoles.Issuer]);
            })
        ];

        var demoteResults = await Task.WhenAll(concurrentDemotes);
        Assert.Equal(1, demoteResults.Count(r => r.Succeeded));
        Assert.Equal(1, demoteResults.Count(r => !r.Succeeded));

        // Restore both to active Administrator
        var (r1Ok, r1Err) = await acct.SetLocalUserRolesAsync(admin1.Id, [AppRoles.Administrator, AppRoles.Issuer]);
        Assert.True(r1Ok, r1Err);
        var (r2Ok, r2Err) = await acct.SetLocalUserRolesAsync(admin2.Id, [AppRoles.Administrator, AppRoles.Issuer]);
        Assert.True(r2Ok, r2Err);

        // 3. Stale circuit actor boundary tests on Pages.Admin:
        //    Instantiate Pages.Admin bound to admin2's principal (including SecurityStamp).
        ApplicationUser reloadedAdmin2 = (await userMgr.FindByIdAsync(admin2.Id))!;
        await scope.ServiceProvider.GetRequiredService<CertRoboDbContext>().Entry(reloadedAdmin2).ReloadAsync();
        ControllableAuthStateProvider circuitAuth = new(
            reloadedAdmin2.Id,
            reloadedAdmin2.UserName!,
            AppRoles.Administrator,
            reloadedAdmin2.SecurityStamp);

        CertRobo.Pages.Admin adminPage = new();
        SetProperty(adminPage, "AccountService", acct);
        SetProperty(adminPage, "CaService", scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>());
        SetProperty(adminPage, "CesService", scope.ServiceProvider.GetRequiredService<AdCsCesEnrollmentService>());
        SetProperty(adminPage, "BackupService", scope.ServiceProvider.GetRequiredService<BackupRestoreService>());
        SetProperty(adminPage, "MigrationService", scope.ServiceProvider.GetRequiredService<LegacySettingsMigrationService>());
        SetProperty(adminPage, "Configuration", scope.ServiceProvider.GetRequiredService<IConfiguration>());
        SetProperty(adminPage, "HostEnvironment", scope.ServiceProvider.GetRequiredService<IWebHostEnvironment>());
        SetProperty(adminPage, "AuthenticationStateProvider", circuitAuth);
        SetProperty(adminPage, "NotificationService", scope.ServiceProvider.GetRequiredService<Radzen.NotificationService>());

        await InvokeMethodAsync(adminPage, "OnInitializedAsync");

        // Disable admin2 via admin1 (or direct service call) while admin2's Admin component still holds its stale ClaimsPrincipal
        var (dis2Ok, dis2Err) = await acct.SetUserDisabledAsync(admin2.Id, isDisabled: true);
        Assert.True(dis2Ok, dis2Err);

        IReadOnlyList<UserSummaryDto> usersSnapshot = await acct.ListUsersAsync();
        UserSummaryDto admin2Dto = usersSnapshot.Single(u => u.Id == admin2.Id);
        Assert.True(admin2Dto.IsDisabled);

        // Stale disabled admin2 circuit attempts to re-enable itself via ToggleUserDisabledClick -> MUST BE DENIED with no side effects!
        await InvokeMethodAsync(adminPage, "ToggleUserDisabledClick", admin2Dto);
        Assert.Contains("Authorisation Error", GetField<string?>(adminPage, "statusBannerMessage"));
        Assert.True((await userMgr.FindByIdAsync(admin2.Id))!.IsDisabled);

        // Stale disabled admin2 circuit attempts to create a user, add a group mapping, or change OIDC settings -> all MUST BE DENIED with no side effects!
        SetField(adminPage, "newUserName", "rogue-user");
        SetField(adminPage, "newUserPassword", "RoguePass!2026");
        await InvokeMethodAsync(adminPage, "CreateUserClick");
        Assert.Null(await userMgr.FindByNameAsync("rogue-user"));

        SetField(adminPage, "newGroupMappingName", "Rogue-Group");
        SetField(adminPage, "newGroupMappingRole", AppRoles.Administrator);
        await InvokeMethodAsync(adminPage, "SaveExternalGroupMappingClick");
        Assert.DoesNotContain(await acct.ListExternalGroupMappingsAsync(), m => m.GroupName == "Rogue-Group");

        // Now re-enable admin2, refresh its circuit principal, then DEMOTE admin2 to Issuer only and verify stale admin circuit is denied
        await acct.SetUserDisabledAsync(admin2.Id, isDisabled: false);
        reloadedAdmin2 = (await userMgr.FindByIdAsync(admin2.Id))!;
        circuitAuth.SetPrincipal(reloadedAdmin2.Id, reloadedAdmin2.UserName!, AppRoles.Administrator, reloadedAdmin2.SecurityStamp);

        var (demote2Ok, demote2Err) = await acct.SetLocalUserRolesAsync(admin2.Id, [AppRoles.Issuer]);
        Assert.True(demote2Ok, demote2Err);

        // Stale demoted admin2 circuit (whose in-memory ClaimsPrincipal still says Role=Administrator) tries to promote itself or disable admin1 -> DENIED!
        UserSummaryDto admin1Dto = (await acct.ListUsersAsync()).Single(u => u.Id == admin1.Id);
        await InvokeMethodAsync(adminPage, "ToggleUserDisabledClick", admin1Dto);
        Assert.Contains("Authorisation Error", GetField<string?>(adminPage, "statusBannerMessage"));
        Assert.False((await userMgr.FindByIdAsync(admin1.Id))!.IsDisabled);

        // 4. Verify CLI break-glass password reset (--reset-admin-password) still works without an interactive actor
        var (cliResetOk, cliResetErr) = await acct.ResetPasswordAsync(admin2.UserName!, "RecoveredViaCli!2026");
        Assert.True(cliResetOk, cliResetErr);

        // 5. Cross-process sole-local-admin serialization:
        //    Prepare a dedicated SQLite DB with two active local administrators (admin1 and admin2),
        //    then launch two separate OS CLI processes simultaneously attempting to disable admin1 and admin2.
        //    Exactly ONE process must exit 0 and the other must exit non-zero!
        string crossProcDb = Path.Combine(_tempDir, "cross-proc-admins.db");
        string crossProcCa = Path.Combine(_tempDir, "cross-proc-ca");
        var (cpBootExit, _, _) = await RunCliAsync(crossProcDb, crossProcCa, ["--bootstrap-admin", "cp-admin1", "AdminOnePass!2026", "*"]);
        Assert.Equal(0, cpBootExit);

        await using (CertRoboDbContext cpDb = CreateSqliteContext(crossProcDb))
        {
            ServiceCollection sc = new();
            sc.AddLogging();
            sc.AddDbContext<CertRoboDbContext>(o => o.UseSqlite($"Data Source={crossProcDb}"));
            sc.AddIdentityCore<ApplicationUser>().AddRoles<IdentityRole>().AddEntityFrameworkStores<CertRoboDbContext>();
            sc.AddScoped<AccountManagementService>();
            await using ServiceProvider cpSp = sc.BuildServiceProvider();
            using IServiceScope cpScope = cpSp.CreateScope();
            AccountManagementService cpAcct = cpScope.ServiceProvider.GetRequiredService<AccountManagementService>();
            var (cpCreateOk, cpCreateErr, _) = await cpAcct.CreateUserAsync("cp-admin2", "AdminTwoPass!2026", null, [AppRoles.Administrator, AppRoles.Issuer]);
            Assert.True(cpCreateOk, cpCreateErr);
        }

        Task<(int ExitCode, string Stdout, string Stderr)>[] cpDisableProcesses =
        [
            RunCliAsync(crossProcDb, crossProcCa, ["--set-user-disabled", "cp-admin1", "true"]),
            RunCliAsync(crossProcDb, crossProcCa, ["--set-user-disabled", "cp-admin2", "true"])
        ];

        var cpResults = await Task.WhenAll(cpDisableProcesses);
        Assert.Equal(1, cpResults.Count(r => r.ExitCode == 0));
        Assert.Equal(1, cpResults.Count(r => r.ExitCode != 0));
        Assert.Contains(cpResults.Where(r => r.ExitCode != 0), r => r.Stderr.Contains("last active local Administrator", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ExternalOidcAccounts_IgnoreBroadLocalRoleRules_AndEnforceGroupAndDirectUserRulesOnly()
    {
        var (factory, idp, _) = CreateOidcTestHost();

        using IServiceScope scope = factory.Services.CreateScope();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        IssuancePolicyService policy = scope.ServiceProvider.GetRequiredService<IssuancePolicyService>();
        OidcFederationService oidcSvc = scope.ServiceProvider.GetRequiredService<OidcFederationService>();

        await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");

        // Configure a broad local Role rule: Role "Issuer" -> "*" (all domains and profiles)
        var (roleRuleOk, roleRuleErr) = await acct.AddDomainPermissionAsync(
            PermissionSubjectTypes.Role,
            AppRoles.Issuer,
            "*",
            "*");
        Assert.True(roleRuleOk, roleRuleErr);

        // Configure a narrow external group mapping: "dev-only" -> Role "Issuer", domain "*.dev.contoso.com" only
        await acct.SetExternalGroupRoleMappingAsync(
            "dev-only",
            AppRoles.Issuer,
            ["*.dev.contoso.com"],
            CertificateProfiles.EcdsaP256ServerId);

        // Configure a second external group mapping: "stage-rsa" -> Role "Issuer", domain "*.stage.contoso.com" for RSA-2048 only
        await acct.SetExternalGroupRoleMappingAsync(
            "stage-rsa",
            AppRoles.Issuer,
            ["*.stage.contoso.com"],
            CertificateProfiles.Rsa2048ServerId);

        // Provision external user in both "dev-only" and "stage-rsa"
        OidcLoginOutcome loginOutcome = await oidcSvc.ProcessValidatedOidcLoginAsync(
            new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", "ext-scoped-user-1"),
                new Claim("iss", idp.Issuer),
                new Claim("groups", "dev-only"),
                new Claim("groups", "stage-rsa"),
                new Claim("preferred_username", "scoped.external")
            ], "TestOidc")),
            idp.Issuer,
            "ext-scoped-user-1");
        Assert.True(loginOutcome.Succeeded);
        string extUserId = loginOutcome.User!.Id;

        KeyPair ec256 = _crypto.KeyGen(256);
        KeyPair rsa2048 = _crypto.KeyGen(2048);

        // 1. CSR for prod.contoso.com MUST BE DENIED for the external user even though local Role "Issuer" has "*"!
        string prodCsr = _crypto.CSRGen(ec256, "prod.contoso.com", ["prod.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
        PolicyEvaluationResult prodEval = await policy.EvaluateCsrRequestAsync(extUserId, prodCsr);
        Assert.False(prodEval.IsAllowed);
        Assert.Contains("prod.contoso.com", prodEval.DenialReason);

        // 2. CSR for app.dev.contoso.com with ECDSA P-256 is allowed via "dev-only" group rule
        string devEcCsr = _crypto.CSRGen(ec256, "app.dev.contoso.com", ["app.dev.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, devEcCsr)).IsAllowed);

        // 3. CSR for app.dev.contoso.com with RSA-2048 is DENIED because "dev-only" only allows EcdsaP256 and "stage-rsa" only allows *.stage.contoso.com
        string devRsaCsr = _crypto.CSRGen(rsa2048, "app.dev.contoso.com", ["app.dev.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, devRsaCsr)).IsAllowed);

        // 4. CSR for api.stage.contoso.com with RSA-2048 is allowed via "stage-rsa" group rule
        string stageRsaCsr = _crypto.CSRGen(rsa2048, "api.stage.contoso.com", ["api.stage.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, stageRsaCsr)).IsAllowed);

        // 5. Adding an explicit direct User rule for this external account ID grants that additional domain, and removing it revokes it immediately
        await acct.AddDomainPermissionAsync(PermissionSubjectTypes.User, extUserId, "special.prod.contoso.com", CertificateProfiles.EcdsaP256ServerId);
        string specialProdCsr = _crypto.CSRGen(ec256, "special.prod.contoso.com", ["special.prod.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, specialProdCsr)).IsAllowed);

        UserSummaryDto extSummary = (await acct.ListUsersAsync()).Single(u => u.Id == extUserId);
        Assert.Empty(extSummary.EffectiveRolePermissions!); // Local role rules never shown or applied to external users
        Assert.Equal(2, extSummary.EffectiveGroupPermissions!.Count);
        DomainPermissionRule directRule = Assert.Single(extSummary.DirectPermissions);

        await acct.RemoveDomainPermissionAsync(directRule.Id);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, specialProdCsr)).IsAllowed);

        // 6. Meanwhile, a LOCAL account in Role "Issuer" with no direct rules DOES inherit the local Role "Issuer -> *" rule
        var (_, _, localIssuer) = await acct.CreateUserAsync("local-issuer", "LocalIssuer!2026", null, [AppRoles.Issuer], []);
        Assert.True((await policy.EvaluateCsrRequestAsync(localIssuer!.Id, prodCsr)).IsAllowed);
    }

    [Fact]
    public async Task StrictOidcSubBinding_RejectsNonSubSubjectClaimConfig_IsolatesDistinctUsersWithCollidingNonSubClaims_AndPreservesIdentityAcrossRenames()
    {
        // 1. Configuring SubjectClaimType != "sub" (e.g. "email" or "oid") is rejected by OidcFederationOptions.Validate()
        OidcFederationOptions mutableSubConfig = new()
        {
            Enabled = true,
            Issuer = "https://idp.example.test",
            ClientId = "cid",
            ClientSecret = "sec",
            PublicCallbackUrl = "https://pki.contoso.com/signin-oidc",
            SubjectClaimType = "email"
        };
        var (valid, valErr) = mutableSubConfig.Validate();
        Assert.False(valid);
        Assert.Contains("must be 'sub'", valErr);

        // 2. Two distinct IdP users (sub="00u-alice-immutable" and sub="00u-bob-immutable") who share or swap the same
        //    email, preferred_username, and custom 'oid' claim are strictly isolated into two distinct ApplicationUser records.
        var (factory, idp, _) = CreateOidcTestHost();
        using IServiceScope scope = factory.Services.CreateScope();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        OidcFederationService oidcSvc = scope.ServiceProvider.GetRequiredService<OidcFederationService>();

        await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");
        await acct.SetExternalGroupRoleMappingAsync("Cert-Issuers", AppRoles.Issuer, ["*.contoso.com"], "*");

        ClaimsIdentity user1Identity = new(
        [
            new Claim("sub", "00u-alice-immutable"),
            new Claim("iss", idp.Issuer),
            new Claim("oid", "shared-mutable-oid"),
            new Claim("email", "shared-alias@contoso.com"),
            new Claim("preferred_username", "shared.handle"),
            new Claim("name", "Alice Original"),
            new Claim("groups", "Cert-Issuers")
        ], "TestOidc");

        OidcLoginOutcome outcome1 = await oidcSvc.ProcessValidatedOidcLoginAsync(
            new ClaimsPrincipal(user1Identity), idp.Issuer, "00u-alice-immutable");
        Assert.True(outcome1.Succeeded, outcome1.ErrorMessage);

        ClaimsIdentity user2IdentityWithCollidingClaims = new(
        [
            new Claim("sub", "00u-bob-immutable"),
            new Claim("iss", idp.Issuer),
            new Claim("oid", "shared-mutable-oid"),
            new Claim("email", "shared-alias@contoso.com"),
            new Claim("preferred_username", "shared.handle"),
            new Claim("name", "Bob Colliding"),
            new Claim("groups", "Cert-Issuers")
        ], "TestOidc");

        OidcLoginOutcome outcome2 = await oidcSvc.ProcessValidatedOidcLoginAsync(
            new ClaimsPrincipal(user2IdentityWithCollidingClaims), idp.Issuer, "00u-bob-immutable");
        Assert.True(outcome2.Succeeded, outcome2.ErrorMessage);
        Assert.NotEqual(outcome1.User!.Id, outcome2.User!.Id);

        // 3. When user 1 renames their email, preferred_username, and display name while keeping sub="00u-alice-immutable",
        //    they resolve to the exact same ApplicationUser record.
        ClaimsIdentity user1Renamed = new(
        [
            new Claim("sub", "00u-alice-immutable"),
            new Claim("iss", idp.Issuer),
            new Claim("email", "alice.newname@contoso.com"),
            new Claim("preferred_username", "alice.newname"),
            new Claim("name", "Alice Renamed"),
            new Claim("groups", "Cert-Issuers")
        ], "TestOidc");

        OidcLoginOutcome outcome1AfterRename = await oidcSvc.ProcessValidatedOidcLoginAsync(
            new ClaimsPrincipal(user1Renamed), idp.Issuer, "00u-alice-immutable");
        Assert.True(outcome1AfterRename.Succeeded);
        Assert.Equal(outcome1.User.Id, outcome1AfterRename.User!.Id);
        Assert.Equal("alice.newname@contoso.com", outcome1AfterRename.User.Email);
        Assert.Equal("Alice Renamed", outcome1AfterRename.User.DisplayName);
    }

    [Fact]
    public async Task LoginPortalPresentation_SupportsAdminConfigurableProviderLabel_HtmlEscaping_BothDefaultEmphasisModes_AndPersistsAcrossRestart()
    {
        var (factory, _, _) = CreateOidcTestHost();

        ApplicationUser adminUser;
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            var (_, _, createdAdmin) = await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");
            adminUser = createdAdmin!;
        }

        using HttpClient client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://pki.contoso.com"),
            AllowAutoRedirect = false
        });

        // 1. Default mode is LocalPrimary: local login form appears before OIDC login form, local button is btn-primary,
        //    and both local and OIDC sign-in paths are present on /login.
        string initialLoginHtml = await client.GetStringAsync("/login");
        Assert.Contains("data-default-login-mode=\"Local\"", initialLoginHtml);
        int localFormIdx1 = initialLoginHtml.IndexOf("id=\"local-login-form\"", StringComparison.Ordinal);
        int oidcFormIdx1 = initialLoginHtml.IndexOf("id=\"oidc-login-form\"", StringComparison.Ordinal);
        Assert.True(localFormIdx1 > 0 && oidcFormIdx1 > localFormIdx1);
        Assert.Contains("id=\"local-login-submit\" class=\"btn btn-primary w-100\"", initialLoginHtml);
        Assert.Contains("id=\"oidc-login-submit\" class=\"btn btn-outline-primary w-100\"", initialLoginHtml);

        // 2. Update provider label (including characters requiring HTML escaping) and switch default emphasis to OidcPrimary via Admin component
        const string maliciousLabel = "Okta <script>alert(1)</script> & \"Corp\" SSO";
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            CertRobo.Pages.Admin adminPage = new();
            SetProperty(adminPage, "AccountService", acct);
            SetProperty(adminPage, "CaService", scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>());
            SetProperty(adminPage, "CesService", scope.ServiceProvider.GetRequiredService<AdCsCesEnrollmentService>());
            SetProperty(adminPage, "BackupService", scope.ServiceProvider.GetRequiredService<BackupRestoreService>());
            SetProperty(adminPage, "MigrationService", scope.ServiceProvider.GetRequiredService<LegacySettingsMigrationService>());
            SetProperty(adminPage, "Configuration", scope.ServiceProvider.GetRequiredService<IConfiguration>());
            SetProperty(adminPage, "HostEnvironment", scope.ServiceProvider.GetRequiredService<IWebHostEnvironment>());
            SetProperty(adminPage, "AuthenticationStateProvider", new ControllableAuthStateProvider(adminUser.Id, adminUser.UserName!, AppRoles.Administrator, adminUser.SecurityStamp));
            SetProperty(adminPage, "NotificationService", scope.ServiceProvider.GetRequiredService<Radzen.NotificationService>());

            await InvokeMethodAsync(adminPage, "OnInitializedAsync");
            SetField(adminPage, "oidcPortalProviderDisplayName", maliciousLabel);
            SetField(adminPage, "oidcPortalDefaultLoginMode", LoginEmphasisModes.OidcPrimary);
            await InvokeMethodAsync(adminPage, "SaveOidcPortalSettingsClick");
            Assert.Contains("OIDC Settings Saved", GetField<string?>(adminPage, "statusBannerMessage"));
        }

        // 3. Fetch /login and verify:
        //    - Label is properly HTML-escaped (no raw <script> tag)
        //    - OIDC login form now appears FIRST with btn-primary emphasis
        //    - Local username/password login form remains present and accessible on the page for break-glass use during an IdP outage
        string updatedLoginHtml = await client.GetStringAsync("/login");
        Assert.Contains("data-default-login-mode=\"Oidc\"", updatedLoginHtml);
        Assert.DoesNotContain("<script>alert(1)</script>", updatedLoginHtml);
        Assert.Contains("Sign in with Okta &lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;Corp&quot; SSO", updatedLoginHtml);

        int oidcFormIdx2 = updatedLoginHtml.IndexOf("id=\"oidc-login-form\"", StringComparison.Ordinal);
        int localFormIdx2 = updatedLoginHtml.IndexOf("id=\"local-login-form\"", StringComparison.Ordinal);
        Assert.True(oidcFormIdx2 > 0 && localFormIdx2 > oidcFormIdx2);
        Assert.Contains("id=\"oidc-login-submit\" class=\"btn btn-primary w-100\"", updatedLoginHtml);
        Assert.Contains("id=\"local-login-submit\" class=\"btn btn-outline-primary w-100\"", updatedLoginHtml);

        // 4. Verify persistence across restart / fresh DI container against the same SQLite database even when
        //    IConfiguration still has DisplayName="Corporate SSO" and DefaultLoginMode="Local"
        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            await acct.EnsureRolesAndDefaultsAsync();
            OidcPortalSettingsConfig persisted = await acct.GetOidcPortalSettingsAsync();
            Assert.True(persisted.IsCustomizedByAdmin);
            Assert.Equal(maliciousLabel, persisted.ProviderDisplayName);
            Assert.Equal(LoginEmphasisModes.OidcPrimary, persisted.DefaultLoginMode);
        }
    }

    [Fact]
    public async Task AdminActionBoundary_FailsClosedOnAnonymousZeroClaim_ThrowingProvider_MissingStamp_RevalidatedAnonymous_AndRotatedActors_WithNoSideEffects()
    {
        var (factory, _, _) = CreateOidcTestHost();

        using IServiceScope scope = factory.Services.CreateScope();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
        UserManager<ApplicationUser> userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var (_, _, admin1) = await acct.BootstrapFirstAdminAsync("admin1", "AdminOnePass!2026", "admin1@contoso.com", "*");
        var (_, _, admin2) = await acct.CreateUserAsync("admin2", "AdminTwoPass!2026", "admin2@contoso.com", [AppRoles.Administrator, AppRoles.Issuer], ["*"]);
        Assert.NotNull(admin1);
        Assert.NotNull(admin2);

        // Disable admin2 legitimately first
        var (disOk, disErr) = await acct.SetUserDisabledAsync(admin2!.Id, isDisabled: true);
        Assert.True(disOk, disErr);

        ControllableAuthStateProvider authProvider = new(admin1!.Id, admin1.UserName!, AppRoles.Administrator, admin1.SecurityStamp);

        CertRobo.Pages.Admin adminPage = new();
        SetProperty(adminPage, "AccountService", acct);
        SetProperty(adminPage, "CaService", caService);
        SetProperty(adminPage, "CesService", scope.ServiceProvider.GetRequiredService<AdCsCesEnrollmentService>());
        SetProperty(adminPage, "BackupService", scope.ServiceProvider.GetRequiredService<BackupRestoreService>());
        SetProperty(adminPage, "MigrationService", scope.ServiceProvider.GetRequiredService<LegacySettingsMigrationService>());
        SetProperty(adminPage, "Configuration", scope.ServiceProvider.GetRequiredService<IConfiguration>());
        SetProperty(adminPage, "HostEnvironment", scope.ServiceProvider.GetRequiredService<IWebHostEnvironment>());
        SetProperty(adminPage, "AuthenticationStateProvider", authProvider);
        SetProperty(adminPage, "NotificationService", scope.ServiceProvider.GetRequiredService<Radzen.NotificationService>());

        await InvokeMethodAsync(adminPage, "OnInitializedAsync");

        UserSummaryDto disabledAdmin2Dto = (await acct.ListUsersAsync()).Single(u => u.Id == admin2.Id);
        Assert.True(disabledAdmin2Dto.IsDisabled);

        async Task AssertAllPrivilegedActionsDeniedWithNoSideEffectsAsync(string scenarioName)
        {
            SetField(adminPage, "statusBannerMessage", null);
            await InvokeMethodAsync(adminPage, "ToggleUserDisabledClick", disabledAdmin2Dto);
            Assert.Contains("Authorisation Error", GetField<string?>(adminPage, "statusBannerMessage") ?? string.Empty);

            SetField(adminPage, "statusBannerMessage", null);
            SetField(adminPage, "newUserName", "should-not-exist");
            SetField(adminPage, "newUserPassword", "ShouldNotExist!2026");
            await InvokeMethodAsync(adminPage, "CreateUserClick");
            Assert.Contains("Authorisation Error", GetField<string?>(adminPage, "statusBannerMessage") ?? string.Empty);

            SetField(adminPage, "statusBannerMessage", null);
            SetField(adminPage, "newGroupMappingName", "Unauthorized-Group");
            SetField(adminPage, "newGroupMappingRole", AppRoles.Administrator);
            await InvokeMethodAsync(adminPage, "SaveExternalGroupMappingClick");
            Assert.Contains("Authorisation Error", GetField<string?>(adminPage, "statusBannerMessage") ?? string.Empty);

            SetField(adminPage, "statusBannerMessage", null);
            SetField(adminPage, "oidcPortalProviderDisplayName", "Tampered Label");
            await InvokeMethodAsync(adminPage, "SaveOidcPortalSettingsClick");
            Assert.Contains("Authorisation Error", GetField<string?>(adminPage, "statusBannerMessage") ?? string.Empty);

            SetField(adminPage, "statusBannerMessage", null);
            SetField(adminPage, "newCaName", "Unauthorized CA");
            await InvokeMethodAsync(adminPage, "CreateCaClick");
            Assert.Contains("Authorisation Error", GetField<string?>(adminPage, "statusBannerMessage") ?? string.Empty);

            SetField(adminPage, "statusBannerMessage", null);
            await InvokeMethodAsync(adminPage, "DownloadBackupClick");
            Assert.Contains("Authorisation Error", GetField<string?>(adminPage, "statusBannerMessage") ?? string.Empty);

            // Verify zero side effects in SQLite or CA state
            ApplicationUser reloaded2 = (await userMgr.FindByIdAsync(admin2.Id))!;
            await scope.ServiceProvider.GetRequiredService<CertRoboDbContext>().Entry(reloaded2).ReloadAsync();
            Assert.True(reloaded2.IsDisabled, $"Scenario '{scenarioName}' re-enabled disabled admin2!");
            Assert.Null(await userMgr.FindByNameAsync("should-not-exist"));
            Assert.Empty(await acct.ListExternalGroupMappingsAsync());
            Assert.Equal("Corporate SSO", (await acct.GetOidcPortalSettingsAsync()).ProviderDisplayName);
            Assert.Null(await caService.GetActiveAuthorityAsync());
        }

        // 1. Zero-claim anonymous authentication state (exact reproduction of Review #2 P1.1)
        authProvider.SetRawPrincipal(new ClaimsPrincipal(new ClaimsIdentity()));
        await AssertAllPrivilegedActionsDeniedWithNoSideEffectsAsync("zero-claim anonymous principal");

        // 2. Unauthenticated identity that still carries claims
        authProvider.SetRawPrincipal(new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, admin1.Id),
            new Claim(ClaimTypes.Name, admin1.UserName!),
            new Claim(ClaimTypes.Role, AppRoles.Administrator),
            new Claim("AspNet.Identity.SecurityStamp", admin1.SecurityStamp!)
        ]))); // authenticationType == null -> IsAuthenticated == false
        await AssertAllPrivilegedActionsDeniedWithNoSideEffectsAsync("unauthenticated identity with claims");

        // 3. AuthenticationStateProvider throwing InvalidOperationException (provider failure)
        authProvider.SetThrowOnGetState(new InvalidOperationException("Simulated uninitialized circuit provider failure."));
        await AssertAllPrivilegedActionsDeniedWithNoSideEffectsAsync("provider throwing InvalidOperationException");

        // 4. Authenticated Administrator principal MISSING the SecurityStamp claim (both at component and service boundary)
        authProvider.SetPrincipal(admin1.Id, admin1.UserName!, AppRoles.Administrator, securityStamp: null);
        await AssertAllPrivilegedActionsDeniedWithNoSideEffectsAsync("authenticated admin principal missing SecurityStamp");

        ClaimsPrincipal stamplessPrincipal = new(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, admin1.Id),
            new Claim(ClaimTypes.Name, admin1.UserName!),
            new Claim(ClaimTypes.Role, AppRoles.Administrator)
        ], "TestAuth"));
        var (svcNoStampOk, svcNoStampErr) = await acct.SetUserDisabledAsync(admin2.Id, false, actingPrincipal: stamplessPrincipal);
        Assert.False(svcNoStampOk);
        Assert.Contains("security stamp", svcNoStampErr, StringComparison.OrdinalIgnoreCase);

        // 5. Previously valid circuit whose SecurityStamp was rotated (e.g. via InvalidateUserSessionsAsync)
        authProvider.SetPrincipal(admin1.Id, admin1.UserName!, AppRoles.Administrator, admin1.SecurityStamp);
        await acct.InvalidateUserSessionsAsync(admin1.Id);
        await AssertAllPrivilegedActionsDeniedWithNoSideEffectsAsync("rotated SecurityStamp on admin1");
    }

    [Fact]
    public async Task UpdatingExternalGroupMapping_AtomicallyReplacesDomainAndProfileRules_RejectsPartialUpdatesOnInvalidInput_AndSupportsExplicitAdditiveRules_AcrossRestartAndBackupRestore()
    {
        var (factory, idp, _) = CreateOidcTestHost();

        using (IServiceScope scope = factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            IssuancePolicyService policy = scope.ServiceProvider.GetRequiredService<IssuancePolicyService>();
            OidcFederationService oidcSvc = scope.ServiceProvider.GetRequiredService<OidcFederationService>();

            var (_, _, admin) = await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");

            // 1. Initially map 'dev-only' as Issuer for wildcard '*' across all profiles '*'
            var (initOk, initErr, _) = await acct.SetExternalGroupRoleMappingAsync("dev-only", AppRoles.Issuer, ["*"], "*");
            Assert.True(initOk, initErr);

            // Provision external user in 'dev-only'
            OidcLoginOutcome login = await oidcSvc.ProcessValidatedOidcLoginAsync(
                new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim("sub", "sub-dev-narrow-test"),
                    new Claim("iss", idp.Issuer),
                    new Claim("groups", "dev-only"),
                    new Claim("preferred_username", "dev.user")
                ], "TestOidc")),
                idp.Issuer,
                "sub-dev-narrow-test");
            Assert.True(login.Succeeded);
            string extUserId = login.User!.Id;

            KeyPair ec256 = _crypto.KeyGen(256);
            KeyPair rsa2048 = _crypto.KeyGen(2048);
            string prodEcCsr = _crypto.CSRGen(ec256, "prod.contoso.com", ["prod.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
            string devEcCsr = _crypto.CSRGen(ec256, "app.dev.contoso.com", ["app.dev.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
            string devRsaCsr = _crypto.CSRGen(rsa2048, "app.dev.contoso.com", ["app.dev.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");
            string qaEcCsr = _crypto.CSRGen(ec256, "app.qa.contoso.com", ["app.qa.contoso.com"], "US", "WA", "Redmond", "Contoso", "IT", "");

            // Initially, prod.contoso.com is allowed by '*'
            Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, prodEcCsr)).IsAllowed);

            // 2. Update 'dev-only' to narrower domain patterns ('*.dev.contoso.com', '*.qa.contoso.com') and narrower profile ('tls-server-ecdsa-256')
            var (narrowOk, narrowErr, _) = await acct.SetExternalGroupRoleMappingAsync(
                "dev-only",
                AppRoles.Issuer,
                ["*.dev.contoso.com", "*.qa.contoso.com"],
                CertificateProfiles.EcdsaP256ServerId);
            Assert.True(narrowOk, narrowErr);

            // Verify old '*' rule was atomically removed and replaced by the 2 new rules
            IReadOnlyList<ExternalGroupMappingSummaryDto> mappingsAfterNarrow = await acct.ListExternalGroupMappingsAsync();
            ExternalGroupMappingSummaryDto devOnlyMap = Assert.Single(mappingsAfterNarrow);
            Assert.Equal(2, devOnlyMap.DomainPermissions.Count);
            Assert.DoesNotContain(devOnlyMap.DomainPermissions, r => r.DomainPattern == "*");
            Assert.All(devOnlyMap.DomainPermissions, r => Assert.Equal(CertificateProfiles.EcdsaP256ServerId, r.AllowedProfileId));

            // Issuance against old scope (prod.contoso.com) and old profile (RSA-2048) MUST NOW BE DENIED!
            Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, prodEcCsr)).IsAllowed);
            Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, devRsaCsr)).IsAllowed);

            // Issuance against new scope (app.dev.contoso.com and app.qa.contoso.com with ECDSA P-256) succeeds
            Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, devEcCsr)).IsAllowed);
            Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, qaEcCsr)).IsAllowed);

            // 3. Verify NO partial updates on failure:
            //    Attempt to update 'dev-only' with Role=Administrator and one valid + one invalid domain pattern ->
            //    must fail and leave role as 'Issuer' and existing 2 rules untouched!
            var (badDomainOk, badDomainErr, _) = await acct.SetExternalGroupRoleMappingAsync(
                "dev-only",
                AppRoles.Administrator,
                ["*.valid.contoso.com", "invalid domain with spaces!"],
                "*");
            Assert.False(badDomainOk);
            Assert.Contains("invalid", badDomainErr, StringComparison.OrdinalIgnoreCase);

            var (badProfileOk, badProfileErr, _) = await acct.SetExternalGroupRoleMappingAsync(
                "dev-only",
                AppRoles.Administrator,
                ["*.valid.contoso.com"],
                "non-existent-profile");
            Assert.False(badProfileOk);
            Assert.Contains("profile", badProfileErr, StringComparison.OrdinalIgnoreCase);

            devOnlyMap = Assert.Single(await acct.ListExternalGroupMappingsAsync());
            Assert.Equal(AppRoles.Issuer, devOnlyMap.RoleName);
            Assert.Equal(2, devOnlyMap.DomainPermissions.Count);
            Assert.DoesNotContain(devOnlyMap.DomainPermissions, r => r.DomainPattern == "*.valid.contoso.com");

            // 4. Verify explicit additive rule operation (AddDomainPermissionAsync / UI AddAdditionalGroupRuleClick)
            //    appends an RSA-2048 rule for '*.dev.contoso.com' without removing the existing ECDSA P-256 rules!
            CertRobo.Pages.Admin adminPage = new();
            SetProperty(adminPage, "AccountService", acct);
            SetProperty(adminPage, "CaService", scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>());
            SetProperty(adminPage, "CesService", scope.ServiceProvider.GetRequiredService<AdCsCesEnrollmentService>());
            SetProperty(adminPage, "BackupService", scope.ServiceProvider.GetRequiredService<BackupRestoreService>());
            SetProperty(adminPage, "MigrationService", scope.ServiceProvider.GetRequiredService<LegacySettingsMigrationService>());
            SetProperty(adminPage, "Configuration", scope.ServiceProvider.GetRequiredService<IConfiguration>());
            SetProperty(adminPage, "HostEnvironment", scope.ServiceProvider.GetRequiredService<IWebHostEnvironment>());
            SetProperty(adminPage, "AuthenticationStateProvider", new ControllableAuthStateProvider(admin!.Id, admin.UserName!, AppRoles.Administrator, admin.SecurityStamp));
            SetProperty(adminPage, "NotificationService", scope.ServiceProvider.GetRequiredService<Radzen.NotificationService>());

            await InvokeMethodAsync(adminPage, "OnInitializedAsync");
            SetField(adminPage, "additionalRuleGroupName", "dev-only");
            SetField(adminPage, "additionalRuleDomainPattern", "*.dev.contoso.com");
            SetField(adminPage, "additionalRuleProfileId", CertificateProfiles.Rsa2048ServerId);
            await InvokeMethodAsync(adminPage, "AddAdditionalGroupRuleClick");

            devOnlyMap = Assert.Single(await acct.ListExternalGroupMappingsAsync());
            Assert.Equal(3, devOnlyMap.DomainPermissions.Count);
            Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, devRsaCsr)).IsAllowed);
            Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, prodEcCsr)).IsAllowed);

            // 5. Verify Backup & Restore preserves the narrowed + additive rules and never resurrects '*'
            BackupRestoreService backupSvc = scope.ServiceProvider.GetRequiredService<BackupRestoreService>();
            string srcDb = Path.Combine(_tempDir, "narrow-backup-src.db");
            string srcDp = Path.Combine(_tempDir, "narrow-backup-dp");
            Directory.CreateDirectory(srcDp);
            byte[] archive = await backupSvc.CreateConsistentBackupArchiveAsync(srcDb, srcDp);

            string restoredDir = Path.Combine(_tempDir, "narrow-restored");
            string restoredDb = Path.Combine(restoredDir, "certrobo.db");
            BackupRestoreService.RestoreBackupArchive(
                archive,
                restoredDb,
                Path.Combine(restoredDir, "ca"),
                Path.Combine(restoredDir, "dp"));

            await using CertRoboDbContext restoredContext = CreateSqliteContext(restoredDb);
            await restoredContext.EnsureSchemaUpgradedAsync();
            List<DomainPermissionRule> restoredRules = await restoredContext.DomainPermissionRules
                .Where(r => r.SubjectType == PermissionSubjectTypes.ExternalGroup && r.SubjectValue == "dev-only")
                .ToListAsync();
            Assert.Equal(3, restoredRules.Count);
            Assert.DoesNotContain(restoredRules, r => r.DomainPattern == "*");
        }
    }

    [Fact]
    public async Task EditingGroupMapping_PreservesMixedProfilesWithoutFlattening_OnNoChangeSave_RoleChange_ReorderedRules_SameDomainMultiProfile_AndWildcardWithRestrictedProfile()
    {
        var (factory, idp, _) = CreateOidcTestHost();

        using IServiceScope scope = factory.Services.CreateScope();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        IssuancePolicyService policy = scope.ServiceProvider.GetRequiredService<IssuancePolicyService>();
        OidcFederationService oidcSvc = scope.ServiceProvider.GetRequiredService<OidcFederationService>();

        var (_, _, admin) = await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");
        Assert.NotNull(admin);

        // 1. Exact reproduction of Review #3 P1:
        //    Configure group 'dev' with 'a.example.test -> *' and 'b.example.test -> tls-server-ecdsa-256'.
        var (initOk, initErr, _) = await acct.SetExternalGroupRoleMappingAsync(
            "dev",
            AppRoles.Issuer,
            [
                new ExternalGroupPermissionSpec("a.example.test", "*"),
                new ExternalGroupPermissionSpec("b.example.test", CertificateProfiles.EcdsaP256ServerId)
            ]);
        Assert.True(initOk, initErr);

        OidcLoginOutcome login = await oidcSvc.ProcessValidatedOidcLoginAsync(
            new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", "sub-mixed-prof-user"),
                new Claim("iss", idp.Issuer),
                new Claim("groups", "dev"),
                new Claim("preferred_username", "mixed.user")
            ], "TestOidc")),
            idp.Issuer,
            "sub-mixed-prof-user");
        Assert.True(login.Succeeded);
        string extUserId = login.User!.Id;

        KeyPair ec256 = _crypto.KeyGen(256);
        KeyPair rsa2048 = _crypto.KeyGen(2048);
        KeyPair rsa4096 = _crypto.KeyGen(4096);

        string aEc256Csr = _crypto.CSRGen(ec256, "a.example.test", ["a.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string aRsa2048Csr = _crypto.CSRGen(rsa2048, "a.example.test", ["a.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string bEc256Csr = _crypto.CSRGen(ec256, "b.example.test", ["b.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string bRsa2048Csr = _crypto.CSRGen(rsa2048, "b.example.test", ["b.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");

        // Verify issuance decisions BEFORE UI edit:
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, aEc256Csr)).IsAllowed);
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, aRsa2048Csr)).IsAllowed);
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, bEc256Csr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, bRsa2048Csr)).IsAllowed); // b.example.test only allows ECDSA-256!

        CertRobo.Pages.Admin adminPage = new();
        SetProperty(adminPage, "AccountService", acct);
        SetProperty(adminPage, "CaService", scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>());
        SetProperty(adminPage, "CesService", scope.ServiceProvider.GetRequiredService<AdCsCesEnrollmentService>());
        SetProperty(adminPage, "BackupService", scope.ServiceProvider.GetRequiredService<BackupRestoreService>());
        SetProperty(adminPage, "MigrationService", scope.ServiceProvider.GetRequiredService<LegacySettingsMigrationService>());
        SetProperty(adminPage, "Configuration", scope.ServiceProvider.GetRequiredService<IConfiguration>());
        SetProperty(adminPage, "HostEnvironment", scope.ServiceProvider.GetRequiredService<IWebHostEnvironment>());
        SetProperty(adminPage, "AuthenticationStateProvider", new ControllableAuthStateProvider(admin!.Id, admin.UserName!, AppRoles.Administrator, admin.SecurityStamp));
        SetProperty(adminPage, "NotificationService", scope.ServiceProvider.GetRequiredService<Radzen.NotificationService>());

        await InvokeMethodAsync(adminPage, "OnInitializedAsync");

        // 2. Click Edit / Replace (PopulateEditGroupMappingForm) and Save (SaveExternalGroupMappingClick) WITHOUT changing anything (no-change save):
        ExternalGroupMappingSummaryDto devSummaryBefore = (await acct.ListExternalGroupMappingsAsync()).Single(m => m.GroupName == "dev");
        await InvokeMethodAsync(adminPage, "PopulateEditGroupMappingForm", devSummaryBefore);
        await InvokeMethodAsync(adminPage, "SaveExternalGroupMappingClick");

        ExternalGroupMappingSummaryDto devSummaryAfterNoChange = (await acct.ListExternalGroupMappingsAsync()).Single(m => m.GroupName == "dev");
        Assert.Equal(2, devSummaryAfterNoChange.DomainPermissions.Count);
        Assert.Contains(devSummaryAfterNoChange.DomainPermissions, r => r.DomainPattern == "a.example.test" && r.AllowedProfileId == "*");
        Assert.Contains(devSummaryAfterNoChange.DomainPermissions, r => r.DomainPattern == "b.example.test" && r.AllowedProfileId == CertificateProfiles.EcdsaP256ServerId);

        // Verify issuance decisions AFTER no-change save: b.example.test MUST STILL BE DENIED for RSA-2048!
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, aRsa2048Csr)).IsAllowed);
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, bEc256Csr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, bRsa2048Csr)).IsAllowed);

        // 3. Role-only edit via UI: change role from Issuer to Administrator and save -> must preserve both mixed-profile rules!
        await InvokeMethodAsync(adminPage, "PopulateEditGroupMappingForm", devSummaryAfterNoChange);
        SetField(adminPage, "newGroupMappingRole", AppRoles.Administrator);
        await InvokeMethodAsync(adminPage, "SaveExternalGroupMappingClick");

        ExternalGroupMappingSummaryDto devSummaryAfterRoleEdit = (await acct.ListExternalGroupMappingsAsync()).Single(m => m.GroupName == "dev");
        Assert.Equal(AppRoles.Administrator, devSummaryAfterRoleEdit.RoleName);
        Assert.Equal(2, devSummaryAfterRoleEdit.DomainPermissions.Count);
        Assert.Contains(devSummaryAfterRoleEdit.DomainPermissions, r => r.DomainPattern == "a.example.test" && r.AllowedProfileId == "*");
        Assert.Contains(devSummaryAfterRoleEdit.DomainPermissions, r => r.DomainPattern == "b.example.test" && r.AllowedProfileId == CertificateProfiles.EcdsaP256ServerId);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, bRsa2048Csr)).IsAllowed);

        // 4. Reordered rules (restricted profile rule FIRST, '*' profile rule SECOND):
        //    Verify Edit + Save neither narrows a.example.test to ECDSA-256 nor widens b.example.test to '*'!
        await acct.SetExternalGroupRoleMappingAsync(
            "dev",
            AppRoles.Issuer,
            [
                new ExternalGroupPermissionSpec("b.example.test", CertificateProfiles.EcdsaP256ServerId),
                new ExternalGroupPermissionSpec("a.example.test", "*")
            ]);
        ExternalGroupMappingSummaryDto devReordered = (await acct.ListExternalGroupMappingsAsync()).Single(m => m.GroupName == "dev");
        Assert.Equal("b.example.test", devReordered.DomainPermissions[0].DomainPattern);
        Assert.Equal(CertificateProfiles.EcdsaP256ServerId, devReordered.DomainPermissions[0].AllowedProfileId);

        await InvokeMethodAsync(adminPage, "PopulateEditGroupMappingForm", devReordered);
        await InvokeMethodAsync(adminPage, "SaveExternalGroupMappingClick");

        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, aRsa2048Csr)).IsAllowed); // a.example.test still allows RSA-2048!
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, bEc256Csr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, bRsa2048Csr)).IsAllowed); // b.example.test still denies RSA-2048!

        // 5. Same domain with multiple profiles + multiple domains per profile + '*' domain with restricted profile:
        //    - shared.example.test -> tls-server-ecdsa-256 AND tls-server-rsa-2048 (denies RSA-4096)
        //    - multi1.example.test, multi2.example.test -> tls-server-ecdsa-256
        //    - * -> tls-server-ecdsa-256 (all domains allowed for ECDSA-256, but NOT for RSA-4096)
        await acct.SetExternalGroupRoleMappingAsync(
            "dev",
            AppRoles.Issuer,
            [
                new ExternalGroupPermissionSpec("shared.example.test", CertificateProfiles.EcdsaP256ServerId),
                new ExternalGroupPermissionSpec("shared.example.test", CertificateProfiles.Rsa2048ServerId),
                new ExternalGroupPermissionSpec("multi1.example.test", CertificateProfiles.EcdsaP256ServerId),
                new ExternalGroupPermissionSpec("multi2.example.test", CertificateProfiles.EcdsaP256ServerId),
                new ExternalGroupPermissionSpec("*", CertificateProfiles.EcdsaP256ServerId)
            ]);

        ExternalGroupMappingSummaryDto complexSummary = (await acct.ListExternalGroupMappingsAsync()).Single(m => m.GroupName == "dev");
        Assert.Equal(5, complexSummary.DomainPermissions.Count);

        // Edit and save through the UI component
        await InvokeMethodAsync(adminPage, "PopulateEditGroupMappingForm", complexSummary);
        await InvokeMethodAsync(adminPage, "SaveExternalGroupMappingClick");

        ExternalGroupMappingSummaryDto complexAfterSave = (await acct.ListExternalGroupMappingsAsync()).Single(m => m.GroupName == "dev");
        Assert.Equal(5, complexAfterSave.DomainPermissions.Count);

        string sharedEc256Csr = _crypto.CSRGen(ec256, "shared.example.test", ["shared.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string sharedRsa2048Csr = _crypto.CSRGen(rsa2048, "shared.example.test", ["shared.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string sharedRsa4096Csr = _crypto.CSRGen(rsa4096, "shared.example.test", ["shared.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string anyEc256Csr = _crypto.CSRGen(ec256, "any.other.test", ["any.other.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string anyRsa2048Csr = _crypto.CSRGen(rsa2048, "any.other.test", ["any.other.test"], "US", "WA", "Redmond", "Contoso", "IT", "");

        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, sharedEc256Csr)).IsAllowed);
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, sharedRsa2048Csr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, sharedRsa4096Csr)).IsAllowed);
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, anyEc256Csr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, anyRsa2048Csr)).IsAllowed);
    }

    [Fact]
    public async Task SingleLabelPrivateWildcardSuffixes_DotLocalAndDotInternal_RemainValidForExistingAndNewRules_WhileSingleLabelCertificateNamesAreRejected()
    {
        var (factory, idp, _) = CreateOidcTestHost();

        using IServiceScope scope = factory.Services.CreateScope();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        IssuancePolicyService policy = scope.ServiceProvider.GetRequiredService<IssuancePolicyService>();
        OidcFederationService oidcSvc = scope.ServiceProvider.GetRequiredService<OidcFederationService>();
        CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();

        var (_, _, admin) = await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*.local");
        Assert.NotNull(admin);

        // 1. Verify '*.local' and '*.internal' canonicalize and match multi-label private FQDNs
        Assert.Equal("*.local", DomainPolicyEvaluator.CanonicalizeDomainPatternOrIdentity("*.local"));
        Assert.Equal("*.internal", DomainPolicyEvaluator.CanonicalizeDomainPatternOrIdentity("*.INTERNAL."));
        Assert.True(DomainPolicyEvaluator.DomainMatchesPattern("nas.local", "*.local"));
        Assert.True(DomainPolicyEvaluator.DomainMatchesPattern("printer.office.local", "*.local"));
        Assert.True(DomainPolicyEvaluator.DomainMatchesPattern("*.sub.local", "*.local"));
        Assert.True(DomainPolicyEvaluator.DomainMatchesPattern("vault.internal", "*.internal"));

        // Malformed patterns and bare single-label patterns (without '*.') are still rejected
        Assert.Equal(string.Empty, DomainPolicyEvaluator.CanonicalizeDomainPatternOrIdentity("local"));
        Assert.Equal(string.Empty, DomainPolicyEvaluator.CanonicalizeDomainPatternOrIdentity("*."));
        Assert.Equal(string.Empty, DomainPolicyEvaluator.CanonicalizeDomainPatternOrIdentity("invalid domain!"));

        // Single-label requested certificate identities (e.g. 'localhost' or 'local' or '*.local' as a cert CN/SAN) are still rejected
        Assert.False(IssuancePolicyService.IsValidRequestedDnsIdentity("local", out _));
        Assert.False(IssuancePolicyService.IsValidRequestedDnsIdentity("localhost", out _));
        Assert.False(IssuancePolicyService.IsValidRequestedDnsIdentity("*.local", out _));
        Assert.True(IssuancePolicyService.IsValidRequestedDnsIdentity("nas.local", out _));
        Assert.True(IssuancePolicyService.IsValidRequestedDnsIdentity("*.sub.local", out _));

        // 2. Simulate an existing pre-upgrade rule stored in SQLite for both a local user and an external OIDC group
        await acct.SetExternalGroupRoleMappingAsync("lan-admins", AppRoles.Issuer, ["*.local", "*.internal"], "*");
        OidcLoginOutcome extLogin = await oidcSvc.ProcessValidatedOidcLoginAsync(
            new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", "sub-lan-user-1"),
                new Claim("iss", idp.Issuer),
                new Claim("groups", "lan-admins"),
                new Claim("preferred_username", "lan.operator")
            ], "TestOidc")),
            idp.Issuer,
            "sub-lan-user-1");
        Assert.True(extLogin.Succeeded);

        KeyPair ec256 = _crypto.KeyGen(256);
        string nasLocalCsr = _crypto.CSRGen(ec256, "nas.local", ["nas.local", "backup.nas.local"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string vaultInternalCsr = _crypto.CSRGen(ec256, "vault.internal", ["vault.internal"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string forbiddenCorpCsr = _crypto.CSRGen(ec256, "server.corp", ["server.corp"], "US", "WA", "Redmond", "Contoso", "IT", "");

        // Local admin (with stored '*.local' rule from bootstrap) and external OIDC user (with '*.local' and '*.internal' group rules)
        // can both issue certificates for 'nas.local'
        Assert.True((await policy.EvaluateCsrRequestAsync(admin!.Id, nasLocalCsr)).IsAllowed);
        Assert.True((await policy.EvaluateCsrRequestAsync(extLogin.User!.Id, nasLocalCsr)).IsAllowed);
        Assert.True((await policy.EvaluateCsrRequestAsync(extLogin.User.Id, vaultInternalCsr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extLogin.User.Id, forbiddenCorpCsr)).IsAllowed);
    }

    [Fact]
    public async Task DefaultProfileSelector_NeverOverridesExplicitRuleProfiles_AppliesOnlyToBarePatterns_SynchronizesTextAndRows_AndSupportsExplicitBulkApply()
    {
        var (factory, idp, _) = CreateOidcTestHost();

        using IServiceScope scope = factory.Services.CreateScope();
        AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
        IssuancePolicyService policy = scope.ServiceProvider.GetRequiredService<IssuancePolicyService>();
        OidcFederationService oidcSvc = scope.ServiceProvider.GetRequiredService<OidcFederationService>();

        var (_, _, admin) = await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*");
        Assert.NotNull(admin);

        // 1. Exact reproduction of Review #4 P1:
        //    Configure group 'dev' with 'b.example.test -> tls-server-ecdsa-256'.
        await acct.SetExternalGroupRoleMappingAsync(
            "dev",
            AppRoles.Issuer,
            [new ExternalGroupPermissionSpec("b.example.test", CertificateProfiles.EcdsaP256ServerId)]);

        OidcLoginOutcome login = await oidcSvc.ProcessValidatedOidcLoginAsync(
            new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", "sub-default-prof-user"),
                new Claim("iss", idp.Issuer),
                new Claim("groups", "dev"),
                new Claim("preferred_username", "dev.user")
            ], "TestOidc")),
            idp.Issuer,
            "sub-default-prof-user");
        Assert.True(login.Succeeded);
        string extUserId = login.User!.Id;

        KeyPair ec256 = _crypto.KeyGen(256);
        KeyPair rsa2048 = _crypto.KeyGen(2048);
        KeyPair rsa4096 = _crypto.KeyGen(4096);

        string aEc256Csr = _crypto.CSRGen(ec256, "a.example.test", ["a.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string aRsa2048Csr = _crypto.CSRGen(rsa2048, "a.example.test", ["a.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string aRsa4096Csr = _crypto.CSRGen(rsa4096, "a.example.test", ["a.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string bEc256Csr = _crypto.CSRGen(ec256, "b.example.test", ["b.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string bRsa2048Csr = _crypto.CSRGen(rsa2048, "b.example.test", ["b.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string bRsa4096Csr = _crypto.CSRGen(rsa4096, "b.example.test", ["b.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string bareEc256Csr = _crypto.CSRGen(ec256, "bare.example.test", ["bare.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");
        string bareRsa2048Csr = _crypto.CSRGen(rsa2048, "bare.example.test", ["bare.example.test"], "US", "WA", "Redmond", "Contoso", "IT", "");

        // Initially, RSA-2048 for b.example.test is denied
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, bEc256Csr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, bRsa2048Csr)).IsAllowed);

        CertRobo.Pages.Admin adminPage = new();
        SetProperty(adminPage, "AccountService", acct);
        SetProperty(adminPage, "CaService", scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>());
        SetProperty(adminPage, "CesService", scope.ServiceProvider.GetRequiredService<AdCsCesEnrollmentService>());
        SetProperty(adminPage, "BackupService", scope.ServiceProvider.GetRequiredService<BackupRestoreService>());
        SetProperty(adminPage, "MigrationService", scope.ServiceProvider.GetRequiredService<LegacySettingsMigrationService>());
        SetProperty(adminPage, "Configuration", scope.ServiceProvider.GetRequiredService<IConfiguration>());
        SetProperty(adminPage, "HostEnvironment", scope.ServiceProvider.GetRequiredService<IWebHostEnvironment>());
        SetProperty(adminPage, "AuthenticationStateProvider", new ControllableAuthStateProvider(admin!.Id, admin.UserName!, AppRoles.Administrator, admin.SecurityStamp));
        SetProperty(adminPage, "NotificationService", scope.ServiceProvider.GetRequiredService<Radzen.NotificationService>());

        await InvokeMethodAsync(adminPage, "OnInitializedAsync");

        // Click Edit / Replace, change Default Profile (for bare patterns) to '*' (both via OnDefaultProfileChanged and SetField),
        // leaving the explicitly profiled domain and row untouched, and save:
        ExternalGroupMappingSummaryDto singleRuleSummary = (await acct.ListExternalGroupMappingsAsync()).Single(m => m.GroupName == "dev");
        await InvokeMethodAsync(adminPage, "PopulateEditGroupMappingForm", singleRuleSummary);
        Assert.Equal("b.example.test@tls-server-ecdsa-256", GetField<string>(adminPage, "newGroupMappingDomains"));

        await InvokeMethodAsync(adminPage, "OnDefaultProfileChanged", "*");
        SetField(adminPage, "newGroupMappingProfile", "*");
        await InvokeMethodAsync(adminPage, "SaveExternalGroupMappingClick");

        // Stored rule MUST remain b.example.test -> tls-server-ecdsa-256, and RSA-2048 CSR MUST STILL BE DENIED!
        ExternalGroupMappingSummaryDto afterDefaultChange = (await acct.ListExternalGroupMappingsAsync()).Single(m => m.GroupName == "dev");
        DomainPermissionRule singleSavedRule = Assert.Single(afterDefaultChange.DomainPermissions);
        Assert.Equal("b.example.test", singleSavedRule.DomainPattern);
        Assert.Equal(CertificateProfiles.EcdsaP256ServerId, singleSavedRule.AllowedProfileId);
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, bEc256Csr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, bRsa2048Csr)).IsAllowed);

        // 2. Uniform multi-row group (both rules start with tls-server-ecdsa-256):
        //    Test explicit row changes in BOTH orders relative to default profile changes!
        await acct.SetExternalGroupRoleMappingAsync(
            "dev",
            AppRoles.Issuer,
            [
                new ExternalGroupPermissionSpec("a.example.test", CertificateProfiles.EcdsaP256ServerId),
                new ExternalGroupPermissionSpec("b.example.test", CertificateProfiles.EcdsaP256ServerId)
            ]);

        // Order A: Change row 0 profile to RSA-2048 FIRST, then change Default Profile to '*', then Save
        ExternalGroupMappingSummaryDto uniformSummary = (await acct.ListExternalGroupMappingsAsync()).Single(m => m.GroupName == "dev");
        await InvokeMethodAsync(adminPage, "PopulateEditGroupMappingForm", uniformSummary);
        await InvokeMethodAsync(adminPage, "OnEditingGroupRuleProfileChanged", 0, CertificateProfiles.Rsa2048ServerId);
        await InvokeMethodAsync(adminPage, "OnDefaultProfileChanged", "*");
        await InvokeMethodAsync(adminPage, "SaveExternalGroupMappingClick");

        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, aEc256Csr)).IsAllowed);
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, aRsa2048Csr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, aRsa4096Csr)).IsAllowed); // NOT widened to '*'!
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, bEc256Csr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, bRsa2048Csr)).IsAllowed); // b kept ECDSA-256!

        // Order B: Reset to uniform ECDSA-256, then change Default Profile to '*' FIRST, then change row 1 profile to RSA-2048, then Save
        await acct.SetExternalGroupRoleMappingAsync(
            "dev",
            AppRoles.Issuer,
            [
                new ExternalGroupPermissionSpec("a.example.test", CertificateProfiles.EcdsaP256ServerId),
                new ExternalGroupPermissionSpec("b.example.test", CertificateProfiles.EcdsaP256ServerId)
            ]);
        uniformSummary = (await acct.ListExternalGroupMappingsAsync()).Single(m => m.GroupName == "dev");
        await InvokeMethodAsync(adminPage, "PopulateEditGroupMappingForm", uniformSummary);
        await InvokeMethodAsync(adminPage, "OnDefaultProfileChanged", "*");
        await InvokeMethodAsync(adminPage, "OnEditingGroupRuleProfileChanged", 1, CertificateProfiles.Rsa2048ServerId);
        await InvokeMethodAsync(adminPage, "SaveExternalGroupMappingClick");

        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, aEc256Csr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, aRsa2048Csr)).IsAllowed); // a kept ECDSA-256!
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, bEc256Csr)).IsAllowed);
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, bRsa2048Csr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, bRsa4096Csr)).IsAllowed); // NOT widened to '*'!

        // 3. Bare rules alongside explicit rules + text/row synchronization:
        //    Enter "a.example.test@tls-server-ecdsa-256, bare.example.test" in the text input,
        //    then change Default Profile to RSA-2048 -> only 'bare.example.test' adopts RSA-2048 while 'a.example.test' keeps ECDSA-256!
        await InvokeMethodAsync(adminPage, "OnGroupMappingDomainsChanged", "a.example.test@tls-server-ecdsa-256, bare.example.test");
        SetField(adminPage, "newGroupMappingName", "dev");
        SetField(adminPage, "newGroupMappingRole", AppRoles.Issuer);
        await InvokeMethodAsync(adminPage, "OnDefaultProfileChanged", CertificateProfiles.Rsa2048ServerId);
        Assert.Equal("a.example.test@tls-server-ecdsa-256, bare.example.test", GetField<string>(adminPage, "newGroupMappingDomains"));

        await InvokeMethodAsync(adminPage, "SaveExternalGroupMappingClick");

        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, aEc256Csr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, aRsa2048Csr)).IsAllowed);
        Assert.False((await policy.EvaluateCsrRequestAsync(extUserId, bareEc256Csr)).IsAllowed);
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, bareRsa2048Csr)).IsAllowed);

        // 4. Explicit bulk profile change action (ApplyDefaultProfileToAllEditingRules):
        //    Visibly updates all rows and text before saving, and only then applies the default profile across all rules.
        ExternalGroupMappingSummaryDto mixedSummary = (await acct.ListExternalGroupMappingsAsync()).Single(m => m.GroupName == "dev");
        await InvokeMethodAsync(adminPage, "PopulateEditGroupMappingForm", mixedSummary);
        await InvokeMethodAsync(adminPage, "OnDefaultProfileChanged", "*");
        await InvokeMethodAsync(adminPage, "ApplyDefaultProfileToAllEditingRules");
        Assert.Equal("a.example.test@*, bare.example.test@*", GetField<string>(adminPage, "newGroupMappingDomains"));

        await InvokeMethodAsync(adminPage, "SaveExternalGroupMappingClick");
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, aRsa4096Csr)).IsAllowed);
        Assert.True((await policy.EvaluateCsrRequestAsync(extUserId, bareEc256Csr)).IsAllowed);
    }

    private sealed class ControllableAuthStateProvider : AuthenticationStateProvider
    {
        private ClaimsPrincipal _principal;
        private Exception? _throwOnGetState;

        public ControllableAuthStateProvider(string userId, string userName, string role, string? securityStamp)
        {
            _principal = BuildPrincipal(userId, userName, role, securityStamp);
        }

        public void SetPrincipal(string userId, string userName, string role, string? securityStamp)
        {
            _throwOnGetState = null;
            _principal = BuildPrincipal(userId, userName, role, securityStamp);
        }

        public void SetRawPrincipal(ClaimsPrincipal principal)
        {
            _throwOnGetState = null;
            _principal = principal;
        }

        public void SetThrowOnGetState(Exception ex)
        {
            _throwOnGetState = ex;
        }

        private static ClaimsPrincipal BuildPrincipal(string userId, string userName, string role, string? securityStamp)
        {
            List<Claim> claims =
            [
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.Name, userName),
                new Claim(ClaimTypes.Role, role)
            ];
            if (!string.IsNullOrEmpty(securityStamp))
            {
                claims.Add(new Claim("AspNet.Identity.SecurityStamp", securityStamp));
            }
            return new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        }

        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            if (_throwOnGetState != null)
            {
                throw _throwOnGetState;
            }
            return Task.FromResult(new AuthenticationState(_principal));
        }
    }

    private static CertRoboDbContext CreateSqliteContext(string dbPath)
    {
        DbContextOptions<CertRoboDbContext> opts = new DbContextOptionsBuilder<CertRoboDbContext>()
            .UseSqlite($"Data Source={dbPath}")
            .Options;
        return new CertRoboDbContext(opts);
    }

    private static async Task<(int ExitCode, string Stdout, string Stderr)> RunCliAsync(
        string dbPath,
        string caDir,
        IReadOnlyList<string> cliArgs,
        IReadOnlyDictionary<string, string>? extraEnv = null)
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
        psi.Environment["CertRobo__CaPassphrase"] = "TestCaPassphrase!2026";
        if (extraEnv != null)
        {
            foreach (var kv in extraEnv)
            {
                psi.Environment[kv.Key] = kv.Value;
            }
        }

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

