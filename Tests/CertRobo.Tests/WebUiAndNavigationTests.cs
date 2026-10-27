using CertRobo.Data;
using CertRobo.Models;
using CertRobo.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Text.RegularExpressions;

namespace CertRobo.Tests;

public class WebUiAndNavigationTests : IDisposable
{
    private readonly string _tempDir;
    private readonly WebApplicationFactory<Program> _factory;

    public WebUiAndNavigationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"certrobo-webui-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);

        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("CertRobo:DataDirectory", _tempDir);
            builder.UseSetting("CertRobo:SqliteFilePath", Path.Combine(_tempDir, "certrobo.db"));
            builder.UseSetting("CertRobo:CaStorageDirectory", Path.Combine(_tempDir, "ca"));
            builder.UseSetting("CertRobo:CaPassphrase", "TestCaPassphrase!2026");
        });
    }

    [Fact]
    public async Task Unauthenticated_ShowsInitialSetup_BeforeBootstrap_And_OnlySignIn_AfterBootstrap()
    {
        using HttpClient client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        // 1. Before bootstrap, /login redirects to /setup, and / renders "Initial Setup" (not "Sign In")
        HttpResponseMessage loginRedirect = await client.GetAsync("/login");
        Assert.Equal(HttpStatusCode.Redirect, loginRedirect.StatusCode);
        Assert.Equal("/setup", loginRedirect.Headers.Location?.OriginalString);

        string homeBeforeHtml = await client.GetStringAsync("/");
        Assert.Contains("Initial Setup", homeBeforeHtml);
        Assert.DoesNotContain(">Sign In<", homeBeforeHtml);

        // 2. Complete initial setup via POST /account/setup
        HttpResponseMessage setupPage = await client.GetAsync("/setup");
        string setupHtml = await setupPage.Content.ReadAsStringAsync();
        string setupToken = ExtractAntiforgeryToken(setupHtml);
        CopyCookies(setupPage, client);

        HttpResponseMessage setupPost = await client.PostAsync("/account/setup", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = setupToken,
            ["userName"] = "admin",
            ["email"] = "admin@contoso.com",
            ["password"] = "AdminPass!2026",
            ["domainPattern"] = "*.contoso.com"
        }));
        Assert.Equal(HttpStatusCode.Redirect, setupPost.StatusCode);
        Assert.Equal("/", setupPost.Headers.Location?.OriginalString);

        // 3. Using a fresh unauthenticated client after bootstrap: /setup redirects to /login, and / shows only "Sign In"
        using HttpClient unauthAfter = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        HttpResponseMessage setupAfter = await unauthAfter.GetAsync("/setup");
        Assert.Equal(HttpStatusCode.Redirect, setupAfter.StatusCode);
        Assert.Equal("/login", setupAfter.Headers.Location?.OriginalString);

        string homeAfterHtml = await unauthAfter.GetStringAsync("/");
        Assert.Contains(">Sign In<", homeAfterHtml);
        Assert.DoesNotContain(">Initial Setup<", homeAfterHtml);
    }

    [Fact]
    public async Task AuthenticatedAdmin_RendersSemanticHeader_AdminSections_AssociatedLabels_And_AntiforgeryLogout()
    {
        using (IServiceScope scope = _factory.Services.CreateScope())
        {
            AccountManagementService acct = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
            await acct.BootstrapFirstAdminAsync("admin", "AdminPass!2026", "admin@contoso.com", "*.contoso.com");
        }

        using HttpClient client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        // 1. Sign in via /login -> POST /account/login
        HttpResponseMessage loginGet = await client.GetAsync("/login");
        string loginHtml = await loginGet.Content.ReadAsStringAsync();
        string loginToken = ExtractAntiforgeryToken(loginHtml);
        CopyCookies(loginGet, client);

        HttpResponseMessage loginPost = await client.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = loginToken,
            ["userName"] = "admin",
            ["password"] = "AdminPass!2026",
            ["returnUrl"] = "/admin"
        }));
        Assert.Equal(HttpStatusCode.Redirect, loginPost.StatusCode);
        Assert.Equal("/admin", loginPost.Headers.Location?.OriginalString);
        CopyCookies(loginPost, client);

        // 2. Fetch /admin and verify semantic header, tabs, and associated form labels
        HttpResponseMessage adminGet = await client.GetAsync("/admin");
        Assert.Equal(HttpStatusCode.OK, adminGet.StatusCode);
        string adminHtml = await adminGet.Content.ReadAsStringAsync();
        CopyCookies(adminGet, client);

        // Semantic header and navigation (note: Blazor CSS isolation adds a b-* scope attribute to elements)
        Assert.Matches(@"<header\s+class=""top-row""\s+role=""banner""", adminHtml);
        Assert.Matches(@"<nav\s+class=""primary-nav""\s+aria-label=""Main navigation""", adminHtml);
        Assert.Contains("Certificate Tool", adminHtml);
        Assert.Contains("Administration", adminHtml);
        Assert.DoesNotContain("<table class=\"top-row auth\"", adminHtml);

        // 4 Admin section tabs
        Assert.Contains("id=\"tab-ca\"", adminHtml);
        Assert.Contains("id=\"tab-users\"", adminHtml);
        Assert.Contains("id=\"tab-certs\"", adminHtml);
        Assert.Contains("id=\"tab-settings\"", adminHtml);

        // Verify all rendered <label for="..."> attributes in /admin match an input/select/textarea id
        MatchCollection labelMatches = Regex.Matches(adminHtml, "<label[^>]*\\bfor=\"([^\"]+)\"");
        Assert.NotEmpty(labelMatches);
        foreach (Match m in labelMatches)
        {
            string targetId = m.Groups[1].Value;
            Assert.Contains($"id=\"{targetId}\"", adminHtml);
        }

        // 3. Extract rendered logout antiforgery token from MainLayout and verify POST /account/logout succeeds
        string logoutToken = ExtractAntiforgeryToken(adminHtml);
        Assert.False(string.IsNullOrWhiteSpace(logoutToken));

        HttpResponseMessage logoutPost = await client.PostAsync("/account/logout", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = logoutToken
        }));
        Assert.Equal(HttpStatusCode.Redirect, logoutPost.StatusCode);
        Assert.Equal("/login", logoutPost.Headers.Location?.OriginalString);
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
        _factory.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (Directory.Exists(_tempDir))
        {
            try { Directory.Delete(_tempDir, recursive: true); }
            catch { }
        }
    }
}
