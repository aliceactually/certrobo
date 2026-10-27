using CertRobo.Data;
using CertRobo.Services;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using System.Net;

namespace CertRobo;

public static class WebEndpoints
{
    public static void MapCertRoboEndpoints(this WebApplication app)
    {
        app.MapGet("/login", async (HttpContext ctx, AccountManagementService accountService, IAntiforgery antiforgery) =>
        {
            if (await accountService.IsBootstrapRequiredAsync())
            {
                ctx.Response.Redirect("/setup");
                return;
            }

            AntiforgeryTokenSet tokens = antiforgery.GetAndStoreTokens(ctx);
            string? error = ctx.Request.Query["error"];
            string? returnUrl = ctx.Request.Query["ReturnUrl"];
            if (string.IsNullOrWhiteSpace(returnUrl) || !Uri.IsWellFormedUriString(returnUrl, UriKind.Relative))
            {
                returnUrl = "/";
            }

            string errorHtml = string.IsNullOrWhiteSpace(error)
                ? string.Empty
                : $"<div class=\"alert alert-danger\">{WebUtility.HtmlEncode(error)}</div>";

            string html = $$"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="utf-8" />
                    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                    <title>CertRobo — Sign In</title>
                    <link rel="stylesheet" href="/css/bootstrap/bootstrap.min.css" />
                    <link rel="stylesheet" href="/css/site.css" />
                    <script src="/js/theme.js"></script>
                </head>
                <body>
                    <div class="container" style="max-width: 460px; margin-top: 4rem;">
                        <div class="card rz-card p-4">
                            <h3 class="mb-3">Sign in to CertRobo</h3>
                            {{errorHtml}}
                            <form method="post" action="/account/login">
                                <input type="hidden" name="{{tokens.FormFieldName}}" value="{{tokens.RequestToken}}" />
                                <input type="hidden" name="returnUrl" value="{{WebUtility.HtmlEncode(returnUrl)}}" />
                                <div class="mb-3">
                                    <label class="form-label" for="userName">Username</label>
                                    <input class="form-control" id="userName" name="userName" type="text" required autocomplete="username" />
                                </div>
                                <div class="mb-3">
                                    <label class="form-label" for="password">Password</label>
                                    <input class="form-control" id="password" name="password" type="password" required autocomplete="current-password" />
                                </div>
                                <button type="submit" class="btn btn-primary w-100">Sign In</button>
                            </form>
                        </div>
                    </div>
                </body>
                </html>
                """;

            ctx.Response.ContentType = "text/html; charset=utf-8";
            await ctx.Response.WriteAsync(html);
        }).AllowAnonymous();

        app.MapPost("/account/login", async (
            HttpContext ctx,
            IAntiforgery antiforgery,
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager) =>
        {
            try
            {
                await antiforgery.ValidateRequestAsync(ctx);
            }
            catch (AntiforgeryValidationException)
            {
                ctx.Response.Redirect("/login?error=" + Uri.EscapeDataString("Session token expired. Please try signing in again."));
                return;
            }

            IFormCollection form = await ctx.Request.ReadFormAsync();
            string userName = form["userName"].ToString().Trim();
            string password = form["password"].ToString();
            string returnUrl = form["returnUrl"].ToString();
            if (string.IsNullOrWhiteSpace(returnUrl) || !Uri.IsWellFormedUriString(returnUrl, UriKind.Relative))
            {
                returnUrl = "/";
            }

            ApplicationUser? user = await userManager.FindByNameAsync(userName);
            if (user == null || user.IsDisabled)
            {
                ctx.Response.Redirect("/login?error=" + Uri.EscapeDataString("Invalid credentials or disabled account."));
                return;
            }

            SignInResult result = await signInManager.PasswordSignInAsync(
                user,
                password,
                isPersistent: false,
                lockoutOnFailure: true);

            if (result.Succeeded)
            {
                ctx.Response.Redirect(returnUrl);
                return;
            }

            if (result.IsLockedOut)
            {
                ctx.Response.Redirect("/login?error=" + Uri.EscapeDataString("Account is locked out."));
                return;
            }

            ctx.Response.Redirect("/login?error=" + Uri.EscapeDataString("Invalid username or password."));
        }).AllowAnonymous();

        app.MapPost("/account/logout", async (
            HttpContext ctx,
            IAntiforgery antiforgery,
            SignInManager<ApplicationUser> signInManager) =>
        {
            bool tokenValid = false;
            try
            {
                await antiforgery.ValidateRequestAsync(ctx);
                tokenValid = true;
            }
            catch (AntiforgeryValidationException)
            {
                // Allow same-origin POST logout even if the antiforgery cookie rotated across tabs
                string secFetchSite = ctx.Request.Headers["Sec-Fetch-Site"].ToString();
                if (string.Equals(secFetchSite, "same-origin", StringComparison.OrdinalIgnoreCase))
                {
                    tokenValid = true;
                }
                else if (Uri.TryCreate(ctx.Request.Headers.Origin.ToString(), UriKind.Absolute, out Uri? originUri)
                    && string.Equals(originUri.Host, ctx.Request.Host.Host, StringComparison.OrdinalIgnoreCase))
                {
                    tokenValid = true;
                }
            }

            if (tokenValid)
            {
                await signInManager.SignOutAsync();
            }
            ctx.Response.Redirect("/login");
        });

        app.MapGet("/setup", async (
            HttpContext ctx,
            AccountManagementService accountService,
            IAntiforgery antiforgery) =>
        {
            if (!await accountService.IsBootstrapRequiredAsync())
            {
                ctx.Response.Redirect("/login");
                return;
            }

            AntiforgeryTokenSet tokens = antiforgery.GetAndStoreTokens(ctx);
            string? error = ctx.Request.Query["error"];
            string errorHtml = string.IsNullOrWhiteSpace(error)
                ? string.Empty
                : $"<div class=\"alert alert-danger\">{WebUtility.HtmlEncode(error)}</div>";

            string html = $$"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="utf-8" />
                    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                    <title>CertRobo — Initial Administrator Setup</title>
                    <link rel="stylesheet" href="/css/bootstrap/bootstrap.min.css" />
                    <link rel="stylesheet" href="/css/site.css" />
                    <script src="/js/theme.js"></script>
                </head>
                <body>
                    <div class="container" style="max-width: 520px; margin-top: 3rem;">
                        <div class="card rz-card p-4">
                            <h3 class="mb-2">CertRobo First-Time Setup</h3>
                            <p class="small mb-3">Create the initial local Administrator account. Public self-registration is disabled.</p>
                            {{errorHtml}}
                            <form method="post" action="/account/setup">
                                <input type="hidden" name="{{tokens.FormFieldName}}" value="{{tokens.RequestToken}}" />
                                <div class="mb-3">
                                    <label class="form-label" for="userName">Administrator Username</label>
                                    <input class="form-control" id="userName" name="userName" type="text" required autocomplete="username" />
                                </div>
                                <div class="mb-3">
                                    <label class="form-label" for="email">Email Address (optional)</label>
                                    <input class="form-control" id="email" name="email" type="email" autocomplete="email" />
                                </div>
                                <div class="mb-3">
                                    <label class="form-label" for="password">Password (min 12 characters)</label>
                                    <input class="form-control" id="password" name="password" type="password" required autocomplete="new-password" />
                                </div>
                                <div class="mb-3">
                                    <label class="form-label" for="domainPattern">Initial Allowed Domain Pattern</label>
                                    <input class="form-control" id="domainPattern" name="domainPattern" type="text" value="*" required />
                                </div>
                                <button type="submit" class="btn btn-primary w-100">Complete Initial Setup</button>
                            </form>
                        </div>
                    </div>
                </body>
                </html>
                """;

            ctx.Response.ContentType = "text/html; charset=utf-8";
            await ctx.Response.WriteAsync(html);
        }).AllowAnonymous();

        app.MapPost("/account/setup", async (
            HttpContext ctx,
            IAntiforgery antiforgery,
            AccountManagementService accountService,
            SignInManager<ApplicationUser> signInManager) =>
        {
            try
            {
                await antiforgery.ValidateRequestAsync(ctx);
            }
            catch (AntiforgeryValidationException)
            {
                ctx.Response.Redirect("/setup?error=" + Uri.EscapeDataString("Session token expired. Please submit setup again."));
                return;
            }

            IFormCollection form = await ctx.Request.ReadFormAsync();
            string userName = form["userName"].ToString().Trim();
            string email = form["email"].ToString().Trim();
            string password = form["password"].ToString();
            string domainPattern = form["domainPattern"].ToString().Trim();

            var (succeeded, errorMessage, user) = await accountService.BootstrapFirstAdminAsync(
                userName,
                password,
                email,
                string.IsNullOrWhiteSpace(domainPattern) ? "*" : domainPattern);

            if (!succeeded || user == null)
            {
                ctx.Response.Redirect("/setup?error=" + Uri.EscapeDataString(errorMessage ?? "Setup failed."));
                return;
            }

            await signInManager.SignInAsync(user, isPersistent: false);
            ctx.Response.Redirect("/");
        }).AllowAnonymous();

        // Public CA Certificate & CRL endpoints (support both GET and HEAD for health checks & PKI probes)
        Func<HttpContext, CertificateAuthorityService, Task> serveCaChain = async (HttpContext ctx, CertificateAuthorityService caService) =>
        {
            CaAuthorityRecord? ca = await caService.GetActiveAuthorityAsync();
            if (ca == null)
            {
                ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                if (!HttpMethods.IsHead(ctx.Request.Method))
                {
                    await ctx.Response.WriteAsync("No active CA is configured.");
                }
                return;
            }
            string pem = CertificateAuthorityService.BuildOrderedCertificateChainPem(ca);
            ctx.Response.ContentType = "application/x-x509-ca-cert";
            ctx.Response.ContentLength = System.Text.Encoding.UTF8.GetByteCount(pem);
            if (!HttpMethods.IsHead(ctx.Request.Method))
            {
                await ctx.Response.WriteAsync(pem);
            }
        };

        app.MapMethods("/ca.crt", ["GET", "HEAD"], serveCaChain).AllowAnonymous();
        app.MapMethods("/rootca.crt", ["GET", "HEAD"], serveCaChain).AllowAnonymous();

        app.MapMethods("/ca.crl", ["GET", "HEAD"], async (HttpContext ctx, CertificateAuthorityService caService) =>
        {
            PublishedCrlRecord? crl = await caService.GetLatestCrlAsync();
            if (crl == null)
            {
                ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                if (!HttpMethods.IsHead(ctx.Request.Method))
                {
                    await ctx.Response.WriteAsync("No CRL has been published yet.");
                }
                return;
            }
            ctx.Response.ContentType = "application/pkix-crl";
            ctx.Response.ContentLength = crl.CrlDer.Length;
            if (!HttpMethods.IsHead(ctx.Request.Method))
            {
                await ctx.Response.Body.WriteAsync(crl.CrlDer);
            }
        }).AllowAnonymous();

        app.MapMethods("/ca.crl.pem", ["GET", "HEAD"], async (HttpContext ctx, CertificateAuthorityService caService) =>
        {
            PublishedCrlRecord? crl = await caService.GetLatestCrlAsync();
            if (crl == null)
            {
                ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                if (!HttpMethods.IsHead(ctx.Request.Method))
                {
                    await ctx.Response.WriteAsync("No CRL has been published yet.");
                }
                return;
            }
            ctx.Response.ContentType = "application/x-pkcs7-crl";
            ctx.Response.ContentLength = System.Text.Encoding.UTF8.GetByteCount(crl.CrlPem);
            if (!HttpMethods.IsHead(ctx.Request.Method))
            {
                await ctx.Response.WriteAsync(crl.CrlPem);
            }
        }).AllowAnonymous();
    }
}
