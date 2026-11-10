using CertRobo;
using CertRobo.Data;
using CertRobo.Models;
using CertRobo.Services;
using CertRobo.Shared;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Radzen;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

IdentityModelEventSource.ShowPII = false;

var builder = WebApplication.CreateBuilder(args);

string[] cliCommandFlags =
[
    "--restore",
    "--reset-admin-password",
    "--backup",
    "--inspect-legacy-settings",
    "--bootstrap-admin",
    "--init-ca",
    "--request-external-ca",
    "--complete-external-ca",
    "--verify-ca-custody",
    "--reprotect-ca-keys",
    "--refresh-crls",
    "--issue-csr",
    "--export-issued",
    "--add-oidc-group-mapping",
    "--remove-oidc-group-mapping",
    "--invalidate-external-sessions"
];
bool isCliCommandMode = args.Any(a => cliCommandFlags.Contains(a, StringComparer.OrdinalIgnoreCase));
bool verboseDiagnostics = args.Contains("--verbose", StringComparer.OrdinalIgnoreCase)
    || string.Equals(Environment.GetEnvironmentVariable("CERTROBO_CLI_VERBOSE"), "1", StringComparison.OrdinalIgnoreCase)
    || string.Equals(
        builder.Configuration["Logging:LogLevel:Microsoft.EntityFrameworkCore.Database.Command"],
        "Information",
        StringComparison.OrdinalIgnoreCase);

if (isCliCommandMode && !verboseDiagnostics)
{
    builder.Logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.Warning);
    builder.Logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
    builder.Logging.AddFilter("Microsoft.AspNetCore.DataProtection", LogLevel.Warning);
}
else if (verboseDiagnostics)
{
    builder.Logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.Information);
}

string appDataDir = builder.Configuration["CertRobo:DataDirectory"]
    ?? Path.Combine(builder.Environment.ContentRootPath, "App_Data");
Directory.CreateDirectory(appDataDir);

string sqliteDbPath = builder.Configuration["CertRobo:SqliteFilePath"]
    ?? Path.Combine(appDataDir, "certrobo.db");
string connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? $"Data Source={sqliteDbPath}";

string dpKeysDir = Path.Combine(appDataDir, "dataprotection-keys");
Directory.CreateDirectory(dpKeysDir);

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(dpKeysDir))
    .SetApplicationName("CertRobo");

builder.Services.AddDbContextFactory<CertRoboDbContext>(options =>
    options.UseSqlite(connectionString));
builder.Services.AddScoped(sp =>
    sp.GetRequiredService<IDbContextFactory<CertRoboDbContext>>().CreateDbContext());

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequiredLength = 12;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = false;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    options.SignIn.RequireConfirmedAccount = false;
})
.AddEntityFrameworkStores<CertRoboDbContext>()
.AddDefaultTokenProviders();

OidcFederationOptions oidcOptions = OidcFederationOptions.FromConfiguration(builder.Configuration);
builder.Services.AddSingleton(oidcOptions);
builder.Services.AddScoped<OidcFederationService>();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "CertRobo.Auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.LoginPath = "/login";
    options.AccessDeniedPath = "/login";
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;
    options.Events.OnValidatePrincipal = async context =>
    {
        OidcFederationService oidcService = context.HttpContext.RequestServices.GetRequiredService<OidcFederationService>();
        bool isValid = await oidcService.ValidateSessionPrincipalAsync(context.Principal, context.HttpContext.RequestAborted);
        if (!isValid)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
        }
    };
});

builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    options.ValidationInterval = TimeSpan.FromSeconds(Math.Max(0, oidcOptions.SessionRevalidationSeconds));
});

builder.Services.AddAuthentication()
    .AddOpenIdConnect(OidcConstants.AuthenticationScheme, _ => { });

builder.Services.AddOptions<OpenIdConnectOptions>(OidcConstants.AuthenticationScheme)
    .Configure<OidcFederationOptions>(ConfigureOidcHandlerOptions);

CaKeyCustodyOptions caOptions = new()
{
    StorageDirectory = builder.Configuration["CertRobo:CaStorageDirectory"] ?? Path.Combine(appDataDir, "ca"),
    PassphraseEnvironmentVariable = builder.Configuration["CertRobo:CaPassphraseEnv"] ?? "CERTROBO_CA_PASSPHRASE",
    PassphraseFilePath = builder.Configuration["CertRobo:CaPassphraseFile"],
    ConfiguredPassphrase = builder.Configuration["CertRobo:CaPassphrase"],
    PublicBaseUrl = builder.Configuration["CertRobo:PublicBaseUrl"],
    CrlValidityHours = int.TryParse(builder.Configuration["CertRobo:CrlValidityHours"], out int crlHrs) ? crlHrs : 168,
    CrossProcessLockTimeoutMs = int.TryParse(builder.Configuration["CertRobo:CrossProcessLockTimeoutMs"], out int lockTimeoutMs) && lockTimeoutMs > 0
        ? lockTimeoutMs
        : 30_000
};
builder.Services.AddSingleton(caOptions);

ReverseProxyOptions reverseProxyOptions = ReverseProxyOptions.FromConfiguration(builder.Configuration);
builder.Services.AddSingleton(reverseProxyOptions);

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.ForwardLimit = Math.Max(1, reverseProxyOptions.ForwardLimit);
    options.RequireHeaderSymmetry = false;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();

    foreach (string rawProxy in reverseProxyOptions.KnownProxies)
    {
        if (System.Net.IPAddress.TryParse(rawProxy, out System.Net.IPAddress? proxyIp))
        {
            options.KnownProxies.Add(proxyIp);
        }
    }

    foreach (string rawNet in reverseProxyOptions.KnownNetworks)
    {
        if (System.Net.IPNetwork.TryParse(rawNet, out System.Net.IPNetwork network))
        {
            options.KnownIPNetworks.Add(network);
        }
    }
});

builder.Services.AddAntiforgery();
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddScoped<AuthenticationStateProvider, RevalidatingIdentityAuthenticationStateProvider>();
builder.Services.AddScoped<NotificationService>();
builder.Services.AddScoped<CertRobo.Shared.ThemeService>();
builder.Services.AddScoped<AccountManagementService>();
builder.Services.AddScoped<LegacySettingsMigrationService>();
builder.Services.AddScoped<IssuancePolicyService>();
builder.Services.AddSingleton<CertificateAuthorityService>();
builder.Services.AddSingleton<AdCsCesEnrollmentService>();
builder.Services.AddSingleton<BackupRestoreService>();
builder.Services.AddHostedService<CrlRefreshBackgroundService>();

var app = builder.Build();

// Handle CLI --restore before initializing an empty SQLite file over the target path
int restoreFlagIdx = Array.IndexOf(args, "--restore");
if (restoreFlagIdx >= 0)
{
    if (restoreFlagIdx + 1 >= args.Length)
    {
        Console.Error.WriteLine("Usage: --restore <inputArchive.zip>");
        Environment.ExitCode = 1;
        return;
    }
    string restoreZipPath = args[restoreFlagIdx + 1];
    if (!File.Exists(restoreZipPath))
    {
        Console.Error.WriteLine($"Backup archive not found: {restoreZipPath}");
        Environment.ExitCode = 1;
        return;
    }
    byte[] archiveBytes = await File.ReadAllBytesAsync(restoreZipPath);
    BackupRestoreService.RestoreBackupArchive(archiveBytes, sqliteDbPath, caOptions.StorageDirectory, dpKeysDir);
    Console.WriteLine($"Restore completed from '{restoreZipPath}'.");
    return;
}

// Ensure SQLite schema and default roles/settings exist
using (IServiceScope scope = app.Services.CreateScope())
{
    CertRoboDbContext db = scope.ServiceProvider.GetRequiredService<CertRoboDbContext>();
    await db.EnsureSchemaUpgradedAsync();

    AccountManagementService accountService = scope.ServiceProvider.GetRequiredService<AccountManagementService>();
    await accountService.EnsureRolesAndDefaultsAsync();

    // Handle CLI break-glass password reset if requested:
    // dotnet run -- --reset-admin-password <username> <newPassword>
    int resetFlagIdx = Array.IndexOf(args, "--reset-admin-password");
    if (resetFlagIdx >= 0)
    {
        if (resetFlagIdx + 2 >= args.Length)
        {
            Console.Error.WriteLine("Usage: --reset-admin-password <username> <newPassword>");
            Environment.ExitCode = 1;
            return;
        }
        string targetUser = args[resetFlagIdx + 1];
        string newPass = args[resetFlagIdx + 2];
        var (ok, err) = await accountService.ResetPasswordAsync(targetUser, newPass);
        if (!ok)
        {
            Console.Error.WriteLine($"Password reset failed: {err}");
            Environment.ExitCode = 1;
            return;
        }
        Console.WriteLine($"Password reset succeeded for user '{targetUser}'.");
        return;
    }

    // Handle CLI online backup if requested:
    // dotnet run -- --backup <outputArchive.zip>
    int backupFlagIdx = Array.IndexOf(args, "--backup");
    if (backupFlagIdx >= 0)
    {
        if (backupFlagIdx + 1 >= args.Length)
        {
            Console.Error.WriteLine("Usage: --backup <outputArchive.zip>");
            Environment.ExitCode = 1;
            return;
        }
        string outputZipPath = args[backupFlagIdx + 1];
        try
        {
            BackupRestoreService backupService = scope.ServiceProvider.GetRequiredService<BackupRestoreService>();
            byte[] archiveBytes = await backupService.CreateConsistentBackupArchiveAsync(sqliteDbPath, dpKeysDir);
            string? parentDir = Path.GetDirectoryName(Path.GetFullPath(outputZipPath));
            if (!string.IsNullOrEmpty(parentDir))
            {
                Directory.CreateDirectory(parentDir);
            }
            await BackupRestoreService.WritePrivateFileBytesAsync(outputZipPath, archiveBytes);
            Console.WriteLine($"Consistent backup written to '{outputZipPath}' ({archiveBytes.Length} bytes).");
            return;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Backup failed: {ex.Message}");
            Environment.ExitCode = 1;
            return;
        }
    }

    // Handle CLI legacy settings.xml inspection / defaults import:
    // dotnet run -- --inspect-legacy-settings <settings.xml> [--import-defaults]
    int inspectFlagIdx = Array.IndexOf(args, "--inspect-legacy-settings");
    if (inspectFlagIdx >= 0)
    {
        if (inspectFlagIdx + 1 >= args.Length)
        {
            Console.Error.WriteLine("Usage: --inspect-legacy-settings <path-to-settings.xml> [--import-defaults]");
            Environment.ExitCode = 1;
            return;
        }
        string xmlPath = args[inspectFlagIdx + 1];
        bool importDefaults = args.Contains("--import-defaults", StringComparer.OrdinalIgnoreCase);
        LegacySettingsMigrationService migrationService = scope.ServiceProvider.GetRequiredService<LegacySettingsMigrationService>();
        var report = await migrationService.InspectAndOptionallyImportDefaultsAsync(xmlPath, importDefaults);
        Console.WriteLine(report.FormatWorksheetText());
        if (importDefaults)
        {
            Console.WriteLine("Imported <Defaults> into standalone SubjectDefaultsConfig.");
        }
        return;
    }

    // Handle CLI first-admin bootstrap:
    // dotnet run -- --bootstrap-admin <username> <password> [<allowedDomainPattern>]
    int bootstrapIdx = Array.IndexOf(args, "--bootstrap-admin");
    if (bootstrapIdx >= 0)
    {
        if (bootstrapIdx + 2 >= args.Length)
        {
            Console.Error.WriteLine("Usage: --bootstrap-admin <username> <password> [<allowedDomainPattern>]");
            Environment.ExitCode = 1;
            return;
        }
        string adminUser = args[bootstrapIdx + 1];
        string adminPass = args[bootstrapIdx + 2];
        string pattern = bootstrapIdx + 3 < args.Length && !args[bootstrapIdx + 3].StartsWith("--", StringComparison.Ordinal)
            ? args[bootstrapIdx + 3]
            : "*";
        var (ok, err, _) = await accountService.BootstrapFirstAdminAsync(adminUser, adminPass, null, pattern);
        if (!ok)
        {
            Console.Error.WriteLine($"Bootstrap failed: {err}");
            Environment.ExitCode = 1;
            return;
        }
        Console.WriteLine($"Bootstrapped initial administrator '{adminUser}' with domain pattern '{pattern}'.");
        return;
    }

    // Handle CLI CA initialization:
    // dotnet run -- --init-ca <caName> <commonName> <keySpec:RSA-4096|RSA-2048|ECDSA-384|ECDSA-256> <validityDays> [<cdpUrl>] [<aiaUrl>] [--subordinate]
    int initCaIdx = Array.IndexOf(args, "--init-ca");
    if (initCaIdx >= 0)
    {
        if (initCaIdx + 4 >= args.Length)
        {
            Console.Error.WriteLine("Usage: --init-ca <caName> <commonName> <RSA-4096|RSA-2048|ECDSA-384|ECDSA-256> <validityDays> [<cdpUrl>] [<aiaUrl>] [--subordinate]");
            Environment.ExitCode = 1;
            return;
        }
        string caName = args[initCaIdx + 1];
        string commonName = args[initCaIdx + 2];
        string keySpec = args[initCaIdx + 3].ToUpperInvariant();
        int validityDays = int.Parse(args[initCaIdx + 4]);
        string cdpUrl = initCaIdx + 5 < args.Length && !args[initCaIdx + 5].StartsWith("--") ? args[initCaIdx + 5] : "/ca.crl";
        string aiaUrl = initCaIdx + 6 < args.Length && !args[initCaIdx + 6].StartsWith("--") ? args[initCaIdx + 6] : "/ca.crt";
        bool subordinate = args.Contains("--subordinate", StringComparer.OrdinalIgnoreCase);

        (CertificateKeyFamily family, int bits) = keySpec switch
        {
            "ECDSA-256" => (CertificateKeyFamily.Ecdsa, 256),
            "ECDSA-384" => (CertificateKeyFamily.Ecdsa, 384),
            "RSA-2048" => (CertificateKeyFamily.Rsa, 2048),
            "RSA-4096" => (CertificateKeyFamily.Rsa, 4096),
            _ => throw new ArgumentException($"Unsupported keySpec '{keySpec}'.")
        };

        CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
        string? passphrase = caService.ResolveEffectivePassphrase();
        if (string.IsNullOrEmpty(passphrase))
        {
            Console.Error.WriteLine("CA passphrase must be configured via CERTROBO_CA_PASSPHRASE or CertRobo:CaPassphraseFile.");
            Environment.ExitCode = 1;
            return;
        }

        SubjectDefaultsConfig defaults = await accountService.GetSubjectDefaultsAsync();
        CaAuthorityRecord? parent = subordinate ? await caService.GetActiveAuthorityAsync() : null;
        try
        {
            CaAuthorityRecord created = await caService.CreateSelfSignedOrIntermediateCaAsync(
                caName,
                commonName,
                defaults.Country,
                defaults.StateOrProvince,
                defaults.Locality,
                defaults.Organisation,
                defaults.OrganisationalUnit,
                family,
                bits,
                validityDays,
                passphrase,
                crlDistributionPointUrl: cdpUrl,
                authorityIssuerCertUrl: aiaUrl,
                parentAuthority: parent,
                parentPassphrase: passphrase);

            Console.WriteLine($"Initialized and activated {(created.IsIntermediate ? "Intermediate" : "Root")} CA '{created.Name}' (SKI={created.SubjectKeyIdentifierHex}).");
            return;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"CA initialization failed: {ex.Message}");
            Environment.ExitCode = 1;
            return;
        }
    }

    // Handle CLI external CA CSR generation:
    // dotnet run -- --request-external-ca <caName> <commonName> <RSA-4096|RSA-2048|ECDSA-384|ECDSA-256> <outCsrPath> [<cdpUrl>] [<aiaUrl>]
    int reqExtCaIdx = Array.IndexOf(args, "--request-external-ca");
    if (reqExtCaIdx >= 0)
    {
        if (reqExtCaIdx + 4 >= args.Length)
        {
            Console.Error.WriteLine("Usage: --request-external-ca <caName> <commonName> <RSA-4096|RSA-2048|ECDSA-384|ECDSA-256> <outCsrPath> [<cdpUrl>] [<aiaUrl>]");
            Environment.ExitCode = 1;
            return;
        }
        string caName = args[reqExtCaIdx + 1];
        string commonName = args[reqExtCaIdx + 2];
        string keySpec = args[reqExtCaIdx + 3].ToUpperInvariant();
        string outCsrPath = args[reqExtCaIdx + 4];
        string cdpUrl = reqExtCaIdx + 5 < args.Length && !args[reqExtCaIdx + 5].StartsWith("--") ? args[reqExtCaIdx + 5] : "/ca.crl";
        string aiaUrl = reqExtCaIdx + 6 < args.Length && !args[reqExtCaIdx + 6].StartsWith("--") ? args[reqExtCaIdx + 6] : "/ca.crt";

        (CertificateKeyFamily family, int bits) = keySpec switch
        {
            "ECDSA-256" => (CertificateKeyFamily.Ecdsa, 256),
            "ECDSA-384" => (CertificateKeyFamily.Ecdsa, 384),
            "RSA-2048" => (CertificateKeyFamily.Rsa, 2048),
            "RSA-4096" => (CertificateKeyFamily.Rsa, 4096),
            _ => throw new ArgumentException($"Unsupported keySpec '{keySpec}'.")
        };

        CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
        string? passphrase = caService.ResolveEffectivePassphrase();
        if (string.IsNullOrEmpty(passphrase))
        {
            Console.Error.WriteLine("CA passphrase must be configured via CERTROBO_CA_PASSPHRASE or CertRobo:CaPassphraseFile.");
            Environment.ExitCode = 1;
            return;
        }

        SubjectDefaultsConfig defaults = await accountService.GetSubjectDefaultsAsync();
        try
        {
            PendingCaEnrollmentRecord pending = await caService.CreatePendingCaEnrollmentAsync(
                caName,
                commonName,
                defaults.Country,
                defaults.StateOrProvince,
                defaults.Locality,
                defaults.Organisation,
                defaults.OrganisationalUnit,
                family,
                bits,
                passphrase,
                requestedPathLengthConstraint: 0,
                crlDistributionPointUrl: cdpUrl,
                authorityIssuerCertUrl: aiaUrl,
                emailAddress: defaults.EmailAddress);

            await File.WriteAllTextAsync(outCsrPath, pending.CsrPem);
            Console.WriteLine($"Generated pending Issuing CA request #{pending.Id} '{pending.CaName}' (SKI={pending.SubjectKeyIdentifierHex}) -> {outCsrPath}");
            return;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"External CA request failed: {ex.Message}");
            Environment.ExitCode = 1;
            return;
        }
    }

    // Handle CLI external CA completion & activation:
    // dotnet run -- --complete-external-ca <signedCertOrBundlePath> [<parentChainPath>]
    int completeExtCaIdx = Array.IndexOf(args, "--complete-external-ca");
    if (completeExtCaIdx >= 0)
    {
        if (completeExtCaIdx + 1 >= args.Length)
        {
            Console.Error.WriteLine("Usage: --complete-external-ca <signedCertOrBundlePath> [<parentChainPath>]");
            Environment.ExitCode = 1;
            return;
        }
        string signedPath = args[completeExtCaIdx + 1];
        string? chainPath = completeExtCaIdx + 2 < args.Length && !args[completeExtCaIdx + 2].StartsWith("--")
            ? args[completeExtCaIdx + 2]
            : null;

        CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
        PendingCaEnrollmentRecord? pending = await caService.GetActivePendingEnrollmentAsync();
        if (pending == null)
        {
            Console.Error.WriteLine("No active pending external CA enrolment request was found.");
            Environment.ExitCode = 1;
            return;
        }

        System.IO.FileInfo signedInfo = new(signedPath);
        if (!signedInfo.Exists || signedInfo.Length > CaChainAndConstraintValidator.MaxBundleRawBytes)
        {
            Console.Error.WriteLine($"External CA validation failed: '{signedPath}' does not exist or exceeds the maximum permitted size ({CaChainAndConstraintValidator.MaxBundleRawBytes} bytes).");
            Environment.ExitCode = 1;
            return;
        }

        if (!string.IsNullOrEmpty(chainPath))
        {
            System.IO.FileInfo chainInfo = new(chainPath);
            if (!chainInfo.Exists || chainInfo.Length > CaChainAndConstraintValidator.MaxBundleRawBytes)
            {
                Console.Error.WriteLine($"External CA validation failed: '{chainPath}' does not exist or exceeds the maximum permitted size ({CaChainAndConstraintValidator.MaxBundleRawBytes} bytes).");
                Environment.ExitCode = 1;
                return;
            }
        }

        byte[] signedBytes = await File.ReadAllBytesAsync(signedPath);
        byte[]? chainBytes = !string.IsNullOrEmpty(chainPath) ? await File.ReadAllBytesAsync(chainPath) : null;

        CaBundleValidationResult valResult = await caService.ValidateAndStageSignedCaBundleAsync(
            pending.Id,
            signedBytes,
            signedCertText: null,
            chainBytes,
            chainCertText: null);

        if (!valResult.IsValid)
        {
            Console.Error.WriteLine($"External CA validation failed: {valResult.ErrorMessage}");
            Environment.ExitCode = 1;
            return;
        }

        try
        {
            CaAuthorityRecord activated = await caService.ActivatePendingCaEnrollmentAsync(pending.Id);
            Console.WriteLine($"Validated and activated external Issuing CA '{activated.Name}' (SKI={activated.SubjectKeyIdentifierHex}).");
            return;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"External CA activation failed: {ex.Message}");
            Environment.ExitCode = 1;
            return;
        }
    }

    // Handle CLI CA custody diagnostic verification:
    // dotnet run -- --verify-ca-custody
    if (args.Contains("--verify-ca-custody", StringComparer.OrdinalIgnoreCase))
    {
        CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
        CaKeyCustodyReport report = await caService.InspectKeyCustodyAsync();
        Console.WriteLine($"Configured Persistent Custody: {(report.HasConfiguredPersistentPassphrase ? report.ConfiguredPersistentSource : "None (manual runtime unlock required after restart)")}");
        Console.WriteLine($"Effective Passphrase Available: {report.HasEffectivePassphrase}");
        foreach (CaAuthorityKeyCustodyStatus auth in report.Authorities)
        {
            string status = auth.CanDecryptWithEffectivePassphrase ? "OK" : $"FAILED ({auth.FailureReason})";
            Console.WriteLine($"CA #{auth.CaAuthorityId} '{auth.CaName}' (Active={auth.IsActive}, MaintainCrl={auth.RequiresCrlMaintenance}): {status}");
        }
        if (report.PendingEnrollment != null)
        {
            string pStatus = report.PendingEnrollment.CanDecryptWithEffectivePassphrase
                ? "OK"
                : $"FAILED ({report.PendingEnrollment.FailureReason})";
            Console.WriteLine($"Pending CA #{report.PendingEnrollment.PendingEnrollmentId} '{report.PendingEnrollment.CaName}': {pStatus}");
        }

        bool hasStoredKeys = report.Authorities.Count > 0 || report.PendingEnrollment != null;
        if (!report.IsCustodyHealthy || (hasStoredKeys && !report.HasEffectivePassphrase))
        {
            Console.Error.WriteLine("CA key custody check failed: one or more stored CA keys cannot be unlocked with the current custody secret.");
            Environment.ExitCode = 1;
            return;
        }

        Console.WriteLine("CA key custody check passed.");
        return;
    }

    // Handle CLI CA key re-protection / migration to shared custody secret:
    // dotnet run -- --reprotect-ca-keys <sourcePassphraseFile>
    int reprotectIdx = Array.IndexOf(args, "--reprotect-ca-keys");
    if (reprotectIdx >= 0)
    {
        if (reprotectIdx + 1 >= args.Length)
        {
            Console.Error.WriteLine("Usage: --reprotect-ca-keys <sourcePassphraseFile>");
            Environment.ExitCode = 1;
            return;
        }

        string sourcePassFile = args[reprotectIdx + 1];
        if (!File.Exists(sourcePassFile))
        {
            Console.Error.WriteLine($"Source passphrase file not found: {sourcePassFile}");
            Environment.ExitCode = 1;
            return;
        }

        CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
        string? targetPassphrase = caService.ResolveConfiguredPassphrase();
        if (string.IsNullOrEmpty(targetPassphrase))
        {
            Console.Error.WriteLine("Target CA storage passphrase must be configured via CERTROBO_CA_PASSPHRASE, CertRobo:CaPassphraseFile, or CertRobo:CaPassphrase.");
            Environment.ExitCode = 1;
            return;
        }

        string[] sourceLines = (await File.ReadAllLinesAsync(sourcePassFile))
            .Select(l => l.Trim())
            .Where(l => !string.IsNullOrEmpty(l))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (sourceLines.Length == 0)
        {
            Console.Error.WriteLine("Source passphrase file did not contain any non-empty passphrases.");
            Environment.ExitCode = 1;
            return;
        }

        try
        {
            CaKeyReprotectionResult reprotectResult = await caService.ReprotectCaKeysAsync(
                sourceLines,
                targetPassphrase);
            CaKeyCustodyReport postReport = await caService.InspectKeyCustodyAsync();
            if (!postReport.IsCustodyHealthy || !postReport.HasEffectivePassphrase)
            {
                Console.Error.WriteLine("CA key re-protection failed post-migration custody verification.");
                Environment.ExitCode = 1;
                return;
            }
            Console.WriteLine(reprotectResult.SummaryMessage);
            return;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"CA key re-protection failed: {ex.Message}");
            Environment.ExitCode = 1;
            return;
        }
    }

    // Handle CLI CRL refresh / pending revocation publication:
    // dotnet run -- --refresh-crls
    if (args.Contains("--refresh-crls", StringComparer.OrdinalIgnoreCase))
    {
        CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
        IReadOnlyList<CrlRefreshOutcome> outcomes = await caService.RefreshDueCrlsAsync(TimeSpan.FromHours(24));
        bool anyFailed = false;
        foreach (CrlRefreshOutcome outcome in outcomes)
        {
            if (outcome.Succeeded && outcome.PublishedCrl != null)
            {
                Console.WriteLine($"Published CRL #{outcome.PublishedCrl.CrlNumber} for CA #{outcome.CaAuthorityId} '{outcome.CaName}'.");
            }
            else
            {
                anyFailed = true;
                Console.Error.WriteLine($"CRL refresh failed for CA #{outcome.CaAuthorityId} '{outcome.CaName}': {outcome.ErrorMessage}");
            }
        }
        if (anyFailed)
        {
            Environment.ExitCode = 1;
        }
        return;
    }

    // Handle CLI CSR issuance:
    // dotnet run -- --issue-csr <username> <csrPath> <outCertPath> [<outTlsServerChainPath>] [--root-out <outRootCertPath>] [--fullchain-out <outFullChainPath>]
    int issueIdx = Array.IndexOf(args, "--issue-csr");
    if (issueIdx >= 0)
    {
        if (issueIdx + 3 >= args.Length)
        {
            Console.Error.WriteLine("Usage: --issue-csr <username> <csrPath> <outCertPath> [<outTlsServerChainPath>] [--root-out <outRootCertPath>] [--fullchain-out <outFullChainPath>]");
            Environment.ExitCode = 1;
            return;
        }
        string reqUser = args[issueIdx + 1];
        string csrPath = args[issueIdx + 2];
        string outCertPath = args[issueIdx + 3];
        string? outChainPath = issueIdx + 4 < args.Length && !args[issueIdx + 4].StartsWith("--", StringComparison.Ordinal)
            ? args[issueIdx + 4]
            : null;
        string? outFullChainPath = null;
        string? fullChainOptErr = null;
        if (!TryExtractOptionValue(args, "--root-out", out string? outRootPath, out string? rootOptErr)
            || !TryExtractOptionValue(args, "--fullchain-out", out outFullChainPath, out fullChainOptErr))
        {
            Console.Error.WriteLine(rootOptErr ?? fullChainOptErr);
            Environment.ExitCode = 1;
            return;
        }
        bool forceReissue = args.Contains("--force-reissue", StringComparer.OrdinalIgnoreCase);

        UserManager<ApplicationUser> userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        ApplicationUser? user = await userMgr.FindByNameAsync(reqUser);
        if (user == null)
        {
            Console.Error.WriteLine($"User '{reqUser}' not found.");
            Environment.ExitCode = 1;
            return;
        }

        string csrPem;
        try
        {
            System.IO.FileInfo csrInfo = new(csrPath);
            if (!csrInfo.Exists || csrInfo.Length > IssuancePolicyService.MaxCsrPemLength)
            {
                Console.Error.WriteLine($"Issuance failed: CSR file '{csrPath}' does not exist or exceeds the maximum permitted size ({IssuancePolicyService.MaxCsrPemLength} bytes).");
                Environment.ExitCode = 1;
                return;
            }

            csrPem = await File.ReadAllTextAsync(csrPath);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Issuance failed: could not read CSR file '{csrPath}': {ex.Message}");
            Environment.ExitCode = 1;
            return;
        }

        List<string> destinationPaths = [outCertPath];
        if (!string.IsNullOrWhiteSpace(outChainPath))
        {
            destinationPaths.Add(outChainPath);
        }
        if (!string.IsNullOrWhiteSpace(outRootPath))
        {
            destinationPaths.Add(outRootPath);
        }
        if (!string.IsNullOrWhiteSpace(outFullChainPath))
        {
            destinationPaths.Add(outFullChainPath);
        }

        // 1. Check whether an unexpired Issued certificate for the exact same CSR public key and identities already exists
        //    so retrying a failed output write recovers the existing certificate without silent duplicate issuance.
        CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
        IssuanceOutcome? recoveredExisting = !forceReissue
            ? await TryRecoverExistingIssuedCertificateForCsrAsync(db, caService, user, csrPem)
            : null;
        if (recoveredExisting != null)
        {
            if (!TryPreflightDestinationPaths(destinationPaths, out string? recoveryPreflightErr))
            {
                Console.Error.WriteLine(
                    $"Output write failed for already-issued certificate serial {recoveredExisting.Record!.SerialNumberHex} ('{recoveredExisting.Record.CommonName}'): {recoveryPreflightErr} " +
                    $"Re-run with a writable output path or run '--export-issued {recoveredExisting.Record.SerialNumberHex} <outCertPath> [<outTlsServerChainPath>]' to write the existing certificate without re-issuing.");
                Environment.ExitCode = 1;
                return;
            }

            if (!await TryWriteIssuedCertificateOutputsAsync(
                    recoveredExisting,
                    outCertPath,
                    outChainPath,
                    outRootPath,
                    outFullChainPath))
            {
                Environment.ExitCode = 1;
                return;
            }

            Console.WriteLine($"Recovered already-issued certificate serial {recoveredExisting.Record!.SerialNumberHex} for '{recoveredExisting.Record.CommonName}' -> {outCertPath}");
            return;
        }

        // 2. Preflight destination writability before allocating a serial or signing a new certificate
        if (!TryPreflightDestinationPaths(destinationPaths, out string? preflightErr))
        {
            Console.Error.WriteLine($"Issuance aborted before signing: {preflightErr}");
            Environment.ExitCode = 1;
            return;
        }

        IssuanceOutcome outcome = await caService.IssueCertificateFromCsrAsync(
            user.Id,
            csrPem,
            recoverExistingForSameCsr: !forceReissue);
        if (!outcome.Succeeded)
        {
            Console.Error.WriteLine($"Issuance failed: {outcome.ErrorMessage}");
            Environment.ExitCode = 1;
            return;
        }

        if (!await TryWriteIssuedCertificateOutputsAsync(
                outcome,
                outCertPath,
                outChainPath,
                outRootPath,
                outFullChainPath))
        {
            Environment.ExitCode = 1;
            return;
        }

        if (outcome.WasRecoveredExisting)
        {
            Console.WriteLine($"Recovered already-issued certificate serial {outcome.Record!.SerialNumberHex} for '{outcome.Record.CommonName}' -> {outCertPath}");
        }
        else
        {
            Console.WriteLine($"Issued certificate serial {outcome.Record!.SerialNumberHex} for '{outcome.Record.CommonName}' -> {outCertPath}");
        }
        return;
    }

    // Handle CLI recovery/export of an already-issued certificate by serial number (hex) or record ID:
    // dotnet run -- --export-issued <serialHexOrId> <outCertPath> [<outTlsServerChainPath>] [--root-out <outRootCertPath>] [--fullchain-out <outFullChainPath>]
    int exportIssuedIdx = Array.IndexOf(args, "--export-issued");
    if (exportIssuedIdx >= 0)
    {
        if (exportIssuedIdx + 2 >= args.Length)
        {
            Console.Error.WriteLine("Usage: --export-issued <serialHexOrRecordId> <outCertPath> [<outTlsServerChainPath>] [--root-out <outRootCertPath>] [--fullchain-out <outFullChainPath>]");
            Environment.ExitCode = 1;
            return;
        }

        string selector = args[exportIssuedIdx + 1].Trim();
        string outCertPath = args[exportIssuedIdx + 2];
        string? outChainPath = exportIssuedIdx + 3 < args.Length && !args[exportIssuedIdx + 3].StartsWith("--", StringComparison.Ordinal)
            ? args[exportIssuedIdx + 3]
            : null;
        string? outFullChainPath = null;
        string? fullChainOptErr = null;
        if (!TryExtractOptionValue(args, "--root-out", out string? outRootPath, out string? rootOptErr)
            || !TryExtractOptionValue(args, "--fullchain-out", out outFullChainPath, out fullChainOptErr))
        {
            Console.Error.WriteLine(rootOptErr ?? fullChainOptErr);
            Environment.ExitCode = 1;
            return;
        }

        IssuedCertificateRecord? record = null;
        if (CertificateAuthorityService.TryNormalizePositiveSerialHex(selector, out var targetBi, out string canonicalHex, out _))
        {
            List<IssuedCertificateRecord> candidates = await db.IssuedCertificates
                .AsNoTracking()
                .Where(c => c.Status == IssuanceStatus.Issued || c.Status == IssuanceStatus.Revoked)
                .OrderByDescending(c => c.Id)
                .ToListAsync();
            record = candidates.FirstOrDefault(c =>
                string.Equals(c.SerialNumberHex, canonicalHex, StringComparison.OrdinalIgnoreCase)
                || (CertificateAuthorityService.TryNormalizePositiveSerialHex(c.SerialNumberHex, out var cBi, out _, out _)
                    && cBi.Equals(targetBi)));
        }

        if (record == null && int.TryParse(selector, out int parsedId))
        {
            record = await db.IssuedCertificates
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == parsedId && !string.IsNullOrEmpty(c.CertificatePem));
        }

        if (record == null || string.IsNullOrWhiteSpace(record.CertificatePem))
        {
            Console.Error.WriteLine($"Export failed: no issued certificate matching '{selector}' was found.");
            Environment.ExitCode = 1;
            return;
        }

        CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
        string issuerChainPem = !string.IsNullOrWhiteSpace(record.ChainPem)
            ? record.ChainPem
            : (await caService.ResolveCertificateChainPemAsync(record.CertificatePem) ?? string.Empty);

        IssuanceOutcome exportOutcome = new(
            true,
            null,
            record,
            record.CertificatePem,
            record.CertificatePem + issuerChainPem,
            CertificateAuthorityService.BuildTlsServerChainPem(record.CertificatePem, issuerChainPem),
            CertificateAuthorityService.ExtractTrustAnchorRootPem(issuerChainPem));

        List<string> destinationPaths = [outCertPath];
        if (!string.IsNullOrWhiteSpace(outChainPath)) destinationPaths.Add(outChainPath);
        if (!string.IsNullOrWhiteSpace(outRootPath)) destinationPaths.Add(outRootPath);
        if (!string.IsNullOrWhiteSpace(outFullChainPath)) destinationPaths.Add(outFullChainPath);

        if (!TryPreflightDestinationPaths(destinationPaths, out string? preflightErr))
        {
            Console.Error.WriteLine($"Export failed for certificate serial {record.SerialNumberHex}: {preflightErr}");
            Environment.ExitCode = 1;
            return;
        }

        if (!await TryWriteIssuedCertificateOutputsAsync(
                exportOutcome,
                outCertPath,
                outChainPath,
                outRootPath,
                outFullChainPath))
        {
            Environment.ExitCode = 1;
            return;
        }

        Console.WriteLine($"Exported issued certificate serial {record.SerialNumberHex} for '{record.CommonName}' -> {outCertPath}");
        return;
    }

    // Handle CLI external group mapping creation/update:
    // dotnet run -- --add-oidc-group-mapping <groupName> <Administrator|Issuer> [<commaSeparatedDomains>] [<allowedProfileId>]
    int addOidcMapIdx = Array.IndexOf(args, "--add-oidc-group-mapping");
    if (addOidcMapIdx >= 0)
    {
        if (addOidcMapIdx + 2 >= args.Length)
        {
            Console.Error.WriteLine("Usage: --add-oidc-group-mapping <groupName> <Administrator|Issuer> [<commaSeparatedDomains>] [<allowedProfileId>]");
            Environment.ExitCode = 1;
            return;
        }

        string groupName = args[addOidcMapIdx + 1];
        string roleName = args[addOidcMapIdx + 2];
        string? domainsCsv = addOidcMapIdx + 3 < args.Length && !args[addOidcMapIdx + 3].StartsWith("--", StringComparison.Ordinal)
            ? args[addOidcMapIdx + 3]
            : null;
        string allowedProfile = addOidcMapIdx + 4 < args.Length && !args[addOidcMapIdx + 4].StartsWith("--", StringComparison.Ordinal)
            ? args[addOidcMapIdx + 4]
            : "*";

        string[] domainPatterns = string.IsNullOrWhiteSpace(domainsCsv)
            ? []
            : domainsCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var (ok, err, _) = await accountService.SetExternalGroupRoleMappingAsync(
            groupName,
            roleName,
            domainPatterns,
            allowedProfile);
        if (!ok)
        {
            Console.Error.WriteLine($"OIDC group mapping failed: {err}");
            Environment.ExitCode = 1;
            return;
        }

        Console.WriteLine($"Configured external group mapping '{groupName}' -> role '{roleName}' (domains: {(domainPatterns.Length > 0 ? string.Join(", ", domainPatterns) : "none")}, profile: {allowedProfile}).");
        return;
    }

    // Handle CLI external group mapping removal:
    // dotnet run -- --remove-oidc-group-mapping <groupName>
    int rmOidcMapIdx = Array.IndexOf(args, "--remove-oidc-group-mapping");
    if (rmOidcMapIdx >= 0)
    {
        if (rmOidcMapIdx + 1 >= args.Length)
        {
            Console.Error.WriteLine("Usage: --remove-oidc-group-mapping <groupName>");
            Environment.ExitCode = 1;
            return;
        }

        string groupName = args[rmOidcMapIdx + 1];
        var (ok, err) = await accountService.RemoveExternalGroupRoleMappingByNameAsync(groupName);
        if (!ok)
        {
            Console.Error.WriteLine($"Removing OIDC group mapping failed: {err}");
            Environment.ExitCode = 1;
            return;
        }

        Console.WriteLine($"Removed external group mapping '{groupName}' and invalidated affected external sessions.");
        return;
    }

    // Handle CLI session kill switch for external (or specific) accounts:
    // dotnet run -- --invalidate-external-sessions [<userNameOrId>]
    int invalidateExtIdx = Array.IndexOf(args, "--invalidate-external-sessions");
    if (invalidateExtIdx >= 0)
    {
        string? targetUser = invalidateExtIdx + 1 < args.Length && !args[invalidateExtIdx + 1].StartsWith("--", StringComparison.Ordinal)
            ? args[invalidateExtIdx + 1]
            : null;
        if (!string.IsNullOrWhiteSpace(targetUser))
        {
            var (ok, err) = await accountService.InvalidateUserSessionsAsync(targetUser);
            if (!ok)
            {
                Console.Error.WriteLine($"Session invalidation failed: {err}");
                Environment.ExitCode = 1;
                return;
            }
            Console.WriteLine($"Invalidated active sessions for user '{targetUser}'.");
            return;
        }

        int count = await accountService.InvalidateAllExternalSessionsAsync();
        Console.WriteLine($"Invalidated active sessions for {count} external OpenID Connect account(s).");
        return;
    }
}

app.UseForwardedHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapCertRoboEndpoints();
app.MapBlazorHub();
app.MapFallbackToPage("/_Host");
app.Run();

static bool TryExtractOptionValue(string[] cliArgs, string flagName, out string? optionValue, out string? errorMessage)
{
    optionValue = null;
    errorMessage = null;
    int idx = Array.FindIndex(cliArgs, a => string.Equals(a, flagName, StringComparison.OrdinalIgnoreCase));
    if (idx < 0)
    {
        return true;
    }

    if (idx + 1 >= cliArgs.Length || cliArgs[idx + 1].StartsWith("--", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(cliArgs[idx + 1]))
    {
        errorMessage = $"Option '{flagName}' requires a file path argument.";
        return false;
    }

    optionValue = cliArgs[idx + 1];
    return true;
}

static bool TryPreflightDestinationPaths(IReadOnlyList<string> paths, out string? errorMessage)
{
    errorMessage = null;
    HashSet<string> seenFullPaths = new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
    foreach (string rawPath in paths)
    {
        if (string.IsNullOrWhiteSpace(rawPath))
        {
            errorMessage = "Output file path cannot be empty.";
            return false;
        }

        try
        {
            string fullPath = Path.GetFullPath(rawPath);
            if (!seenFullPaths.Add(fullPath))
            {
                errorMessage = $"Duplicate output file path '{rawPath}' is not allowed; each requested output must use a distinct path.";
                return false;
            }

            if (Directory.Exists(fullPath))
            {
                errorMessage = $"Destination path '{rawPath}' is an existing directory, not a file.";
                return false;
            }

            string? dir = Path.GetDirectoryName(fullPath);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
            {
                errorMessage = $"Destination directory for '{rawPath}' does not exist.";
                return false;
            }

            string probePath = Path.Combine(dir, $".certrobo-write-probe-{Guid.NewGuid():N}.tmp");
            using (new FileStream(probePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose))
            {
            }

            if (File.Exists(fullPath))
            {
                using (new FileStream(fullPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
                {
                }
            }
        }
        catch (Exception ex)
        {
            errorMessage = $"Destination path '{rawPath}' is not writable ({ex.Message}).";
            return false;
        }
    }

    return true;
}

static async Task<bool> TryWriteIssuedCertificateOutputsAsync(
    IssuanceOutcome outcome,
    string outCertPath,
    string? outTlsServerChainPath,
    string? outRootPath,
    string? outFullChainPath)
{
    List<(string TargetPath, string TempPath)> stagedFiles = [];
    try
    {
        string leafPem = outcome.CertificatePem ?? string.Empty;
        string issuerChainPem = outcome.Record?.ChainPem ?? string.Empty;
        string tlsServerChainPem = !string.IsNullOrEmpty(outcome.TlsServerChainPem)
            ? outcome.TlsServerChainPem
            : CertificateAuthorityService.BuildTlsServerChainPem(leafPem, issuerChainPem);
        string fullChainPem = !string.IsNullOrEmpty(outcome.FullChainPem)
            ? outcome.FullChainPem
            : (leafPem + issuerChainPem);
        string rootPem = !string.IsNullOrEmpty(outcome.RootTrustAnchorPem)
            ? outcome.RootTrustAnchorPem
            : CertificateAuthorityService.ExtractTrustAnchorRootPem(issuerChainPem);

        List<(string Path, string Content)> requestedWrites = [(outCertPath, leafPem)];
        if (!string.IsNullOrWhiteSpace(outTlsServerChainPath))
        {
            requestedWrites.Add((outTlsServerChainPath, tlsServerChainPem));
        }
        if (!string.IsNullOrWhiteSpace(outRootPath))
        {
            requestedWrites.Add((outRootPath, rootPem));
        }
        if (!string.IsNullOrWhiteSpace(outFullChainPath))
        {
            requestedWrites.Add((outFullChainPath, fullChainPem));
        }

        string? simulatedFailTarget = Environment.GetEnvironmentVariable("CERTROBO_TEST_FAIL_CLI_OUTPUT_PATH");

        for (int i = 0; i < requestedWrites.Count; i++)
        {
            var (targetPath, content) = requestedWrites[i];
            if (!string.IsNullOrEmpty(simulatedFailTarget)
                && (string.Equals(targetPath, simulatedFailTarget, StringComparison.Ordinal)
                    || (string.Equals(simulatedFailTarget, "CHAIN", StringComparison.OrdinalIgnoreCase) && i > 0)))
            {
                throw new IOException($"Simulated post-issuance write failure for '{targetPath}'.");
            }

            string fullTarget = Path.GetFullPath(targetPath);
            string dir = Path.GetDirectoryName(fullTarget)!;
            string tempPath = Path.Combine(dir, $".{Path.GetFileName(fullTarget)}.tmp-{Guid.NewGuid():N}");
            await File.WriteAllTextAsync(tempPath, content);
            stagedFiles.Add((fullTarget, tempPath));
        }

        foreach (var (fullTarget, tempPath) in stagedFiles)
        {
            File.Move(tempPath, fullTarget, overwrite: true);
        }

        return true;
    }
    catch (Exception ex)
    {
        foreach (var (_, tempPath) in stagedFiles)
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch
            {
            }
        }

        string serialHex = outcome.Record?.SerialNumberHex ?? "UNKNOWN";
        string commonName = outcome.Record?.CommonName ?? "unknown";
        Console.Error.WriteLine(
            $"Certificate serial {serialHex} for '{commonName}' was issued and recorded, but writing output file(s) failed: {ex.Message} " +
            $"Recover the issued certificate without duplicate issuance by re-running the same '--issue-csr' command with a writable path or running: " +
            $"./CertRobo --export-issued {serialHex} <outCertPath> [<outTlsServerChainPath>]");
        return false;
    }
}

static async Task<IssuanceOutcome?> TryRecoverExistingIssuedCertificateForCsrAsync(
    CertRoboDbContext db,
    CertificateAuthorityService caService,
    ApplicationUser user,
    string csrPem)
{
    var (csrValid, _, validatedCsr) = IssuancePolicyService.ParseAndValidateCsr(csrPem);
    if (!csrValid || validatedCsr == null)
    {
        return null;
    }

    CaAuthorityRecord? activeCa = await caService.GetActiveAuthorityAsync();
    if (activeCa == null)
    {
        return null;
    }

    byte[] csrSpkiDer = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory
        .CreateSubjectPublicKeyInfo(validatedCsr.PublicKey)
        .GetDerEncoded();
    string requestedSansCsv = string.Join(",", validatedCsr.CanonicalDnsIdentities);
    DateTimeOffset now = DateTimeOffset.UtcNow;

    List<IssuedCertificateRecord> candidates = await db.IssuedCertificates
        .AsNoTracking()
        .Where(c => c.CaAuthorityId == activeCa.Id
                 && c.RequestedByUserId == user.Id
                 && c.Status == IssuanceStatus.Issued
                 && c.CommonName == validatedCsr.CommonName
                 && c.SubjectAlternativeNamesCsv == requestedSansCsv)
        .OrderByDescending(c => c.Id)
        .ToListAsync();

    foreach (IssuedCertificateRecord candidate in candidates)
    {
        if (candidate.NotAfterUtc <= now || string.IsNullOrWhiteSpace(candidate.CertificatePem))
        {
            continue;
        }

        try
        {
            using var cert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(candidate.CertificatePem);
            if (cert.PublicKey.ExportSubjectPublicKeyInfo().SequenceEqual(csrSpkiDer))
            {
                string issuerChainPem = !string.IsNullOrWhiteSpace(candidate.ChainPem)
                    ? candidate.ChainPem
                    : CertificateAuthorityService.BuildOrderedCertificateChainPem(activeCa);
                return new IssuanceOutcome(
                    true,
                    null,
                    candidate,
                    candidate.CertificatePem,
                    candidate.CertificatePem + issuerChainPem,
                    CertificateAuthorityService.BuildTlsServerChainPem(candidate.CertificatePem, issuerChainPem),
                    CertificateAuthorityService.ExtractTrustAnchorRootPem(issuerChainPem));
            }
        }
        catch
        {
        }
    }

    return null;
}

static void ConfigureOidcHandlerOptions(OpenIdConnectOptions options, OidcFederationOptions oidcOptions)
{
    options.SignInScheme = IdentityConstants.ApplicationScheme;
    options.Authority = !string.IsNullOrWhiteSpace(oidcOptions.EffectiveAuthority)
        ? oidcOptions.EffectiveAuthority
        : "https://disabled.oidc.invalid";
    if (!string.IsNullOrWhiteSpace(oidcOptions.MetadataAddress))
    {
        options.MetadataAddress = oidcOptions.MetadataAddress;
    }

    options.ClientId = !string.IsNullOrWhiteSpace(oidcOptions.ClientId)
        ? oidcOptions.ClientId
        : "disabled";
    options.ClientSecret = oidcOptions.ResolveEffectiveClientSecret() ?? "disabled";
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.ResponseMode = OpenIdConnectResponseMode.Query;
    options.UsePkce = true;
    options.SaveTokens = false;
    options.GetClaimsFromUserInfoEndpoint = oidcOptions.GetClaimsFromUserInfoEndpoint;
    options.MapInboundClaims = false;
    options.RequireHttpsMetadata = true;
    options.DisableTelemetry = true;
    options.CallbackPath = new PathString(oidcOptions.EffectiveCallbackPath);
    options.SignedOutCallbackPath = new PathString(oidcOptions.SignedOutCallbackPath);

    options.CorrelationCookie.Name = "CertRobo.Oidc.Correlation.";
    options.CorrelationCookie.HttpOnly = true;
    options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
    options.CorrelationCookie.SameSite = SameSiteMode.Lax;

    options.NonceCookie.Name = "CertRobo.Oidc.Nonce.";
    options.NonceCookie.HttpOnly = true;
    options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
    options.NonceCookie.SameSite = SameSiteMode.Lax;

    options.Scope.Clear();
    options.Scope.Add("openid");
    foreach (string scope in oidcOptions.Scopes)
    {
        if (!string.IsNullOrWhiteSpace(scope) && !options.Scope.Contains(scope))
        {
            options.Scope.Add(scope);
        }
    }

    string[] mappedClaimTypes =
    [
        oidcOptions.GroupClaimType,
        oidcOptions.PreferredUsernameClaimType,
        oidcOptions.EmailClaimType,
        oidcOptions.DisplayNameClaimType
    ];
    foreach (string claimType in mappedClaimTypes
        .Where(c => !string.IsNullOrWhiteSpace(c)
                 && !string.Equals(c.Trim(), "sub", StringComparison.OrdinalIgnoreCase)
                 && !string.Equals(c.Trim(), "iss", StringComparison.OrdinalIgnoreCase))
        .Distinct(StringComparer.Ordinal))
    {
        options.ClaimActions.Add(new MultiValueJsonClaimAction(claimType));
    }

    options.ProtocolValidator.RequireNonce = true;

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = !string.IsNullOrWhiteSpace(oidcOptions.EffectiveIssuer)
            ? oidcOptions.EffectiveIssuer
            : null,
        ValidateAudience = true,
        ValidAudience = oidcOptions.ClientId,
        ValidateIssuerSigningKey = true,
        RequireSignedTokens = true,
        ValidateLifetime = true,
        RequireExpirationTime = true,
        ClockSkew = TimeSpan.FromMinutes(2),
        NameClaimType = oidcOptions.PreferredUsernameClaimType,
        RoleClaimType = ClaimTypes.Role
    };

    if (oidcOptions.BackchannelHttpHandler != null)
    {
        options.BackchannelHttpHandler = oidcOptions.BackchannelHttpHandler;
    }

    options.Events = new OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = context =>
        {
            var (valid, err) = oidcOptions.Validate();
            if (!oidcOptions.Enabled || !valid)
            {
                context.HandleResponse();
                context.Response.Redirect("/login?error=" + Uri.EscapeDataString(err ?? "OpenID Connect federated login is not enabled."));
                return Task.CompletedTask;
            }

            context.ProtocolMessage.RedirectUri = oidcOptions.PublicCallbackUrl.Trim();
            return Task.CompletedTask;
        },
        OnRedirectToIdentityProviderForSignOut = context =>
        {
            if (!oidcOptions.Enabled || !oidcOptions.EnableIdpSignOut)
            {
                context.HandleResponse();
                context.Response.Redirect("/login");
                return Task.CompletedTask;
            }

            if (Uri.TryCreate(oidcOptions.PublicCallbackUrl.Trim(), UriKind.Absolute, out Uri? callbackUri))
            {
                UriBuilder postLogoutBuilder = new(callbackUri.Scheme, callbackUri.Host, callbackUri.Port, oidcOptions.SignedOutCallbackPath);
                context.ProtocolMessage.PostLogoutRedirectUri = postLogoutBuilder.Uri.ToString();
            }

            return Task.CompletedTask;
        },
        OnMessageReceived = context =>
        {
            var (valid, err) = oidcOptions.Validate();
            if (!oidcOptions.Enabled || !valid)
            {
                context.HandleResponse();
                context.Response.Redirect("/login?error=" + Uri.EscapeDataString(err ?? "OpenID Connect federated login is not enabled."));
                return Task.CompletedTask;
            }

            if (!context.Request.IsHttps)
            {
                context.HandleResponse();
                context.Response.Redirect("/login?error=" + Uri.EscapeDataString("OpenID Connect callback requires HTTPS (or a trusted reverse proxy forwarding X-Forwarded-Proto: https)."));
                return Task.CompletedTask;
            }

            return Task.CompletedTask;
        },
        OnAuthorizationCodeReceived = context =>
        {
            if (context.TokenEndpointRequest != null && !string.IsNullOrWhiteSpace(oidcOptions.PublicCallbackUrl))
            {
                context.TokenEndpointRequest.RedirectUri = oidcOptions.PublicCallbackUrl.Trim();
            }
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            string? alg = context.SecurityToken?.SignatureAlgorithm;
            if (string.IsNullOrWhiteSpace(alg) || string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
            {
                context.Fail("Unsigned OIDC tokens are not permitted.");
                return Task.CompletedTask;
            }

            string? idTokenSub = context.SecurityToken?.Subject;
            if (string.IsNullOrWhiteSpace(idTokenSub))
            {
                context.Fail("OIDC ID token is missing required 'sub' claim.");
                return Task.CompletedTask;
            }

            context.HttpContext.Items["certrobo:validated_token_issuer"] = context.SecurityToken?.Issuer;
            context.HttpContext.Items["certrobo:validated_token_subject"] = idTokenSub;
            return Task.CompletedTask;
        },
        OnTicketReceived = async context =>
        {
            OidcFederationService oidcService = context.HttpContext.RequestServices.GetRequiredService<OidcFederationService>();
            string? validatedIssuer = context.HttpContext.Items.TryGetValue("certrobo:validated_token_issuer", out object? rawIssuer)
                ? rawIssuer as string
                : null;
            string? validatedSubject = context.HttpContext.Items.TryGetValue("certrobo:validated_token_subject", out object? rawSub)
                ? rawSub as string
                : null;

            if (context.Principal == null)
            {
                context.HandleResponse();
                context.Response.Redirect("/login?error=" + Uri.EscapeDataString("OpenID Connect authentication did not produce a valid principal."));
                return;
            }

            OidcLoginOutcome outcome = await oidcService.ProcessValidatedOidcLoginAsync(
                context.Principal,
                validatedIssuer,
                validatedSubject,
                context.HttpContext.RequestAborted);

            if (!outcome.Succeeded || outcome.ApplicationPrincipal == null)
            {
                context.HandleResponse();
                context.Response.Redirect("/login?error=" + Uri.EscapeDataString(outcome.ErrorMessage ?? "OpenID Connect sign-in was denied."));
                return;
            }

            context.Principal = outcome.ApplicationPrincipal;
            context.Properties ??= new AuthenticationProperties();
            context.Properties.IsPersistent = false;
            context.Properties.AllowRefresh = false;
            context.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(Math.Clamp(oidcOptions.MaxSessionLifetimeMinutes, 1, 1440));
            context.ReturnUri = OidcFederationService.NormalizeReturnUrl(context.ReturnUri);
        },
        OnRemoteFailure = context =>
        {
            string safeMessage = ClassifyOidcFailureMessage(context.Failure);
            context.HandleResponse();
            context.Response.Redirect("/login?error=" + Uri.EscapeDataString(safeMessage));
            return Task.CompletedTask;
        }
    };
}

static string ClassifyOidcFailureMessage(Exception? failure)
{
    if (failure == null)
    {
        return "OpenID Connect authentication failed or was cancelled.";
    }

    for (Exception? ex = failure; ex != null; ex = ex.InnerException)
    {
        if (ex is SecurityTokenExpiredException or SecurityTokenNoExpirationException or SecurityTokenInvalidLifetimeException)
        {
            return "OpenID Connect authentication failed: token has expired or lifetime is invalid.";
        }
        if (ex is SecurityTokenInvalidIssuerException)
        {
            return "OpenID Connect authentication failed: token issuer is invalid.";
        }
        if (ex is SecurityTokenInvalidAudienceException)
        {
            return "OpenID Connect authentication failed: token audience is invalid.";
        }
        if (ex is SecurityTokenInvalidSignatureException or SecurityTokenNotYetValidException)
        {
            return "OpenID Connect authentication failed: token signature or validity check failed.";
        }
        if (ex is OpenIdConnectProtocolInvalidNonceException)
        {
            return "OpenID Connect authentication failed: invalid or missing nonce.";
        }
        if (ex is OpenIdConnectProtocolInvalidStateException)
        {
            return "OpenID Connect authentication failed: invalid or expired state parameter.";
        }
        if (ex.Message.Contains("Correlation failed", StringComparison.OrdinalIgnoreCase)
            || ex.Message.Contains("state", StringComparison.OrdinalIgnoreCase))
        {
            return "OpenID Connect authentication failed: invalid or expired state correlation.";
        }
        if (ex.Message.Contains("nonce", StringComparison.OrdinalIgnoreCase))
        {
            return "OpenID Connect authentication failed: invalid or missing nonce.";
        }
        if (ex.Message.Contains("Unsigned OIDC tokens", StringComparison.OrdinalIgnoreCase))
        {
            return "OpenID Connect authentication failed: token signature or validity check failed.";
        }
        if (ex.Message.Contains("'sub'", StringComparison.OrdinalIgnoreCase)
            || ex.Message.Contains("IDX21314", StringComparison.OrdinalIgnoreCase))
        {
            return "OpenID Connect authentication failed: token is missing a required subject ('sub') claim.";
        }
    }

    return "OpenID Connect authentication failed or was rejected by the identity provider.";
}

public partial class Program { }
