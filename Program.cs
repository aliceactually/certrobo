using CertRobo;
using CertRobo.Data;
using CertRobo.Models;
using CertRobo.Services;
using CertRobo.Shared;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Radzen;

var builder = WebApplication.CreateBuilder(args);

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

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "CertRobo.Auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.LoginPath = "/login";
    options.AccessDeniedPath = "/login";
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;
});

builder.Services.Configure<SecurityStampValidatorOptions>(options =>
{
    options.ValidationInterval = TimeSpan.FromSeconds(10);
});

CaKeyCustodyOptions caOptions = new()
{
    StorageDirectory = builder.Configuration["CertRobo:CaStorageDirectory"] ?? Path.Combine(appDataDir, "ca"),
    PassphraseEnvironmentVariable = builder.Configuration["CertRobo:CaPassphraseEnv"] ?? "CERTROBO_CA_PASSPHRASE",
    PassphraseFilePath = builder.Configuration["CertRobo:CaPassphraseFile"],
    ConfiguredPassphrase = builder.Configuration["CertRobo:CaPassphrase"],
    PublicBaseUrl = builder.Configuration["CertRobo:PublicBaseUrl"],
    CrlValidityHours = int.TryParse(builder.Configuration["CertRobo:CrlValidityHours"], out int crlHrs) ? crlHrs : 168
};
builder.Services.AddSingleton(caOptions);

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
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
        BackupRestoreService backupService = scope.ServiceProvider.GetRequiredService<BackupRestoreService>();
        byte[] archiveBytes = await backupService.CreateConsistentBackupArchiveAsync(sqliteDbPath, dpKeysDir);
        string? parentDir = Path.GetDirectoryName(Path.GetFullPath(outputZipPath));
        if (!string.IsNullOrEmpty(parentDir))
        {
            Directory.CreateDirectory(parentDir);
        }
        await File.WriteAllBytesAsync(outputZipPath, archiveBytes);
        Console.WriteLine($"Consistent backup written to '{outputZipPath}' ({archiveBytes.Length} bytes).");
        return;
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
        string pattern = bootstrapIdx + 3 < args.Length ? args[bootstrapIdx + 3] : "*";
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

        CaAuthorityRecord activated = await caService.ActivatePendingCaEnrollmentAsync(pending.Id);
        Console.WriteLine($"Validated and activated external Issuing CA '{activated.Name}' (SKI={activated.SubjectKeyIdentifierHex}).");
        return;
    }

    // Handle CLI CSR issuance:
    // dotnet run -- --issue-csr <username> <csrPath> <outCertPath> [<outChainPath>]
    int issueIdx = Array.IndexOf(args, "--issue-csr");
    if (issueIdx >= 0)
    {
        if (issueIdx + 3 >= args.Length)
        {
            Console.Error.WriteLine("Usage: --issue-csr <username> <csrPath> <outCertPath> [<outChainPath>]");
            Environment.ExitCode = 1;
            return;
        }
        string reqUser = args[issueIdx + 1];
        string csrPath = args[issueIdx + 2];
        string outCertPath = args[issueIdx + 3];
        string? outChainPath = issueIdx + 4 < args.Length ? args[issueIdx + 4] : null;

        UserManager<ApplicationUser> userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        ApplicationUser? user = await userMgr.FindByNameAsync(reqUser);
        if (user == null)
        {
            Console.Error.WriteLine($"User '{reqUser}' not found.");
            Environment.ExitCode = 1;
            return;
        }

        System.IO.FileInfo csrInfo = new(csrPath);
        if (!csrInfo.Exists || csrInfo.Length > IssuancePolicyService.MaxCsrPemLength)
        {
            Console.Error.WriteLine($"Issuance failed: CSR file '{csrPath}' does not exist or exceeds the maximum permitted size ({IssuancePolicyService.MaxCsrPemLength} bytes).");
            Environment.ExitCode = 1;
            return;
        }

        string csrPem = await File.ReadAllTextAsync(csrPath);
        CertificateAuthorityService caService = scope.ServiceProvider.GetRequiredService<CertificateAuthorityService>();
        IssuanceOutcome outcome = await caService.IssueCertificateFromCsrAsync(user.Id, csrPem);
        if (!outcome.Succeeded)
        {
            Console.Error.WriteLine($"Issuance failed: {outcome.ErrorMessage}");
            Environment.ExitCode = 1;
            return;
        }

        await File.WriteAllTextAsync(outCertPath, outcome.CertificatePem);
        if (!string.IsNullOrEmpty(outChainPath))
        {
            await File.WriteAllTextAsync(outChainPath, outcome.FullChainPem);
        }
        Console.WriteLine($"Issued certificate serial {outcome.Record!.SerialNumberHex} for '{outcome.Record.CommonName}' -> {outCertPath}");
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

public partial class Program { }
