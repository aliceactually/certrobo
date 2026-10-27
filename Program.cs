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
    await db.Database.EnsureCreatedAsync();

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
